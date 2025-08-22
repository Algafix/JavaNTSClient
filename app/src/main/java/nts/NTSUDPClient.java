/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nts;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.net.DatagramSocketClient;

import nts.NTSExtensionFields.FieldType;
import nts.NTSExtensionFields.NTSExtensionField;

/**
 * The NTPUDPClient class is a UDP implementation of a client for the Network Time Protocol (NTP) described in RFC 1305 as well as the Simple Network Time
 * Protocol (SNTP) in RFC-2030. To use the class, merely open a local datagram socket with <a href="#open"> open </a> and call <a href="#getTime"> getTime </a>
 * to retrieve the time. Then call <a href="org.apache.commons.net.DatagramSocketClient.html#close"> close </a> to close the connection properly. Successive
 * calls to <a href="#getTime"> getTime </a> are permitted without re-establishing a connection. That is because UDP is a connectionless protocol and the
 * Network Time Protocol is stateless.
 */
public final class NTSUDPClient extends DatagramSocketClient {
    /** The default NTP port. It is set to 123 according to RFC 1305. */
    public static final int DEFAULT_PORT = 123;

    private int version = NtpV3Packet.VERSION_4;

    private List<NTSPeer> peers = new ArrayList<>();

    private NTSPeer getNtsPeer(final InetAddress host) {
        for (NTSPeer peer : peers) {
            if (peer.KEHost.equals(host.getHostAddress())) {
                return peer;
            }
        }
        NTSPeer peer = new NTSPeer(host.getHostAddress());
        peers.add(peer);
        return peer;
    }

    private void removeNtsPeer(final InetAddress host){
        NTSPeer peer = getNtsPeer(host);
        if(peer != null)
        {
            peers.remove(peer);
        }
    }

    /**
     * Retrieves the time information from the specified server on the default NTP port and returns it. The time is the number of milliseconds since 00:00
     * (midnight) 1 January 1900 UTC, as specified by RFC 1305. This method reads the raw NTP packet and constructs a <i>TimeInfo</i> object that allows access
     * to all the fields of the NTP message header.
     *
     * @param host The address of the server.
     * @return The time value retrieved from the server.
     * @throws IOException If an error occurs while retrieving the time.
     */
    public TimeInfo getTime(final InetAddress host) throws IOException, AuthenticationFailureException, NtsNakException {
        return getTime(host, NtpV3Packet.NTP_PORT);
    }

    /**
     * Retrieves the time information from the specified server and port and returns it. The time is the number of milliseconds since 00:00 (midnight) 1 January
     * 1900 UTC, as specified by RFC 1305. This method reads the raw NTP packet and constructs a <i>TimeInfo</i> object that allows access to all the fields of
     * the NTP message header.
     *
     * @param host The address of the server.
     * @param port The port of the service.
     * @return The time value retrieved from the server.
     * @throws IOException If an error occurs while retrieving the time or if received packet does not match the request.
     */
    public TimeInfo getTime(final InetAddress host, final int port) throws IOException, AuthenticationFailureException, NtsNakException {

        // Check if we have a valid handshake with the host
        NTSPeer peer = getNtsPeer(host);
        if(peer.nakReceived)
        {
            peer.doHandshake();
        }
        NTSConfig ntsConfig = peer.ntsConfig;

        // if not connected then open to next available UDP port
        if (!isOpen()) {
            open();
        }

        // Craft the client message
        final NtsImpl message = new NtsImpl(ntsConfig.C2SKey);

        // Use one of the negotiated cookies
        byte [] cookie = ntsConfig.cookies.get(0);
        ntsConfig.cookies.remove(0);

        // Replace used cookies (try to maintain a backlog of 8)
        final int ncookies_needed = 8 - ntsConfig.cookies.size();
        message.buildRequest(cookie, ncookies_needed);

        // Obtain the datagram packets for the request and response
        final DatagramPacket sendPacket = message.getDatagramPacket();
        sendPacket.setAddress(host);
        sendPacket.setPort(port);

        final NtsPacket recMessage = new NtsImpl(ntsConfig.S2CKey);
        final DatagramPacket receivePacket = recMessage.getDatagramPacket(sendPacket.getLength());

        /*
         * Must minimize the time between getting the current time, timestamping the packet, and sending it out which introduces an error in the delay time. No
         * extraneous logging and initializations here !!!
         */
        final TimeStamp now = TimeStamp.getCurrentTime();

        // Note that if you do not set the transmit time field then originating time
        // in server response is all 0's which is "Thu Feb 07 01:28:16 EST 2036".
        message.setTransmitTime(now);
        // And now we can create the authentication and encryption Extension Field
        message.createAuthAndEncEF();

        checkOpen().send(sendPacket);
        checkOpen().receive(receivePacket);

        final long returnTimeMillis = System.currentTimeMillis();

        // Prevent invalid time information if response does not match request
        try
        {
            recMessage.validate(message);
            peer.nakReceived = false;

            List<NTSExtensionField> new_cookies = recMessage.getExtensionFields(FieldType.NTS_COOKIE.getValue());
            for(NTSExtensionField new_cookie: new_cookies)
            {
                ntsConfig.cookies.add(new_cookie.body);
            }
        }
        catch( NtsNakException e)
        {
            // RFC8915: store the fact that a NAK has been received
            // And try to re-initiate the handshake (but don't throw out the old cookies)
            peer.nakReceived = true;
            throw e;
        }
        catch(Exception e)
        {
            throw e;
        }

        // create TimeInfo message container but don't pre-compute the details yet
        return new TimeInfo(recMessage, returnTimeMillis, false);
    }

    /**
     * Returns the NTP protocol version number that client sets on request packet that is sent to remote host (e.g. 3=NTP v3, 4=NTP v4, etc.)
     *
     * @return the NTP protocol version number that client sets on request packet.
     * @see #setVersion(int)
     */
    public int getVersion() {
        return version;
    }

    /**
     * Sets the NTP protocol version number that client sets on request packet communicate with remote host.
     *
     * @param version the NTP protocol version number
     */
    public void setVersion(final int version) {
        this.version = version;
    }

}
