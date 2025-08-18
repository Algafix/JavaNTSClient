import java.text.NumberFormat;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import nts.*;
//import org.apache.commons.net.ntp.*;

public class NtpTime {

    private static final NumberFormat numberFormat = new java.text.DecimalFormat("0.00");

    public static void main(String[] args) throws Exception {
        //String TIME_SERVER = "pool.ntp.org";
        //String TIME_SERVER = "paris.time.system76.com";
        final List<String> TIME_SERVERS = new ArrayList<>(
            List.of("paris.time.system76.com", "time.cloudflare.com"));
        for( String srv : TIME_SERVERS)
        {
            NTPUDPClient client = new NTPUDPClient();
            client.setVersion(4);
            InetAddress hostAddr = InetAddress.getByName(srv);
            TimeInfo info = client.getTime(hostAddr);
            System.out.println(" Server: " + srv);
            processResponse(info);

            client.close();
        }
    }
    
    public static void processResponse(final TimeInfo info) {
        final NtpV3Packet message = info.getMessage();
        final int stratum = message.getStratum();
        final String refType;
        if (stratum <= 0) {
            refType = "(Unspecified or Unavailable)";
        } else if (stratum == 1) {
            refType = "(Primary Reference; e.g., GPS)"; // GPS, radio clock, etc.
        } else {
            refType = "(Secondary Reference; e.g. via NTP or SNTP)";
        }
        // stratum should be 0..15...
        System.out.println(" Stratum: " + stratum + " " + refType);
        final int version = message.getVersion();
        final int li = message.getLeapIndicator();
        System.out.println(" leap=" + li + ", version=" + version + ", precision=" + message.getPrecision());

        System.out.println(" mode: " + message.getModeName() + " (" + message.getMode() + ")");
        final int poll = message.getPoll();
        // poll value typically btwn MINPOLL (4) and MAXPOLL (14)
        System.out.println(" poll: " + (poll <= 0 ? 1 : (int) Math.pow(2, poll)) + " seconds" + " (2 ** " + poll + ")");
        final double disp = message.getRootDispersionInMillisDouble();
        System.out.println(" rootdelay=" + numberFormat.format(message.getRootDelayInMillisDouble()) + ", rootdispersion(ms): " + numberFormat.format(disp));

        final int refId = message.getReferenceId();
        String refAddr = NtpUtils.getHostAddress(refId);
        String refName = null;
        if (refId != 0) {
            if (refAddr.equals("127.127.1.0")) {
                refName = "LOCAL"; // This is the ref address for the Local Clock
            } else if (stratum >= 2) {
                // If reference id has 127.127 prefix then it uses its own reference clock
                // defined in the form 127.127.clock-type.unit-num (e.g. 127.127.8.0 mode 5
                // for GENERIC DCF77 AM; see refclock.htm from the NTP software distribution.
                if (!refAddr.startsWith("127.127")) {
                    try {
                        final InetAddress addr = InetAddress.getByName(refAddr);
                        final String name = addr.getHostName();
                        if (name != null && !name.equals(refAddr)) {
                            refName = name;
                        }
                    } catch (final UnknownHostException e) {
                        // some stratum-2 servers sync to ref clock device but fudge stratum level higher... (e.g. 2)
                        // ref not valid host maybe it's a reference clock name?
                        // otherwise just show the ref IP address.
                        refName = NtpUtils.getReferenceClock(message);
                    }
                }
            } else if (version >= 3 && (stratum == 0 || stratum == 1)) {
                refName = NtpUtils.getReferenceClock(message);
                // refname usually have at least 3 characters (e.g. GPS, WWV, LCL, etc.)
            }
            // otherwise give up on naming the beast...
        }
        if (refName != null && refName.length() > 1) {
            refAddr += " (" + refName + ")";
        }
        System.out.println(" Reference Identifier:\t" + refAddr);

        final TimeStamp refNtpTime = message.getReferenceTimeStamp();
        System.out.println(" Reference Timestamp:\t" + refNtpTime + "  " + refNtpTime.toDateString());

        // Originate Time is time request sent by client (t1)
        final TimeStamp origNtpTime = message.getOriginateTimeStamp();
        System.out.println(" Originate Timestamp:\t" + origNtpTime + "  " + origNtpTime.toDateString());

        final long destTimeMillis = info.getReturnTime();
        // Receive Time is time request received by server (t2)
        final TimeStamp rcvNtpTime = message.getReceiveTimeStamp();
        System.out.println(" Receive Timestamp:\t" + rcvNtpTime + "  " + rcvNtpTime.toDateString());

        // Transmit time is time reply sent by server (t3)
        final TimeStamp xmitNtpTime = message.getTransmitTimeStamp();
        System.out.println(" Transmit Timestamp:\t" + xmitNtpTime + "  " + xmitNtpTime.toDateString());

        // Destination time is time reply received by client (t4)
        final TimeStamp destNtpTime = TimeStamp.getNtpTime(destTimeMillis);
        System.out.println(" Destination Timestamp:\t" + destNtpTime + "  " + destNtpTime.toDateString());

        info.computeDetails(); // compute offset/delay if not already done
        final Long offsetMillis = info.getOffset();
        final Long delayMillis = info.getDelay();
        final String delay = delayMillis == null ? "N/A" : delayMillis.toString();
        final String offset = offsetMillis == null ? "N/A" : offsetMillis.toString();

        System.out.println(" Roundtrip delay(ms)=" + delay + ", clock offset(ms)=" + offset); // offset in ms
    }
}
