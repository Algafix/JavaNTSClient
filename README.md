# JavaNTSClient

JavaNTSClient is a Java-based library designed to interact as a client with Network Time Security (NTS) server.

The file [NTSTime.java](https://github.com/Algafix/JavaNTSClient/blob/main/app/src/main/java/NTSTime.java) contains an very easy example on how to use the library. A more complex example of its use by an Android app can be found [here](https://github.com/odrisci/SntsSampleAndroidApp).

In general, only one `NTSUDPClient` object need to be instatiated. Multiple time severs can be queried from the same `NTSUDPClient` object using the `getTime` method.
The library handles the TLS handshake, key extraction and cookie management independently for each time server.

The interface is compatible and inspired by the [Apache Commons NTP library](https://commons.apache.org/proper/commons-net/apidocs/org/apache/commons/net/ntp/package-summary.html).

## Attribution

This library was developed by:

* [Aleix Galan-Figueras](https://orcid.org/0000-0002-5762-6982), KU Leuven, Belgium
* [Cillian O'Driscoll](https://orcid.org/0000-0002-2416-5761), Independent consultant, Ireland
* [Ignacio Fernandez-Hernandez](https://orcid.org/0000-0002-9308-1668), KU Leuven, Belgium
