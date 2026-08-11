# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## Check BSSIDs

With a Wi-Fi capture open in Wireshark, select _Wireless → WLAN Traffic_ to summarize the wireless networks observed in the capture; each row represents one wireless network.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (492).png>)

### Brute Force

For WPA/WPA2-PSK captures, `aircrack-ng` requires a usable four-way EAPOL handshake and tests candidate passphrases with a dictionary. Use `-w` to provide the wordlist and `-b` to target the access point's BSSID:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

If a candidate matches, Aircrack-ng recovers the pre-shared key; the matching password and SSID can then be configured in Wireshark's 802.11 decryption settings when the capture and security mode support it.<sup>[[2]](#references)[[5]](#references)</sup>

## Data in Beacons / Side Channel

If you suspect that **data is being leaked in beacon-side-channel traffic**, start with a display filter such as `wlan contains "NAMEofNETWORK"` or `wlan.ssid == "NAMEofNETWORK"`, then inspect matching frames for suspicious strings. The first form is a broad byte search; the second matches the SSID field.<sup>[[3]](#references)[[4]](#references)</sup>

## Find Unknown MAC Addresses in a Wi-Fi Network

Wireshark exposes `wlan.ta` as the transmitter address and `wlan.addr` as a hardware/MAC address; display filters can combine these fields with logical operators:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

If you already know **MAC addresses, remove them from the output** by adding checks like `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Once you have detected **unknown MAC** addresses communicating inside the network, use a filter such as `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` to narrow its traffic. The FTP, HTTP, SSH, and Telnet filters are useful only when Wireshark can dissect the corresponding decrypted payload.<sup>[[3]](#references)[[5]](#references)</sup>

## Decrypt Traffic

To add an 802.11 decryption key in Wireshark, open _Edit → Preferences → Protocols → IEEE 802.11_ and click _Edit_ next to _Decryption Keys_.<sup>[[5]](#references)</sup>

![Find Unknown MAC Addresses in A Wifi Network - Decrypt Traffic: Once you have detected unknown MAC addresses communicating inside the network you can use filters like the following one:...](<../../../images/image (499).png>)

For WPA/WPA2, Wireshark normally needs the EAPOL four-way handshake and the matching password/SSID; supplying the transient key can avoid the handshake requirement. WPA3 per-connection decryption requires the connection's PMK.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Building Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)

{{#include ../../../banners/hacktricks-training.md}}
