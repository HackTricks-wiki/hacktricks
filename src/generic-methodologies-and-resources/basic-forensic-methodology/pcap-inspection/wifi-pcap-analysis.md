# Uchambuzi wa Wifi Pcap

## Kagua BSSID

Ukiwa na Wi-Fi capture iliyofunguliwa kwenye Wireshark, chagua _Wireless → WLAN Traffic_ ili kutoa muhtasari wa wireless networks zilizoonekana kwenye capture; kila safu inawakilisha wireless network moja.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Kagua BSSID: Unapopokea capture ambayo traffic yake kuu ni Wifi ukitumia WireShark, unaweza kuanza kuchunguza SSID zote za capture kwa kutumia Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Kagua BSSID: Unapopokea capture ambayo traffic yake kuu ni Wifi ukitumia WireShark, unaweza kuanza kuchunguza SSID zote za capture kwa kutumia Wireless --...](<../../../images/image (492).png>)

### Brute Force

Kwa WPA/WPA2-PSK captures, `aircrack-ng` inahitaji four-way EAPOL handshake inayoweza kutumika na hujaribu passphrases mbadala kwa kutumia dictionary. Tumia `-w` kutoa wordlist na `-b` kulenga BSSID ya access point:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Ikiwa candidate inalingana, Aircrack-ng hurejesha pre-shared key; password na SSID inayolingana zinaweza kisha kusanidiwa katika mipangilio ya decryption ya 802.11 ya Wireshark wakati capture na security mode zinaunga mkono hilo.<sup>[[2]](#references)[[5]](#references)</sup>

## Data katika Beacons / Side Channel

Ikiwa unashuku kuwa **data inavuja katika beacon-side-channel traffic**, anza na display filter kama `wlan contains "NAMEofNETWORK"` au `wlan.ssid == "NAMEofNETWORK"`, kisha kagua frames zinazolingana kwa strings zinazotiliwa shaka. Aina ya kwanza ni utafutaji mpana wa bytes; ya pili inalinganisha sehemu ya SSID.<sup>[[3]](#references)[[4]](#references)</sup>

## Tafuta Unknown MAC Addresses katika Wi-Fi Network

Wireshark huonyesha `wlan.ta` kama transmitter address na `wlan.addr` kama hardware/MAC address; display filters zinaweza kuchanganya fields hizi kwa kutumia logical operators:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Ikiwa tayari unajua **MAC addresses, ziondoe kwenye output** kwa kuongeza checks kama `&& !(wlan.addr == 5c:51:88:31:a0:3b)`.

Baada ya kugundua **unknown MAC** addresses zinazowasiliana ndani ya network, tumia filter kama `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` ili kupunguza traffic yake. Filters za FTP, HTTP, SSH, na Telnet zinafaa tu wakati Wireshark inaweza kudissect payload iliyodecryptiwa inayolingana.<sup>[[3]](#references)[[5]](#references)</sup>

## Decrypt Traffic

Ili kuongeza 802.11 decryption key katika Wireshark, fungua _Edit → Preferences → Protocols → IEEE 802.11_ na ubofye _Edit_ karibu na _Decryption Keys_.<sup>[[5]](#references)</sup>

![Tafuta Unknown MAC Addresses katika Wi-Fi Network - Decrypt Traffic: Baada ya kugundua unknown MAC addresses zinazowasiliana ndani ya network, unaweza kutumia filters kama ifuatayo:...](<../../../images/image (499).png>)

Kwa WPA/WPA2, Wireshark kwa kawaida huhitaji EAPOL four-way handshake na password/SSID inayolingana; kutoa transient key kunaweza kuondoa hitaji la handshake. WPA3 per-connection decryption huhitaji PMK ya connection.<sup>[[5]](#references)</sup>

## References

- [1] [Mwongozo wa Mtumiaji wa Wireshark: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Mwongozo wa Mtumiaji wa Wireshark: Kujenga Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Mwongozo wa Mtumiaji wa Wireshark: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
