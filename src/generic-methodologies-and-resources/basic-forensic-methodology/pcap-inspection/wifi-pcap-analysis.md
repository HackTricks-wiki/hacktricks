# Wi-Fi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDの確認

Wi-Fi captureをWiresharkで開き、_Wireless → WLAN Traffic_ を選択すると、capture内で観測された wireless network の概要を確認できます。各行は1つの wireless network を表します。<sup>[[1]](#references)</sup>

![Wi-Fi Pcap Analysis - BSSIDの確認: 主なtrafficがWi-FiであるcaptureをWireSharkで受け取った場合、Wireless --...を使用してcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (106).png>)

![Wi-Fi Pcap Analysis - BSSIDの確認: 主なtrafficがWi-FiであるcaptureをWireSharkで受け取った場合、Wireless --...を使用してcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK captureの場合、`aircrack-ng` は使用可能な4-way EAPOL handshakeを必要とし、dictionaryを使って候補となるpassphraseをテストします。`-w` でwordlistを指定し、`-b` でaccess pointのBSSIDを対象にします。<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
候補が一致すると、Aircrack-ng は pre-shared key を復元します。その後、capture と security mode が対応していれば、一致した password と SSID を Wireshark の 802.11 decryption settings に設定できます。<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons 内のデータ / Side Channel

**data が beacon-side-channel traffic で leak している**と疑われる場合は、まず `wlan contains "NAMEofNETWORK"` や `wlan.ssid == "NAMEofNETWORK"` のような display filter から始め、該当する frames に suspicious strings がないか調べます。前者は広範な byte search で、後者は SSID field に一致します。<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi Network 内の Unknown MAC Addresses を見つける

Wireshark では、`wlan.ta` は transmitter address として、`wlan.addr` は hardware/MAC address として扱われます。display filters では、logical operators を使ってこれらの fields を組み合わせられます。<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

既知の **MAC addresses** がある場合は、`&& !(wlan.addr == 5c:51:88:31:a0:3b)` のような checks を追加して、**MAC addresses を output から除外**します。

Network 内で通信している **unknown MAC** addresses を検出したら、`wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` のような filter を使って、その traffic を絞り込みます。FTP、HTTP、SSH、Telnet の filters は、Wireshark が対応する decrypted payload を dissect できる場合にのみ有用です。<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic を復号する

Wireshark に 802.11 decryption key を追加するには、_Edit → Preferences → Protocols → IEEE 802.11_ を開き、_Decryption Keys_ の隣にある _Edit_ をクリックします。<sup>[[5]](#references)</sup>

![Wi-Fi Network 内の Unknown MAC Addresses を見つける - Traffic を復号する: Network 内で通信している unknown MAC addresses を検出したら、次のような filters を使用できます:...](<../../../images/image (499).png>)

WPA/WPA2 では、Wireshark は通常、EAPOL four-way handshake と一致する password/SSID を必要とします。transient key を指定すれば、handshake の要件を回避できます。WPA3 の per-connection decryption には、その connection の PMK が必要です。<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expressions の構築](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
