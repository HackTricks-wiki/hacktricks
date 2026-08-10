# Wifi Pcap Analysis

## BSSIDの確認

WiresharkでWi-Fi captureを開き、_Wireless → WLAN Traffic_を選択すると、captureで確認されたwireless networkの概要が表示されます。各行は1つのwireless networkを表します。<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - BSSIDの確認: WireSharkを使用して主なtrafficがWifiであるcaptureを受け取った場合、Wireless --...からcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSIDの確認: WireSharkを使用して主なtrafficがWifiであるcaptureを受け取った場合、Wireless --...からcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK capturesの場合、`aircrack-ng`は使用可能な4-way EAPOL handshakeを必要とし、dictionaryを使用して候補passphraseをテストします。wordlistを指定するには`-w`を使用し、access pointのBSSIDを対象にするには`-b`を使用します。<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
候補が一致すると、Aircrack-ng は pre-shared key を復元します。その後、キャプチャとセキュリティモードが対応していれば、一致した password と SSID を Wireshark の 802.11 復号設定に構成できます。<sup>[[2]](#references)[[5]](#references)</sup>

## Data in Beacons / Side Channel

**データが beacon-side-channel traffic で leak している**と疑われる場合は、まず `wlan contains "NAMEofNETWORK"` や `wlan.ssid == "NAMEofNETWORK"` などの display filter から始め、一致するフレームに suspicious strings がないか確認します。前者は広範な byte search で、後者は SSID field に一致します。<sup>[[3]](#references)[[4]](#references)</sup>

## Find Unknown MAC Addresses in a Wi-Fi Network

Wireshark では、`wlan.ta` は transmitter address、`wlan.addr` は hardware/MAC address として公開されています。display filter では、logical operators を使ってこれらの field を組み合わせられます。<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

既知の **MAC addresses** がある場合は、`&& !(wlan.addr == 5c:51:88:31:a0:3b)` のような check を追加して、出力から除外します。

ネットワーク内で通信している **unknown MAC** addresses を検出したら、`wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` のような filter を使用して、その traffic を絞り込みます。FTP、HTTP、SSH、Telnet の filter が役立つのは、Wireshark が対応する decrypted payload を dissect できる場合に限られます。<sup>[[3]](#references)[[5]](#references)</sup>

## Decrypt Traffic

Wireshark に 802.11 decryption key を追加するには、_Edit → Preferences → Protocols → IEEE 802.11_ を開き、_Decryption Keys_ の横にある _Edit_ をクリックします。<sup>[[5]](#references)</sup>

![Wi-Fi Network で Unknown MAC Addresses を見つける - Decrypt Traffic: ネットワーク内で通信している unknown MAC addresses を検出したら、次のような filter を使用できます:...](<../../../images/image (499).png>)

WPA/WPA2 では、通常、Wireshark は EAPOL four-way handshake と一致する password/SSID を必要とします。transient key を指定すると、handshake の要件を回避できます。WPA3 の per-connection decryption には、その connection の PMK が必要です。<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expressions の構築](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
