# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDs जाँचें

Wi-Fi capture को Wireshark में खोलकर, capture में देखे गए wireless networks का सारांश देखने के लिए _Wireless → WLAN Traffic_ चुनें; प्रत्येक row एक wireless network को दर्शाती है।<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - BSSIDs जाँचें: जब आपको ऐसा capture मिलता है जिसमें मुख्य traffic WireShark का उपयोग करने वाला Wifi होता है, तो आप Wireless --... के माध्यम से capture के सभी SSIDs की जाँच शुरू कर सकते हैं।](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSIDs जाँचें: जब आपको ऐसा capture मिलता है जिसमें मुख्य traffic WireShark का उपयोग करने वाला Wifi होता है, तो आप Wireless --... के माध्यम से capture के सभी SSIDs की जाँच शुरू कर सकते हैं।](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK captures के लिए, `aircrack-ng` को एक usable four-way EAPOL handshake की आवश्यकता होती है और यह dictionary की सहायता से candidate passphrases का परीक्षण करता है। wordlist देने के लिए `-w` और access point के BSSID को target करने के लिए `-b` का उपयोग करें:<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
यदि कोई candidate match करता है, तो Aircrack-ng pre-shared key recover कर लेता है; इसके बाद matching password और SSID को Wireshark की 802.11 decryption settings में configure किया जा सकता है, जब capture और security mode इसका support करते हों।<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons / Side Channel में Data

यदि आपको संदेह है कि **data beacon-side-channel traffic में leak हो रहा है**, तो `wlan contains "NAMEofNETWORK"` या `wlan.ssid == "NAMEofNETWORK"` जैसे display filter से शुरुआत करें, फिर matching frames में suspicious strings की जांच करें। पहला form broad byte search करता है; दूसरा SSID field से match करता है।<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi Network में Unknown MAC Addresses खोजें

Wireshark `wlan.ta` को transmitter address और `wlan.addr` को hardware/MAC address के रूप में दिखाता है; display filters इन fields को logical operators के साथ combine कर सकते हैं:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

यदि आपको **MAC addresses पहले से पता हैं, तो उन्हें output से हटाएं** और `&& !(wlan.addr == 5c:51:88:31:a0:3b)` जैसे checks जोड़ें।

जब आप network के अंदर communicate कर रहे **unknown MAC** addresses का पता लगा लें, तो उसके traffic को सीमित करने के लिए `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` जैसा filter इस्तेमाल करें। FTP, HTTP, SSH और Telnet filters तभी उपयोगी होते हैं जब Wireshark संबंधित decrypted payload को dissect कर सके।<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic Decrypt करें

Wireshark में 802.11 decryption key जोड़ने के लिए _Edit → Preferences → Protocols → IEEE 802.11_ खोलें और _Decryption Keys_ के पास _Edit_ पर click करें।<sup>[[5]](#references)</sup>

![Wi-Fi Network में Unknown MAC Addresses खोजें - Traffic Decrypt करें: जब आप network के अंदर communicate कर रहे unknown MAC addresses का पता लगा लें, तो आप निम्नलिखित जैसे filters इस्तेमाल कर सकते हैं:...](<../../../images/image (499).png>)

WPA/WPA2 के लिए, Wireshark को सामान्यतः EAPOL four-way handshake और matching password/SSID की आवश्यकता होती है; transient key देने से handshake की आवश्यकता से बचा जा सकता है। WPA3 per-connection decryption के लिए उस connection का PMK आवश्यक है।<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expressions बनाना](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
