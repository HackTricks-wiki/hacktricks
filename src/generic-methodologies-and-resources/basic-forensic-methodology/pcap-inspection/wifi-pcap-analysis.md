# Wifi Pcap विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDs जाँचें

Wi-Fi capture को Wireshark में खोलकर, capture में देखे गए wireless networks का सारांश देखने के लिए _Wireless → WLAN Traffic_ चुनें; हर पंक्ति एक wireless network दर्शाती है।<sup>[[1]](#references)</sup>

![Wifi Pcap विश्लेषण - BSSIDs जाँचें: जब आपको ऐसा capture मिलता है जिसका मुख्य traffic Wireshark का उपयोग करके Wifi है, तो आप Wireless --... के साथ capture के सभी SSIDs की जाँच शुरू कर सकते हैं](<../../../images/image (106).png>)

![Wifi Pcap विश्लेषण - BSSIDs जाँचें: जब आपको ऐसा capture मिलता है जिसका मुख्य traffic Wireshark का उपयोग करके Wifi है, तो आप Wireless --... के साथ capture के सभी SSIDs की जाँच शुरू कर सकते हैं](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK captures के लिए, `aircrack-ng` को उपयोगी four-way EAPOL handshake की आवश्यकता होती है और यह dictionary की मदद से संभावित passphrases जाँचता है। wordlist देने के लिए `-w` और access point के BSSID को लक्ष्य बनाने के लिए `-b` का उपयोग करें:<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

यदि कोई candidate match करता है, तो Aircrack-ng pre-shared key रिकवर कर लेता है; matching password और SSID को बाद में Wireshark की 802.11 decryption settings में configure किया जा सकता है, बशर्ते capture और security mode इसका समर्थन करते हों।<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons / Side Channel में डेटा

यदि आपको संदेह है कि **beacon-side-channel traffic में डेटा leak हो रहा है**, तो `wlan contains "NAMEofNETWORK"` या `wlan.ssid == "NAMEofNETWORK"` जैसे display filter से शुरुआत करें, फिर suspicious strings के लिए matching frames की जाँच करें। पहला विकल्प व्यापक byte search करता है; दूसरा SSID field से match करता है।<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi Network में Unknown MAC Addresses ढूँढ़ें

Wireshark `wlan.ta` को transmitter address और `wlan.addr` को hardware/MAC address के रूप में दिखाता है; display filters इन fields को logical operators के साथ जोड़ सकते हैं:<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

यदि आपको **MAC addresses** पहले से पता हैं, तो `&& !(wlan.addr == 5c:51:88:31:a0:3b)` जैसी जाँच जोड़कर उन्हें output से हटाएँ।

Network के अंदर संचार करते हुए **unknown MAC** addresses का पता चलने पर, उसके traffic को सीमित करने के लिए `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` जैसा filter इस्तेमाल करें। FTP, HTTP, SSH और Telnet filters तभी उपयोगी हैं, जब Wireshark संबंधित decrypted payload को dissect कर सके।<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic Decrypt करें

Wireshark में 802.11 decryption key जोड़ने के लिए, _Edit → Preferences → Protocols → IEEE 802.11_ खोलें और _Decryption Keys_ के बगल में _Edit_ पर क्लिक करें।<sup>[[5]](#references)</sup>

![Wi-Fi Network में Unknown MAC Addresses ढूँढ़ें - Traffic Decrypt करें: Network के अंदर संचार करते हुए unknown MAC addresses का पता चलने पर, आप निम्नलिखित जैसे filters इस्तेमाल कर सकते हैं:...](<../../../images/image (499).png>)

WPA/WPA2 के लिए Wireshark को आम तौर पर EAPOL four-way handshake और matching password/SSID की ज़रूरत होती है; transient key देने से handshake की आवश्यकता नहीं रहती। WPA3 में प्रति-connection decryption के लिए उस connection का PMK आवश्यक है।<sup>[[5]](#references)</sup>

Wi-Fi traffic रिकवर करने के बाद application-layer TLS decryption के लिए, [Wireshark tricks](wireshark-tricks.md#decrypting-tls) देखें।

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expressions बनाना](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
