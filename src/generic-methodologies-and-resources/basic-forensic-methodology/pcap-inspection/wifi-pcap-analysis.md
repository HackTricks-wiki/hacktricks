# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDs जांचें

जब आपको ऐसा capture मिलता है जिसमें मुख्य traffic Wifi का हो, तो WireShark का उपयोग करके आप _Wireless --> WLAN Traffic_ के माध्यम से capture के सभी SSIDs की जांच शुरू कर सकते हैं:

![Wifi Pcap Analysis - BSSIDs जांचें: जब आपको ऐसा capture मिलता है जिसमें मुख्य traffic Wifi का हो, तो WireShark का उपयोग करके आप Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSIDs जांचें: जब आपको ऐसा capture मिलता है जिसमें मुख्य traffic Wifi का हो, तो WireShark का उपयोग करके आप Wireless --...](<../../../images/image (492).png>)

### Brute Force

उस screen के एक column से पता चलता है कि **क्या pcap के अंदर कोई authentication मिला है**। यदि ऐसा है, तो आप `aircrack-ng` का उपयोग करके इसे Brute force करने का प्रयास कर सकते हैं:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
उदाहरण के लिए, यह PSK (pre shared-key) को सुरक्षित रखने वाला WPA passphrase प्राप्त करेगा, जिसकी बाद में traffic को decrypt करने के लिए आवश्यकता होगी।

## Beacons / Side Channel में Data

यदि आपको संदेह है कि **किसी Wifi network के beacons के अंदर data leak हो रहा है**, तो आप निम्नलिखित जैसे filter का उपयोग करके network के beacons को check कर सकते हैं: `wlan contains <NAMEofNETWORK>`, या `wlan.ssid == "NAMEofNETWORK"`। फ़िल्टर किए गए packets के अंदर suspicious strings खोजें।

## A Wifi Network में Unknown MAC Addresses खोजें

निम्नलिखित link **Wifi Network के अंदर data भेजने वाली machines** खोजने के लिए उपयोगी होगा:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

यदि आप **MAC addresses पहले से जानते हैं, तो checks जोड़कर उन्हें output से हटा सकते हैं**: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Network के अंदर communicate करने वाले **unknown MAC** addresses का पता लगाने के बाद, आप इसके traffic को filter करने के लिए निम्नलिखित जैसे **filters** का उपयोग कर सकते हैं: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`। ध्यान दें कि ftp/http/ssh/telnet filters तब उपयोगी होते हैं जब आपने traffic को decrypt कर लिया हो।

## Traffic Decrypt करें

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![A Wifi Network में Unknown MAC Addresses खोजें - Traffic Decrypt करें: Network के अंदर communicate करने वाले unknown MAC addresses का पता लगाने के बाद, आप इसके traffic को filter करने के लिए निम्नलिखित जैसे filters का उपयोग कर सकते हैं...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
