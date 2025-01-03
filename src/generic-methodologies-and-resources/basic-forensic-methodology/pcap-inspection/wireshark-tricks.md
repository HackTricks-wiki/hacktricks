# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## अपने Wireshark कौशल में सुधार करें

### ट्यूटोरियल

निम्नलिखित ट्यूटोरियल कुछ शानदार बुनियादी ट्रिक्स सीखने के लिए अद्भुत हैं:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### विश्लेषित जानकारी

**विशेषज्ञ जानकारी**

_**Analyze** --> **Expert Information**_ पर क्लिक करने से आपको पैकेट्स में हो रही घटनाओं का **अवलोकन** मिलेगा **विश्लेषित**:

![](<../../../images/image (256).png>)

**समाधान किए गए पते**

_**Statistics --> Resolved Addresses**_ के तहत आप कई **जानकारी** पा सकते हैं जो wireshark द्वारा "**समाधान**" की गई थी जैसे पोर्ट/परिवहन से प्रोटोकॉल, MAC से निर्माता, आदि। यह जानना दिलचस्प है कि संचार में क्या शामिल है।

![](<../../../images/image (893).png>)

**प्रोटोकॉल पदानुक्रम**

_**Statistics --> Protocol Hierarchy**_ के तहत आप संचार में शामिल **प्रोटोकॉल** और उनके बारे में डेटा पा सकते हैं।

![](<../../../images/image (586).png>)

**संवाद**

_**Statistics --> Conversations**_ के तहत आप संचार में **संवादों का सारांश** और उनके बारे में डेटा पा सकते हैं।

![](<../../../images/image (453).png>)

**अंत बिंदु**

_**Statistics --> Endpoints**_ के तहत आप संचार में **अंत बिंदुओं का सारांश** और उनके बारे में डेटा पा सकते हैं।

![](<../../../images/image (896).png>)

**DNS जानकारी**

_**Statistics --> DNS**_ के तहत आप कैप्चर किए गए DNS अनुरोध के बारे में सांख्यिकी पा सकते हैं।

![](<../../../images/image (1063).png>)

**I/O ग्राफ**

_**Statistics --> I/O Graph**_ के तहत आप संचार का **ग्राफ** पा सकते हैं।

![](<../../../images/image (992).png>)

### फ़िल्टर

यहां आप प्रोटोकॉल के आधार पर wireshark फ़िल्टर पा सकते हैं: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
अन्य दिलचस्प फ़िल्टर:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS ट्रैफ़िक
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS ट्रैफ़िक + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS ट्रैफ़िक + TCP SYN + DNS अनुरोध

### खोज

यदि आप सत्रों के **पैकेट्स** के अंदर **सामग्री** के लिए **खोज** करना चाहते हैं तो _CTRL+f_ दबाएं। आप मुख्य जानकारी बार (No., Time, Source, आदि) में नए लेयर जोड़ सकते हैं दाएं बटन को दबाकर और फिर कॉलम संपादित करके।

### मुफ्त pcap प्रयोगशालाएँ

**मुफ्त चुनौतियों के साथ अभ्यास करें:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## डोमेन की पहचान करना

आप एक कॉलम जोड़ सकते हैं जो होस्ट HTTP हेडर दिखाता है:

![](<../../../images/image (639).png>)

और एक कॉलम जो एक प्रारंभिक HTTPS कनेक्शन से सर्वर नाम जोड़ता है (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## स्थानीय होस्टनाम की पहचान करना

### DHCP से

वर्तमान Wireshark में `bootp` के बजाय आपको `DHCP` के लिए खोज करनी होगी

![](<../../../images/image (1013).png>)

### NBNS से

![](<../../../images/image (1003).png>)

## TLS को डिक्रिप्ट करना

### सर्वर प्राइवेट की के साथ https ट्रैफ़िक को डिक्रिप्ट करना

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

_संपादित_ पर क्लिक करें और सर्वर और प्राइवेट की का सभी डेटा (_IP, Port, Protocol, Key file और password_) जोड़ें।

### सममित सत्र कुंजी के साथ https ट्रैफ़िक को डिक्रिप्ट करना

Firefox और Chrome दोनों में TLS सत्र कुंजी लॉग करने की क्षमता होती है, जिसका उपयोग Wireshark के साथ TLS ट्रैफ़िक को डिक्रिप्ट करने के लिए किया जा सकता है। यह सुरक्षित संचार का गहन विश्लेषण करने की अनुमति देता है। इस डिक्रिप्शन को कैसे करना है, इस पर अधिक विवरण [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) में एक गाइड में पाया जा सकता है।

इसका पता लगाने के लिए वातावरण के अंदर `SSLKEYLOGFILE` वेरिएबल के लिए खोजें।

साझा कुंजियों की एक फ़ाइल इस तरह दिखेगी:

![](<../../../images/image (820).png>)

इसे wireshark में आयात करने के लिए _edit > preference > protocol > ssl > और इसे (Pre)-Master-Secret लॉग फ़ाइल नाम में आयात करें:

![](<../../../images/image (989).png>)

## ADB संचार

जहां APK भेजा गया था, ADB संचार से एक APK निकालें:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{{#include ../../../banners/hacktricks-training.md}}
