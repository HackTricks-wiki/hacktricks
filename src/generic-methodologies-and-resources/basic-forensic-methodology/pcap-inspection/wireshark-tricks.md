# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## अपने Wireshark skills सुधारें

### Tutorials

निम्नलिखित tutorials कुछ cool basic tricks सीखने के लिए शानदार हैं:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ पर क्लिक करने पर आपको **analyzed** packets में क्या हो रहा है उसका **overview** मिलेगा:

![](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ के तहत आपको कई **information** मिल सकती है जो wireshark द्वारा "**resolved**" की गई थी, जैसे port/transport से protocol, MAC से manufacturer, आदि। यह जानना दिलचस्प है कि communication में क्या शामिल है।

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ के तहत आपको communication में शामिल **protocols** और उनके बारे में data मिल सकता है।

![](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ के तहत आपको communication में conversations का **summary** और उनके बारे में data मिल सकता है।

![](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ के तहत आपको communication में endpoints का **summary** और उनमें से प्रत्येक के बारे में data मिल सकता है।

![](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ के तहत आपको captured DNS request के बारे में statistics मिल सकती हैं।

![](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ के तहत आपको communication का एक **graph** मिल सकता है।

![](<../../../images/image (992).png>)

### Filters

यहाँ आपको protocol के अनुसार wireshark filter मिल सकते हैं: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Current Wireshark में पुराने `ssl.*` filter names की जगह `tls.*` का उपयोग करें।\
Other interesting filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- ClientHello में भेजे गए SNI पर pivot करें, भले ही आप payload decrypt न कर सकें
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- classic HTTPS, HTTP/2 और HTTP/3 capable sessions को जल्दी split करें
- `quic or http3`
- modern UDP/443 traffic ढूँढें जो सिर्फ TCP conversations review करने पर miss हो जाएगा

### Search

यदि आप sessions के **packets** के अंदर **content** **search** करना चाहते हैं, तो _CTRL+f_ दबाएँ। आप right button दबाकर और फिर edit column चुनकर main information bar (No., Time, Source, etc.) में नए layers जोड़ सकते हैं।

### Following multiplexed streams

Recent Wireshark versions सीधे `TLS`, `HTTP/2` और `QUIC` streams follow कर सकते हैं। noisy captures पर यह आमतौर पर केवल `Follow TCP Stream` इस्तेमाल करने से तेज़ होता है, खासकर जब कई requests एक ही connection share करती हैं।

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

आप एक column जोड़ सकते हैं जो Host HTTP header दिखाएगा:

![](<../../../images/image (639).png>)

और एक column जो initiating HTTPS connection (**tls.handshake.type == 1**) से Server name जोड़ता है:

![](<../../../images/image (408) (1).png>)

यदि capture ज्यादातर encrypted है, तो इन fields को columns के रूप में जोड़ने से triage बहुत तेज़ हो जाएगा:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

यह आपको payload encrypted रहने पर भी sessions को hostname, ALPN (`http/1.1`, `h2`, `h3`, आदि) और client fingerprint के आधार पर cluster करने देता है। Decrypted HTTP/2 और HTTP/3 captures के लिए, `http2.header.value` या `http3.headers.header.value` को columns के रूप में जोड़ना और paths, authorities तथा अन्य interesting metadata पर pivot करना भी उपयोगी है।
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## स्थानीय hostnames की पहचान

### DHCP से

वर्तमान Wireshark में `bootp` की बजाय आपको `DHCP` search करना होगा

![](<../../../images/image (1013).png>)

### NBNS से

![](<../../../images/image (1003).png>)

## TLS decrypt करना

### server private key के साथ https traffic decrypt करना

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

_press _Edit_ करें और server तथा private key का पूरा data add करें (_IP, Port, Protocol, Key file and password_)_

यह method केवल सीमित cases में काम करती है। वर्तमान TLS 1.3 / ECDHE traffic के लिए, नीचे दिया गया session key log method आमतौर पर practical option होता है।

### symmetric session keys के साथ https traffic decrypt करना

Firefox और Chrome, दोनों में TLS session keys log करने की capability होती है, जिन्हें Wireshark के साथ TLS traffic decrypt करने के लिए इस्तेमाल किया जा सकता है। इससे secure communications का in-depth analysis संभव होता है। इस decryption को कैसे perform करना है, इसकी अधिक जानकारी [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) पर guide में मिल सकती है। आधुनिक TLS 1.3 और QUIC/HTTP/3 captures को decrypt करने का सामान्य तरीका भी यही है।

इसे detect करने के लिए environment में variable `SSLKEYLOGFILE` search करें

shared keys वाली file इस तरह दिखेगी:

![](<../../../images/image (820).png>)

यदि capture `pcapng` है, तो host filesystem में search करने से पहले check करें कि उसमें पहले से embedded decryption secrets मौजूद हैं या नहीं:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
इसे wireshark में import करने के लिए \_edit > preferences > protocols > tls > and import it in (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

एक ADB communication से एक APK extract करें जहाँ APK भेजा गया था:
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
## संदर्भ

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
