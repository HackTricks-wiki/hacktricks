# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## अपनी Wireshark skills बेहतर बनाएं

### Tutorials

कुछ उपयोगी basic tricks सीखने के लिए निम्नलिखित tutorials शानदार हैं:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ पर क्लिक करने से आपको **analyzed** packets में क्या हो रहा है, उसका एक **overview** मिलेगा:

![Tutorials - Analysed Information: Analyze -- Expert Information पर क्लिक करने से आपको analyzed packets में क्या हो रहा है, उसका overview मिलेगा](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ के अंतर्गत आपको Wireshark द्वारा "**resolved**" की गई कई **information** मिल सकती हैं, जैसे port/transport से protocol, MAC से manufacturer आदि। Communication में क्या-क्या शामिल है, यह जानना उपयोगी है।

![Tutorials - Analysed Information: Statistics -- Resolved Addresses के अंतर्गत आपको Wireshark द्वारा " resolved " की गई कई information मिल सकती हैं, जैसे port/transport से protocol, MAC से manufacturer आदि](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ के अंतर्गत आप communication में **involved** **protocols** और उनके बारे में data देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- Protocol Hierarchy के अंतर्गत आप communication में involved protocols और उनके बारे में data देख सकते हैं](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ के अंतर्गत आप communication में मौजूद **conversations का summary** और उनके बारे में data देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- Conversations के अंतर्गत आप communication में मौजूद conversations का summary और उनके बारे में data देख सकते हैं](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ के अंतर्गत आप communication में मौजूद **endpoints का summary** और प्रत्येक endpoint के बारे में data देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- Endpoints के अंतर्गत आप communication में मौजूद endpoints का summary और प्रत्येक endpoint के बारे में data देख सकते हैं](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ के अंतर्गत आप captured DNS request के बारे में statistics देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- DNS के अंतर्गत आप captured DNS request के बारे में statistics देख सकते हैं](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ के अंतर्गत आप **communication का graph** देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- I/O Graph के अंतर्गत आप communication का graph देख सकते हैं](<../../../images/image (992).png>)

### Filters

यहाँ आप protocol के आधार पर Wireshark filters देख सकते हैं: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
वर्तमान Wireshark में पुराने `ssl.*` filter names के बजाय `tls.*` का उपयोग करें।<sup>[[1]](#references)</sup>\
अन्य उपयोगी filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP और प्रारंभिक HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload को decrypt न कर पाने पर भी ClientHello में भेजे गए SNI पर pivot करें
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Classic HTTPS, HTTP/2 और HTTP/3 capable sessions को तेज़ी से अलग करें
- `quic or http3`
- आधुनिक UDP/443 traffic खोजें, जो केवल TCP conversations की समीक्षा करने पर छूट जाएगा

### Search

यदि आप sessions के **packets** के अंदर मौजूद **content** को **search** करना चाहते हैं, तो _CTRL+f_ दबाएँ। Right button दबाकर और फिर edit column चुनकर आप main information bar (No., Time, Source आदि) में नई layers जोड़ सकते हैं।

### Following multiplexed streams

Wireshark सीधे `TLS`, `HTTP/2` और `QUIC` streams को follow कर सकता है। इसके HTTP/2 और QUIC dialogs connection और substream selectors दिखाते हैं, जिससे एक ही lower-level connection साझा करने वाले multiplexed streams को अलग करना आसान हो जाता है।<sup>[[4]](#references)</sup>

### Free pcap labs

**इन free challenges के साथ practice करें:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains की पहचान करना

आप एक ऐसा column जोड़ सकते हैं जो Host HTTP header दिखाता है:

![Free pcap labs - Identifying Domains: आप एक ऐसा column जोड़ सकते हैं जो Host HTTP header दिखाता है](<../../../images/image (639).png>)

और एक ऐसा column जो initiating HTTPS connection (**tls.handshake.type == 1**) से Server name दिखाता है:

![Free pcap labs - Identifying Domains: एक ऐसा column जो initiating HTTPS connection ( tls.handshake.type == 1 ) से Server name दिखाता है](<../../../images/image (408) (1).png>)

यदि capture अधिकतर encrypted है, तो इन fields को columns के रूप में जोड़ने से triage काफी तेज़ हो जाएगा:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

इससे आप hostname, ALPN (`http/1.1`, `h2`, `h3` आदि) और client fingerprint के आधार पर sessions को cluster कर सकते हैं, भले ही payload स्वयं encrypted रहे। Decrypted HTTP/2 और HTTP/3 captures के लिए `http2.header.value` या `http3.headers.header.value` को columns के रूप में जोड़ना और paths, authorities तथा अन्य उपयोगी metadata पर pivot करना भी लाभदायक है।<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## स्थानीय hostnames की पहचान

### DHCP से

वर्तमान Wireshark में `bootp` की जगह `DHCP` खोजें।

![स्थानीय hostnames की पहचान - DHCP से: वर्तमान Wireshark में bootp की जगह DHCP खोजें](<../../../images/image (1013).png>)

### NBNS से

![DHCP से - NBNS से: वर्तमान Wireshark में bootp की जगह DHCP खोजें](<../../../images/image (1003).png>)

## TLS को decrypt करना

### server private key से https traffic को decrypt करना

_edit > preferences > protocols > tls >_

![TLS को decrypt करना - server private key से https traffic को decrypt करना: server private key से https traffic को decrypt करना](<../../../images/image (1103).png>)

_Edit_ दबाएँ और server तथा private key का सारा data (_IP, Port, Protocol, Key file और password_) जोड़ें।

यह method सीमित मामलों में ही काम करती है। वर्तमान TLS 1.3 / ECDHE traffic के लिए, नीचे दी गई session key log method आमतौर पर व्यावहारिक विकल्प है।<sup>[[1]](#references)</sup>

### symmetric session keys से https traffic को decrypt करना

Firefox और Chrome, दोनों में TLS session keys को log करने की capability होती है, जिनका उपयोग Wireshark के साथ TLS traffic को decrypt करने के लिए किया जा सकता है। इससे secure communications का गहन analysis संभव होता है। इस decryption को करने के तरीके की अधिक जानकारी [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) की guide में मिल सकती है।<sup>[[3]](#references)</sup> आधुनिक TLS 1.3 और QUIC/HTTP/3 captures को decrypt करने के लिए भी यही सामान्य तरीका है।<sup>[[2]](#references)</sup>

इसे detect करने के लिए environment में `SSLKEYLOGFILE` variable खोजें।

Shared keys वाली file इस प्रकार दिखाई देगी:

![server private key से https traffic को decrypt करना - symmetric session keys से https traffic को decrypt करना: Shared keys वाली file इस प्रकार दिखाई देगी](<../../../images/image (820).png>)

यदि capture `pcapng` है, तो host filesystem में खोजने से पहले जाँच लें कि उसमें decryption secrets embedded तो नहीं हैं:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
इसे Wireshark में import करने के लिए \_edit > preferences > protocols > tls > पर जाएँ और इसे (Pre)-Master-Secret log filename में import करें:

![server private key के साथ https traffic को decrypt करना - symmetric session keys के साथ https traffic को decrypt करना: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB संचार

उस ADB संचार से APK extract करें जिसमें APK भेजा गया था:
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
## References

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Wireshark में HTTP/3 traffic को decrypt और parse करना](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark के साथ TLS Browser Traffic को decrypt करना – आसान तरीका!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protocol Streams का अनुसरण करना](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
