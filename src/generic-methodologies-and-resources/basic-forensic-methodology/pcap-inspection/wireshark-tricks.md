# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## अपनी Wireshark skills सुधारें

### Tutorials

कुछ उपयोगी basic tricks सीखने के लिए निम्नलिखित tutorials शानदार हैं:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ पर क्लिक करने से आपको packets में क्या हो रहा है, इसका एक **overview** मिलेगा:

![Tutorials - Analysed Information: Analyze -- Expert Information पर क्लिक करने से आपको analyzed packets में क्या हो रहा है, इसका एक overview मिलेगा](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ के अंतर्गत आप wireshark द्वारा "**resolved**" की गई कई **information** देख सकते हैं, जैसे port/transport से protocol, MAC से manufacturer आदि। Communication में क्या-क्या शामिल है, यह जानना उपयोगी होता है।

![Tutorials - Analysed Information: Statistics -- Resolved Addresses के अंतर्गत आप wireshark द्वारा " resolved " की गई कई information देख सकते हैं, जैसे port/transport से protocol, MAC से manufacturer आदि](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ के अंतर्गत आप communication में **involved** **protocols** और उनके बारे में data देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- Protocol Hierarchy के अंतर्गत आप communication में involved protocols और उनके बारे में data देख सकते हैं](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ के अंतर्गत आप communication में हुई **conversations का summary** और उनके बारे में data देख सकते हैं।

![Tutorials - Analysed Information: Statistics -- Conversations के अंतर्गत आप communication में हुई conversations का summary और उनके बारे में data देख सकते हैं](<../../../images/image (453).png>)

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
वर्तमान Wireshark में पुराने `ssl.*` filter names के बजाय `tls.*` का उपयोग करें।\
अन्य उपयोगी filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP और initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP और initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP और initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload को decrypt न कर पाने पर भी ClientHello में भेजे गए SNI पर pivot करें
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Classic HTTPS, HTTP/2 और HTTP/3 सक्षम sessions को शीघ्रता से अलग करें
- `quic or http3`
- आधुनिक UDP/443 traffic खोजें, जो केवल TCP conversations की समीक्षा करने पर छूट जाएगा

### Search

यदि आप sessions के **packets** के अंदर **content** **search** करना चाहते हैं, तो _CTRL+f_ दबाएँ। Right button दबाकर और फिर edit column चुनकर आप main information bar (No., Time, Source आदि) में नई layers जोड़ सकते हैं।

### Following multiplexed streams

हाल के Wireshark versions `TLS`, `HTTP/2` और `QUIC` streams को सीधे follow कर सकते हैं। Noisy captures पर यह आमतौर पर केवल `Follow TCP Stream` का उपयोग करने से तेज़ होता है, खासकर तब जब कई requests एक ही connection share करती हों।

### Free pcap labs

**इन free challenges के साथ practice करें:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains की पहचान करना

आप एक ऐसा column जोड़ सकते हैं जो Host HTTP header दिखाता है:

![Free pcap labs - Identifying Domains: आप एक ऐसा column जोड़ सकते हैं जो Host HTTP header दिखाता है](<../../../images/image (639).png>)

और एक ऐसा column जो initiating HTTPS connection (**tls.handshake.type == 1**) से Server name जोड़ता है:

![Free pcap labs - Identifying Domains: एक ऐसा column जो initiating HTTPS connection ( tls.handshake.type == 1 ) से Server name जोड़ता है](<../../../images/image (408) (1).png>)

यदि capture अधिकांशतः encrypted है, तो इन fields को columns के रूप में जोड़ने से triage काफी तेज़ हो जाएगा:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

इससे आप sessions को hostname, ALPN (`http/1.1`, `h2`, `h3` आदि) और client fingerprint के आधार पर cluster कर सकते हैं, भले ही payload स्वयं encrypted रहे। Decrypted HTTP/2 और HTTP/3 captures के लिए `http2.header.value` या `http3.headers.header.value` को columns के रूप में जोड़ना और paths, authorities तथा अन्य उपयोगी metadata पर pivot करना भी उपयोगी है।<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## स्थानीय hostnames की पहचान करना

### DHCP से

वर्तमान Wireshark में `bootp` के बजाय आपको `DHCP` के लिए search करना होगा

![स्थानीय hostnames की पहचान करना - DHCP से: वर्तमान Wireshark में bootp के बजाय आपको DHCP के लिए search करना होगा](<../../../images/image (1013).png>)

### NBNS से

![DHCP से - NBNS से: वर्तमान Wireshark में bootp के बजाय आपको DHCP के लिए search करना होगा](<../../../images/image (1003).png>)

## TLS को decrypt करना

### server private key के साथ https traffic को decrypt करना

_edit > preferences > protocols > tls >_

![TLS को decrypt करना - server private key के साथ https traffic को decrypt करना: server private key के साथ https traffic को decrypt करना](<../../../images/image (1103).png>)

_Edit_ दबाएँ और server तथा private key का सभी data (_IP, Port, Protocol, Key file और password_) जोड़ें।

यह method सीमित मामलों में ही काम करता है। वर्तमान TLS 1.3 / ECDHE traffic के लिए, नीचे दी गई session key log method आमतौर पर व्यावहारिक विकल्प है।<sup>[[1]](#references)</sup>

### symmetric session keys के साथ https traffic को decrypt करना

Firefox और Chrome दोनों में TLS session keys को log करने की क्षमता होती है, जिनका उपयोग Wireshark के साथ TLS traffic को decrypt करने के लिए किया जा सकता है। इससे secure communications का गहन analysis संभव होता है। इस decryption को करने के तरीके की अधिक जानकारी [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) की guide में मिल सकती है।<sup>[[3]](#references)</sup> आधुनिक TLS 1.3 और QUIC/HTTP/3 captures को decrypt करने का यह सामान्य तरीका भी है।<sup>[[2]](#references)</sup>

इसे detect करने के लिए environment के अंदर `SSLKEYLOGFILE` variable को search करें।

shared keys की file इस प्रकार दिखाई देगी:

![server private key के साथ https traffic को decrypt करना - symmetric session keys के साथ https traffic को decrypt करना: shared keys की file इस प्रकार दिखाई देगी](<../../../images/image (820).png>)

यदि capture `pcapng` है, तो host filesystem में खोज करने से पहले जाँच लें कि उसमें embedded decryption secrets पहले से मौजूद हैं या नहीं:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
इसे wireshark में import करने के लिए \_edit > preferences > protocols > tls > पर जाएँ और इसे (Pre)-Master-Secret log filename में import करें:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

उस ADB communication से APK extract करें जिसमें APK भेजा गया था:
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

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Decrypting TLS Browser Traffic With Wireshark – The Easy Way!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
