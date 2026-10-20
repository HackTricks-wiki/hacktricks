# Wireshark की तरकीबें

{{#include ../../../banners/hacktricks-training.md}}

## अपने Wireshark कौशल बेहतर करें

### ट्यूटोरियल

कुछ उपयोगी बुनियादी तरकीबें सीखने के लिए ये ट्यूटोरियल बेहतरीन हैं:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### विश्लेषित जानकारी

**विशेषज्ञ जानकारी**

_**Analyze** --> **Expert Information**_ पर क्लिक करने से आपको **विश्लेषित** पैकेटों में हो रही गतिविधियों का **अवलोकन** मिलेगा:

![ट्यूटोरियल - विश्लेषित जानकारी: Analyze -- Expert Information पर क्लिक करने से आपको विश्लेषित पैकेटों में हो रही गतिविधियों का अवलोकन मिलेगा](<../../../images/image (256).png>)

**रिज़ॉल्व किए गए पते**

_**Statistics --> Resolved Addresses**_ के अंतर्गत आपको Wireshark द्वारा "**रिज़ॉल्व**" की गई कई जानकारियाँ मिलेंगी, जैसे पोर्ट/ट्रांसपोर्ट से प्रोटोकॉल, MAC से निर्माता आदि। इससे यह जानने में मदद मिलती है कि संचार में क्या-क्या शामिल है।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- Resolved Addresses के अंतर्गत आपको Wireshark द्वारा " रिज़ॉल्व " की गई कई जानकारियाँ मिलेंगी, जैसे पोर्ट/ट्रांसपोर्ट से प्रोटोकॉल, MAC से...](<../../../images/image (893).png>)

**प्रोटोकॉल पदानुक्रम**

_**Statistics --> Protocol Hierarchy**_ के अंतर्गत आप संचार में शामिल **प्रोटोकॉल** और उनके बारे में जानकारी देख सकते हैं।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- Protocol Hierarchy के अंतर्गत आप संचार में शामिल प्रोटोकॉल और उनके बारे में जानकारी देख सकते हैं](<../../../images/image (586).png>)

**वार्तालाप**

_**Statistics --> Conversations**_ के अंतर्गत आप संचार में हुए **वार्तालापों का सारांश** और उनके बारे में जानकारी देख सकते हैं।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- Conversations के अंतर्गत आप संचार में हुए वार्तालापों का सारांश और उनके बारे में जानकारी देख सकते हैं](<../../../images/image (453).png>)

**एंडपॉइंट**

_**Statistics --> Endpoints**_ के अंतर्गत आप संचार के **एंडपॉइंट का सारांश** और प्रत्येक के बारे में जानकारी देख सकते हैं।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- Endpoints के अंतर्गत आप संचार के एंडपॉइंट का सारांश और प्रत्येक के बारे में जानकारी देख सकते हैं](<../../../images/image (896).png>)

**DNS जानकारी**

_**Statistics --> DNS**_ के अंतर्गत आप कैप्चर किए गए DNS अनुरोधों के आँकड़े देख सकते हैं।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- DNS के अंतर्गत आप कैप्चर किए गए DNS अनुरोधों के आँकड़े देख सकते हैं](<../../../images/image (1063).png>)

**I/O ग्राफ़**

_**Statistics --> I/O Graph**_ के अंतर्गत आप संचार का **ग्राफ़** देख सकते हैं।

![ट्यूटोरियल - विश्लेषित जानकारी: Statistics -- I/O Graph के अंतर्गत आप संचार का ग्राफ़ देख सकते हैं](<../../../images/image (992).png>)

### फ़िल्टर

प्रोटोकॉल के अनुसार Wireshark फ़िल्टर यहाँ मिलेंगे: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
वर्तमान Wireshark में पुराने `ssl.*` फ़िल्टर नामों के बजाय `tls.*` का उपयोग करें।<sup>[[1]](#references)</sup>\
अन्य उपयोगी फ़िल्टर:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP और शुरुआती HTTPS ट्रैफ़िक
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP और शुरुआती HTTPS ट्रैफ़िक + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP और शुरुआती HTTPS ट्रैफ़िक + TCP SYN + DNS अनुरोध
- `tls.handshake.extensions_server_name contains "example.com"`
  - ClientHello में भेजे गए SNI के आधार पर खोजें, भले ही आप payload को decrypt न कर सकें
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - क्लासिक HTTPS, HTTP/2 और HTTP/3 सक्षम सेशन को तुरंत अलग करें
- `quic or http3`
  - आधुनिक UDP/443 ट्रैफ़िक ढूँढ़ें, जो केवल TCP वार्तालाप देखने पर छूट जाएगा

### खोज

अगर आप सेशन के **पैकेटों** के भीतर मौजूद **सामग्री** **खोजना** चाहते हैं, तो _CTRL+f_ दबाएँ। मुख्य जानकारी बार (No., Time, Source आदि) में नए कॉलम जोड़ने के लिए, दायाँ बटन दबाएँ और फिर edit column चुनें।

### मल्टीप्लेक्स्ड स्ट्रीम को फ़ॉलो करना

Wireshark सीधे `TLS`, `HTTP/2` और `QUIC` स्ट्रीम को फ़ॉलो कर सकता है। इसके HTTP/2 और QUIC डायलॉग में कनेक्शन और सबस्ट्रीम चुनने के विकल्प होते हैं, जो एक ही निचले-स्तर के कनेक्शन को साझा करने वाली मल्टीप्लेक्स्ड स्ट्रीम को अलग करने में मदद करते हैं।<sup>[[4]](#references)</sup>

सेशन keys उपलब्ध होने पर, पहले अनुरोध का stream ID पहचानें, फिर पूरे TCP या UDP वार्तालाप के बजाय उस सबस्ट्रीम को फ़ॉलो करें। `0,1` उदाहरण TCP stream 0 पर HTTP/2 stream ID 1 चुनता है; QUIC के लिए `follow,quic,utf-8,<connection-number>,<stream-id>` का उपयोग करें। केवल five-tuple को फ़ॉलो करने से स्वतंत्र अनुरोध एक साथ मिल सकते हैं या migration के बाद QUIC कनेक्शन छूट सकता है।<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### मुफ़्त pcap लैब्स

**इन मुफ़्त challenges के साथ अभ्यास करें:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains की पहचान करना

आप Host HTTP header दिखाने वाला column जोड़ सकते हैं:

![मुफ़्त pcap लैब्स - Domains की पहचान करना: आप Host HTTP header दिखाने वाला column जोड़ सकते हैं](<../../../images/image (639).png>)

और किसी initiating HTTPS connection से Server name दिखाने वाला column जोड़ सकते हैं (**tls.handshake.type == 1**):

![मुफ़्त pcap लैब्स - Domains की पहचान करना: और किसी initiating HTTPS connection से Server name दिखाने वाला column जोड़ सकते हैं ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

अगर capture का अधिकांश हिस्सा encrypted है, तो इन fields को columns के रूप में जोड़ने से triage काफ़ी तेज़ हो जाएगा:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

इससे आप hostname, ALPN (`http/1.1`, `h2`, `h3` आदि) और client fingerprint के आधार पर sessions को cluster कर सकते हैं, भले ही payload encrypted रहे। Decrypted HTTP/2 और HTTP/3 captures के लिए, `http2.header.value` या `http3.headers.header.value` को columns के रूप में जोड़ना और paths, authorities तथा अन्य दिलचस्प metadata के आधार पर pivot करना भी उपयोगी है।<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: outer SNI को origin न समझें

Encrypted ClientHello (ECH) visible outer SNI में एक public cover name रख सकता है, जबकि inner name को encrypt करता है। इसलिए, केवल SNI पर आधारित domain inventory में ECH traffic को गलत origin से जोड़ा जा सकता है। केवल ECH extension होना इस बात का प्रमाण नहीं है कि ECH सफल हुआ: clients GREASE ECH extension भेज सकते हैं। Wireshark 4.2+ पर outer ECH offers खोजने के लिए नीचे दिया गया filter इस्तेमाल करें और रिपोर्ट किए गए SNI को requested site नहीं, बल्कि cover candidate मानें।<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

यदि आपके पास matching client session keys हैं, तो outer SNI से origin का अनुमान लगाने के बजाय decrypted HTTP authority/Host की जाँच करें। Keys के बिना, captured origin के अन्य सबूत देखें, जैसे plaintext DNS, लेकिन outer SNI को hidden name न मानें।<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## स्थानीय hostnames की पहचान

### DHCP से

वर्तमान Wireshark में `bootp` के बजाय `DHCP` खोजें

![स्थानीय hostnames की पहचान - DHCP से: वर्तमान Wireshark में bootp के बजाय DHCP खोजें](<../../../images/image (1013).png>)

### NBNS से

![DHCP से - NBNS से: वर्तमान Wireshark में bootp के बजाय DHCP खोजें](<../../../images/image (1003).png>)

## TLS को decrypt करना

Wi-Fi link-layer decryption, TLS session decryption से अलग है; इसकी key और handshake की आवश्यकताओं के लिए [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) देखें।

### Server की private key से https traffic को decrypt करना

_edit > preferences > protocols > tls >_

![TLS को decrypt करना - Server की private key से https traffic को decrypt करना: Server की private key से https traffic को decrypt करना](<../../../images/image (1103).png>)

_**Edit**_ दबाएँ और server तथा private key का पूरा data जोड़ें (_IP, Port, Protocol, Key file और password_)

यह तरीका केवल सीमित मामलों में काम करता है। मौजूदा TLS 1.3 / ECDHE traffic के लिए, नीचे दिया गया session key log तरीका आमतौर पर व्यावहारिक विकल्प है।<sup>[[1]](#references)</sup>

### Symmetric session keys से https traffic को decrypt करना

Firefox और Chrome, दोनों में TLS session keys log करने की क्षमता है। इन keys का उपयोग Wireshark के साथ TLS traffic को decrypt करने के लिए किया जा सकता है। इससे secure communications का गहराई से विश्लेषण संभव होता है। इस decryption को करने के तरीके की अधिक जानकारी [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) की guide में मिल सकती है।<sup>[[3]](#references)</sup> आधुनिक TLS 1.3 और QUIC/HTTP/3 captures को decrypt करने का यह सामान्य तरीका भी है।<sup>[[2]](#references)</sup>

इसे पहचानने के लिए environment में `SSLKEYLOGFILE` variable खोजें

Shared keys की file कुछ ऐसी दिखेगी:

![Server की private key से https traffic को decrypt करना - Symmetric session keys से https traffic को decrypt करना: Shared keys की file कुछ ऐसी दिखेगी](<../../../images/image (820).png>)

अगर capture `pcapng` है, तो host filesystem में खोजने से पहले जाँचें कि उसमें decryption secrets पहले से embedded तो नहीं हैं:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

इसे Wireshark में import करने के लिए \_edit > preferences > protocols > tls > पर जाएँ और इसे (Pre)-Master-Secret log filename में import करें:

![सर्वर की private key से https ट्रैफ़िक decrypt करना - symmetric session keys से https ट्रैफ़िक decrypt करना: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB संचार

उस ADB संचार से APK निकालें जिसमें APK भेजा गया था:

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

- [1] [Wireshark TLS विकि](https://wiki.wireshark.org/TLS)
- [2] [Wireshark में HTTP/3 ट्रैफ़िक को decrypt और parse करना](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark से TLS Browser ट्रैफ़िक को decrypt करना – आसान तरीका!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protocol Streams को फ़ॉलो करना](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark मैनुअल](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
