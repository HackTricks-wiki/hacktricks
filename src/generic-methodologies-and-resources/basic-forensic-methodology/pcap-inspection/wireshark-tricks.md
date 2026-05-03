# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark becerilerinizi geliştirin

### Tutorials

Aşağıdaki tutorials, bazı havalı temel trik'leri öğrenmek için harikadır:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ üzerine tıkladığınızda, **analyzed** paketlerde neler olduğuna dair bir **overview** elde edersiniz:

![](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ altında, wireshark tarafından "resolved" edilmiş çeşitli **information** bulabilirsiniz; örneğin port/transport to protocol, MAC to the manufacturer, vb. İletişimde nelerin yer aldığını bilmek ilginçtir.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ altında, iletişimde yer alan **protocols** ve bunlar hakkındaki verileri bulabilirsiniz.

![](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ altında, iletişimdeki konuşmaların bir **summary of the conversations** ve bunlar hakkındaki verileri bulabilirsiniz.

![](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ altında, iletişimdeki uç noktaların bir **summary of the endpoints** ve her biri hakkındaki verileri bulabilirsiniz.

![](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ altında, yakalanan DNS request hakkında istatistikler bulabilirsiniz.

![](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ altında, iletişimin bir **graph of the communication.** bulabilirsiniz.

![](<../../../images/image (992).png>)

### Filters

Burada protokole bağlı wireshark filter bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Güncel Wireshark'ta eski `ssl.*` filter isimleri yerine `tls.*` kullanın.\
Diğer ilginç filtreler:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload'u decrypt edemeseniz bile ClientHello içinde gönderilen SNI üzerinde pivot yapın
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Classic HTTPS, HTTP/2 ve HTTP/3 destekli oturumları hızlıca ayırın
- `quic or http3`
- Sadece TCP conversations incelemeniz durumunda kaçırılacak modern UDP/443 trafiğini bulun

### Search

Session'ların **packets** içindeki **content**'ini **search** etmek istiyorsanız _CTRL+f_ tuşuna basın. Ana bilgi çubuğuna (No., Time, Source, etc.) sağ butona basıp ardından edit column seçerek yeni katmanlar ekleyebilirsiniz.

### Following multiplexed streams

Wireshark'ın yeni sürümleri `TLS`, `HTTP/2` ve `QUIC` stream'lerini doğrudan takip edebilir. Gürültülü capture'larda bu genellikle yalnızca `Follow TCP Stream` kullanmaktan daha hızlıdır, özellikle birden fazla request aynı connection'ı paylaşıyorsa.

### Free pcap labs

**Şunların ücretsiz challenges'ları ile pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

HTTP Host header'ını gösteren bir column ekleyebilirsiniz:

![](<../../../images/image (639).png>)

Ve başlatan bir HTTPS connection'dan Server name ekleyen bir column da ekleyebilirsiniz (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Capture çoğunlukla encrypted ise, bu field'ları column olarak eklemek triage sürecini çok hızlandırır:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Bu, payload'ın kendisi encrypted kalsa bile session'ları hostname, ALPN (`http/1.1`, `h2`, `h3`, vb.) ve client fingerprint'e göre gruplamanızı sağlar. Decrypted HTTP/2 ve HTTP/3 captures için, `http2.header.value` veya `http3.headers.header.value` ekleyip paths, authorities ve diğer ilginç metadata üzerinde pivot yapmak da faydalıdır.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Yerel hostname’leri belirleme

### DHCP’den

Güncel Wireshark’ta `bootp` yerine `DHCP` aramanız gerekir

![](<../../../images/image (1013).png>)

### NBNS’den

![](<../../../images/image (1003).png>)

## TLS şifre çözme

### Server private key ile https trafiğini çözme

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

_Edit_’e basın ve server ile private key’in tüm verilerini ekleyin (_IP, Port, Protocol, Key file and password_)

Bu yöntem yalnızca sınırlı sayıda durumda çalışır. Güncel TLS 1.3 / ECDHE trafiğinde, aşağıdaki session key log yöntemi genellikle pratik seçenektir.

### Simetrik session key’lerle https trafiğini çözme

Hem Firefox hem de Chrome, TLS session key’lerini loglama yeteneğine sahiptir; bunlar Wireshark ile TLS trafiğini çözmek için kullanılabilir. Bu, güvenli iletişimlerin derinlemesine analizine olanak tanır. Bu şifre çözmenin nasıl yapılacağına dair daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) adresindeki bir rehberde bulunabilir. Bu aynı zamanda modern TLS 1.3 ve QUIC/HTTP/3 capture’larını çözmek için de normal yoldur.

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın

Ortak key’lerden oluşan bir dosya şöyle görünür:

![](<../../../images/image (820).png>)

Eğer capture `pcapng` ise, host filesystem’i araştırmadan önce içine gömülü decryption secret’ları zaten içerip içermediğini kontrol edin:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Bunu wireshark içine import etmek için \_edit > preferences > protocols > tls > ve bunu (Pre)-Master-Secret log filename içine import edin:

![](<../../../images/image (989).png>)

## ADB iletişimi

APK’nin gönderildiği bir ADB communication içinden bir APK çıkarın:
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

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
