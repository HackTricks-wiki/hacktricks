# Wireshark tricks

## Wireshark becerilerinizi geliştirin

### Tutorials

Aşağıdaki tutorials bazı kullanışlı temel tricks öğrenmek için harikadır:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ seçeneğine tıklayarak **analiz edilen** paketlerde neler olduğuna dair bir **genel bakış** elde edebilirsiniz:

![Tutorials - Analysed Information: Analyze -- Expert Information seçeneğine tıklayarak analiz edilen paketlerde neler olduğuna dair bir genel bakış elde edebilirsiniz](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ altında Wireshark tarafından "**resolved**" edilen çeşitli **bilgileri** (port/transport protokolü, MAC adresinin üreticisi vb.) bulabilirsiniz. İletişimde nelerin yer aldığını bilmek faydalıdır.

![Tutorials - Analysed Information: Statistics -- Resolved Addresses altında Wireshark tarafından " resolved " edilen çeşitli bilgileri (port/transport protokolü, MAC adresinin üreticisi vb.) bulabilirsiniz](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ altında iletişimde **yer alan** **protocol**'leri ve bunlar hakkındaki verileri bulabilirsiniz.

![Tutorials - Analysed Information: Statistics -- Protocol Hierarchy altında iletişimde yer alan protocol'leri ve bunlar hakkındaki verileri bulabilirsiniz](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ altında iletişimdeki **conversations özetini** ve bunlar hakkındaki verileri bulabilirsiniz.

![Tutorials - Analysed Information: Statistics -- Conversations altında iletişimdeki conversations özetini ve bunlar hakkındaki verileri bulabilirsiniz](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ altında iletişimdeki **endpoints özetini** ve her biri hakkındaki verileri bulabilirsiniz.

![Tutorials - Analysed Information: Statistics -- Endpoints altında iletişimdeki endpoints özetini ve her biri hakkındaki verileri bulabilirsiniz](<../../../images/image (896).png>)

**DNS bilgisi**

_**Statistics --> DNS**_ altında yakalanan DNS request'leri hakkındaki istatistikleri bulabilirsiniz.

![Tutorials - Analysed Information: Statistics -- DNS altında yakalanan DNS request'leri hakkındaki istatistikleri bulabilirsiniz](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ altında iletişimin bir **grafiğini** bulabilirsiniz.

![Tutorials - Analysed Information: Statistics -- I/O Graph altında iletişimin bir grafiğini bulabilirsiniz](<../../../images/image (992).png>)

### Filters

Burada protocol'e göre Wireshark filter'larını bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Güncel Wireshark sürümünde eski `ssl.*` filter adları yerine `tls.*` kullanın.<sup>[[1]](#references)</sup>\
Diğer ilginç filter'lar:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS request'leri
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload'u decrypt edemeseniz bile ClientHello'da gönderilen SNI üzerinden pivot yapın
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Klasik HTTPS, HTTP/2 ve HTTP/3 destekli session'ları hızlıca ayırın
- `quic or http3`
- Yalnızca TCP conversations'larını incelerseniz gözden kaçacak modern UDP/443 trafiğini bulun

### Search

Session'ların **packet'leri** içindeki **content'i** **search** etmek istiyorsanız _CTRL+f_ tuşlarına basın. Sağ tuşa basıp ardından edit column seçeneğini kullanarak ana bilgi çubuğuna (No., Time, Source vb.) yeni katmanlar ekleyebilirsiniz.

### Following multiplexed streams

Wireshark `TLS`, `HTTP/2` ve `QUIC` stream'lerini doğrudan takip edebilir. HTTP/2 ve QUIC dialog'ları connection ve substream selector'larını gösterir; bu da aynı alt düzey connection'ı paylaşan multiplexed stream'leri izole etmeye yardımcı olur.<sup>[[4]](#references)</sup>

### Free pcap labs

**Ücretsiz challenge'larla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domain'leri belirleme

HTTP Host header'ını gösteren bir column ekleyebilirsiniz:

![Free pcap labs - Identifying Domains: HTTP Host header'ını gösteren bir column ekleyebilirsiniz](<../../../images/image (639).png>)

Ayrıca başlangıç HTTPS connection'ından Server name'i ekleyen bir column da ekleyebilirsiniz (**tls.handshake.type == 1**):

![Free pcap labs - Identifying Domains: Başlangıç HTTPS connection'ından Server name'i ekleyen bir column ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Capture çoğunlukla encrypted ise bu field'ları column olarak eklemek triage işlemini büyük ölçüde hızlandırır:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Bu, payload'un kendisi encrypted kalmaya devam etse bile session'ları hostname, ALPN (`http/1.1`, `h2`, `h3` vb.) ve client fingerprint'ine göre cluster etmenizi sağlar. Decrypted HTTP/2 ve HTTP/3 capture'larında `http2.header.value` veya `http3.headers.header.value` değerlerini column olarak eklemek ve path'ler, authority'ler ile diğer ilginç metadata üzerinden pivot yapmak da faydalıdır.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Yerel host adlarını belirleme

### DHCP'den

Güncel Wireshark'ta `bootp` yerine `DHCP` aramanız gerekir.

![Yerel host adlarını belirleme - DHCP'den: Güncel Wireshark'ta bootp yerine DHCP aramanız gerekir](<../../../images/image (1013).png>)

### NBNS'den

![DHCP'den - NBNS'den: Güncel Wireshark'ta bootp yerine DHCP aramanız gerekir](<../../../images/image (1003).png>)

## TLS şifresini çözme

### Sunucunun private key'i ile https trafiğinin şifresini çözme

_edit > preferences > protocols > tls >_

![TLS şifresini çözme - Sunucunun private key'i ile https trafiğinin şifresini çözme: Sunucunun private key'i ile https trafiğinin şifresini çözme](<../../../images/image (1103).png>)

_Edit_ düğmesine basın ve sunucunun tüm bilgilerini ve private key'ini ekleyin (_IP, Port, Protocol, Key file ve password_).

Bu yöntem yalnızca sınırlı sayıda durumda çalışır. Güncel TLS 1.3 / ECDHE trafiği için aşağıdaki session key log yöntemi genellikle pratik seçenektir.<sup>[[1]](#references)</sup>

### Simetrik session key'ler ile https trafiğinin şifresini çözme

Hem Firefox hem de Chrome, Wireshark ile TLS trafiğinin şifresini çözmek için kullanılabilecek TLS session key'lerini loglama özelliğine sahiptir. Bu, güvenli iletişimlerin ayrıntılı analizini mümkün kılar. Bu şifre çözme işleminin nasıl gerçekleştirileceğine ilişkin daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) tarafından hazırlanmış bir kılavuzda bulunabilir.<sup>[[3]](#references)</sup> Bu yöntem, modern TLS 1.3 ve QUIC/HTTP/3 capture'larının şifresini çözmek için de normal yöntemdir.<sup>[[2]](#references)</sup>

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan key'lerden oluşan bir dosya şu şekilde görünür:

![Sunucunun private key'i ile https trafiğinin şifresini çözme - Simetrik session key'ler ile https trafiğinin şifresini çözme: Paylaşılan key'lerden oluşan bir dosya şu şekilde görünür](<../../../images/image (820).png>)

Capture `pcapng` ise host filesystem'inde arama yapmadan önce embedded decryption secret'ları içerip içermediğini kontrol edin:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Bunu Wireshark'a aktarmak için \_edit > preferences > protocols > tls > bölümüne gidin ve (Pre)-Master-Secret log filename alanına aktarın:

![Sunucu özel anahtarıyla HTTPS trafiğinin şifresini çözme - Simetrik oturum anahtarlarıyla HTTPS trafiğinin şifresini çözme: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB iletişimi

APK'nin gönderildiği bir ADB iletişiminden APK çıkarma:
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
- [2] [Wireshark'de HTTP/3 trafiğini çözme ve ayrıştırma](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [TLS Browser trafiğini Wireshark ile çözme – Kolay yol!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protokol akışlarını izleme](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Görüntüleme filtresi referansı: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Görüntüleme filtresi referansı: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Görüntüleme filtresi referansı: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
