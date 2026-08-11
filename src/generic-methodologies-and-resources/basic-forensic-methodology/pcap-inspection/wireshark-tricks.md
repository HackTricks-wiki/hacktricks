# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark becerilerinizi geliştirin

### Öğreticiler

Aşağıdaki öğreticiler bazı kullanışlı temel trick'leri öğrenmek için harikadır:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgileri**

_**Analyze** --> **Expert Information**_ seçeneğine tıklayarak **analiz edilen** paketlerde neler olduğunu gösteren bir **genel bakış** elde edebilirsiniz:

![Öğreticiler - Analiz Edilen Bilgiler: Analyze -- Expert Information seçeneğine tıklayarak analiz edilen paketlerde neler olduğunu gösteren bir genel bakış elde edebilirsiniz](<../../../images/image (256).png>)

**Çözümlenen Adresler**

_**Statistics --> Resolved Addresses**_ altında Wireshark tarafından "**çözümlenen**" çeşitli **bilgileri** bulabilirsiniz; örneğin port/transport'tan protokole, MAC adresinden üreticiye vb. İletişimde nelerin yer aldığını bilmek ilginç olabilir.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- Resolved Addresses altında Wireshark tarafından " çözümlenen " çeşitli bilgileri bulabilirsiniz; örneğin port/transport'tan protokole, MAC adresinden...](<../../../images/image (893).png>)

**Protokol Hiyerarşisi**

_**Statistics --> Protocol Hierarchy**_ altında iletişimde **yer alan** **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- Protocol Hierarchy altında iletişimde yer alan protokolleri ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (586).png>)

**Konuşmalar**

_**Statistics --> Conversations**_ altında iletişimdeki **konuşmaların bir özetini** ve bunlarla ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- Conversations altında iletişimdeki konuşmaların bir özetini ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (453).png>)

**Uç Noktalar**

_**Statistics --> Endpoints**_ altında iletişimdeki **uç noktaların bir özetini** ve her biriyle ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- Endpoints altında iletişimdeki uç noktaların bir özetini ve her biriyle ilgili verileri bulabilirsiniz](<../../../images/image (896).png>)

**DNS bilgileri**

_**Statistics --> DNS**_ altında yakalanan DNS istekleriyle ilgili istatistikleri bulabilirsiniz.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- DNS altında yakalanan DNS istekleriyle ilgili istatistikleri bulabilirsiniz](<../../../images/image (1063).png>)

**I/O Grafiği**

_**Statistics --> I/O Graph**_ altında **iletişimin bir grafiğini** bulabilirsiniz.

![Öğreticiler - Analiz Edilen Bilgiler: Statistics -- I/O Graph altında iletişimin bir grafiğini bulabilirsiniz](<../../../images/image (992).png>)

### Filtreler

Burada protokole göre Wireshark filtrelerini bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Güncel Wireshark sürümünde eski `ssl.*` filtre adları yerine `tls.*` kullanın.<sup>[[1]](#references)</sup>\
Diğer ilginç filtreler:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload'u decrypt edemediğiniz durumlarda bile ClientHello'da gönderilen SNI üzerinden pivot yapın
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Klasik HTTPS, HTTP/2 ve HTTP/3 destekli oturumları hızlıca ayırın
- `quic or http3`
- Yalnızca TCP konuşmalarını incelerseniz gözden kaçacak modern UDP/443 trafiğini bulun

### Arama

Oturumların **paketleri** içindeki **içeriği** **aramak** istiyorsanız _CTRL+f_ tuşlarına basın. Sağ tuşa basıp ardından sütunu düzenleyerek ana bilgi çubuğuna (No., Time, Source vb.) yeni katmanlar ekleyebilirsiniz.

### Multiplexed stream'leri takip etme

Wireshark `TLS`, `HTTP/2` ve `QUIC` stream'lerini doğrudan takip edebilir. HTTP/2 ve QUIC iletişim kutuları bağlantı ve alt stream seçicilerini gösterir; bu da aynı alt düzey bağlantıyı paylaşan multiplexed stream'leri ayırmaya yardımcı olur.<sup>[[4]](#references)</sup>

### Ücretsiz pcap lab'leri

**Şu ücretsiz challenge'larla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domain'leri Tanımlama

HTTP Host header'ını gösteren bir sütun ekleyebilirsiniz:

![Ücretsiz pcap lab'leri - Domain'leri Tanımlama: HTTP Host header'ını gösteren bir sütun ekleyebilirsiniz](<../../../images/image (639).png>)

Başlatılan bir HTTPS bağlantısından Server adını ekleyen bir sütun da ekleyebilirsiniz (**tls.handshake.type == 1**):

![Ücretsiz pcap lab'leri - Domain'leri Tanımlama: Başlatılan bir HTTPS bağlantısından Server adını ekleyen bir sütun da ekleyebilirsiniz ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Capture çoğunlukla encrypted ise bu alanları sütun olarak eklemek triage işlemini önemli ölçüde hızlandırır:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Bu, payload'un kendisi encrypted kalmaya devam etse bile oturumları hostname, ALPN (`http/1.1`, `h2`, `h3` vb.) ve client fingerprint'ine göre cluster'lamanızı sağlar. Decrypted HTTP/2 ve HTTP/3 capture'ları için `http2.header.value` veya `http3.headers.header.value` alanlarını sütun olarak eklemek ve path'ler, authority'ler ile diğer ilginç metadata üzerinden pivot yapmak da yararlıdır.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Yerel hostname'leri belirleme

### DHCP'den

Güncel Wireshark'ta `bootp` yerine `DHCP` için arama yapmanız gerekir.

![Yerel hostname'leri belirleme - DHCP'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1013).png>)

### NBNS'den

![DHCP'den - NBNS'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1003).png>)

## TLS şifresini çözme

### Server private key ile https trafiğinin şifresini çözme

_edit > preferences > protocols > tls >_

![TLS şifresini çözme - Server private key ile https trafiğinin şifresini çözme: Server private key ile https trafiğinin şifresini çözme](<../../../images/image (1103).png>)

_Edit_ düğmesine basın ve server ile private key'e ait tüm verileri ekleyin (_IP, Port, Protocol, Key file ve password_).

Bu yöntem yalnızca sınırlı sayıda durumda çalışır. Güncel TLS 1.3 / ECDHE trafiği için aşağıdaki session key log yöntemi genellikle pratik seçenektir.<sup>[[1]](#references)</sup>

### Symmetric session keys ile https trafiğinin şifresini çözme

Hem Firefox hem de Chrome, TLS session key'lerini loglama özelliğine sahiptir. Bu anahtarlar Wireshark ile TLS trafiğinin şifresini çözmek için kullanılabilir. Bu, secure communications üzerinde derinlemesine analiz yapılmasına olanak tanır. Bu şifre çözme işleminin nasıl gerçekleştirileceğiyle ilgili daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) rehberinde bulunabilir.<sup>[[3]](#references)</sup> Bu yöntem, modern TLS 1.3 ve QUIC/HTTP/3 yakalamalarının şifresini çözmek için de normal yoldur.<sup>[[2]](#references)</sup>

Bunu tespit etmek için environment içinde `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan anahtarların bulunduğu bir dosya şu şekilde görünür:

![Server private key ile https trafiğinin şifresini çözme - Symmetric session keys ile https trafiğinin şifresini çözme: Paylaşılan anahtarların bulunduğu bir dosya şu şekilde görünür](<../../../images/image (820).png>)

Yakalama `pcapng` ise host filesystem'inde arama yapmadan önce, dosyanın embedded decryption secrets içerip içermediğini kontrol edin:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Bunu Wireshark'a aktarmak için \_edit > preferences > protocols > tls > bölümüne gidin ve (Pre)-Master-Secret log filename alanına aktarın:

![Sunucu özel anahtarıyla https trafiğinin şifresini çözme - Simetrik oturum anahtarlarıyla https trafiğinin şifresini çözme: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

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
- [2] [Wireshark'da HTTP/3 trafiğini şifresini çözme ve ayrıştırma](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark ile TLS Browser trafiğinin şifresini çözme – Kolay yol!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protocol Streams'i takip etme](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
