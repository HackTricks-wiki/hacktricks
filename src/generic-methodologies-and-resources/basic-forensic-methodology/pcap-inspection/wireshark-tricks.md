# Wireshark ipuçları

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark becerilerinizi geliştirin

### Eğitimler

Aşağıdaki eğitimler bazı kullanışlı temel ipuçlarını öğrenmek için harikadır:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgileri**

_**Analyze** --> **Expert Information**_ seçeneğine tıklayarak **analiz edilen** paketlerde neler olduğuna dair bir **genel bakış** elde edebilirsiniz:

![Eğitimler - Analiz Edilen Bilgiler: Analyze -- Expert Information seçeneğine tıklayarak analiz edilen paketlerde neler olduğuna dair bir genel bakış elde edebilirsiniz](<../../../images/image (256).png>)

**Çözümlenen Adresler**

_**Statistics --> Resolved Addresses**_ altında Wireshark tarafından "**çözümlenen**" port/transport bilgisinin protokole, MAC adresinin üreticiye eşlenmesi gibi çeşitli **bilgileri** bulabilirsiniz. İletişimde nelerin rol oynadığını bilmek ilginç olabilir.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- Resolved Addresses altında Wireshark tarafından " çözümlenen " port/transport bilgisinin protokole, MAC adresinin ise üreticiye eşlenmesi gibi çeşitli bilgileri bulabilirsiniz](<../../../images/image (893).png>)

**Protokol Hiyerarşisi**

_**Statistics --> Protocol Hierarchy**_ altında iletişimde **yer alan** **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- Protocol Hierarchy altında iletişimde yer alan protokolleri ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ altında iletişimdeki **conversations özeti** ve bunlarla ilgili verileri bulabilirsiniz.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- Conversations altında iletişimdeki conversations özetini ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ altında iletişimdeki **endpoints özeti** ve her biriyle ilgili verileri bulabilirsiniz.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- Endpoints altında iletişimdeki endpoints özetini ve her biriyle ilgili verileri bulabilirsiniz](<../../../images/image (896).png>)

**DNS bilgileri**

_**Statistics --> DNS**_ altında yakalanan DNS isteğiyle ilgili istatistikleri bulabilirsiniz.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- DNS altında yakalanan DNS isteğiyle ilgili istatistikleri bulabilirsiniz](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ altında **iletişimin grafiğini** bulabilirsiniz.

![Eğitimler - Analiz Edilen Bilgiler: Statistics -- I/O Graph altında iletişimin grafiğini bulabilirsiniz](<../../../images/image (992).png>)

### Filtreler

Protokole göre Wireshark filtrelerini burada bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Güncel Wireshark sürümünde eski `ssl.*` filtre adları yerine `tls.*` kullanın.\
Diğer ilginç filtreler:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri
- `tls.handshake.extensions_server_name contains "example.com"`
- Payload'ı decrypt edemediğiniz durumlarda bile ClientHello'da gönderilen SNI üzerinden pivot yapın
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Klasik HTTPS, HTTP/2 ve HTTP/3 destekli oturumları hızlıca ayırın
- `quic or http3`
- Yalnızca TCP conversations'larını incelerseniz gözden kaçacak modern UDP/443 trafiğini bulun

### Arama

Oturumların **paketleri** içindeki **içerikte** **arama** yapmak istiyorsanız _CTRL+f_ tuşlarına basın. Sağ düğmeye basıp ardından sütunu düzenleyerek ana bilgi çubuğuna (No., Time, Source vb.) yeni katmanlar ekleyebilirsiniz.

### Çoklanmış akışları takip etme

Güncel Wireshark sürümleri `TLS`, `HTTP/2` ve `QUIC` akışlarını doğrudan takip edebilir. Gürültülü capture'larda bu yöntem genellikle yalnızca `Follow TCP Stream` kullanmaktan daha hızlıdır; özellikle de birden fazla istek aynı bağlantıyı paylaşıyorsa.

### Ücretsiz pcap laboratuvarları

**Ücretsiz challenge'larla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domain'leri Belirleme

HTTP Host header'ını gösteren bir sütun ekleyebilirsiniz:

![Ücretsiz pcap laboratuvarları - Domain'leri Belirleme: HTTP Host header'ını gösteren bir sütun ekleyebilirsiniz](<../../../images/image (639).png>)

Ayrıca başlatılan bir HTTPS bağlantısından Server name bilgisini ekleyen bir sütun da ekleyebilirsiniz (**tls.handshake.type == 1**):

![Ücretsiz pcap laboratuvarları - Domain'leri Belirleme: Başlatılan bir HTTPS bağlantısından Server name bilgisini ekleyen bir sütun da ekleyebilirsiniz ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Capture çoğunlukla şifreliyse bu alanları sütun olarak eklemek triage işlemini büyük ölçüde hızlandırır:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Bu sayede payload'ın kendisi şifreli kalmaya devam etse bile oturumları hostname, ALPN (`http/1.1`, `h2`, `h3` vb.) ve client fingerprint'a göre kümelendirebilirsiniz. Decrypted HTTP/2 ve HTTP/3 capture'ları için `http2.header.value` veya `http3.headers.header.value` alanlarını sütun olarak eklemek ve path'ler, authority'ler ile diğer ilginç metadata üzerinden pivot yapmak da faydalıdır.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Yerel hostname'leri belirleme

### DHCP'den

Güncel Wireshark'ta `bootp` yerine `DHCP` için arama yapmanız gerekir

![Yerel hostname'leri belirleme - DHCP'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1013).png>)

### NBNS'den

![DHCP'den - NBNS'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1003).png>)

## TLS şifresini çözme

### Sunucunun private key'i ile https trafiğinin şifresini çözme

_edit > preferences > protocols > tls >_

![TLS şifresini çözme - Sunucunun private key'i ile https trafiğinin şifresini çözme: Sunucunun private key'i ile https trafiğinin şifresini çözme](<../../../images/image (1103).png>)

_Edit_ düğmesine basın ve sunucu ile private key'e ait tüm verileri (_IP, Port, Protocol, Key file ve password_) ekleyin.

Bu yöntem yalnızca sınırlı sayıda durumda çalışır. Güncel TLS 1.3 / ECDHE trafiği için aşağıdaki session key log yöntemi genellikle pratik seçenektir.<sup>[[1]](#references)</sup>

### Symmetric session keys ile https trafiğinin şifresini çözme

Hem Firefox hem de Chrome, Wireshark ile TLS trafiğinin şifresini çözmek için kullanılabilecek TLS session key'lerini loglama yeteneğine sahiptir. Bu, güvenli iletişimlerin derinlemesine analiz edilmesini sağlar. Bu şifre çözme işleminin nasıl gerçekleştirileceğine ilişkin daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) tarafından hazırlanmış bir kılavuzda bulunabilir.<sup>[[3]](#references)</sup> Bu, modern TLS 1.3 ve QUIC/HTTP/3 capture'larının şifresini çözmek için de normal yöntemdir.<sup>[[2]](#references)</sup>

Bunu tespit etmek için ortam içinde `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan key'lerden oluşan bir dosya şu şekilde görünür:

![Sunucunun private key'i ile https trafiğinin şifresini çözme - Symmetric session keys ile https trafiğinin şifresini çözme: Paylaşılan key'lerden oluşan bir dosya şu şekilde görünür](<../../../images/image (820).png>)

Capture `pcapng` ise, host filesystem'ini aramaya başlamadan önce içinde embedded decryption secret'larının zaten bulunup bulunmadığını kontrol edin:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Bunu Wireshark'a aktarmak için \_edit > preferences > protocols > tls > bölümüne gidin ve (Pre)-Master-Secret log filename alanına aktarın:

![Sunucu private key kullanarak https trafiğinin şifresini çözme - Simetrik oturum anahtarlarıyla https trafiğinin şifresini çözme: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

APK'nin gönderildiği bir ADB communication içinden APK'yi çıkarın:
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
## Referanslar

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Wireshark'ta HTTP/3 trafiğinin şifresini çözme ve ayrıştırma](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark ile TLS Browser Trafiğinin Şifresini Çözme - Kolay Yol!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
