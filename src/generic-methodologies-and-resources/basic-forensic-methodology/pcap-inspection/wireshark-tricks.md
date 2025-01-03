# Wireshark ipuçları

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark becerilerinizi geliştirin

### Eğitimler

Aşağıdaki eğitimler bazı harika temel ipuçlarını öğrenmek için mükemmeldir:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz Edilen Bilgiler

**Uzman Bilgisi**

_**Analyze** --> **Expert Information**_ seçeneğine tıkladığınızda, **analiz edilen** paketlerde neler olduğunu gösteren bir **genel bakış** alırsınız:

![](<../../../images/image (256).png>)

**Çözülmüş Adresler**

_**Statistics --> Resolved Addresses**_ altında, wireshark tarafından "**çözülen**" çeşitli **bilgiler** bulabilirsiniz; örneğin port/taşıyıcıdan protokole, MAC'tan üreticiye vb. İletişimde nelerin yer aldığını bilmek ilginçtir.

![](<../../../images/image (893).png>)

**Protokol Hiyerarşisi**

_**Statistics --> Protocol Hierarchy**_ altında, iletişimde yer alan **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../images/image (586).png>)

**Görüşmeler**

_**Statistics --> Conversations**_ altında, iletişimdeki **görüşmelerin özeti** ve bunlarla ilgili verileri bulabilirsiniz.

![](<../../../images/image (453).png>)

**Uç Noktalar**

_**Statistics --> Endpoints**_ altında, iletişimdeki **uç noktaların özeti** ve her biriyle ilgili verileri bulabilirsiniz.

![](<../../../images/image (896).png>)

**DNS bilgisi**

_**Statistics --> DNS**_ altında, yakalanan DNS isteği hakkında istatistikler bulabilirsiniz.

![](<../../../images/image (1063).png>)

**G/Ç Grafiği**

_**Statistics --> I/O Graph**_ altında, iletişimin **grafiğini** bulabilirsiniz.

![](<../../../images/image (992).png>)

### Filtreler

Burada protokole bağlı wireshark filtrelerini bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Diğer ilginç filtreler:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri

### Arama

Eğer oturumların **paketleri** içinde **içerik** aramak istiyorsanız, _CTRL+f_ tuşlarına basın. Ana bilgi çubuğuna (No., Zaman, Kaynak, vb.) yeni katmanlar eklemek için sağ tıklayıp ardından sütunu düzenleyebilirsiniz.

### Ücretsiz pcap laboratuvarları

**Ücretsiz zorluklarla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Alan Adlarını Tanımlama

Host HTTP başlığını gösteren bir sütun ekleyebilirsiniz:

![](<../../../images/image (639).png>)

Ve başlatan bir HTTPS bağlantısından sunucu adını ekleyen bir sütun (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Yerel Alan Adlarını Tanımlama

### DHCP'den

Güncel Wireshark'ta `bootp` yerine `DHCP` aramanız gerekiyor.

![](<../../../images/image (1013).png>)

### NBNS'den

![](<../../../images/image (1003).png>)

## TLS'yi Şifre Çözme

### Sunucu özel anahtarı ile https trafiğini şifre çözme

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Sunucu ve özel anahtarın tüm verilerini (_IP, Port, Protokol, Anahtar dosyası ve şifre_) eklemek için _Edit_ seçeneğine basın.

### Simetrik oturum anahtarları ile https trafiğini şifre çözme

Hem Firefox hem de Chrome, TLS oturum anahtarlarını kaydetme yeteneğine sahiptir; bu anahtarlar Wireshark ile TLS trafiğini şifre çözmek için kullanılabilir. Bu, güvenli iletişimlerin derinlemesine analizine olanak tanır. Bu şifre çözme işlemini nasıl gerçekleştireceğinizle ilgili daha fazla ayrıntı [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) rehberinde bulunabilir.

Bunu tespit etmek için ortamda `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan anahtarların bir dosyası şöyle görünecektir:

![](<../../../images/image (820).png>)

Bunu wireshark'a aktarmak için _edit > preference > protocol > ssl > ve (Pre)-Master-Secret log filename_ kısmına aktarın:

![](<../../../images/image (989).png>)

## ADB iletişimi

APK'nın gönderildiği bir ADB iletişiminden bir APK çıkarın:
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
