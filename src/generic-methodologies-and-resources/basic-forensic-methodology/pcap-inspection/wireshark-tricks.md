# Wireshark ipuçları

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark becerilerinizi geliştirin

### Öğreticiler

Bazı kullanışlı temel ipuçlarını öğrenmek için aşağıdaki öğreticiler harika kaynaklardır:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analiz edilen bilgiler

**Uzman bilgileri**

_**Analyze** --> **Expert Information**_ seçeneğine tıkladığınızda, **analiz edilen** paketlerde neler olup bittiğine dair bir **genel bakış** elde edersiniz:

![Öğreticiler - Analiz edilen bilgiler: Analyze -- Expert Information seçeneğine tıkladığınızda analiz edilen paketlerde neler olup bittiğine dair bir genel bakış elde edersiniz](<../../../images/image (256).png>)

**Çözümlenen adresler**

_**Statistics --> Resolved Addresses**_ altında Wireshark tarafından "**çözümlenmiş**" çeşitli bilgileri (ör. port/transport bilgilerini protokole, MAC adresini üreticiye eşleme) bulabilirsiniz. İletişimde nelerin yer aldığını anlamak için bu bilgiler yararlıdır.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- Resolved Addresses altında Wireshark tarafından " çözümlenmiş " çeşitli bilgileri (ör. port/transport bilgilerini protokole, MAC adresini...) bulabilirsiniz](<../../../images/image (893).png>)

**Protokol hiyerarşisi**

_**Statistics --> Protocol Hierarchy**_ altında iletişimde **yer alan** **protokolleri** ve bunlarla ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- Protocol Hierarchy altında iletişimde yer alan protokolleri ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (586).png>)

**Konuşmalar**

_**Statistics --> Conversations**_ altında iletişimdeki **konuşmaların özetini** ve bunlarla ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- Conversations altında iletişimdeki konuşmaların özetini ve bunlarla ilgili verileri bulabilirsiniz](<../../../images/image (453).png>)

**Uç noktalar**

_**Statistics --> Endpoints**_ altında iletişimdeki **uç noktaların özetini** ve her biriyle ilgili verileri bulabilirsiniz.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- Endpoints altında iletişimdeki uç noktaların özetini ve her biriyle ilgili verileri bulabilirsiniz](<../../../images/image (896).png>)

**DNS bilgileri**

_**Statistics --> DNS**_ altında yakalanan DNS istekleriyle ilgili istatistikleri bulabilirsiniz.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- DNS altında yakalanan DNS istekleriyle ilgili istatistikleri bulabilirsiniz](<../../../images/image (1063).png>)

**G/Ç grafiği**

_**Statistics --> I/O Graph**_ altında iletişimin **grafiğini** bulabilirsiniz.

![Öğreticiler - Analiz edilen bilgiler: Statistics -- I/O Graph altında iletişimin grafiğini bulabilirsiniz](<../../../images/image (992).png>)

### Filtreler

Protokole göre Wireshark filtrelerini burada bulabilirsiniz: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Güncel Wireshark sürümünde eski `ssl.*` filtre adları yerine `tls.*` kullanın.<sup>[[1]](#references)</sup>\
Diğer kullanışlı filtreler:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP ve başlangıç HTTPS trafiği
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP ve başlangıç HTTPS trafiği + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP ve başlangıç HTTPS trafiği + TCP SYN + DNS istekleri
- `tls.handshake.extensions_server_name contains "example.com"`
  - İletinin içeriğini çözemediğiniz durumlarda bile ClientHello içinde gönderilen SNI üzerinden arama yapın
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Klasik HTTPS, HTTP/2 ve HTTP/3 destekli oturumları hızla ayırın
- `quic or http3`
  - Yalnızca TCP konuşmalarını incelerseniz gözden kaçacak modern UDP/443 trafiğini bulun

### Arama

Oturum paketlerinin içindeki **içerikte** **arama** yapmak için _CTRL+f_ tuşlarına basın. Sağ tıklayıp ardından sütunu düzenleme seçeneğini kullanarak ana bilgi çubuğuna (No., Time, Source vb.) yeni katmanlar ekleyebilirsiniz.

### Çoklanmış akışları izleme

Wireshark, `TLS`, `HTTP/2` ve `QUIC` akışlarını doğrudan izleyebilir. HTTP/2 ve QUIC iletişim pencereleri bağlantı ve alt akış seçicileri sunar; böylece aynı alt düzey bağlantıyı paylaşan çoklanmış akışları birbirinden ayırabilirsiniz.<sup>[[4]](#references)</sup>

Oturum anahtarları mevcutsa önce isteğin akış kimliğini belirleyin, ardından tüm TCP veya UDP konuşması yerine ilgili alt akışı izleyin. `0,1` örneği, TCP akışı 0 üzerindeki HTTP/2 akış kimliği 1'i seçer; QUIC için `follow,quic,utf-8,<connection-number>,<stream-id>` kullanın. Yalnızca beşli üzerinden izleme, bağımsız istekleri birbirine karıştırabilir veya geçiş yaptıktan sonra QUIC bağlantısını kaçırabilir.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Ücretsiz pcap laboratuvarları

**Şu ücretsiz challenge'larla pratik yapın:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Alan Adlarını Belirleme

Host HTTP header'ını gösteren bir sütun ekleyebilirsiniz:

![Ücretsiz pcap laboratuvarları - Alan Adlarını Belirleme: Host HTTP header'ını gösteren bir sütun ekleyebilirsiniz](<../../../images/image (639).png>)

Başlatılan bir HTTPS bağlantısındaki Server name'i ekleyen bir sütun da ekleyebilirsiniz (**tls.handshake.type == 1**):

![Ücretsiz pcap laboratuvarları - Alan Adlarını Belirleme: Başlatılan bir HTTPS bağlantısındaki Server name'i ekleyen bir sütun da ekleyebilirsiniz ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Yakalama verilerinin çoğu şifreliyse, bu alanları sütun olarak eklemek triyajı önemli ölçüde hızlandırır:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Bu sayede, payload şifreli kalmaya devam etse bile oturumları hostname, ALPN (`http/1.1`, `h2`, `h3` vb.) ve client fingerprint'e göre gruplandırabilirsiniz. Şifresi çözülmüş HTTP/2 ve HTTP/3 yakalama verilerinde, `http2.header.value` veya `http3.headers.header.value` alanlarını sütun olarak ekleyip path'ler, authority'ler ve diğer ilgi çekici metadata üzerinden pivot yapmak da faydalıdır.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: dış SNI'yi origin ile karıştırmayın

Encrypted ClientHello (ECH), görünür dış SNI'ye herkese açık bir örtü adı yerleştirirken iç adı şifreleyebilir. Bu nedenle yalnızca SNI'ye dayalı bir alan adı envanteri, ECH trafiğini yanlış origin ile ilişkilendirebilir. ECH uzantısının tek başına bulunması, ECH'nin başarılı olduğunun kanıtı değildir: istemciler GREASE ECH uzantısı gönderebilir. Wireshark 4.2+ sürümünde, dış ECH tekliflerini aşağıdaki filtreyle bulun ve bildirilen SNI'yi istenen site olarak değil, olası bir örtü adı olarak değerlendirin.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Eşleşen client session keys elinizdeyse, origin'i dış SNI'dan çıkarsamak yerine şifresi çözülmüş HTTP authority/Host değerini inceleyin. Anahtarlar yoksa, plaintext DNS gibi yakalanmış diğer origin kanıtlarını kontrol edin; ancak dış SNI'ı gizli adla eş tutmayın.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Yerel ana bilgisayar adlarını belirleme

### DHCP'den

Güncel Wireshark'ta `bootp` yerine `DHCP` için arama yapmanız gerekir.

![Yerel ana bilgisayar adlarını belirleme - DHCP'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1013).png>)

### NBNS'den

![DHCP'den - NBNS'den: Güncel Wireshark'ta bootp yerine DHCP için arama yapmanız gerekir](<../../../images/image (1003).png>)

## TLS'yi çözme

Wi-Fi bağlantı katmanı şifre çözme işlemi, TLS oturumu şifre çözme işleminden ayrıdır; anahtar ve el sıkışma ön koşulları için [Wi-Fi PCAP analysis](wifi-pcap-analysis.md) sayfasına bakın.

### Sunucunun özel anahtarıyla HTTPS trafiğini çözme

_edit > preferences > protocols > tls >_

![TLS'yi çözme - Sunucunun özel anahtarıyla HTTPS trafiğini çözme: Sunucunun özel anahtarıyla HTTPS trafiğini çözme](<../../../images/image (1103).png>)

_Edit_'e basın ve sunucuya ve özel anahtara ait tüm bilgileri ekleyin (_IP, Port, Protocol, Key file ve password_).

Bu yöntem yalnızca sınırlı sayıda durumda işe yarar. Güncel TLS 1.3 / ECDHE trafiğinde oturum anahtarı günlüğü yöntemi genellikle pratik seçenektir.<sup>[[1]](#references)</sup>

### Simetrik oturum anahtarlarıyla HTTPS trafiğini çözme

Hem Firefox hem de Chrome, TLS oturum anahtarlarını günlüğe kaydedebilir; bu anahtarlar Wireshark ile TLS trafiğini çözmek için kullanılabilir. Böylece güvenli iletişimler derinlemesine analiz edilebilir. Bu şifre çözme işleminin nasıl yapılacağına ilişkin daha fazla bilgi [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) kılavuzunda bulunabilir.<sup>[[3]](#references)</sup> Bu, modern TLS 1.3 ve QUIC/HTTP/3 yakalamalarının şifresini çözmek için de olağan yöntemdir.<sup>[[2]](#references)</sup>

Bunu tespit etmek için ortamda `SSLKEYLOGFILE` değişkenini arayın.

Paylaşılan anahtarların bulunduğu bir dosya şöyle görünür:

![Sunucunun özel anahtarıyla HTTPS trafiğini çözme - Simetrik oturum anahtarlarıyla HTTPS trafiğini çözme: Paylaşılan anahtarların bulunduğu bir dosya şöyle görünür](<../../../images/image (820).png>)

Yakalama `pcapng` biçimindeyse, ana makinenin dosya sistemini araştırmadan önce dosyanın içinde şifre çözme sırlarının zaten bulunup bulunmadığını kontrol edin:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Bunu Wireshark'a aktarmak için \_Düzenle > Tercihler > Protokoller > TLS bölümüne gidin ve (Pre)-Master-Secret günlük dosyası adı alanına aktarın:

![Sunucu özel anahtarıyla HTTPS trafiğinin şifresini çözme - Simetrik oturum anahtarlarıyla HTTPS trafiğinin şifresini çözme: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB iletişimi

APK'nın gönderildiği bir ADB iletişiminden APK çıkarın:

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

- [1] [Wireshark TLS vikisi](https://wiki.wireshark.org/TLS)
- [2] [Wireshark'ta HTTP/3 trafiğinin şifresini çözme ve ayrıştırma](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark ile TLS tarayıcı trafiğinin şifresini çözme – Kolay yol!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protokol akışlarını izleme](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Görüntüleme filtresi başvurusu: Taşıma Katmanı Güvenliği](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Görüntüleme filtresi başvurusu: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Görüntüleme filtresi başvurusu: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Şifrelenmiş İstemci Merhaba](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark kılavuzu](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
