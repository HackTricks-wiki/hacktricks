# Трюки Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Покращення навичок роботи з Wireshark

### Навчальні матеріали

Ці чудові навчальні матеріали допоможуть опанувати корисні базові прийоми:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Проаналізована інформація

**Інформація для експертів**

Якщо натиснути _**Analyze** --> **Expert Information**_, ви побачите **огляд** того, що відбувається в **проаналізованих** пакетах:

![Навчальні матеріали — проаналізована інформація: натиснувши Analyze -- Expert Information, ви побачите огляд того, що відбувається в проаналізованих пакетах](<../../../images/image (256).png>)

**Визначені адреси**

У розділі _**Statistics --> Resolved Addresses**_ можна знайти різну інформацію, яку Wireshark «визначив», наприклад відповідність порту/транспорту протоколу, MAC-адреси виробнику тощо. Це допомагає зрозуміти, що залучено до обміну даними.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- Resolved Addresses можна знайти різну інформацію, яку Wireshark «визначив», наприклад відповідність порту/транспорту протоколу, MAC-адреси виробнику тощо](<../../../images/image (893).png>)

**Ієрархія протоколів**

У розділі _**Statistics --> Protocol Hierarchy**_ можна переглянути **протоколи**, **задіяні** в обміні даними, і відомості про них.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- Protocol Hierarchy можна переглянути протоколи, задіяні в обміні даними, і відомості про них](<../../../images/image (586).png>)

**Сеанси зв’язку**

У розділі _**Statistics --> Conversations**_ можна переглянути **зведення сеансів зв’язку** та відомості про них.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- Conversations можна переглянути зведення сеансів зв’язку та відомості про них](<../../../images/image (453).png>)

**Кінцеві точки**

У розділі _**Statistics --> Endpoints**_ можна переглянути **зведення кінцевих точок** та відомості про кожну з них.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- Endpoints можна переглянути зведення кінцевих точок та відомості про кожну з них](<../../../images/image (896).png>)

**Відомості про DNS**

У розділі _**Statistics --> DNS**_ можна переглянути статистику за перехопленими DNS-запитами.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- DNS можна переглянути статистику за перехопленими DNS-запитами](<../../../images/image (1063).png>)

**Графік вводу/виводу**

У розділі _**Statistics --> I/O Graph**_ можна переглянути **графік обміну даними**.

![Навчальні матеріали — проаналізована інформація: у розділі Statistics -- I/O Graph можна переглянути графік обміну даними](<../../../images/image (992).png>)

### Фільтри

Фільтри Wireshark для різних протоколів можна знайти тут: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
У поточній версії Wireshark використовуйте `tls.*` замість старих назв фільтрів `ssl.*`.<sup>[[1]](#references)</sup>\
Інші корисні фільтри:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP-трафік і початковий HTTPS-трафік
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP-трафік і початковий HTTPS-трафік + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP-трафік і початковий HTTPS-трафік + TCP SYN + DNS-запити
- `tls.handshake.extensions_server_name contains "example.com"`
  - Шукайте за SNI, переданим у ClientHello, навіть якщо не можете розшифрувати корисне навантаження
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Швидко відокремлюйте сеанси зі звичайним HTTPS, HTTP/2 і підтримкою HTTP/3
- `quic or http3`
  - Знаходьте сучасний UDP/443-трафік, який не буде виявлено, якщо переглядати лише TCP-сеанси зв’язку

### Пошук

Щоб **шукати** **вміст** у **пакетах** сеансів, натисніть _CTRL+f_. Можна додати нові стовпці до головної інформаційної панелі (No., Time, Source тощо): натисніть правою кнопкою миші, а потім виберіть редагування стовпців.

### Перегляд мультиплексованих потоків

Wireshark може безпосередньо переглядати потоки `TLS`, `HTTP/2` і `QUIC`. У діалогових вікнах HTTP/2 і QUIC можна вибрати з’єднання та підпотік, що допомагає відокремити мультиплексовані потоки, які використовують одне й те саме з’єднання нижчого рівня.<sup>[[4]](#references)</sup>

Якщо у вас є ключі сеансу, спершу визначте ID потоку запиту, а потім перегляньте цей підпотік, а не весь обмін даними через TCP або UDP. У прикладі `0,1` вибрано потік HTTP/2 з ID 1 у потоці TCP 0; для QUIC використовуйте `follow,quic,utf-8,<connection-number>,<stream-id>`. Перегляд лише за п’ятіркою параметрів може об’єднати незалежні запити або не виявити QUIC-з’єднання після міграції.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Безкоштовні pcap-лабораторії

**Практикуйтеся на безкоштовних завданнях:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Визначення доменів

Можна додати стовпець, який показуватиме HTTP-заголовок Host:

![Безкоштовні pcap-лабораторії — Визначення доменів: можна додати стовпець, який показуватиме HTTP-заголовок Host](<../../../images/image (639).png>)

А також стовпець з ім’ям сервера з ініційованого HTTPS-з’єднання (**tls.handshake.type == 1**):

![Безкоштовні pcap-лабораторії — Визначення доменів: а також стовпець з ім’ям сервера з ініційованого HTTPS-з’єднання ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Якщо трафік у захопленні переважно зашифрований, додавання цих полів у стовпці значно пришвидшить первинний аналіз:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Це дає змогу групувати сеанси за іменем хоста, ALPN (`http/1.1`, `h2`, `h3` тощо) та відбитком клієнта, навіть коли корисне навантаження залишається зашифрованим. Для розшифрованих захоплень HTTP/2 і HTTP/3 також корисно додати `http2.header.value` або `http3.headers.header.value` як стовпці й аналізувати шляхи, authorities та інші цікаві метадані.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: не плутайте зовнішній SNI з origin

Encrypted ClientHello (ECH) може розміщувати публічне маскувальне ім’я у видимому зовнішньому SNI, шифруючи внутрішнє ім’я. Тому інвентаризація доменів лише за SNI може помилково приписати трафік ECH іншому origin. Саме розширення ECH не доводить, що ECH спрацював: клієнти можуть надсилати розширення GREASE ECH. У Wireshark 4.2+ скористайтеся наведеним нижче фільтром, щоб знайти зовнішні пропозиції ECH, і вважайте вказаний SNI лише можливим маскувальним ім’ям, а не запитаним сайтом.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Якщо у вас є відповідні ключі сеансу клієнта, перевірте розшифроване значення HTTP authority/Host, а не робіть висновок про origin на основі зовнішнього SNI. Якщо ключів немає, перевірте інші зафіксовані свідчення щодо origin, наприклад DNS у відкритому вигляді, але не вважайте зовнішній SNI прихованим ім’ям.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Визначення локальних імен хостів

### За DHCP

У сучасному Wireshark замість `bootp` потрібно шукати `DHCP`

![Визначення локальних імен хостів — За DHCP: У сучасному Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1013).png>)

### За NBNS

![За DHCP — За NBNS: У сучасному Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1003).png>)

## Розшифрування TLS

Розшифрування Wi-Fi на канальному рівні відрізняється від розшифрування TLS-сеансу; вимоги до ключа й рукостискання див. у статті [Аналіз Wi-Fi PCAP](wifi-pcap-analysis.md).

### Розшифрування HTTPS-трафіку за допомогою приватного ключа сервера

_edit > preferences > protocols > tls >_

![Розшифрування TLS — Розшифрування HTTPS-трафіку за допомогою приватного ключа сервера: Розшифрування HTTPS-трафіку за допомогою приватного ключа сервера](<../../../images/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та приватний ключ (_IP, порт, протокол, файл ключа й пароль_).

Цей метод працює лише в обмеженій кількості випадків. Для сучасного трафіку TLS 1.3 / ECDHE зазвичай практичніше використовувати метод із журналом ключів сеансу, описаний нижче.<sup>[[1]](#references)</sup>

### Розшифрування HTTPS-трафіку за допомогою симетричних ключів сеансу

Firefox і Chrome можуть записувати ключі TLS-сеансів, які можна використовувати у Wireshark для розшифрування TLS-трафіку. Це дає змогу детально аналізувати захищені комунікації. Докладніші відомості про це розшифрування наведено в посібнику на сайті [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Це також стандартний спосіб розшифрування захопленого сучасного трафіку TLS 1.3 і QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Щоб знайти цей параметр, перевірте середовище на наявність змінної `SSLKEYLOGFILE`.

Файл із ключами сеансів виглядатиме так:

![Розшифрування HTTPS-трафіку за допомогою приватного ключа сервера — Розшифрування HTTPS-трафіку за допомогою симетричних ключів сеансу: Файл із ключами сеансів виглядатиме так](<../../../images/image (820).png>)

Якщо файл захоплення має формат `pcapng`, спершу перевірте, чи містить він вбудовані секрети розшифрування, перш ніж шукати їх у файловій системі хоста:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Щоб імпортувати це у Wireshark, перейдіть до \_edit > preferences > protocols > tls > і імпортуйте його в поле (Pre)-Master-Secret log filename:

![Розшифрування HTTPS-трафіку за допомогою приватного ключа сервера — розшифрування HTTPS-трафіку за допомогою симетричних ключів сеансу: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Комунікація ADB

Витягніть APK із трафіку ADB, у якому було надіслано APK:

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

- [1] [Вікі Wireshark TLS](https://wiki.wireshark.org/TLS)
- [2] [Розшифрування та розбір трафіку HTTP/3 у Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Розшифрування трафіку TLS у браузері за допомогою Wireshark — простий спосіб!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Відстеження потоків протоколів](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Довідник фільтрів відображення: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Довідник фільтрів відображення: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Довідник фільтрів відображення: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: зашифроване привітання клієнта TLS](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Посібник TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
