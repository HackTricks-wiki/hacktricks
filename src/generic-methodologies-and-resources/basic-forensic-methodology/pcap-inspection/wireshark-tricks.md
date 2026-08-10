# Трюки Wireshark

## Покращення навичок роботи з Wireshark

### Tutorials

Наступні tutorials чудово допоможуть вивчити кілька корисних базових прийомів:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Проаналізована інформація

**Експертна інформація**

Натиснувши _**Analyze** --> **Expert Information**_, ви отримаєте **огляд** того, що відбувається в **проаналізованих** пакетах:

![Tutorials - Проаналізована інформація: натиснувши Analyze -- Expert Information, ви отримаєте огляд того, що відбувається в проаналізованих пакетах](<../../../images/image (256).png>)

**Визначені адреси**

У розділі _**Statistics --> Resolved Addresses**_ можна знайти різну **інформацію**, яку Wireshark "**визначив**", наприклад відповідність порту/транспорту протоколу, MAC-адреси виробнику тощо. Цікаво знати, що саме залучено до комунікації.

![Tutorials - Проаналізована інформація: у розділі Statistics -- Resolved Addresses можна знайти різну інформацію, яку Wireshark " визначив ", наприклад відповідність порту/транспорту протоколу, MAC-адреси...](<../../../images/image (893).png>)

**Ієрархія протоколів**

У розділі _**Statistics --> Protocol Hierarchy**_ можна знайти **протоколи**, **залучені** до комунікації, і дані про них.

![Tutorials - Проаналізована інформація: у розділі Statistics -- Protocol Hierarchy можна знайти протоколи, залучені до комунікації, і дані про них](<../../../images/image (586).png>)

**З'єднання**

У розділі _**Statistics --> Conversations**_ можна знайти **підсумок з'єднань** у комунікації та дані про них.

![Tutorials - Проаналізована інформація: у розділі Statistics -- Conversations можна знайти підсумок з'єднань у комунікації та дані про них](<../../../images/image (453).png>)

**Кінцеві точки**

У розділі _**Statistics --> Endpoints**_ можна знайти **підсумок кінцевих точок** у комунікації та дані про кожну з них.

![Tutorials - Проаналізована інформація: у розділі Statistics -- Endpoints можна знайти підсумок кінцевих точок у комунікації та дані про кожну з них](<../../../images/image (896).png>)

**Інформація DNS**

У розділі _**Statistics --> DNS**_ можна знайти статистику щодо перехоплених DNS-запитів.

![Tutorials - Проаналізована інформація: у розділі Statistics -- DNS можна знайти статистику щодо перехоплених DNS-запитів](<../../../images/image (1063).png>)

**Графік I/O**

У розділі _**Statistics --> I/O Graph**_ можна знайти **графік комунікації.**

![Tutorials - Проаналізована інформація: у розділі Statistics -- I/O Graph можна знайти графік комунікації](<../../../images/image (992).png>)

### Фільтри

Тут можна знайти фільтри Wireshark залежно від протоколу: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
У поточних версіях Wireshark використовуйте `tls.*` замість старих назв фільтрів `ssl.*`.<sup>[[1]](#references)</sup>\
Інші цікаві фільтри:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік + TCP SYN + DNS-запити
- `tls.handshake.extensions_server_name contains "example.com"`
- Виконайте pivot за SNI, надісланим у ClientHello, навіть якщо ви не можете розшифрувати payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Швидко розділіть класичні HTTPS-сесії та сесії з підтримкою HTTP/2 і HTTP/3
- `quic or http3`
- Знайдіть сучасний UDP/443-трафік, який буде пропущено, якщо переглядати лише TCP-з'єднання

### Пошук

Якщо ви хочете **шукати** **вміст** усередині **пакетів** сесій, натисніть _CTRL+f_. Можна додати нові шари до основної інформаційної панелі (No., Time, Source тощо), натиснувши праву кнопку, а потім вибравши редагування стовпців.

### Перегляд multiplexed streams

Wireshark може безпосередньо переглядати streams `TLS`, `HTTP/2` і `QUIC`. Його діалоги HTTP/2 і QUIC містять селектори з'єднань і substreams, що допомагає ізолювати multiplexed streams, які спільно використовують одне й те саме lower-level з'єднання.<sup>[[4]](#references)</sup>

### Безкоштовні лабораторні роботи з pcap

**Практикуйтеся на безкоштовних завданнях:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Визначення доменів

Можна додати стовпець, який відображає HTTP-заголовок Host:

![Free pcap labs - Визначення доменів: можна додати стовпець, який відображає HTTP-заголовок Host](<../../../images/image (639).png>)

А також стовпець, який додає ім'я Server із початкового HTTPS-з'єднання (**tls.handshake.type == 1**):

![Free pcap labs - Визначення доменів: а також стовпець, який додає ім'я Server із початкового HTTPS-з'єднання ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Якщо перехоплення здебільшого зашифроване, додавання цих полів як стовпців значно пришвидшить triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Це дає змогу групувати сесії за hostname, ALPN (`http/1.1`, `h2`, `h3` тощо) і fingerprint клієнта, навіть коли сам payload залишається зашифрованим. Для розшифрованих перехоплень HTTP/2 і HTTP/3 також корисно додати `http2.header.value` або `http3.headers.header.value` як стовпці та виконувати pivot за шляхами, authorities й іншими цікавими metadata.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Визначення локальних імен хостів

### З DHCP

У поточній версії Wireshark замість `bootp` потрібно шукати `DHCP`

![Визначення локальних імен хостів — З DHCP: У поточній версії Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1013).png>)

### З NBNS

![З DHCP — З NBNS: У поточній версії Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1003).png>)

## Розшифрування TLS

### Розшифрування https-трафіку за допомогою приватного ключа сервера

_edit > preferences > protocols > tls >_

![Розшифрування TLS — Розшифрування https-трафіку за допомогою приватного ключа сервера: Розшифрування https-трафіку за допомогою приватного ключа сервера](<../../../images/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та приватного ключа (_IP, Port, Protocol, Key file і password_)

Цей метод працює лише в обмеженій кількості випадків. Для поточного трафіку TLS 1.3 / ECDHE практичним варіантом зазвичай є метод журналу ключів сеансу, описаний нижче.<sup>[[1]](#references)</sup>

### Розшифрування https-трафіку за допомогою симетричних ключів сеансу

Firefox і Chrome можуть записувати ключі сеансу TLS, які можна використовувати з Wireshark для розшифрування TLS-трафіку. Це дає змогу детально аналізувати захищені комунікації. Докладнішу інформацію про виконання цього розшифрування наведено в посібнику на [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Це також стандартний спосіб розшифрування сучасних захоплень TLS 1.3 і QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Щоб виявити це, виконайте пошук змінної `SSLKEYLOGFILE` в середовищі

Файл із спільними ключами матиме такий вигляд:

![Розшифрування https-трафіку за допомогою приватного ключа сервера — Розшифрування https-трафіку за допомогою симетричних ключів сеансу: Файл із спільними ключами матиме такий вигляд](<../../../images/image (820).png>)

Якщо захоплення має формат `pcapng`, перевірте, чи не містить воно вже вбудованих секретів для розшифрування, перш ніж шукати їх у файловій системі хоста:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Щоб імпортувати це у wireshark, перейдіть до \_edit > preferences > protocols > tls > і імпортуйте це в (Pre)-Master-Secret log filename:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

Витягніть APK з ADB communication, під час якого APK було надіслано:
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
- [2] [Розшифрування та аналіз HTTP/3 traffic у Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Розшифрування TLS Browser Traffic за допомогою Wireshark — простий спосіб!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Перегляд Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Довідник Display Filter: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Довідник Display Filter: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Довідник Display Filter: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
