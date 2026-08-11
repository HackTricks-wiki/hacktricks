# Трюки Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Покращення навичок роботи з Wireshark

### Навчальні матеріали

Наведені нижче навчальні матеріали чудово допоможуть вивчити корисні базові трюки:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Проаналізована інформація

**Експертна інформація**

Натиснувши _**Analyze** --> **Expert Information**_, ви отримаєте **огляд** того, що відбувається в **проаналізованих** пакетах:

![Навчальні матеріали - Проаналізована інформація: натиснувши Analyze -- Expert Information, ви отримаєте огляд того, що відбувається в проаналізованих пакетах](<../../../images/image (256).png>)

**Визначені адреси**

У розділі _**Statistics --> Resolved Addresses**_ можна знайти різну **інформацію**, яку wireshark "**визначив**", наприклад порт/транспорт до протоколу, MAC-адресу до виробника тощо. Цікаво знати, що саме задіяно у взаємодії.

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- Resolved Addresses можна знайти різну інформацію, яку " визначив " wireshark, наприклад порт/транспорт до протоколу, MAC-адресу до...](<../../../images/image (893).png>)

**Ієрархія протоколів**

У розділі _**Statistics --> Protocol Hierarchy**_ можна знайти **протоколи**, **задіяні** у взаємодії, та дані про них.

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- Protocol Hierarchy можна знайти протоколи, задіяні у взаємодії, та дані про них](<../../../images/image (586).png>)

**З'єднання**

У розділі _**Statistics --> Conversations**_ можна знайти **підсумок з'єднань** у взаємодії та дані про них.

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- Conversations можна знайти підсумок з'єднань у взаємодії та дані про них](<../../../images/image (453).png>)

**Кінцеві точки**

У розділі _**Statistics --> Endpoints**_ можна знайти **підсумок кінцевих точок** у взаємодії та дані про кожну з них.

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- Endpoints можна знайти підсумок кінцевих точок у взаємодії та дані про кожну з них](<../../../images/image (896).png>)

**Інформація DNS**

У розділі _**Statistics --> DNS**_ можна знайти статистику щодо перехоплених DNS-запитів.

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- DNS можна знайти статистику щодо перехоплених DNS-запитів](<../../../images/image (1063).png>)

**Графік I/O**

У розділі _**Statistics --> I/O Graph**_ можна знайти **графік взаємодії.**

![Навчальні матеріали - Проаналізована інформація: у розділі Statistics -- I/O Graph можна знайти графік взаємодії](<../../../images/image (992).png>)

### Фільтри

Тут можна знайти фільтр Wireshark залежно від протоколу: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
У поточній версії Wireshark використовуйте `tls.*` замість старих назв фільтрів `ssl.*`.<sup>[[1]](#references)</sup>\
Інші цікаві фільтри:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP і початковий HTTPS-трафік + TCP SYN + DNS-запити
- `tls.handshake.extensions_server_name contains "example.com"`
- Виконання pivot за SNI, надісланим у ClientHello, навіть коли неможливо розшифрувати payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Швидке розділення класичних HTTPS-сеансів і сеансів із підтримкою HTTP/2 та HTTP/3
- `quic or http3`
- Пошук сучасного UDP/443-трафіку, який буде пропущено, якщо переглядати лише TCP-з'єднання

### Пошук

Якщо потрібно **шукати** **вміст** усередині **пакетів** сеансів, натисніть _CTRL+f_. Можна додати нові стовпці до основної інформаційної панелі (No., Time, Source тощо), натиснувши праву кнопку миші, а потім вибравши редагування стовпця.

### Перегляд мультиплексованих потоків

Wireshark може безпосередньо переглядати потоки `TLS`, `HTTP/2` і `QUIC`. Його діалогові вікна HTTP/2 і QUIC надають селектори з'єднань і підпотоків, що допомагає ізолювати мультиплексовані потоки, які використовують спільне з'єднання нижчого рівня.<sup>[[4]](#references)</sup>

### Безкоштовні pcap-лабораторії

**Практикуйтеся на безкоштовних завданнях:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Визначення доменів

Можна додати стовпець, який показує HTTP-заголовок Host:

![Безкоштовні pcap-лабораторії - Визначення доменів: можна додати стовпець, який показує HTTP-заголовок Host](<../../../images/image (639).png>)

А також стовпець, який додає ім'я сервера з HTTPS-з'єднання, що ініціюється (**tls.handshake.type == 1**):

![Безкоштовні pcap-лабораторії - Визначення доменів: а також стовпець, який додає ім'я сервера з HTTPS-з'єднання, що ініціюється ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Якщо захоплення переважно зашифроване, додавання цих полів як стовпців значно пришвидшить triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Це дає змогу групувати сеанси за іменем хоста, ALPN (`http/1.1`, `h2`, `h3` тощо) і відбитком клієнта, навіть якщо сам payload залишається зашифрованим. Для розшифрованих захоплень HTTP/2 і HTTP/3 також корисно додати `http2.header.value` або `http3.headers.header.value` як стовпці та виконувати pivot за шляхами, authorities та іншими цікавими метаданими.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
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

![Визначення локальних імен хостів - З DHCP: У поточній версії Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1013).png>)

### З NBNS

![З DHCP - З NBNS: У поточній версії Wireshark замість bootp потрібно шукати DHCP](<../../../images/image (1003).png>)

## Розшифрування TLS

### Розшифрування https-трафіку за допомогою приватного ключа сервера

_редагування > налаштування > протоколи > tls >_

![Розшифрування TLS - Розшифрування https-трафіку за допомогою приватного ключа сервера: Розшифрування https-трафіку за допомогою приватного ключа сервера](<../../../images/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та приватний ключ (_IP, Port, Protocol, Key file і пароль_)

Цей метод працює лише в обмеженій кількості випадків. Для поточного трафіку TLS 1.3 / ECDHE зазвичай практичним варіантом є наведений нижче метод журналу ключів сеансу.<sup>[[1]](#references)</sup>

### Розшифрування https-трафіку за допомогою симетричних ключів сеансу

Firefox і Chrome можуть записувати ключі сеансу TLS, які можна використовувати у Wireshark для розшифрування TLS-трафіку. Це дає змогу детально аналізувати захищені комунікації. Докладнішу інформацію про виконання цього розшифрування наведено в посібнику на [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Це також стандартний спосіб розшифрування сучасних захоплень TLS 1.3 і QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Щоб виявити це, виконайте пошук змінної `SSLKEYLOGFILE` у середовищі

Файл із спільними ключами матиме такий вигляд:

![Розшифрування https-трафіку за допомогою приватного ключа сервера - Розшифрування https-трафіку за допомогою симетричних ключів сеансу: Файл із спільними ключами матиме такий вигляд](<../../../images/image (820).png>)

Якщо захоплення має формат `pcapng`, перевірте, чи не містить воно вже вбудованих секретів для розшифрування, перш ніж шукати їх у файловій системі хоста:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Щоб імпортувати це у Wireshark, перейдіть до \_edit > preferences > protocols > tls > і імпортуйте його в (Pre)-Master-Secret log filename:

![Розшифрування https-трафіку за допомогою приватного ключа сервера — Розшифрування https-трафіку за допомогою симетричних ключів сесії: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

Extract an APK from an ADB communication where the APK was sent:
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
- [2] [Розшифрування та аналіз HTTP/3-трафіку у Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Розшифрування браузерного TLS-трафіку за допомогою Wireshark — простий спосіб!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Перегляд потоків протоколів](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Довідник фільтрів відображення: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Довідник фільтрів відображення: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Довідник фільтрів відображення: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
