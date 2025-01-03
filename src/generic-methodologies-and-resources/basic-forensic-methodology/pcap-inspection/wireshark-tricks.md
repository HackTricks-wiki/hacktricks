# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Покращте свої навички Wireshark

### Підручники

Наступні підручники чудові для вивчення деяких класних базових трюків:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Проаналізована інформація

**Експертна інформація**

Натискаючи на _**Analyze** --> **Expert Information**_, ви отримаєте **огляд** того, що відбувається в **аналізованих** пакетах:

![](<../../../images/image (256).png>)

**Вирішені адреси**

У _**Statistics --> Resolved Addresses**_ ви можете знайти кілька **інформації**, яка була "**вирішена**" Wireshark, наприклад, порт/транспорт до протоколу, MAC до виробника тощо. Цікаво знати, що залучено в комунікацію.

![](<../../../images/image (893).png>)

**Ієрархія протоколів**

У _**Statistics --> Protocol Hierarchy**_ ви можете знайти **протоколи**, **залучені** в комунікацію, та дані про них.

![](<../../../images/image (586).png>)

**Розмови**

У _**Statistics --> Conversations**_ ви можете знайти **резюме розмов** у комунікації та дані про них.

![](<../../../images/image (453).png>)

**Точки доступу**

У _**Statistics --> Endpoints**_ ви можете знайти **резюме точок доступу** в комунікації та дані про кожну з них.

![](<../../../images/image (896).png>)

**DNS інформація**

У _**Statistics --> DNS**_ ви можете знайти статистику про захоплені DNS запити.

![](<../../../images/image (1063).png>)

**I/O графік**

У _**Statistics --> I/O Graph**_ ви можете знайти **графік комунікації.**

![](<../../../images/image (992).png>)

### Фільтри

Тут ви можете знайти фільтри Wireshark в залежності від протоколу: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Інші цікаві фільтри:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP та початковий HTTPS трафік
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP та початковий HTTPS трафік + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP та початковий HTTPS трафік + TCP SYN + DNS запити

### Пошук

Якщо ви хочете **шукати** **вміст** всередині **пакетів** сесій, натисніть _CTRL+f_. Ви можете додати нові шари до основної інформаційної панелі (No., Time, Source тощо), натиснувши праву кнопку миші, а потім редагуючи стовпець.

### Безкоштовні лабораторії pcap

**Практикуйтеся з безкоштовними викликами на:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Ідентифікація доменів

Ви можете додати стовпець, який показує заголовок Host HTTP:

![](<../../../images/image (639).png>)

І стовпець, який додає ім'я сервера з ініціюючого HTTPS з'єднання (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Ідентифікація локальних імен хостів

### З DHCP

У сучасному Wireshark замість `bootp` вам потрібно шукати `DHCP`

![](<../../../images/image (1013).png>)

### З NBNS

![](<../../../images/image (1003).png>)

## Дешифрування TLS

### Дешифрування HTTPS трафіку з приватним ключем сервера

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Натисніть _Edit_ і додайте всі дані сервера та приватний ключ (_IP, Port, Protocol, Key file and password_)

### Дешифрування HTTPS трафіку з симетричними сесійними ключами

Як Firefox, так і Chrome мають можливість записувати сесійні ключі TLS, які можна використовувати з Wireshark для дешифрування TLS трафіку. Це дозволяє проводити детальний аналіз захищених комунікацій. Більше деталей про те, як виконати це дешифрування, можна знайти в посібнику на [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Щоб виявити це, шукайте в середовищі змінну `SSLKEYLOGFILE`

Файл спільних ключів виглядатиме так:

![](<../../../images/image (820).png>)

Щоб імпортувати це в Wireshark, перейдіть до \_edit > preference > protocol > ssl > і імпортуйте його в (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB комунікація

Витягніть APK з ADB комунікації, де APK був надісланий:
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
