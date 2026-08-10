# Шпаргалка Suricata та Iptables

## Iptables

### Ланцюжки

В iptables кожен ланцюжок є послідовним списком правил зіставлення пакетів. Таблиця `filter` за замовчуванням містить вбудовані ланцюжки `INPUT`, `FORWARD` і `OUTPUT`; інші таблиці, наприклад `nat`, можуть бути доступні залежно від конфігурації ядра та завантажених модулів.<sup>[[1]](#references)</sup>

- **Ланцюжок Input**: використовується для керування поведінкою вхідних з'єднань.
- **Ланцюжок Forward**: використовується для обробки вхідних з'єднань, не призначених для локальної системи. Це типово для пристроїв, що виконують роль маршрутизаторів, коли отримані дані мають бути перенаправлені до іншого призначення. Цей ланцюжок має значення переважно тоді, коли система бере участь у маршрутизації, NATing або подібних операціях.
- **Ланцюжок Output**: призначений для регулювання вихідних з'єднань.

Ці ланцюжки забезпечують впорядковану обробку мережевого трафіку, даючи змогу визначати детальні правила, що керують потоком даних у систему, через неї та з неї.

У прикладах зіставлення рядків використовується стандартне зіставлення `string`; зіставлення чутливе до регістру, якщо не вказано `--icase`, а `--algo` вибирає стратегію пошуку BM або KMP.<sup>[[2]](#references)</sup>
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Встановлення та налаштування

Наведені нижче команди для роботи з пакетами залежать від дистрибутива та версії; в офіційному посібнику зі встановлення описано Ubuntu PPA, backports для Debian, RPM-пакети та керування службами systemd.<sup>[[3]](#references)</sup>
```bash
# Package installation details vary by distribution and release; see References.
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update update-sources
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl start suricata
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure Suricata as an IPS
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
Послідовність `suricata-update` відповідає задокументованому робочому процесу Suricata для отримання, переліку, увімкнення та завантаження джерел правил.<sup>[[4]](#references)</sup> Наведена вище команда `suricatasc` є задокументованим неблокувальним методом перезавантаження правил через Unix-сокет.<sup>[[8]](#references)</sup> Правила NFQUEUE надсилають локальний вхідний і вихідний трафік до Suricata, а `-q 0` вибирає чергу 0 для inline-обробки.<sup>[[7]](#references)</sup>

### Визначення правил

Правило/сигнатура Suricata складається з трьох частин.<sup>[[5]](#references)</sup>

- **Дія** визначає, що відбувається, коли сигнатура збігається.
- **Заголовок** визначає протокол, IP-адреси, порти та напрямок.
- **Параметри правила** визначають деталі, специфічні для збігу.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Допустимі дії**

- alert - згенерувати alert
- pass - припинити подальшу перевірку пакета
- **drop** - відкинути пакет і згенерувати alert
- **reject** - надіслати помилку RST/ICMP unreachable відправнику відповідного пакета.
- rejectsrc - те саме, що й _reject_
- rejectdst - надіслати пакет помилки RST/ICMP отримувачу відповідного пакета.
- rejectboth - надіслати пакети помилки RST/ICMP обом сторонам з'єднання.

#### **Протоколи**

- tcp (для tcp-traffic)
- udp
- icmp
- ip (ip означає «усі» або «будь-які»)
- _протоколи рівня 7_: http, ftp, tls, smb, dns, ssh та інші.<sup>[[5]](#references)</sup>

#### Адреси джерела та призначення

Suricata підтримує діапазони IP-адрес, заперечення та згруповані списки адрес.<sup>[[5]](#references)</sup>

| Приклад                     | Значення                                  |
| --------------------------- | ----------------------------------------- |
| ! 1.1.1.1                   | Кожна IP-адреса, крім 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]        | Кожна IP-адреса, крім 1.1.1.1 та 1.1.1.2 |
| $HOME_NET                   | Ваше значення HOME_NET у yaml             |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET, але не HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]   | 10.0.0.0/24, за винятком 10.0.0.5         |

#### Порти джерела та призначення

Suricata підтримує діапазони портів, заперечення та списки портів.<sup>[[5]](#references)</sup>

| Приклад         | Значення                                  |
| --------------- | ----------------------------------------- |
| any             | будь-яка адреса                           |
| \[80, 81, 82]   | порти 80, 81 та 82                        |
| \[80: 82]       | діапазон від 80 до 82                     |
| \[1024: ]       | від 1024 до найбільшого номера порту      |
| !80             | кожен порт, крім 80                       |
| \[80:100,!99]   | діапазон від 80 до 100, але без 99        |
| \[1:80,!\[2,4]] | діапазон від 1 до 80, крім портів 2 та 4  |

#### Напрямок

Правила Suricata можуть визначати напрямок з'єднання, що перевіряється.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Ключові слова

У наведених нижче прикладах використовуються rule keywords Suricata, зокрема параметри metadata, IP, ICMP, payload і application-layer; в офіційній документації до правил описано ці групи та їхній синтаксис.<sup>[[6]](#references)[[9]](#references)</sup>
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
## The replace modifier is IPS-only and operates on individual packets
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
## References

- [1] [iptables(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Встановлення — документація Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Керування правилами за допомогою Suricata-Update — документація Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Формат правил — документація Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Ключові слова корисного навантаження — документація Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Налаштування IPS/inline для Linux — документація Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Перезавантаження правил — документація Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Правила Suricata — документація Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
