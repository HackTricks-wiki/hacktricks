# Шпаргалка Suricata та Iptables

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Ланцюги

В iptables списки правил, відомі як ланцюги, обробляються послідовно. Серед них три основні ланцюги присутні всюди, а додаткові, наприклад NAT, можуть підтримуватися залежно від можливостей системи.

- **Input Chain**: Використовується для керування поведінкою вхідних з'єднань.
- **Forward Chain**: Використовується для обробки вхідних з'єднань, призначених не для локальної системи. Це типово для пристроїв, що працюють як маршрутизатори, де отримані дані потрібно переспрямувати до іншого пункту призначення. Цей ланцюг має значення переважно тоді, коли система бере участь у маршрутизації, NAT або подібних операціях.
- **Output Chain**: Призначений для регулювання вихідних з'єднань.

Ці ланцюги забезпечують упорядковану обробку мережевого трафіку, даючи змогу визначати детальні правила, що керують потоком даних у систему, через неї та з неї.
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
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
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
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
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
### Визначення правил

[З документації:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Правило/сигнатура складається з такого:

- **дія** визначає, що відбувається, коли сигнатура спрацьовує.
- **заголовок** визначає протокол, IP-адреси, порти та напрямок правила.
- **опції правила** визначають його специфіку.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Допустимі дії**

- alert - згенерувати сповіщення
- pass - припинити подальшу перевірку пакета
- **drop** - відкинути пакет і згенерувати сповіщення
- **reject** - надіслати відправнику відповідного пакета помилку RST/ICMP unreachable.
- rejectsrc - те саме, що й _reject_
- rejectdst - надіслати отримувачу відповідного пакета пакет із помилкою RST/ICMP.
- rejectboth - надіслати пакети з помилкою RST/ICMP обом сторонам з'єднання.

#### **Протоколи**

- tcp (для tcp-трафіку)
- udp
- icmp
- ip (ip означає «all» або «any»)
- _протоколи layer7_: http, ftp, tls, smb, dns, ssh... (більше в [**документації**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Адреси джерела та призначення

Підтримуються діапазони IP-адрес, заперечення та список адрес:

| Приклад                       | Значення                                  |
| ----------------------------- | ----------------------------------------- |
| ! 1.1.1.1                     | Кожна IP-адреса, крім 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Кожна IP-адреса, крім 1.1.1.1 і 1.1.1.2   |
| $HOME_NET                     | Ваше значення HOME_NET у yaml             |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET, але не HOME_NET             |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24, за винятком 10.0.0.5         |

#### Порти джерела та призначення

Підтримуються діапазони портів, заперечення та списки портів

| Приклад         | Значення                              |
| --------------- | ------------------------------------- |
| any             | будь-яка адреса                       |
| \[80, 81, 82]   | порти 80, 81 і 82                     |
| \[80: 82]       | діапазон від 80 до 82                 |
| \[1024: ]       | від 1024 до найбільшого номера порту  |
| !80             | кожен порт, крім 80                  |
| \[80:100,!99]   | діапазон від 80 до 100, крім 99       |
| \[1:80,!\[2,4]] | діапазон від 1 до 80, крім портів 2 і 4 |

#### Напрямок

Можна вказати напрямок з'єднання, до якого застосовується правило:
```
source -> destination
source <> destination  (both directions)
```
#### Ключові слова

У Suricata доступні **сотні опцій** для пошуку **конкретного пакета**, який ви шукаєте; тут буде зазначено, якщо буде знайдено щось цікаве. Перегляньте [**документацію** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)для отримання додаткової інформації!
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
{{#include ../../../banners/hacktricks-training.md}}
