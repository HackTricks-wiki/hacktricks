# Suricata & Iptables - ściągawka

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Łańcuchy

W iptables listy reguł znane jako łańcuchy są przetwarzane sekwencyjnie. Wśród nich zawsze obecne są trzy podstawowe łańcuchy, a dodatkowe, takie jak NAT, mogą być obsługiwane w zależności od możliwości systemu.

- **Input Chain**: Używany do zarządzania zachowaniem połączeń przychodzących.
- **Forward Chain**: Służy do obsługi połączeń przychodzących, które nie są przeznaczone dla systemu lokalnego. Jest to typowe dla urządzeń działających jako routery, gdzie odebrane dane mają zostać przekazane do innego miejsca docelowego. Ten łańcuch ma znaczenie głównie wtedy, gdy system uczestniczy w routingu, NATowaniu lub podobnych działaniach.
- **Output Chain**: Przeznaczony do regulowania połączeń wychodzących.

Łańcuchy te zapewniają uporządkowane przetwarzanie ruchu sieciowego, umożliwiając określanie szczegółowych reguł sterujących przepływem danych do systemu, przez niego oraz poza nim.
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

### Instalacja i konfiguracja
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
### Definicje reguł

[Z dokumentacji:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Reguła/sygnatura składa się z następujących elementów:

- **action** określa, co się dzieje, gdy sygnatura pasuje.
- **header** definiuje protokół, adresy IP, porty i kierunek reguły.
- **rule options** definiują szczegóły reguły.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Dostępne akcje to**

- alert - generuje alert
- pass - zatrzymuje dalszą inspekcję pakietu
- **drop** - odrzuca pakiet i generuje alert
- **reject** - wysyła błąd RST/ICMP unreachable do nadawcy pasującego pakietu.
- rejectsrc - to samo co _reject_
- rejectdst - wysyła pakiet błędu RST/ICMP do odbiorcy pasującego pakietu.
- rejectboth - wysyła pakiety błędu RST/ICMP do obu stron komunikacji.

#### **Protokoły**

- tcp (dla ruchu tcp)
- udp
- icmp
- ip (ip oznacza ‘all’ lub ‘any’)
- _protokoły layer7_: http, ftp, tls, smb, dns, ssh... (więcej w [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Adresy źródłowe i docelowe

Obsługuje zakresy adresów IP, negacje oraz listę adresów:

| Przykład                     | Znaczenie                                  |
| ---------------------------- | ------------------------------------------ |
| ! 1.1.1.1                    | Każdy adres IP oprócz 1.1.1.1              |
| !\[1.1.1.1, 1.1.1.2]         | Każdy adres IP oprócz 1.1.1.1 i 1.1.1.2   |
| $HOME_NET                    | Twoje ustawienie HOME_NET w yaml           |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET, ale nie HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]    | 10.0.0.0/24 z wyjątkiem 10.0.0.5          |

#### Porty źródłowe i docelowe

Obsługuje zakresy portów, negacje oraz listy portów

| Przykład        | Znaczenie                              |
| --------------- | -------------------------------------- |
| any             | dowolny adres                          |
| \[80, 81, 82]   | porty 80, 81 i 82                      |
| \[80: 82]       | Zakres od 80 do 82                     |
| \[1024: ]       | Od 1024 do najwyższego numeru portu    |
| !80             | Każdy port oprócz 80                   |
| \[80:100,!99]   | Zakres od 80 do 100 z wykluczeniem 99  |
| \[1:80,!\[2,4]] | Zakres od 1 do 80 z wyjątkiem portów 2 i 4  |

#### Kierunek

Możliwe jest wskazanie kierunku komunikacji, do którego stosowana jest reguła:
```
source -> destination
source <> destination  (both directions)
```
#### Słowa kluczowe

W Suricata dostępne są **setki opcji** umożliwiających wyszukiwanie **konkretnego pakietu**, którego szukasz. W tym miejscu zostanie wspomniane, jeśli zostanie znalezione coś interesującego. Więcej informacji znajdziesz w [**dokumentacji** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)!
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
