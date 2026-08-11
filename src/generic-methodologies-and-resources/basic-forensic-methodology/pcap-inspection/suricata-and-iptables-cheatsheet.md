# Suricata i Iptables — ściągawka

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Łańcuchy

W iptables każdy łańcuch jest sekwencyjną listą reguł dopasowujących pakiety. Domyślna tabela `filter` zawiera wbudowane łańcuchy `INPUT`, `FORWARD` i `OUTPUT`; inne tabele, takie jak `nat`, mogą być dostępne w zależności od konfiguracji jądra i załadowanych modułów.<sup>[[1]](#references)</sup>

- **Łańcuch Input**: Wykorzystywany do zarządzania zachowaniem połączeń przychodzących.
- **Łańcuch Forward**: Służy do obsługi połączeń przychodzących, które nie są przeznaczone dla systemu lokalnego. Jest to typowe dla urządzeń działających jako routery, gdzie odebrane dane mają zostać przekazane do innego miejsca docelowego. Ten łańcuch ma znaczenie przede wszystkim wtedy, gdy system uczestniczy w routingu, NATowaniu lub podobnych działaniach.
- **Łańcuch Output**: Przeznaczony do regulowania połączeń wychodzących.

Łańcuchy te zapewniają uporządkowane przetwarzanie ruchu sieciowego, umożliwiając określanie szczegółowych reguł zarządzających przepływem danych do systemu, przez system i z systemu.

Przykłady dopasowywania ciągów znaków używają standardowego dopasowania `string`; dopasowywanie uwzględnia wielkość liter, chyba że podano `--icase`, a `--algo` wybiera strategię wyszukiwania BM lub KMP.<sup>[[2]](#references)</sup>
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

Poniższe polecenia dotyczące pakietów są zależne od dystrybucji i wydania; oficjalny przewodnik instalacji opisuje Ubuntu PPA, backporty Debiana, pakiety RPM oraz zarządzanie usługami systemd.<sup>[[3]](#references)</sup>
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
Sekwencja `suricata-update` jest zgodna z udokumentowanym workflow Suricata dotyczącym pobierania, wyświetlania, włączania i ładowania źródeł reguł.<sup>[[4]](#references)</sup> Powyższe polecenie `suricatasc` to udokumentowana, nieblokująca metoda przeładowywania reguł za pośrednictwem gniazda Unix.<sup>[[8]](#references)</sup> Reguły NFQUEUE przekazują lokalny ruch przychodzący i wychodzący do Suricata, natomiast `-q 0` wybiera kolejkę 0 na potrzeby przetwarzania inline.<sup>[[7]](#references)</sup>

### Definicje reguł

Reguła/sygnatura Suricata składa się z trzech części.<sup>[[5]](#references)</sup>

- **Akcja** określa, co się stanie, gdy sygnatura zostanie dopasowana.
- **Nagłówek** określa protokół, adresy IP, porty i kierunek.
- **Opcje reguły** definiują szczegóły właściwe dla danego dopasowania.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Prawidłowe akcje to**

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
- ip (ip oznacza „all” lub „any”)
- _protokoły layer7_: http, ftp, tls, smb, dns, ssh i inne.<sup>[[5]](#references)</sup>

#### Adresy źródłowe i docelowe

Suricata obsługuje zakresy adresów IP, negację i grupowane listy adresów.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Każdy adres IP oprócz 1.1.1.1            |
| !\[1.1.1.1, 1.1.1.2]          | Każdy adres IP oprócz 1.1.1.1 i 1.1.1.2  |
| $HOME_NET                     | Ustawienie HOME_NET w yaml               |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET, ale nie HOME_NET           |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 z wyjątkiem 10.0.0.5         |

#### Porty źródłowe i docelowe

Suricata obsługuje zakresy portów, negację i listy portów.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | dowolny adres                          |
| \[80, 81, 82]   | porty 80, 81 i 82                      |
| \[80: 82]       | zakres od 80 do 82                     |
| \[1024: ]       | od 1024 do najwyższego numeru portu    |
| !80             | każdy port oprócz 80                   |
| \[80:100,!99]   | zakres od 80 do 100 bez portu 99       |
| \[1:80,!\[2,4]] | zakres od 1 do 80 oprócz portów 2 i 4  |

#### Kierunek

Reguły Suricata mogą określać kierunek analizowanej komunikacji.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Słowa kluczowe

Poniższe przykłady używają słów kluczowych reguł Suricata, w tym opcji dotyczących metadanych, IP, ICMP, payloadu i warstwy aplikacji; oficjalna dokumentacja reguł zawiera katalog tych rodzin oraz ich składnię.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Instalacja — dokumentacja Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Zarządzanie regułami za pomocą Suricata-Update — dokumentacja Suricata 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Format reguł — dokumentacja Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Słowa kluczowe payloadu — dokumentacja Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Konfiguracja IPS/inline dla Linux — dokumentacja Suricata 7.0.15](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Przeładowywanie reguł — dokumentacja Suricata 7.0.14](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Reguły Suricata — dokumentacja Suricata 8.0.3](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
