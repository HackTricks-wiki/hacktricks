# Suricata & Iptables-Spickzettel

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Ketten

In iptables werden Listen von Regeln, die als Ketten bezeichnet werden, sequenziell verarbeitet. Drei primäre Ketten sind grundsätzlich vorhanden; zusätzliche Ketten wie NAT werden abhängig von den Fähigkeiten des Systems möglicherweise unterstützt.

- **Input Chain**: Wird zur Verwaltung des Verhaltens eingehender Verbindungen verwendet.
- **Forward Chain**: Wird zur Verarbeitung eingehender Verbindungen verwendet, die nicht für das lokale System bestimmt sind. Dies ist typisch für Geräte, die als Router fungieren, bei denen die empfangenen Daten an ein anderes Ziel weitergeleitet werden sollen. Diese Kette ist hauptsächlich relevant, wenn das System am Routing, NATing oder ähnlichen Aktivitäten beteiligt ist.
- **Output Chain**: Dient der Regulierung ausgehender Verbindungen.

Diese Ketten gewährleisten die geordnete Verarbeitung des Netzwerkverkehrs und ermöglichen die Festlegung detaillierter Regeln für den Datenfluss in ein System, durch ein System hindurch und aus einem System heraus.
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

### Installation und Konfiguration
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
### Regeldefinitionen

[Aus der Dokumentation:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Eine Regel/Signatur besteht aus Folgendem:

- Die **action** bestimmt, was passiert, wenn die Signatur übereinstimmt.
- Der **header** definiert das Protokoll, IP-Adressen, Ports und die Richtung der Regel.
- Die **rule options** definieren die Details der Regel.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Gültige Aktionen sind**

- alert - einen Alert erzeugen
- pass - die weitere Inspektion des Pakets stoppen
- **drop** - Paket verwerfen und einen Alert erzeugen
- **reject** - einen RST/ICMP-unreachable-Fehler an den Absender des übereinstimmenden Pakets senden.
- rejectsrc - dasselbe wie _reject_
- rejectdst - ein RST/ICMP-Fehlerpaket an den Empfänger des übereinstimmenden Pakets senden.
- rejectboth - RST/ICMP-Fehlerpakete an beide Seiten der Kommunikation senden.

#### **Protokolle**

- tcp (für tcp-traffic)
- udp
- icmp
- ip (ip steht für „all“ oder „any“)
- _Layer-7-Protokolle_: http, ftp, tls, smb, dns, ssh... (mehr in der [**Dokumentation**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Quell- und Zieladressen

IP-Bereiche, Negationen und eine Liste von Adressen werden unterstützt:

| Beispiel                      | Bedeutung                                  |
| ----------------------------- | ------------------------------------------ |
| ! 1.1.1.1                     | Jede IP-Adresse außer 1.1.1.1              |
| !\[1.1.1.1, 1.1.1.2]          | Jede IP-Adresse außer 1.1.1.1 und 1.1.1.2 |
| $HOME_NET                     | Deine Einstellung von HOME_NET in yaml     |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET und nicht HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 außer 10.0.0.5                |

#### Quell- und Zielports

Portbereiche, Negationen und Listen von Ports werden unterstützt.

| Beispiel         | Bedeutung                              |
| --------------- | -------------------------------------- |
| any             | jede Adresse                          |
| \[80, 81, 82]   | Port 80, 81 und 82                     |
| \[80: 82]       | Bereich von 80 bis 82                  |
| \[1024: ]       | Von 1024 bis zur höchsten Portnummer   |
| !80             | Jeder Port außer 80                    |
| \[80:100,!99]   | Bereich von 80 bis 100, außer Port 99  |
| \[1:80,!\[2,4]] | Bereich von 1–80, außer den Ports 2 und 4 |

#### Richtung

Es ist möglich, die Richtung der Kommunikation anzugeben, auf die die Regel angewendet wird:
```
source -> destination
source <> destination  (both directions)
```
#### Schlüsselwörter

In Suricata stehen **Hunderte von Optionen** zur Verfügung, um nach dem **spezifischen Paket** zu suchen, nach dem du suchst. Hier wird erwähnt, wenn etwas Interessantes gefunden wird. Sieh dir die [**Dokumentation** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) für weitere Informationen an!
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
