# Suricata & Iptables-spiekbrief

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Kettings

In iptables word lyste reëls, bekend as kettings, opeenvolgend verwerk. Hiervan is drie primêre kettings universeel teenwoordig, terwyl bykomende kettings soos NAT moontlik ondersteun word, afhangend van die stelsel se vermoëns.

- **Input Chain**: Word gebruik om die gedrag van inkomende verbindings te bestuur.
- **Forward Chain**: Word gebruik om inkomende verbindings te hanteer wat nie vir die plaaslike stelsel bestem is nie. Dit is tipies vir toestelle wat as routers optree, waar die ontvangde data na ’n ander bestemming aangestuur moet word. Hierdie ketting is hoofsaaklik relevant wanneer die stelsel by routing, NATing of soortgelyke aktiwiteite betrokke is.
- **Output Chain**: Word toegewy aan die regulering van uitgaande verbindings.

Hierdie kettings verseker die ordelike verwerking van netwerkverkeer, wat die spesifikasie van gedetailleerde reëls moontlik maak om die vloei van data na, deur en uit ’n stelsel te beheer.
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

### Installering en konfigurasie
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
### Reëldefinisies

[Uit die dokumentasie:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) ’n Reël/handtekening bestaan uit die volgende:

- Die **aksie** bepaal wat gebeur wanneer die handtekening ooreenstem.
- Die **kopteks** definieer die protokol, IP-adresse, poorte en rigting van die reël.
- Die **reëlopsies** definieer die besonderhede van die reël.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geldige actions is**

- alert - genereer ’n alert
- pass - stop verdere inspection van die packet
- **drop** - drop die packet en genereer ’n alert
- **reject** - stuur ’n RST/ICMP unreachable error na die sender van die matching packet.
- rejectsrc - dieselfde as net _reject_
- rejectdst - stuur ’n RST/ICMP error packet na die receiver van die matching packet.
- rejectboth - stuur RST/ICMP error packets na beide kante van die gesprek.

#### **Protokolle**

- tcp (for tcp-traffic)
- udp
- icmp
- ip (ip staan vir ‘all’ of ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (meer in die [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Source- en Destination-addresses

Dit ondersteun IP-ranges, negations en ’n lys addresses:

| Example                       | Betekenis                                  |
| ----------------------------- | ------------------------------------------ |
| ! 1.1.1.1                     | Elke IP-address behalwe 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Elke IP-address behalwe 1.1.1.1 en 1.1.1.2 |
| $HOME_NET                     | Jou instelling van HOME_NET in yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET en nie HOME_NET nie            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 behalwe 10.0.0.5          |

#### Source- en Destination-ports

Dit ondersteun port ranges, negations en lyste van ports

| Example         | Betekenis                                |
| --------------- | -------------------------------------- |
| any             | enige address                            |
| \[80, 81, 82]   | port 80, 81 en 82                     |
| \[80: 82]       | Range van 80 tot 82                  |
| \[1024: ]       | Vanaf 1024 tot die hoogste port-number |
| !80             | Elke port behalwe 80                      |
| \[80:100,!99]   | Range van 80 tot 100, maar 99 uitgesluit |
| \[1:80,!\[2,4]] | Range van 1-80, behalwe ports 2 en 4  |

#### Direction

Dit is moontlik om die rigting van die kommunikasie aan te dui waarop die rule toegepas word:
```
source -> destination
source <> destination  (both directions)
```
#### Sleutelwoorde

Daar is **honderde opsies** beskikbaar in Suricata om na die **spesifieke pakkie** te soek waarna jy op soek is; hier sal dit vermeld word indien iets interessants gevind word. Kyk na die [**dokumentasie** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)vir meer!
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
