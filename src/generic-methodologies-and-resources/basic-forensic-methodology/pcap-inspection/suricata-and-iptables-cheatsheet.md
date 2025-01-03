# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

In iptables, lyste van reëls bekend as chains word opeenvolgend verwerk. Onder hierdie is daar drie primêre chains wat universeel teenwoordig is, met addisionele soos NAT wat moontlik ondersteun word, afhangende van die stelsels se vermoëns.

- **Input Chain**: Gebruik om die gedrag van inkomende verbindings te bestuur.
- **Forward Chain**: Gebruik om inkomende verbindings te hanteer wat nie bestem is vir die plaaslike stelsel nie. Dit is tipies vir toestelle wat as routers optree, waar die data wat ontvang word bedoel is om na 'n ander bestemming gestuur te word. Hierdie chain is hoofsaaklik relevant wanneer die stelsel betrokke is by routing, NATing, of soortgelyke aktiwiteite.
- **Output Chain**: Toegewyd aan die regulering van uitgaande verbindings.

Hierdie chains verseker die ordelike verwerking van netwerkverkeer, wat die spesifikasie van gedetailleerde reëls wat die vloei van data in, deur, en uit 'n stelsel regeer, moontlik maak.
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

### Installeer & Konfigureer
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
### Reëls Definisies

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 'n Reël/handtekening bestaan uit die volgende:

- Die **aksie**, bepaal wat gebeur wanneer die handtekening ooreenstem.
- Die **kop**, definieer die protokol, IP adresse, poorte en rigting van die reël.
- Die **reël opsies**, definieer die spesifieke van die reël.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geldige aksies is**

- alert - genereer 'n waarskuwing
- pass - stop verdere inspeksie van die pakket
- **drop** - laat pakket val en genereer waarskuwing
- **reject** - stuur RST/ICMP onbereikbaar fout na die sender van die ooreenstemmende pakket.
- rejectsrc - dieselfde as net _reject_
- rejectdst - stuur RST/ICMP foutpakket na die ontvanger van die ooreenstemmende pakket.
- rejectboth - stuur RST/ICMP foutpakkette na albei kante van die gesprek.

#### **Protokolle**

- tcp (vir tcp-verkeer)
- udp
- icmp
- ip (ip staan vir 'alle' of 'enige')
- _laag7 protokolle_: http, ftp, tls, smb, dns, ssh... (meer in die [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Bron- en Bestemmingsadresse

Dit ondersteun IP-reekse, ontkennings en 'n lys van adresse:

| Voorbeeld                       | Betekenis                                  |
| ------------------------------- | ------------------------------------------ |
| ! 1.1.1.1                       | Elke IP-adres behalwe 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]            | Elke IP-adres behalwe 1.1.1.1 en 1.1.1.2 |
| $HOME_NET                       | Jou instelling van HOME_NET in yaml       |
| \[$EXTERNAL\_NET, !$HOME_NET]  | EXTERNAL_NET en nie HOME_NET nie         |
| \[10.0.0.0/24, !10.0.0.5]       | 10.0.0.0/24 behalwe vir 10.0.0.5          |

#### Bron- en Bestemmingspoorte

Dit ondersteun poortreekse, ontkennings en lyste van poorte

| Voorbeeld         | Betekenis                                |
| ----------------- | ---------------------------------------- |
| any               | enige adres                              |
| \[80, 81, 82]     | poort 80, 81 en 82                      |
| \[80: 82]         | Reeks van 80 tot 82                     |
| \[1024: ]         | Van 1024 tot die hoogste poortnommer    |
| !80               | Elke poort behalwe 80                    |
| \[80:100,!99]     | Reeks van 80 tot 100 maar 99 uitgesluit  |
| \[1:80,!\[2,4]]   | Reeks van 1-80, behalwe poorte 2 en 4   |

#### Rigting

Dit is moontlik om die rigting van die kommunikasie reël wat toegepas word aan te dui:
```
source -> destination
source <> destination  (both directions)
```
#### Sleutelwoorde

Daar is **honderde opsies** beskikbaar in Suricata om die **spesifieke pakket** te soek waarna jy op soek is, hier sal genoem word of iets interessant gevind word. Kyk na die [**dokumentasie** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) vir meer!
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
