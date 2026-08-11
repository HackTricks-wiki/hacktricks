# Suricata & Iptables-cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Kettings

In iptables is elke ketting ’n opeenvolgende lys reëls wat met pakkette ooreenstem. Die verstek-`filter`-tabel het die ingeboude `INPUT`-, `FORWARD`- en `OUTPUT`-kettings; ander tabelle, soos `nat`, kan beskikbaar wees, afhangend van die kernkonfigurasie en gelaaide modules.<sup>[[1]](#references)</sup>

- **Input Chain**: Word gebruik om die gedrag van inkomende verbindings te bestuur.
- **Forward Chain**: Word gebruik om inkomende verbindings te hanteer wat nie vir die plaaslike stelsel bestem is nie. Dit is tipies vir toestelle wat as routers optree, waar die ontvangde data na ’n ander bestemming aangestuur moet word. Hierdie ketting is hoofsaaklik relevant wanneer die stelsel by routing, NATing of soortgelyke aktiwiteite betrokke is.
- **Output Chain**: Toegewy aan die regulering van uitgaande verbindings.

Hierdie kettings verseker die ordelike verwerking van netwerkverkeer, wat die spesifikasie van gedetailleerde reëls moontlik maak wat die vloei van data na, deur en uit ’n stelsel beheer.

Die string-match-voorbeelde gebruik die standaard `string`-passing; passing is hooflettergevoelig tensy `--icase` verskaf word, en `--algo` kies die BM- of KMP-soekstrategie.<sup>[[2]](#references)</sup>
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

### Installasie & Konfigurasie

Pakketopdragte is spesifiek vir die verspreiding en vrystelling; die amptelike installasiegids dokumenteer die Ubuntu PPA, Debian backports, RPM packages en systemd-diensbestuur.<sup>[[3]](#references)</sup>
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
Die `suricata-update`-volgorde volg Suricata se gedokumenteerde werkvloei vir die ophaal, lys, aktivering en laai van reëlbronne.<sup>[[4]](#references)</sup> Die `suricatasc`-opdrag hierbo is ’n gedokumenteerde nie-blokkerende Unix-soketmetode vir die herlaai van reëls.<sup>[[8]](#references)</sup> Die NFQUEUE-reëls stuur plaaslike in- en uitsetverkeer na Suricata, terwyl `-q 0` tou 0 vir inline-verwerking kies.<sup>[[7]](#references)</sup>

### Reëldefinisies

’n Suricata-reël/signature het drie dele.<sup>[[5]](#references)</sup>

- Die **aksie** spesifiseer wat gebeur wanneer die signature ooreenstem.
- Die **kopskrif** kies die protokol, IP-adresse, poorte en rigting.
- Die **reëlopsies** definieer die besonderhede wat spesifiek vir die passing is.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Geldige aksies is**

- alert - genereer 'n alert
- pass - stop verdere inspeksie van die packet
- **drop** - drop packet en genereer 'n alert
- **reject** - stuur 'n RST/ICMP unreachable-fout aan die sender van die ooreenstemmende packet.
- rejectsrc - dieselfde as _reject_
- rejectdst - stuur 'n RST/ICMP-foutpacket aan die ontvanger van die ooreenstemmende packet.
- rejectboth - stuur RST/ICMP-foutpakette aan albei kante van die gesprek.

#### **Protokolle**

- tcp (vir tcp-traffic)
- udp
- icmp
- ip (ip staan vir ‘all’ of ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh, en ander.<sup>[[5]](#references)</sup>

#### Bron- en Bestemmingsadresse

Suricata ondersteun IP-reekse, negasie en gegroepeerde adreslyste.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Elke IP-adres behalwe 1.1.1.1            |
| !\[1.1.1.1, 1.1.1.2]          | Elke IP-adres behalwe 1.1.1.1 en 1.1.1.2 |
| $HOME_NET                     | Jou instelling van HOME_NET in yaml      |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET en nie HOME_NET nie         |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 behalwe 10.0.0.5             |

#### Bron- en Bestemmingspoorte

Suricata ondersteun poortreekse, negasie en lyste van poorte.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | enige adres                           |
| \[80, 81, 82]   | poort 80, 81 en 82                     |
| \[80: 82]       | Reeks van 80 tot 82                    |
| \[1024: ]       | Vanaf 1024 tot by die hoogste poortnommer |
| !80             | Elke poort behalwe 80                 |
| \[80:100,!99]   | Reeks van 80 tot 100, maar 99 uitgesluit |
| \[1:80,!\[2,4]] | Reeks van 1-80, behalwe poorte 2 en 4  |

#### Rigting

Suricata-reëls kan die kommunikasierigting spesifiseer wat geëvalueer word.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Sleutelwoorde

Die voorbeelde hieronder gebruik Suricata se reëlsleutelwoorde, insluitend metadata-, IP-, ICMP-, payload- en toepassingslaagopsies; die amptelike reëldokumentasie katalogiseer hierdie families en hul sintaksis.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux-handleidingblad](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux-handleidingblad](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installasie — Suricata 7.0.14-dokumentasie](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Reëlbestuur met Suricata-Update — Suricata 8.0.1-dokumentasie](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Reëlsformaat — Suricata 8.0.3-dokumentasie](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload-sleutelwoorde — Suricata 8.0.3-dokumentasie](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Opstelling van IPS/inline vir Linux — Suricata 7.0.15-dokumentasie](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Herlaai van reëls — Suricata 7.0.14-dokumentasie](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata-reëls — Suricata 8.0.3-dokumentasie](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
