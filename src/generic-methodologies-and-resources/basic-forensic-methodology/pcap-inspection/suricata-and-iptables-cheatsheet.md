# Suricata & Iptables-Spickzettel

## Iptables

### Ketten

In iptables ist jede Kette eine sequenzielle Liste von Regeln, die Pakete abgleichen. Die standardmäßige Tabelle `filter` enthält die integrierten Ketten `INPUT`, `FORWARD` und `OUTPUT`; je nach Kernel-Konfiguration und geladenen Modulen können weitere Tabellen wie `nat` verfügbar sein.<sup>[[1]](#references)</sup>

- **Input Chain**: Wird zur Verwaltung des Verhaltens eingehender Verbindungen verwendet.
- **Forward Chain**: Wird zur Verarbeitung eingehender Verbindungen verwendet, die nicht für das lokale System bestimmt sind. Dies ist typisch für Geräte, die als Router fungieren, bei denen die empfangenen Daten an ein anderes Ziel weitergeleitet werden sollen. Diese Kette ist hauptsächlich relevant, wenn das System am Routing, NATing oder ähnlichen Aktivitäten beteiligt ist.
- **Output Chain**: Dient der Regulierung ausgehender Verbindungen.

Diese Ketten gewährleisten die geordnete Verarbeitung des Netzwerkverkehrs und ermöglichen die Festlegung detaillierter Regeln für den Datenfluss in ein System, durch ein System hindurch und aus einem System heraus.

Die Beispiele für String-Matching verwenden den standardmäßigen `string`-Match; das Matching unterscheidet zwischen Groß- und Kleinschreibung, sofern nicht `--icase` angegeben wird, und `--algo` wählt die BM- oder KMP-Suchstrategie aus.<sup>[[2]](#references)</sup>
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

### Installation & Konfiguration

Die folgenden Paketbefehle sind distributions- und release-spezifisch; die offizielle Installationsanleitung dokumentiert das Ubuntu-PPA, Debian-Backports, RPM-Pakete und die Verwaltung von systemd-Diensten.<sup>[[3]](#references)</sup>
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
Die `suricata-update`-Sequenz folgt dem dokumentierten Suricata-Workflow zum Abrufen, Auflisten, Aktivieren und Laden von Regelquellen.<sup>[[4]](#references)</sup> Der oben gezeigte Befehl `suricatasc` ist eine dokumentierte Methode zum nicht blockierenden Neuladen von Regeln über einen Unix-Socket.<sup>[[8]](#references)</sup> Die NFQUEUE-Regeln leiten lokalen eingehenden und ausgehenden Datenverkehr an Suricata weiter, während `-q 0` die Queue 0 für die Inline-Verarbeitung auswählt.<sup>[[7]](#references)</sup>

### Regeldefinitionen

Eine Suricata-Regel/Signatur besteht aus drei Teilen.<sup>[[5]](#references)</sup>

- Die **action** legt fest, was geschieht, wenn die Signatur übereinstimmt.
- Der **header** wählt das Protokoll, die IP-Adressen, die Ports und die Richtung aus.
- Die **rule options** definieren die detailspezifischen Übereinstimmungsbedingungen.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Gültige Aktionen sind**

- alert - eine Warnung erzeugen
- pass - weitere Inspektion des Pakets stoppen
- **drop** - Paket verwerfen und eine Warnung erzeugen
- **reject** - einen RST/ICMP-unreachable-Fehler an den Absender des passenden Pakets senden.
- rejectsrc - dasselbe wie _reject_
- rejectdst - ein RST/ICMP-Fehlerpaket an den Empfänger des passenden Pakets senden.
- rejectboth - RST/ICMP-Fehlerpakete an beide Seiten der Kommunikation senden.

#### **Protokolle**

- tcp (für tcp-traffic)
- udp
- icmp
- ip (ip steht für „alle“ oder „beliebige“)
- _Layer-7-Protokolle_: http, ftp, tls, smb, dns, ssh und andere.<sup>[[5]](#references)</sup>

#### Quell- und Zieladressen

Suricata unterstützt IP-Bereiche, Negation und gruppierte Adresslisten.<sup>[[5]](#references)</sup>

| Beispiel                      | Bedeutung                                  |
| ----------------------------- | ------------------------------------------ |
| ! 1.1.1.1                     | Jede IP-Adresse außer 1.1.1.1              |
| !\[1.1.1.1, 1.1.1.2]          | Jede IP-Adresse außer 1.1.1.1 und 1.1.1.2 |
| $HOME_NET                     | Ihre Einstellung von HOME_NET in yaml      |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET und nicht HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 außer 10.0.0.5                 |

#### Quell- und Zielports

Suricata unterstützt Portbereiche, Negation und Portlisten.<sup>[[5]](#references)</sup>

| Beispiel         | Bedeutung                                  |
| --------------- | ------------------------------------------ |
| any             | beliebige Adresse                          |
| \[80, 81, 82]   | Port 80, 81 und 82                          |
| \[80: 82]       | Bereich von 80 bis 82                       |
| \[1024: ]       | Von 1024 bis zur höchsten Portnummer        |
| !80             | Jeder Port außer 80                         |
| \[80:100,!99]   | Bereich von 80 bis 100, jedoch ohne 99      |
| \[1:80,!\[2,4]] | Bereich von 1–80, außer den Ports 2 und 4   |

#### Richtung

Suricata-Regeln können die zu bewertende Kommunikationsrichtung angeben.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Schlüsselwörter

Die folgenden Beispiele verwenden die Regel-Schlüsselwörter von Suricata, einschließlich Optionen für Metadaten, IP, ICMP, Payload und die Anwendungsschicht; die offizielle Regeldokumentation katalogisiert diese Kategorien und ihre Syntax.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — Suricata 7.0.14-Dokumentation](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Regelverwaltung mit Suricata-Update — Suricata 8.0.1-Dokumentation](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Regelformat — Suricata 8.0.3-Dokumentation](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload-Schlüsselwörter — Suricata 8.0.3-Dokumentation](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Einrichten von IPS/inline für Linux — Suricata 7.0.15-Dokumentation](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Neuladen von Regeln — Suricata 7.0.14-Dokumentation](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata-Regeln — Suricata 8.0.3-Dokumentation](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
