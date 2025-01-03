# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

U iptables-u, liste pravila poznate kao lanci se obrađuju sekvencijalno. Među njima, tri primarna lanca su univerzalno prisutna, dok dodatni kao što je NAT mogu biti potencijalno podržani u zavisnosti od mogućnosti sistema.

- **Input Chain**: Koristi se za upravljanje ponašanjem dolaznih konekcija.
- **Forward Chain**: Koristi se za rukovanje dolaznim konekcijama koje nisu namenjene lokalnom sistemu. Ovo je tipično za uređaje koji deluju kao ruteri, gde su podaci koji se primaju namenjeni za prosleđivanje na drugu destinaciju. Ovaj lanac je relevantan prvenstveno kada je sistem uključen u rutiranje, NAT-ovanje ili slične aktivnosti.
- **Output Chain**: Posvećen regulaciji odlaznih konekcija.

Ovi lanci osiguravaju urednu obradu mrežnog saobraćaja, omogućavajući precizno definisanje detaljnih pravila koja upravljaju protokom podataka u, kroz i iz sistema.
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

### Instalacija i Konfiguracija
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
### Pravila Definicije

[Iz dokumenata:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Pravilo/potpis se sastoji od sledećeg:

- **akcija**, određuje šta se dešava kada se potpis poklapa.
- **zaglavlje**, definiše protokol, IP adrese, portove i pravac pravila.
- **opcije pravila**, definišu specifičnosti pravila.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Validne akcije su**

- alert - generiši upozorenje
- pass - zaustavi dalju inspekciju paketa
- **drop** - odbaci paket i generiši upozorenje
- **reject** - pošalji RST/ICMP grešku nedostupnosti pošiljaocu odgovarajućeg paketa.
- rejectsrc - isto kao _reject_
- rejectdst - pošalji RST/ICMP grešku paketa primaocu odgovarajućeg paketa.
- rejectboth - pošalji RST/ICMP greške paketa obe strane razgovora.

#### **Protokoli**

- tcp (za tcp-traffic)
- udp
- icmp
- ip (ip znači ‘svi’ ili ‘bilo koji’)
- _layer7 protokoli_: http, ftp, tls, smb, dns, ssh... (više u [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Izvori i odredišne adrese

Podržava IP opsege, negacije i listu adresa:

| Primer                        | Značenje                                  |
| ----------------------------- | ----------------------------------------- |
| ! 1.1.1.1                     | Svaka IP adresa osim 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Svaka IP adresa osim 1.1.1.1 i 1.1.1.2   |
| $HOME_NET                     | Vaša postavka HOME_NET u yaml            |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET i ne HOME_NET                |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 osim 10.0.0.5                |

#### Izvori i odredišne portove

Podržava opsege portova, negacije i liste portova

| Primer         | Značenje                                |
| --------------- | -------------------------------------- |
| any             | bilo koja adresa                       |
| \[80, 81, 82]   | port 80, 81 i 82                       |
| \[80: 82]       | Opseg od 80 do 82                      |
| \[1024: ]       | Od 1024 do najvećeg broja porta       |
| !80             | Svaki port osim 80                     |
| \[80:100,!99]   | Opseg od 80 do 100 osim 99             |
| \[1:80,!\[2,4]] | Opseg od 1-80, osim portova 2 i 4      |

#### Smer

Moguće je naznačiti smer komunikacijske pravila koja se primenjuje:
```
source -> destination
source <> destination  (both directions)
```
#### Ključne reči

Postoji **stotine opcija** dostupnih u Suricati za pretragu **specifičnog paketa** koji tražite, ovde će biti pomenuto ako se pronađe nešto zanimljivo. Proverite [**dokumentaciju**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) za više informacija!
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
