# Suricata i Iptables podsetnik

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Lanci

U iptables-u, svaki lanac je sekvencijalna lista pravila za podudaranje paketa. Podrazumevana `filter` tabela ima ugrađene lance `INPUT`, `FORWARD` i `OUTPUT`; druge tabele, kao što je `nat`, mogu biti dostupne u zavisnosti od konfiguracije kernela i učitanih modula.<sup>[[1]](#references)</sup>

- **Input Chain**: Koristi se za upravljanje ponašanjem dolaznih konekcija.
- **Forward Chain**: Koristi se za obradu dolaznih konekcija koje nisu namenjene lokalnom sistemu. Ovo je uobičajeno za uređaje koji imaju ulogu rutera, gde primljeni podaci treba da budu prosleđeni na drugo odredište. Ovaj lanac je prvenstveno relevantan kada je sistem uključen u rutiranje, NATing ili slične aktivnosti.
- **Output Chain**: Namenjen je regulisanju odlaznih konekcija.

Ovi lanci obezbeđuju uređenu obradu mrežnog saobraćaja, omogućavajući definisanje detaljnih pravila koja regulišu tok podataka u sistem, kroz sistem i iz sistema.

Primeri podudaranja stringova koriste standardno `string` podudaranje; podudaranje razlikuje velika i mala slova osim ako se ne navede `--icase`, dok `--algo` bira strategiju pretrage BM ili KMP.<sup>[[2]](#references)</sup>
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

### Instalacija i konfiguracija

Komande za pakete navedene u nastavku zavise od distribucije i izdanja; zvanični vodič za instalaciju opisuje Ubuntu PPA, Debian backports, RPM pakete i upravljanje systemd servisima.<sup>[[3]](#references)</sup>
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
Sekvenca `suricata-update` prati dokumentovani tok rada Suricata za preuzimanje, izlistavanje, omogućavanje i učitavanje izvora pravila.<sup>[[4]](#references)</sup> Komanda `suricatasc` iznad predstavlja dokumentovani neblokirajući metod ponovnog učitavanja pravila putem Unix soketa.<sup>[[8]](#references)</sup> Pravila NFQUEUE prosleđuju lokalni ulazni/izlazni saobraćaj Suricati, dok `-q 0` bira red 0 za inline obradu.<sup>[[7]](#references)</sup>

### Definicije pravila

Suricata pravilo/potpis ima tri dela.<sup>[[5]](#references)</sup>

- **Radnja** određuje šta se dešava kada se potpis podudari.
- **Zaglavlje** bira protokol, IP adrese, portove i smer.
- **Opcije pravila** definišu detalje specifične za podudaranje.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Važeće akcije su**

- alert - generisanje upozorenja
- pass - prekid dalje inspekcije paketa
- **drop** - odbacivanje paketa i generisanje upozorenja
- **reject** - slanje RST/ICMP unreachable greške pošiljaocu paketa koji se podudara.
- rejectsrc - isto što i _reject_
- rejectdst - slanje RST/ICMP paketa sa greškom primaocu paketa koji se podudara.
- rejectboth - slanje RST/ICMP paketa sa greškom objema stranama komunikacije.

#### **Protokoli**

- tcp (za tcp-traffic)
- udp
- icmp
- ip (ip označava „all“ ili „any“)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh i drugi.<sup>[[5]](#references)</sup>

#### Izvorne i odredišne adrese

Suricata podržava opsege IP adresa, negaciju i grupisane liste adresa.<sup>[[5]](#references)</sup>

| Primer                        | Značenje                                  |
| ----------------------------- | ----------------------------------------- |
| ! 1.1.1.1                     | Svaka IP adresa osim 1.1.1.1              |
| !\[1.1.1.1, 1.1.1.2]          | Svaka IP adresa osim 1.1.1.1 i 1.1.1.2    |
| $HOME_NET                     | Vaša postavka za HOME_NET u yaml          |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET, ali ne HOME_NET             |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 osim 10.0.0.5                 |

#### Izvorni i odredišni portovi

Suricata podržava opsege portova, negaciju i liste portova.<sup>[[5]](#references)</sup>

| Primer          | Značenje                              |
| --------------- | ------------------------------------- |
| any             | bilo koja adresa                     |
| \[80, 81, 82]   | portovi 80, 81 i 82                   |
| \[80: 82]       | Opseg od 80 do 82                     |
| \[1024: ]       | Od 1024 do najvećeg broja porta      |
| !80             | Svaki port osim 80                    |
| \[80:100,!99]   | Opseg od 80 do 100, osim porta 99     |
| \[1:80,!\[2,4]] | Opseg od 1 do 80, osim portova 2 i 4  |

#### Smer

Suricata pravila mogu navesti smer komunikacije koji se procenjuje.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Ključne reči

Primeri u nastavku koriste ključne reči Suricata pravila, uključujući metadata, IP, ICMP, payload i opcije aplikacionog sloja; zvanična dokumentacija pravila katalogizuje ove grupe i njihovu sintaksu.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Instalacija — Suricata 7.0.14 dokumentacija](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Upravljanje pravilima pomoću Suricata-Update — Suricata 8.0.1 dokumentacija](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Format pravila — Suricata 8.0.3 dokumentacija](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Ključne reči korisnog sadržaja — Suricata 8.0.3 dokumentacija](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Podešavanje IPS/inline za Linux — Suricata 7.0.15 dokumentacija](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Ponovno učitavanje pravila — Suricata 7.0.14 dokumentacija](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata pravila — Suricata 8.0.3 dokumentacija](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
