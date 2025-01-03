# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

Katika iptables, orodha za sheria zinazojulikana kama chains zinashughulikiwa kwa mpangilio. Kati ya hizi, chains tatu kuu zipo kila wakati, huku zingine kama NAT zikiwa zinaweza kuungwa mkono kulingana na uwezo wa mfumo.

- **Input Chain**: Inatumika kwa usimamizi wa tabia ya muunganisho unaoingia.
- **Forward Chain**: Inatumika kwa kushughulikia muunganisho unaoingia ambao haujielekezi kwa mfumo wa ndani. Hii ni ya kawaida kwa vifaa vinavyofanya kazi kama routers, ambapo data inayopokelewa inakusudiwa kupelekwa kwenye eneo lingine. Chain hii inahusiana hasa wakati mfumo unahusika katika routing, NATing, au shughuli zinazofanana.
- **Output Chain**: Imetengwa kwa udhibiti wa muunganisho unaotoka.

Chains hizi zinahakikisha usindikaji wa mpangilio wa trafiki ya mtandao, zikiruhusu kuwekwa kwa sheria za kina zinazodhibiti mtiririko wa data kuingia, kupitia, na kutoka kwa mfumo.
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

### Sakinisha & Sanidi
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
### Mwelekeo wa Mifumo

[Kutoka kwenye hati:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Kanuni/saini inajumuisha yafuatayo:

- **kitendo**, kinatengeneza kinachotokea wakati saini inapatana.
- **kichwa**, kinaelezea itifaki, anwani za IP, bandari na mwelekeo wa kanuni.
- **chaguzi za kanuni**, zinaelezea maelezo maalum ya kanuni.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Vitendo halali ni**

- alert - tengeneza tahadhari
- pass - simamisha ukaguzi zaidi wa pakiti
- **drop** - angusha pakiti na tengeneza tahadhari
- **reject** - tuma kosa la RST/ICMP lisilofikika kwa mtumaji wa pakiti inayolingana.
- rejectsrc - sawa na tu _reject_
- rejectdst - tuma pakiti ya kosa la RST/ICMP kwa mpokeaji wa pakiti inayolingana.
- rejectboth - tuma pakiti za kosa la RST/ICMP kwa pande zote za mazungumzo.

#### **Protokali**

- tcp (kwa trafiki ya tcp)
- udp
- icmp
- ip (ip inasimama kwa ‘yote’ au ‘yoyote’)
- _protokali za layer7_: http, ftp, tls, smb, dns, ssh... (zaidi katika [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Anwani za Chanzo na Kielelezo

Inasaidia anuwai za IP, kukanusha na orodha ya anwani:

| Mfano                       | Maana                                  |
| --------------------------- | -------------------------------------- |
| ! 1.1.1.1                   | Anwani zote za IP isipokuwa 1.1.1.1    |
| !\[1.1.1.1, 1.1.1.2]        | Anwani zote za IP isipokuwa 1.1.1.1 na 1.1.1.2 |
| $HOME_NET                   | Mpangilio wako wa HOME_NET katika yaml |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET na si HOME_NET          |
| \[10.0.0.0/24, !10.0.0.5]   | 10.0.0.0/24 isipokuwa 10.0.0.5        |

#### Bandari za Chanzo na Kielelezo

Inasaidia anuwai za bandari, kukanusha na orodha za bandari

| Mfano         | Maana                                |
| ------------- | ------------------------------------ |
| any           | anwani yoyote                        |
| \[80, 81, 82] | bandari 80, 81 na 82                |
| \[80: 82]     | Anuwai kutoka 80 hadi 82             |
| \[1024: ]     | Kuanzia 1024 hadi nambari ya juu ya bandari |
| !80           | Bandari zote isipokuwa 80            |
| \[80:100,!99] | Anuwai kutoka 80 hadi 100 isipokuwa 99 |
| \[1:80,!\[2,4]] | Anuwai kutoka 1-80, isipokuwa bandari 2 na 4 |

#### Mwelekeo

Inawezekana kuashiria mwelekeo wa sheria ya mawasiliano inayotumika:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Kuna **mamia ya chaguzi** zinazopatikana katika Suricata kutafuta **pakiti maalum** unayotafuta, hapa itatajwa ikiwa kitu cha kuvutia kimepatikana. Angalia [**documentation** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)kwa maelezo zaidi!
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
