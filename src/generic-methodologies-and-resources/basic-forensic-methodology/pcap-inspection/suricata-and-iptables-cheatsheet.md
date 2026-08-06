# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

Katika iptables, orodha za rules zinazojulikana kama chains huchakatwa kwa mfuatano. Kati ya hizi, kuna chains tatu kuu ambazo hupatikana kwa ujumla, huku nyingine kama NAT zikiweza kuungwa mkono kulingana na uwezo wa mfumo.

- **Input Chain**: Hutumika kudhibiti tabia ya connections zinazoingia.
- **Forward Chain**: Hutumika kushughulikia connections zinazoingia ambazo hazilengi mfumo wa ndani. Hii ni kawaida kwa vifaa vinavyofanya kazi kama routers, ambapo data iliyopokelewa inakusudiwa ku-forwardiwa kwenye destination nyingine. Chain hii huhusika hasa wakati mfumo unashiriki katika routing, NATing, au shughuli zinazofanana.
- **Output Chain**: Hutumika kudhibiti connections zinazotoka.

Chains hizi huhakikisha traffic ya mtandao inachakatwa kwa utaratibu, na kuruhusu kubainishwa kwa rules za kina zinazosimamia mtiririko wa data inayoingia, inayopita ndani ya, na inayotoka kwenye mfumo.
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

### Usakinishaji na Usanidi
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
### Ufafanuzi wa Rules

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Rule/signature ina vitu vifuatavyo:

- **action**, huamua kinachotokea signature inapolingana.
- **header**, hufafanua protocol, anwani za IP, ports na mwelekeo wa rule.
- **rule options**, hufafanua maelezo mahususi ya rule.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Vitendo halali ni**

- alert - generate an alert
- pass - stop further inspection of the packet
- **drop** - drop packet and generate alert
- **reject** - send RST/ICMP unreachable error to the sender of the matching packet.
- rejectsrc - same as just _reject_
- rejectdst - send RST/ICMP error packet to the receiver of the matching packet.
- rejectboth - send RST/ICMP error packets to both sides of the conversation.

#### **Protocols**

- tcp (for tcp-traffic)
- udp
- icmp
- ip (ip stands for ‘all’ or ‘any’)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... (more in the [**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Anwani za Chanzo na Lengwa

Inaauni IP ranges, negations na orodha ya anwani:

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | Kila IP address isipokuwa 1.1.1.1             |
| !\[1.1.1.1, 1.1.1.2]          | Kila IP address isipokuwa 1.1.1.1 na 1.1.1.2 |
| $HOME_NET                     | Mpangilio wako wa HOME_NET katika yaml         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET na si HOME_NET            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.0/24 isipokuwa 10.0.0.5          |

#### Ports za Chanzo na Lengwa

Inaauni port ranges, negations na orodha za ports

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | address yoyote                            |
| \[80, 81, 82]   | port 80, 81 na 82                     |
| \[80: 82]       | Range kutoka 80 hadi 82                  |
| \[1024: ]       | Kuanzia 1024 hadi port-number ya juu zaidi |
| !80             | Kila port isipokuwa 80                      |
| \[80:100,!99]   | Range kutoka 80 hadi 100, lakini 99 imeondolewa |
| \[1:80,!\[2,4]] | Range kutoka 1-80, isipokuwa ports 2 na 4  |

#### Mwelekeo

Inawezekana kuonyesha mwelekeo wa mawasiliano ambao rule inatumika:
```
source -> destination
source <> destination  (both directions)
```
#### Maneno muhimu

Kuna **mamia ya chaguo** zinazopatikana katika Suricata za kutafuta **paketi mahususi** unayoitafuta; hapa itatajwa ikiwa kitu cha kuvutia kitapatikana. Angalia [**nyaraka** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) kwa maelezo zaidi!
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
