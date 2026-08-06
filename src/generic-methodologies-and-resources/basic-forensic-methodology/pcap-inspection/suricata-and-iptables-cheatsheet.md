# Suricata & Iptables चीटशीट

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

iptables में, chains के रूप में ज्ञात rules की सूचियों को क्रमिक रूप से process किया जाता है। इनमें से तीन primary chains सार्वभौमिक रूप से मौजूद होती हैं, जबकि NAT जैसी अतिरिक्त chains system की capabilities के आधार पर supported हो सकती हैं।

- **Input Chain**: incoming connections के behavior को manage करने के लिए उपयोग की जाती है।
- **Forward Chain**: ऐसी incoming connections को handle करने के लिए उपयोग की जाती है जो local system के लिए destined नहीं होतीं। यह उन devices के लिए सामान्य है जो routers के रूप में कार्य करते हैं, जहाँ received data को किसी अन्य destination पर forward किया जाना होता है। यह chain मुख्य रूप से तब relevant होती है जब system routing, NATing या इसी प्रकार की activities में शामिल हो।
- **Output Chain**: outgoing connections को regulate करने के लिए dedicated होती है।

ये chains network traffic की orderly processing सुनिश्चित करती हैं और system में data के आने, system के माध्यम से गुजरने तथा system से बाहर जाने के flow को नियंत्रित करने वाले detailed rules specify करने की अनुमति देती हैं।
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

### Install और Config
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
### Rules Definitions

[From the docs:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) एक rule/signature में निम्न शामिल होते हैं:

- **action**, signature के match होने पर क्या होता है, यह निर्धारित करता है।
- **header**, rule के protocol, IP addresses, ports और direction को परिभाषित करता है।
- **rule options**, rule की विशिष्टताओं को परिभाषित करते हैं।
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **मान्य actions हैं**

- alert - alert generate करें
- pass - packet की आगे की inspection रोकें
- **drop** - packet drop करें और alert generate करें
- **reject** - matching packet के sender को RST/ICMP unreachable error भेजें।
- rejectsrc - केवल _reject_ के समान
- rejectdst - matching packet के receiver को RST/ICMP error packet भेजें।
- rejectboth - conversation के दोनों sides को RST/ICMP error packets भेजें।

#### **Protocols**

- tcp (tcp-traffic के लिए)
- udp
- icmp
- ip (ip का अर्थ ‘all’ या ‘any’ है)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... ([**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html) में अधिक)

#### Source और Destination Addresses

यह IP ranges, negations और addresses की list को support करता है:

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1 को छोड़कर प्रत्येक IP address    |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 और 1.1.1.2 को छोड़कर प्रत्येक IP address |
| $HOME_NET                     | yaml में HOME_NET की आपकी setting         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET और HOME_NET नहीं            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5 को छोड़कर 10.0.0.0/24          |

#### Source और Destination Ports

यह port ranges, negations और ports की lists को support करता है।

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | कोई भी address                         |
| \[80, 81, 82]   | port 80, 81 और 82                      |
| \[80: 82]       | 80 से 82 तक की range                  |
| \[1024: ]       | 1024 से highest port-number तक         |
| !80             | 80 को छोड़कर प्रत्येक port             |
| \[80:100,!99]   | 80 से 100 तक की range, लेकिन 99 excluded |
| \[1:80,!\[2,4]] | 1-80 तक की range, ports 2 और 4 को छोड़कर |

#### Direction

लागू किए जा रहे communication rule की direction बताना संभव है:
```
source -> destination
source <> destination  (both directions)
```
#### कीवर्ड्स

Suricata में उस **विशिष्ट packet** को खोजने के लिए **सैकड़ों विकल्प** उपलब्ध हैं जिसे आप ढूंढ रहे हैं। यहां कुछ दिलचस्प मिलने पर उसका उल्लेख किया जाएगा। अधिक जानकारी के लिए [**दस्तावेज़ीकरण** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) देखें!
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
