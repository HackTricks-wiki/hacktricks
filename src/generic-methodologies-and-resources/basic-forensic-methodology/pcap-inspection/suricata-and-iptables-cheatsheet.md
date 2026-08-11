# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

iptables में, प्रत्येक chain packet-matching rules की एक क्रमिक सूची होती है। डिफ़ॉल्ट `filter` table में अंतर्निहित `INPUT`, `FORWARD`, और `OUTPUT` chains होती हैं; kernel configuration और loaded modules के आधार पर `nat` जैसी अन्य tables भी उपलब्ध हो सकती हैं।<sup>[[1]](#references)</sup>

- **Input Chain**: incoming connections के व्यवहार को manage करने के लिए उपयोग की जाती है।
- **Forward Chain**: ऐसी incoming connections को handle करने के लिए उपयोग की जाती है जो local system के लिए destined नहीं होतीं। यह उन devices के लिए सामान्य है जो routers के रूप में कार्य करते हैं, जहाँ प्राप्त data को किसी अन्य destination पर forward किया जाना होता है। यह chain मुख्य रूप से तब relevant होती है जब system routing, NATing या इसी प्रकार की activities में शामिल हो।
- **Output Chain**: outgoing connections के regulation के लिए dedicated होती है।

ये chains network traffic की orderly processing सुनिश्चित करती हैं और system में data के flow, system के through data के flow तथा system से बाहर data के flow को नियंत्रित करने वाले detailed rules निर्दिष्ट करने की अनुमति देती हैं।

string-match examples standard `string` match का उपयोग करते हैं; जब तक `--icase` supplied न हो, matching case-sensitive होती है, और `--algo` BM या KMP search strategy का चयन करता है।<sup>[[2]](#references)</sup>
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

### Install & Config

नीचे दिए गए Package commands distribution और release के अनुसार अलग-अलग होते हैं; official installation guide में Ubuntu PPA, Debian backports, RPM packages और systemd service management का documentation दिया गया है।<sup>[[3]](#references)</sup>
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
`suricata-update` sequence, rules sources को fetch, list, enable और load करने के लिए Suricata के documented workflow का पालन करता है।<sup>[[4]](#references)</sup> ऊपर दिया गया `suricatasc` command documented non-blocking Unix-socket rule-reload method है।<sup>[[8]](#references)</sup> NFQUEUE rules local input/output traffic को Suricata तक भेजते हैं, जबकि `-q 0` inline processing के लिए queue 0 चुनता है।<sup>[[7]](#references)</sup>

### Rules की Definitions

एक Suricata rule/signature के तीन parts होते हैं।<sup>[[5]](#references)</sup>

- **action** यह निर्दिष्ट करता है कि signature match होने पर क्या होता है।
- **header** protocol, IP addresses, ports और direction चुनता है।
- **rule options** match-specific details को define करते हैं।
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **मान्य actions हैं**

- alert - alert generate करना
- pass - packet की आगे की inspection रोकना
- **drop** - packet drop करना और alert generate करना
- **reject** - matching packet के sender को RST/ICMP unreachable error भेजना।
- rejectsrc - केवल _reject_ के समान
- rejectdst - matching packet के receiver को RST/ICMP error packet भेजना।
- rejectboth - conversation के दोनों sides को RST/ICMP error packets भेजना।

#### **Protocols**

- tcp (tcp-traffic के लिए)
- udp
- icmp
- ip (ip का अर्थ ‘all’ या ‘any’ है)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh, और अन्य।<sup>[[5]](#references)</sup>

#### Source और Destination Addresses

Suricata IP ranges, negation और grouped address lists को support करता है।<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1 को छोड़कर प्रत्येक IP address             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 और 1.1.1.2 को छोड़कर प्रत्येक IP address |
| $HOME_NET                     | yaml में HOME_NET की आपकी setting         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET और HOME_NET नहीं            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5 को छोड़कर 10.0.0.0/24          |

#### Source और Destination Ports

Suricata port ranges, negation और ports की lists को support करता है।<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | कोई भी address                            |
| \[80, 81, 82]   | port 80, 81 और 82                     |
| \[80: 82]       | 80 से 82 तक की range                  |
| \[1024: ]       | 1024 से highest port-number तक         |
| !80             | 80 को छोड़कर प्रत्येक port             |
| \[80:100,!99]   | 80 से 100 तक की range, लेकिन 99 excluded |
| \[1:80,!\[2,4]] | 1-80 तक की range, ports 2 और 4 को छोड़कर  |

#### Direction

Suricata rules में evaluate की जा रही communication direction specify की जा सकती है।<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

नीचे दिए गए उदाहरणों में Suricata के rule keywords का उपयोग किया गया है, जिनमें metadata, IP, ICMP, payload और application-layer options शामिल हैं; आधिकारिक rule documentation इन families और उनके syntax को सूचीबद्ध करता है।<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — Suricata 7.0.14 दस्तावेज़](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Rule Management with Suricata-Update — Suricata 8.0.1 दस्तावेज़](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Rules Format — Suricata 8.0.3 दस्तावेज़](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload Keywords — Suricata 8.0.3 दस्तावेज़](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Setting up IPS/inline for Linux — Suricata 7.0.15 दस्तावेज़](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Rule Reloads — Suricata 7.0.14 दस्तावेज़](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata Rules — Suricata 8.0.3 दस्तावेज़](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
