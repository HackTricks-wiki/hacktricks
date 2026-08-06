# Suricata & Iptables 치트시트

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### 체인

iptables에서는 체인으로 알려진 규칙 목록이 순차적으로 처리됩니다. 이 중 세 가지 기본 체인은 항상 존재하며, NAT와 같은 추가 체인은 시스템의 기능에 따라 지원될 수 있습니다.

- **Input Chain**: 들어오는 연결의 동작을 관리하는 데 사용됩니다.
- **Forward Chain**: 로컬 시스템을 대상으로 하지 않는 들어오는 연결을 처리하는 데 사용됩니다. 이는 수신된 데이터가 다른 대상으로 전달되는 라우터 역할을 하는 장치에서 일반적입니다. 이 체인은 주로 시스템이 라우팅, NAT 또는 이와 유사한 작업에 관여할 때 사용됩니다.
- **Output Chain**: 나가는 연결을 제어하는 데 사용됩니다.

이러한 체인은 네트워크 트래픽이 질서 있게 처리되도록 하며, 시스템으로 들어오고 시스템을 통과하며 시스템에서 나가는 데이터의 흐름을 제어하는 세부 규칙을 지정할 수 있게 합니다.
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

### 설치 및 구성
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
### 규칙 정의

[문서에서:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) 규칙/시그니처는 다음으로 구성됩니다:

- **action**은 시그니처가 일치할 때 발생하는 동작을 결정합니다.
- **header**는 규칙의 프로토콜, IP 주소, 포트 및 방향을 정의합니다.
- **rule options**는 규칙의 세부 사항을 정의합니다.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **유효한 action은**

- alert - alert 생성
- pass - packet의 추가 inspection 중지
- **drop** - packet을 drop하고 alert 생성
- **reject** - 일치하는 packet의 sender에게 RST/ICMP unreachable error 전송
- rejectsrc - _reject_와 동일
- rejectdst - 일치하는 packet의 receiver에게 RST/ICMP error packet 전송
- rejectboth - conversation의 양쪽에 RST/ICMP error packet 전송

#### **Protocols**

- tcp (tcp-traffic용)
- udp
- icmp
- ip (ip는 ‘all’ 또는 ‘any’를 의미)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh... ([**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)에 더 있음)

#### Source 및 Destination Addresses

IP ranges, negations 및 address 목록을 지원합니다:

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1을 제외한 모든 IP address             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 및 1.1.1.2를 제외한 모든 IP address |
| $HOME_NET                     | yaml의 HOME_NET 설정         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET이며 HOME_NET은 아님            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5를 제외한 10.0.0.0/24          |

#### Source 및 Destination Ports

port ranges, negations 및 port 목록을 지원합니다.

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | 모든 address                            |
| \[80, 81, 82]   | port 80, 81 및 82                     |
| \[80: 82]       | 80부터 82까지의 range                  |
| \[1024: ]       | 1024부터 가장 높은 port-number까지 |
| !80             | 80을 제외한 모든 port                      |
| \[80:100,!99]   | 80부터 100까지의 range에서 99는 제외 |
| \[1:80,!\[2,4]] | 1-80 range에서 port 2 및 4 제외  |

#### Direction

적용되는 communication rule의 direction을 지정할 수 있습니다:
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Suricata에는 찾고 있는 **특정 packet**을 검색할 수 있는 **수백 가지 옵션**이 있으며, 여기서는 흥미로운 항목이 발견되면 언급합니다. 자세한 내용은 [**documentation** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)을 확인하세요!
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
