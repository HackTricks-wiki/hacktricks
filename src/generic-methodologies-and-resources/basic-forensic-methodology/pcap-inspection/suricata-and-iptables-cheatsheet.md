# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

iptables에서 각 chain은 packet-matching rules가 순차적으로 나열된 목록입니다. 기본 `filter` table에는 내장된 `INPUT`, `FORWARD`, `OUTPUT` chain이 있으며, `nat`과 같은 다른 table은 kernel configuration 및 로드된 module에 따라 사용할 수 있습니다.<sup>[[1]](#references)</sup>

- **Input Chain**: incoming connections의 동작을 관리하는 데 사용됩니다.
- **Forward Chain**: local system을 대상으로 하지 않는 incoming connections을 처리하는 데 사용됩니다. 이는 수신한 data를 다른 destination으로 forward해야 하는 router 역할의 device에서 일반적입니다. 이 chain은 주로 system이 routing, NATing 또는 이와 유사한 activity에 관여할 때 관련됩니다.
- **Output Chain**: outgoing connections을 조절하는 역할을 전담합니다.

이러한 chain은 network traffic을 질서 있게 처리하며, system으로 들어오고, system을 통과하고, system에서 나가는 data의 흐름을 제어하는 세부 rules를 지정할 수 있도록 합니다.

string-match examples는 standard `string` match를 사용합니다. `--icase`가 제공되지 않으면 matching은 case-sensitive이며, `--algo`는 BM 또는 KMP search strategy를 선택합니다.<sup>[[2]](#references)</sup>
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

### 설치 및 설정

아래의 패키지 명령은 배포판 및 릴리스에 따라 다릅니다. 공식 설치 가이드에는 Ubuntu PPA, Debian backports, RPM 패키지 및 systemd 서비스 관리 방법이 설명되어 있습니다.<sup>[[3]](#references)</sup>
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
`suricata-update` 시퀀스는 rule source를 가져오고, 나열하고, 활성화하고, 로드하는 Suricata의 문서화된 workflow를 따릅니다.<sup>[[4]](#references)</sup> 위의 `suricatasc` command는 문서화된 non-blocking Unix-socket rule-reload method입니다.<sup>[[8]](#references)</sup> NFQUEUE rules는 local input/output traffic을 Suricata로 전송하며, `-q 0`은 inline processing을 위해 queue 0을 선택합니다.<sup>[[7]](#references)</sup>

### Rules Definitions

Suricata rule/signature는 세 부분으로 구성됩니다.<sup>[[5]](#references)</sup>

- **action**은 signature가 match될 때 발생하는 동작을 지정합니다.
- **header**는 protocol, IP addresses, ports 및 direction을 선택합니다.
- **rule options**는 match에 필요한 세부 사항을 정의합니다.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **유효한 action은 다음과 같습니다**

- alert - alert 생성
- pass - packet에 대한 추가 inspection 중지
- **drop** - packet을 drop하고 alert 생성
- **reject** - 일치하는 packet의 sender에게 RST/ICMP unreachable error 전송
- rejectsrc - 단순히 _reject_와 동일
- rejectdst - 일치하는 packet의 receiver에게 RST/ICMP error packet 전송
- rejectboth - 통신 양쪽에 RST/ICMP error packet 전송

#### **프로토콜**

- tcp (tcp-traffic용)
- udp
- icmp
- ip (ip는 ‘all’ 또는 ‘any’를 의미)
- _layer7 프로토콜_: http, ftp, tls, smb, dns, ssh 및 기타 프로토콜.<sup>[[5]](#references)</sup>

#### Source 및 Destination Address

Suricata는 IP range, negation 및 그룹화된 address list를 지원합니다.<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1을 제외한 모든 IP address             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 및 1.1.1.2를 제외한 모든 IP address |
| $HOME_NET                     | yaml의 HOME_NET 설정         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET이면서 HOME_NET이 아님            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5를 제외한 10.0.0.0/24          |

#### Source 및 Destination Port

Suricata는 port range, negation 및 port list를 지원합니다.<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | 모든 address                            |
| \[80, 81, 82]   | port 80, 81 및 82                     |
| \[80: 82]       | 80부터 82까지의 range                  |
| \[1024: ]       | 1024부터 가장 높은 port-number까지 |
| !80             | 80을 제외한 모든 port                      |
| \[80:100,!99]   | 80부터 100까지의 range에서 99는 제외 |
| \[1:80,!\[2,4]] | 1-80의 range에서 port 2 및 4는 제외  |

#### Direction

Suricata rule은 평가할 communication direction을 지정할 수 있습니다.<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### 키워드

아래 예제에서는 metadata, IP, ICMP, payload 및 application-layer options를 비롯한 Suricata의 규칙 키워드를 사용하며, 공식 규칙 문서에는 이러한 분류와 구문이 정리되어 있습니다.<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. 설치 — Suricata 7.0.14 문서](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Suricata-Update를 사용한 규칙 관리 — Suricata 8.0.1 문서](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. 규칙 형식 — Suricata 8.0.3 문서](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload 키워드 — Suricata 8.0.3 문서](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Linux에서 IPS/inline 설정 — Suricata 7.0.15 문서](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. 규칙 다시 로드 — Suricata 7.0.14 문서](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata 규칙 — Suricata 8.0.3 문서](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
