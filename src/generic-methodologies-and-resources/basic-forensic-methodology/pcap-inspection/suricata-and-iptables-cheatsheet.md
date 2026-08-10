# Suricata & Iptables チートシート

## Iptables

### Chains

iptables では、各 chain はパケットに一致するルールを順番に並べたリストです。デフォルトの `filter` table には、組み込みの `INPUT`、`FORWARD`、`OUTPUT` chain があります。`nat` などの他の table は、kernel の設定やロードされている module に応じて利用できる場合があります。<sup>[[1]](#references)</sup>

- **Input Chain**: incoming connection の動作を管理するために使用されます。
- **Forward Chain**: local system 宛てではない incoming connection を処理するために使用されます。これは、受信したデータを別の宛先へ転送する router として動作する device で一般的です。この chain は、system が routing、NATing、または類似の処理に関与している場合に主に関係します。
- **Output Chain**: outgoing connection を制御します。

これらの chain により network traffic を秩序立てて処理でき、system に入るデータ、system を通過するデータ、system から出るデータの流れを制御する詳細なルールを指定できます。

string-match の例では標準の `string` match を使用します。`--icase` を指定しない限り matching は大文字と小文字を区別し、`--algo` により BM または KMP の検索方式を選択します。<sup>[[2]](#references)</sup>
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

### インストールと設定

以下のパッケージコマンドはディストリビューションおよびリリース固有です。公式のインストールガイドには、Ubuntu PPA、Debian backports、RPM packages、systemd service managementについて記載されています。<sup>[[3]](#references)</sup>
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
`suricata-update` のシーケンスは、rule source の取得、一覧表示、有効化、読み込みに関する Suricata の文書化された workflow に従います。<sup>[[4]](#references)</sup> 上記の `suricatasc` コマンドは、文書化された non-blocking Unix-socket による rule-reload method です。<sup>[[8]](#references)</sup> NFQUEUE rules は local input/output traffic を Suricata に送信し、`-q 0` は inline processing 用の queue 0 を選択します。<sup>[[7]](#references)</sup>

### Rules Definitions

Suricata の rule/signature には3つの部分があります。<sup>[[5]](#references)</sup>

- **action** は、signature が match したときに何が起こるかを指定します。
- **header** は、protocol、IP addresses、ports、direction を選択します。
- **rule options** は、match 固有の詳細を定義します。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有効なアクション**

- alert - alertを生成
- pass - packetの以降の検査を停止
- **drop** - packetをdropし、alertを生成
- **reject** - 該当するpacketの送信元にRST/ICMP unreachableエラーを送信
- rejectsrc - _reject_と同じ
- rejectdst - 該当するpacketの受信側にRST/ICMPエラーpacketを送信
- rejectboth - 通信の両側にRST/ICMPエラーpacketを送信

#### **Protocols**

- tcp (tcp-traffic用)
- udp
- icmp
- ip (ipは「all」または「any」を表す)
- _layer7 protocols_: http、ftp、tls、smb、dns、sshなど。<sup>[[5]](#references)</sup>

#### Source and Destination Addresses

SuricataはIP range、negation、group化されたaddress listをサポートします。<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1以外のすべてのIP address             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1と1.1.1.2以外のすべてのIP address |
| $HOME_NET                     | yaml内のHOME_NETの設定         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NETで、HOME_NETではない            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5を除く10.0.0.0/24          |

#### Source and Destination Ports

Suricataはport range、negation、port listをサポートします。<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | 任意のaddress                            |
| \[80, 81, 82]   | port 80、81、82                     |
| \[80: 82]       | 80から82までのrange                  |
| \[1024: ]       | 1024から最大port-numberまで |
| !80             | 80以外のすべてのport                      |
| \[80:100,!99]   | 99を除く80から100までのrange |
| \[1:80,!\[2,4]] | 2と4を除く1から80までのrange  |

#### Direction

Suricata rulesでは、評価対象となるcommunicationのdirectionを指定できます。<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

以下の例では、metadata、IP、ICMP、payload、application-layer options など、Suricata の rule keywords を使用しています。公式の rule documentation では、これらのカテゴリとその構文がまとめられています。<sup>[[6]](#references)[[9]](#references)</sup>
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

- [1] [iptables(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/iptables.8.html)
- [2] [iptables-extensions(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [3] [3. Installation — Suricata 7.0.14 ドキュメント](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Rule Management with Suricata-Update — Suricata 8.0.1 ドキュメント](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. Rules Format — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload Keywords — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Setting up IPS/inline for Linux — Suricata 7.0.15 ドキュメント](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. Rule Reloads — Suricata 7.0.14 ドキュメント](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata Rules — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
