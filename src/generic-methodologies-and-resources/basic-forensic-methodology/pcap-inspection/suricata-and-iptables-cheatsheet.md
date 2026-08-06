# Suricata & Iptables cheatsheet

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### Chains

iptables では、チェーンと呼ばれるルールのリストが順番に処理されます。このうち、3つの主要なチェーンは常に存在し、NAT などの追加チェーンは、システムの機能によってサポートされる場合があります。

- **Input Chain**: incoming connections の動作を管理するために使用されます。
- **Forward Chain**: ローカルシステム宛てではない incoming connections を処理するために使用されます。これは、受信したデータを別の宛先へ転送するルーターとして動作するデバイスで一般的です。このチェーンは、システムが routing、NATing、または同様の処理に関与している場合に主に関係します。
- **Output Chain**: outgoing connections を制御します。

これらのチェーンにより、network traffic が順序立てて処理され、システムへのデータの流入、システム内の通過、システムからの流出を制御する詳細なルールを指定できます。
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
### ルール定義

[ドキュメントより:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) ルール/シグネチャは以下で構成されます:

- **アクション**は、シグネチャが一致したときに何が起こるかを決定します。
- **ヘッダー**は、ルールのプロトコル、IPアドレス、ポート、方向を定義します。
- **ルールオプション**は、ルールの詳細を定義します。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有効なアクション**

- alert - alertを生成
- pass - パケットの以降の検査を停止
- **drop** - パケットをdropしてalertを生成
- **reject** - 一致するパケットの送信元にRST/ICMP unreachableエラーを送信
- rejectsrc - _reject_と同じ
- rejectdst - 一致するパケットの受信先にRST/ICMPエラーパケットを送信
- rejectboth - 通信の両側にRST/ICMPエラーパケットを送信

#### **プロトコル**

- tcp (tcp-traffic用)
- udp
- icmp
- ip (ipは「all」または「any」を意味する)
- _layer7 protocols_: http, ftp, tls, smb, dns, ssh...（詳細は[**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)を参照）

#### Source and Destination Addresses

IP範囲、否定、およびアドレスのリストをサポートします。

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1以外のすべてのIPアドレス             |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1および1.1.1.2以外のすべてのIPアドレス |
| $HOME_NET                     | yamlで設定したHOME_NET         |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NETで、HOME_NETではない            |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5を除く10.0.0.0/24          |

#### Source and Destination Ports

ポート範囲、否定、およびポートのリストをサポートします。

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | 任意のアドレス                            |
| \[80, 81, 82]   | ポート80、81、82                     |
| \[80: 82]       | 80から82までの範囲                  |
| \[1024: ]       | 1024からポート番号の最大値まで |
| !80             | 80以外のすべてのポート                      |
| \[80:100,!99]   | 80から100までの範囲。ただし99を除く |
| \[1:80,!\[2,4]] | 1から80までの範囲。ただしポート2および4を除く  |

#### Direction

適用する通信ルールの方向を指定できます。
```
source -> destination
source <> destination  (both directions)
```
#### Keywords

Suricata には、探している **特定のパケット** を検索するための **数百ものオプション** が用意されています。ここでは、興味深いものが見つかった場合に記載します。詳細については、[**ドキュメント** ](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)を確認してください。
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
