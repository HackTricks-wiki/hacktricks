# Suricata & Iptables チートシート

{{#include ../../../banners/hacktricks-training.md}}

## Iptables

### チェーン

iptables では、各チェーンはパケットに一致するルールを順番に並べたリストです。デフォルトの `filter` テーブルには、組み込みの `INPUT`、`FORWARD`、`OUTPUT` チェーンがあります。`nat` などの他のテーブルは、カーネルの設定やロードされているモジュールによって利用できる場合があります。<sup>[[1]](#references)</sup>

- **入力チェーン**: 受信接続の動作を管理するために使用されます。
- **転送チェーン**: ローカルシステム宛てではない受信接続を処理するために使用されます。これは、受信したデータを別の宛先へ転送するルーターとして動作するデバイスで一般的です。このチェーンは、主にシステムがルーティング、NAT、または類似の処理に関与している場合に関係します。
- **出力チェーン**: 送信接続を制御するために使用されます。

これらのチェーンにより、ネットワークトラフィックが秩序立って処理され、システムへのデータの流入、システム内の通過、システムからの流出を制御する詳細なルールを指定できます。

文字列マッチの例では標準の `string` マッチを使用します。`--icase` を指定しない限り、大文字と小文字は区別されます。また、`--algo` によって BM または KMP の検索方式を選択できます。<sup>[[2]](#references)</sup>
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

以下のパッケージコマンドはディストリビューションおよびリリース固有です。公式のインストールガイドでは、Ubuntu PPA、Debian backports、RPM packages、systemd service managementについて説明しています。<sup>[[3]](#references)</sup>
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
`suricata-update` の手順は、ルールソースの取得、一覧表示、有効化、読み込みを行う Suricata の文書化されたワークフローに従います。<sup>[[4]](#references)</sup> 上記の `suricatasc` コマンドは、文書化されている非ブロッキングの Unix ソケットによるルール再読み込み方法です。<sup>[[8]](#references)</sup> NFQUEUE ルールはローカルの入力/出力トラフィックを Suricata に送信し、`-q 0` は inline 処理用のキュー 0 を選択します。<sup>[[7]](#references)</sup>

### ルールの定義

Suricata のルール/シグネチャには 3 つの部分があります。<sup>[[5]](#references)</sup>

- **action** は、シグネチャが一致したときに何が起こるかを指定します。
- **header** は、プロトコル、IP アドレス、ポート、方向を選択します。
- **rule options** は、一致に固有の詳細を定義します。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有効なアクション**

- alert - alert を生成する
- pass - パケットの以降の検査を停止する
- **drop** - パケットを drop し、alert を生成する
- **reject** - 一致したパケットの送信元に RST/ICMP unreachable エラーを送信する。
- rejectsrc - _reject_ と同じ
- rejectdst - 一致したパケットの受信先に RST/ICMP エラーパケットを送信する。
- rejectboth - 通信の両側に RST/ICMP エラーパケットを送信する。

#### **Protocols**

- tcp (tcp-traffic 用)
- udp
- icmp
- ip (ip は「all」または「any」を意味する)
- _layer7 protocols_: http、ftp、tls、smb、dns、ssh、その他。<sup>[[5]](#references)</sup>

#### Source and Destination Addresses

Suricata は、IP 範囲、否定、およびグループ化されたアドレスリストをサポートする。<sup>[[5]](#references)</sup>

| Example                       | Meaning                                  |
| ----------------------------- | ---------------------------------------- |
| ! 1.1.1.1                     | 1.1.1.1 以外のすべての IP アドレス       |
| !\[1.1.1.1, 1.1.1.2]          | 1.1.1.1 と 1.1.1.2 以外のすべての IP アドレス |
| $HOME_NET                     | yaml 内の HOME_NET の設定                |
| \[$EXTERNAL\_NET, !$HOME_NET] | EXTERNAL_NET かつ HOME_NET ではない      |
| \[10.0.0.0/24, !10.0.0.5]     | 10.0.0.5 を除く 10.0.0.0/24              |

#### Source and Destination Ports

Suricata は、ポート範囲、否定、およびポートのリストをサポートする。<sup>[[5]](#references)</sup>

| Example         | Meaning                                |
| --------------- | -------------------------------------- |
| any             | 任意のアドレス                         |
| \[80, 81, 82]   | ポート 80、81、82                      |
| \[80: 82]       | 80 から 82 までの範囲                  |
| \[1024: ]       | 1024 から最大のポート番号まで          |
| !80             | 80 以外のすべてのポート               |
| \[80:100,!99]   | 80 から 100 までの範囲。ただし 99 を除く |
| \[1:80,!\[2,4]] | 1 から 80 までの範囲。ただしポート 2 と 4 を除く |

#### Direction

Suricata のルールでは、評価対象となる通信方向を指定できる。<sup>[[5]](#references)</sup>
```
source -> destination
source <> destination  (both directions)
```
#### キーワード

以下の例では、Suricata のルールキーワード（metadata、IP、ICMP、payload、アプリケーション層オプションなど）を使用しています。公式のルールドキュメントでは、これらの分類と構文がまとめられています。<sup>[[6]](#references)[[9]](#references)</sup>
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
- [3] [3. インストール — Suricata 7.0.14 ドキュメント](https://docs.suricata.io/en/suricata-7.0.14/install.html)
- [4] [9.1. Suricata-Update によるルール管理 — Suricata 8.0.1 ドキュメント](https://docs.suricata.io/en/suricata-8.0.1/rule-management/suricata-update.html)
- [5] [8.1. ルール形式 — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/intro.html)
- [6] [8.7. Payload キーワード — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/payload-keywords.html)
- [7] [15. Linux での IPS/inline のセットアップ — Suricata 7.0.15 ドキュメント](https://docs.suricata.io/en/suricata-7.0.15/setting-up-ipsinline-for-linux.html)
- [8] [9.3. ルールの再読み込み — Suricata 7.0.14 ドキュメント](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)
- [9] [8. Suricata ルール — Suricata 8.0.3 ドキュメント](https://docs.suricata.io/en/suricata-8.0.3/rules/index.html)
{{#include ../../../banners/hacktricks-training.md}}
