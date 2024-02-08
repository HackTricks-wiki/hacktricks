# Suricata & Iptables チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**してみたいですか？または、**PEASS の最新バージョンを入手したり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションをご覧ください
* [**公式 PEASS & HackTricks スウェグ**](https://peass.creator-spring.com) を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) Discord グループ**に**参加**するか、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)** をフォロー**してください。
* **ハッキングトリックを共有するために、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks) と [hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)** に PR を提出してください。

</details>

## Iptables

### チェーン

iptables では、チェーンとして知られるルールのリストが順次処理されます。これらの中で、3 つの主要なチェーンが普遍的に存在し、システムの機能に応じて NAT のような追加のチェーンがサポートされることがあります。

- **Input チェーン**：着信接続の動作を管理するために使用されます。
- **Forward チェーン**：ローカルシステムに向けられていない着信接続を処理するために使用されます。これは、データが別の宛先に転送されることを意味するデバイスがルーターとして機能する場合に一般的です。このチェーンは、システムがルーティング、NAT、または類似のアクティビティに関与している場合に主に関連します。
- **Output チェーン**：送信接続の規制に専念しています。

これらのチェーンは、ネットワークトラフィックの整然な処理を確保し、システムにデータの流れを詳細に規定するルールを指定することを可能にします。
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

### インストール＆設定
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
### ルールの定義

[ドキュメントから：](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) ルール/シグネチャは以下で構成されます：

* **アクション**：シグネチャが一致したときの動作を決定します。
* **ヘッダー**：ルールのプロトコル、IPアドレス、ポート、および方向を定義します。
* **ルールオプション**：ルールの具体的な内容を定義します。
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **有効なアクションは**

* alert - アラートを生成する
* pass - パケットのさらなる検査を停止する
* **drop** - パケットを破棄してアラートを生成する
* **reject** - 一致するパケットの送信元にRST/ICMP unreachableエラーを送信する
* rejectsrc - 単に _reject_ と同じ
* rejectdst - 一致するパケットの受信者にRST/ICMPエラーパケットを送信する
* rejectboth - 会話の両側にRST/ICMPエラーパケットを送信する

#### **プロトコル**

* tcp (tcpトラフィック用)
* udp
* icmp
* ip (ipは 'all' または 'any' を表す)
* _layer7プロトコル_: http, ftp, tls, smb, dns, ssh... (詳細は[**docs**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)を参照)

#### 送信元および宛先アドレス

IP範囲、否定、アドレスのリストをサポートしています:

| 例                           | 意味                                  |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1以外のすべてのIPアドレス             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1および1.1.1.2以外のすべてのIPアドレス |
| $HOME\_NET                     | yamlでのHOME\_NETの設定        |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NETおよびHOME\_NET以外          |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24、ただし10.0.0.5を除く          |

#### 送信元および宛先ポート

ポート範囲、否定、ポートのリストをサポートしています

| 例         | 意味                                |
| --------------- | -------------------------------------- |
| any             | 任意のアドレス                            |
| \[80, 81, 82]   | ポート80、81、82                     |
| \[80: 82]       | 80から82までの範囲                  |
| \[1024: ]       | 1024から最も高いポート番号まで |
| !80             | ポート80以外のすべてのポート                      |
| \[80:100,!99]   | 80から100までの範囲、ただし99を除く |
| \[1:80,!\[2,4]] | 1から80までの範囲、ただしポート2および4を除く  |

#### 方向

適用される通信ルールの方向を示すことが可能です:
```
source -> destination
source <> destination  (both directions)
```
#### キーワード

Suricataには**数百のオプション**があり、探している**特定のパケット**を検索するためのオプションがたくさんあります。ここでは、興味深いものが見つかった場合に言及されます。詳細については、[**ドキュメント**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)をチェックしてください！
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？**HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
