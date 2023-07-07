# Suricata & Iptables チートシート

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## Iptables

### チェーン

Iptablesのチェーンは、順番に処理されるルールのリストです。以下の3つは常に存在しますが、NATなどの他のチェーンもサポートされている場合があります。

* **Input** - このチェーンは、受信接続の動作を制御するために使用されます。
* **Forward** - このチェーンは、ローカルに配信されていない受信接続に使用されます。ルーターのように考えてください - データは常に送信されていますが、実際にはルーター自体に宛てられているわけではありません。データは単に目的地に転送されます。ルーティング、NAT、または他のシステムで転送が必要な場合を除いて、このチェーンは使用しません。
* **Output** - このチェーンは、送信接続に使用されます。
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

#### インストール

Suricataをインストールするには、次のコマンドを使用します。

```bash
sudo apt-get install suricata
```

#### 設定

Suricataの設定ファイルは、通常`/etc/suricata/suricata.yaml`にあります。以下のコマンドを使用して、設定ファイルを編集します。

```bash
sudo nano /etc/suricata/suricata.yaml
```

設定ファイルを編集する際には、次の項目に注意してください。

- `HOME_NET`：ネットワークの範囲を指定します。デフォルトでは、`[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`が設定されています。
- `EXTERNAL_NET`：外部ネットワークの範囲を指定します。デフォルトでは、`!$HOME_NET`が設定されています。
- `RULE_PATHS`：ルールファイルのパスを指定します。デフォルトでは、`/etc/suricata/rules`が設定されています。

設定を変更した後は、Suricataを再起動する必要があります。

```bash
sudo service suricata restart
```

### インターフェースの監視

Suricataを特定のインターフェースで実行するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i <interface>
```

`<interface>`には、監視するインターフェースの名前を指定します。

### ログの表示

Suricataのログは、デフォルトでは`/var/log/suricata/fast.log`に保存されます。次のコマンドを使用して、ログを表示します。

```bash
sudo tail -f /var/log/suricata/fast.log
```

### イベントの表示

Suricataが検出したイベントを表示するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -T
```

### イベントのフィルタリング

Suricataのイベントをフィルタリングするには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file> "filter"
```

`<pcap_file>`には、解析するPCAPファイルのパスを指定します。`"filter"`には、適用するフィルターを指定します。

### イベントの解析

Suricataのイベントを解析するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file> -l <output_directory>
```

`<pcap_file>`には、解析するPCAPファイルのパスを指定します。`<output_directory>`には、解析結果を保存するディレクトリのパスを指定します。

### イベントのエクスポート

Suricataのイベントをエクスポートするには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file> -l <output_directory> --output <output_format>
```

`<pcap_file>`には、解析するPCAPファイルのパスを指定します。`<output_directory>`には、解析結果を保存するディレクトリのパスを指定します。`<output_format>`には、エクスポートする形式を指定します。

### イベントの統計情報

Suricataのイベントの統計情報を表示するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file> -l <output_directory> --stats
```

`<pcap_file>`には、解析するPCAPファイルのパスを指定します。`<output_directory>`には、解析結果を保存するディレクトリのパスを指定します。

### イベントの比較

Suricataのイベントを比較するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file1> -r <pcap_file2> --compare
```

`<pcap_file1>`と`<pcap_file2>`には、比較する2つのPCAPファイルのパスを指定します。

### イベントの統合

Suricataのイベントを統合するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file1> -r <pcap_file2> --merge
```

`<pcap_file1>`と`<pcap_file2>`には、統合する2つのPCAPファイルのパスを指定します。

### イベントのフィルタリングと解析

Suricataのイベントをフィルタリングして解析するには、次のコマンドを使用します。

```bash
sudo suricata -c /etc/suricata/suricata.yaml -r <pcap_file> -l <output_directory> --filter <filter> --output <output_format>
```

`<pcap_file>`には、解析するPCAPファイルのパスを指定します。`<output_directory>`には、解析結果を保存するディレクトリのパスを指定します。`<filter>`には、適用するフィルターを指定します。`<output_format>`には、エクスポートする形式を指定します。
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

ルール/シグネチャは以下の要素で構成されます：

* **アクション**：シグネチャが一致した場合に何が起こるかを決定します。
* **ヘッダ**：ルールのプロトコル、IPアドレス、ポート、方向を定義します。
* **ルールオプション**：ルールの詳細を定義します。

![](<../../../.gitbook/assets/image (642) (3).png>)

#### **有効なアクションは以下の通りです**

* alert - アラートを生成します
* pass - パケットのさらなる検査を停止します
* **drop** - パケットを破棄し、アラートを生成します
* **reject** - 一致するパケットの送信元にRST/ICMP unreachableエラーを送信します。
* rejectsrc - _reject_ と同じです
* rejectdst - 一致するパケットの受信者にRST/ICMPエラーパケットを送信します。
* rejectboth - 会話の両側にRST/ICMPエラーパケットを送信します。

#### **プロトコル**

* tcp（tcpトラフィック用）
* udp
* icmp
* ip（ipは「all」または「any」を表します）
* _layer7プロトコル_：http、ftp、tls、smb、dns、ssh...（[**ドキュメント**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html)に詳細あり）

#### 送信元と宛先のアドレス

IP範囲、否定、アドレスのリストをサポートしています：

| 例                            | 意味                                      |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | 1.1.1.1以外のすべてのIPアドレス             |
| !\[1.1.1.1, 1.1.1.2]           | 1.1.1.1と1.1.1.2以外のすべてのIPアドレス |
| $HOME\_NET                     | yamlでのHOME\_NETの設定                   |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NETでありHOME\_NETでない         |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24で10.0.0.5を除く               |

#### 送信元と宛先のポート

ポート範囲、否定、ポートのリストをサポートしています

| 例         | 意味                                |
| --------------- | -------------------------------------- |
| any             | 任意のアドレス                            |
| \[80, 81, 82]   | ポート80、81、82                     |
| \[80: 82]       | 80から82までの範囲                  |
| \[1024: ]       | 1024から最大のポート番号まで |
| !80             | ポート80以外のすべてのポート                      |
| \[80:100,!99]   | 80から100までの範囲で99を除く |
| \[1:80,!\[2,4]] | 1から80までの範囲でポート2と4を除く  |

#### 方向

適用される通信ルールの方向を示すことができます：
```
source -> destination
source <> destination  (both directions)
```
#### キーワード

Suricataには、探している特定のパケットを検索するための数百のオプションがあります。ここでは、興味深いものが見つかった場合にそれを示します。詳細については、[ドキュメント](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html)をチェックしてください！
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

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
