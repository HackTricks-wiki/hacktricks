# Pcap Inspection

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
- **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの1つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家の熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
**PCAP** vs **PCAPNG**についての注意：PCAPファイル形式には2つのバージョンがあります。**PCAPNGは新しいバージョンであり、すべてのツールでサポートされていません**。他のツールで使用するためにファイルをWiresharkなどの互換ツールを使用してPCAPNGからPCAPに変換する必要がある場合があります。
{% endhint %}

## Pcap用のオンラインツール

- もしpcapのヘッダーが**壊れて**いる場合は、[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)を使用して**修正**してみてください
- [**PacketTotal**](https://packettotal.com)でpcap内の**情報**や**マルウェア**を検索して抽出する
- [**www.virustotal.com**](https://www.virustotal.com) と [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) を使用して**悪意のある活動**を検索する
- [**https://apackets.com/**](https://apackets.com/) で**ブラウザからの完全なpcap解析**

## 情報の抽出

以下のツールは統計情報、ファイルなどを抽出するのに役立ちます。

### Wireshark

{% hint style="info" %}
**PCAPを分析する場合、基本的にWiresharkの使用方法を知っている必要があります**
{% endhint %}

Wiresharkのトリックは次の場所で見つけることができます：

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### [**https://apackets.com/**](https://apackets.com/)

ブラウザからのPcap解析。

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)（Linuxのみ）は**pcap**を分析し、その情報を抽出できます。たとえば、pcapファイルからXplicoは各電子メール（POP、IMAP、SMTPプロトコル）、すべてのHTTPコンテンツ、各VoIP通話（SIP）、FTP、TFTPなどを抽出します。

**インストール**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**実行**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
アクセスは _**127.0.0.1:9876**_ で、資格情報は _**xplico:xplico**_ です。

その後、**新しいケース**を作成し、ケース内に**新しいセッション**を作成し、**pcap**ファイルを**アップロード**してください。

### NetworkMiner

Xplicoと同様に、これはpcapからオブジェクトを**分析および抽出**するツールです。[**こちら**](https://www.netresec.com/?page=NetworkMiner) から無料版を**ダウンロード**できます。**Windows**と互換性があります。\
このツールは、**パケットから他の情報を取得**し、**より迅速**に何が起こっていたのかを知ることができるようにします。

### NetWitness Investigator

[**こちら**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) から**NetWitness Investigator**をダウンロードできます **(Windowsで動作します)**。\
これは、**パケットを分析**し、情報を有用な方法で整理して**内部で何が起こっているかを知る**のに役立つ別の便利なツールです。

### [BruteShark](https://github.com/odedshimon/BruteShark)

* ユーザー名とパスワードの抽出とエンコード (HTTP、FTP、Telnet、IMAP、SMTP...)
* 認証ハッシュの抽出とHashcatを使用してクラック (Kerberos、NTLM、CRAM-MD5、HTTP-Digest...)
* ビジュアルネットワークダイアグラムの作成 (ネットワークノードとユーザー)
* DNSクエリの抽出
* すべてのTCPおよびUDPセッションの再構築
* ファイルの彫刻

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

pcap内で**何か**を**探している**場合は、**ngrep**を使用できます。以下は、主なフィルターを使用した例です：
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### カービング

一般的なカービング技術を使用して、pcap からファイルや情報を抽出するのに役立ちます:

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 資格情報のキャプチャ

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) のようなツールを使用して、pcap またはライブインターフェースから資格情報を解析できます。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**で最も重要なイベントの一つです。**技術知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての沸騰する出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

## Exploits/Malware のチェック

### Suricata

**インストールとセットアップ**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcapのチェック**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)は次のことを行うツールです。

* PCAPファイルを読み取り、HTTPストリームを抽出します。
* 圧縮されたストリームをgzipで解凍します。
* すべてのファイルをyaraでスキャンします。
* report.txtを書き込みます。
* オプションで一致するファイルをディレクトリに保存します。

### Malware Analysis

既知のマルウェアの指紋を見つけることができるかどうかをチェックしてください:

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html)は、受動的なオープンソースのネットワークトラフィックアナライザーです。多くのオペレーターは、疑わしいまたは悪意のある活動の調査をサポートするために、Zeekをネットワークセキュリティモニター（NSM）として使用しています。 Zeekは、セキュリティ領域を超えたさまざまなトラフィック分析タスクをサポートしており、パフォーマンス測定やトラブルシューティングも含まれています。

基本的に、`zeek`によって作成されたログは**pcap**ではありません。したがって、pcapsに関する**情報**が含まれているログを分析するためには、**他のツール**を使用する必要があります。
```bash
#Get info about longest connections (add "grep udp" to see only udp traffic)
#The longest connection might be of malware (constant reverse shell?)
cat conn.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p proto service duration | sort -nrk 7 | head -n 10

10.55.100.100   49778   65.52.108.225   443     tcp     -       86222.365445
10.55.100.107   56099   111.221.29.113  443     tcp     -       86220.126151
10.55.100.110   60168   40.77.229.82    443     tcp     -       86160.119664


#Improve the metrics by summing up the total duration time for connections that have the same destination IP and Port.
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += $5 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10

10.55.100.100   65.52.108.225   443     tcp     86222.4
10.55.100.107   111.221.29.113  443     tcp     86220.1
10.55.100.110   40.77.229.82    443     tcp     86160.1

#Get the number of connections summed up per each line
cat conn.log | zeek-cut id.orig_h id.resp_h duration | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2] += $3; count[$1 FS $2] += 1 } END{ for (key in arr) printf "%s%s%s%s%s\n", key, FS, count[key], FS, arr[key] }' | sort -nrk 4 | head -n 10

10.55.100.100   65.52.108.225   1       86222.4
10.55.100.107   111.221.29.113  1       86220.1
10.55.100.110   40.77.229.82    134       86160.1

#Check if any IP is connecting to 1.1.1.1
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | grep '1.1.1.1' | sort | uniq -c

#Get number of connections per source IP, dest IP and dest Port
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | awk 'BEGIN{ FS="\t" } { arr[$1 FS $2 FS $3 FS $4] += 1 } END{ for (key in arr) printf "%s%s%s\n", key, FS, arr[key] }' | sort -nrk 5 | head -n 10


# RITA
#Something similar can be done with the tool rita
rita show-long-connections -H --limit 10 zeek_logs

+---------------+----------------+--------------------------+----------------+
|   SOURCE IP   | DESTINATION IP | DSTPORT:PROTOCOL:SERVICE |    DURATION    |
+---------------+----------------+--------------------------+----------------+
| 10.55.100.100 | 65.52.108.225  | 443:tcp:-                | 23h57m2.3655s  |
| 10.55.100.107 | 111.221.29.113 | 443:tcp:-                | 23h57m0.1262s  |
| 10.55.100.110 | 40.77.229.82   | 443:tcp:-                | 23h56m0.1197s  |

#Get connections info from rita
rita show-beacons zeek_logs | head -n 10
Score,Source IP,Destination IP,Connections,Avg Bytes,Intvl Range,Size Range,Top Intvl,Top Size,Top Intvl Count,Top Size Count,Intvl Skew,Size Skew,Intvl Dispersion,Size Dispersion
1,192.168.88.2,165.227.88.15,108858,197,860,182,1,89,53341,108319,0,0,0,0
1,10.55.100.111,165.227.216.194,20054,92,29,52,1,52,7774,20053,0,0,0,0
0.838,10.55.200.10,205.251.194.64,210,69,29398,4,300,70,109,205,0,0,0,0
```
### DNS情報
```bash
#Get info about each DNS request performed
cat dns.log | zeek-cut -c id.orig_h query qtype_name answers

#Get the number of times each domain was requested and get the top 10
cat dns.log | zeek-cut query | sort | uniq | rev | cut -d '.' -f 1-2 | rev | sort | uniq -c | sort -nr | head -n 10

#Get all the IPs
cat dns.log | zeek-cut id.orig_h query | grep 'example\.com' | cut -f 1 | sort | uniq -c

#Sort the most common DNS record request (should be A)
cat dns.log | zeek-cut qtype_name | sort | uniq -c | sort -nr

#See top DNS domain requested with rita
rita show-exploded-dns -H --limit 10 zeek_logs
```
## その他のpcap分析のトリック

{% content-ref url="dnscat-exfiltration.md" %}
[dnscat-exfiltration.md](dnscat-exfiltration.md)
{% endcontent-ref %}

{% content-ref url="wifi-pcap-analysis.md" %}
[wifi-pcap-analysis.md](wifi-pcap-analysis.md)
{% endcontent-ref %}

{% content-ref url="usb-keystrokes.md" %}
[usb-keystrokes.md](usb-keystrokes.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的知識の促進を使命**とするこの会議は、あらゆる分野のテクノロジーとサイバーセキュリティ専門家にとっての熱い出会いの場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で**ゼロからヒーローまでのAWSハッキングを学ぶ**</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**したり、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)を**フォロー**する
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
