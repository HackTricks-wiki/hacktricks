# Pcap検査

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。技術的な知識を促進することを目的として、この会議はあらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

{% hint style="info" %}
**PCAP** vs **PCAPNG**についての注意事項：PCAPファイル形式には2つのバージョンがあります。**PCAPNGは新しいバージョンであり、すべてのツールでサポートされていません**。他のツールで使用するために、Wiresharkなどの互換性のあるツールを使用して、PCAPNGファイルをPCAPに変換する必要がある場合があります。
{% endhint %}

## PCAPのためのオンラインツール

* もしPCAPのヘッダーが**壊れている**場合は、[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)を使用して**修正**してみてください。
* [**PacketTotal**](https://packettotal.com)でPCAP内の**情報**を抽出し、**マルウェア**を検索します。
* [**www.virustotal.com**](https://www.virustotal.com)と[**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)を使用して、**悪意のある活動**を検索します。

## 情報の抽出

以下のツールは、統計情報やファイルなどを抽出するのに役立ちます。

### Wireshark

{% hint style="info" %}
**PCAPを分析する場合、基本的にはWiresharkの使用方法を知っている必要があります**
{% endhint %}

Wiresharkのトリックは次の場所で見つけることができます：

{% content-ref url="wireshark-tricks.md" %}
[wireshark-tricks.md](wireshark-tricks.md)
{% endcontent-ref %}

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(Linuxのみ)_は、**pcap**を分析し、情報を抽出することができます。例えば、pcapファイルからXplicoは、各メール（POP、IMAP、SMTPプロトコル）、すべてのHTTPコンテンツ、各VoIP通話（SIP）、FTP、TFTPなどを抽出します。

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
_**127.0.0.1:9876**_の資格情報は _**xplico:xplico**_ でアクセスしてください。

次に、**新しいケース**を作成し、ケース内に**新しいセッション**を作成し、**pcap**ファイルを**アップロード**してください。

### NetworkMiner

Xplicoと同様に、pcapからオブジェクトを**分析および抽出**するためのツールです。[**こちら**](https://www.netresec.com/?page=NetworkMiner)から無料版を**ダウンロード**できます。**Windows**で動作します。\
このツールは、パケットから**他の情報を分析**して、**より迅速に**何が起こっていたのかを知るためにも役立ちます。

### NetWitness Investigator

[**こちら**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)から**NetWitness Investigator**をダウンロードできます（**Windows**で動作します）。\
これは、パケットを**分析**し、情報を有用な方法で**整理**して、内部で何が起こっているかを**把握**するのに役立つ別の便利なツールです。

![](<../../../.gitbook/assets/image (567) (1).png>)

### [BruteShark](https://github.com/odedshimon/BruteShark)

* ユーザー名とパスワードの抽出とエンコード（HTTP、FTP、Telnet、IMAP、SMTP...）
* 認証ハッシュの抽出とHashcatを使用してクラック（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
* ビジュアルネットワークダイアグラムの作成（ネットワークノードとユーザー）
* DNSクエリの抽出
* すべてのTCPおよびUDPセッションの再構築
* ファイルの抽出

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

もし pcap 内で何かを探している場合は、**ngrep** を使用することができます。以下は、主なフィルタを使用した例です:
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### カービング

一般的なカービング技術を使用すると、pcapからファイルや情報を抽出するのに役立ちます。

{% content-ref url="../partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### 資格情報のキャプチャ

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz)のようなツールを使用して、pcapまたはライブインターフェースから資格情報を解析することができます。

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的な知識の促進を使命**として、この会議はあらゆる分野の技術とサイバーセキュリティの専門家の熱い交流の場です。

{% embed url="https://www.rootedcon.com/" %}

## Exploits/Malwareのチェック

### Suricata

**インストールとセットアップ**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcapの確認**

To analyze network traffic, you can use a packet capture (pcap) file. This file contains recorded network packets that can be inspected to gather information about network communications. The pcap file can be obtained from various sources, such as network monitoring tools or packet sniffers.

To check a pcap file, you can use tools like Wireshark or tcpdump. These tools allow you to open the pcap file and view the captured packets. You can analyze the packet headers, payload, and other relevant information.

When inspecting a pcap file, you should look for any suspicious or abnormal network activity. This can include unusual traffic patterns, unexpected connections, or any signs of malicious activity. By carefully examining the packets, you can identify potential security issues or vulnerabilities in the network.

It is important to note that analyzing pcap files requires some level of expertise in network protocols and packet analysis. It is recommended to have a good understanding of networking concepts and security principles before diving into pcap inspection.

Overall, checking pcap files is an essential part of forensic analysis and can provide valuable insights into network behavior and potential security threats.
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap)は、次の機能を持つツールです。

- PCAPファイルを読み込み、HTTPストリームを抽出します。
- 圧縮されたストリームをgzipで解凍します。
- 各ファイルをYaraでスキャンします。
- report.txtを作成します。
- 必要に応じて一致するファイルをディレクトリに保存します。

### マルウェア解析

既知のマルウェアのフィンガープリントを見つけることができるかどうかを確認してください。

{% content-ref url="../malware-analysis.md" %}
[malware-analysis.md](../malware-analysis.md)
{% endcontent-ref %}

## Zeek

> Zeekは、パッシブなオープンソースのネットワークトラフィックアナライザーです。多くのオペレーターは、Zeekをネットワークセキュリティモニター（NSM）として使用し、不審または悪意のある活動の調査をサポートしています。Zeekは、セキュリティドメインを超えたさまざまなトラフィック分析タスクもサポートしており、パフォーマンス測定やトラブルシューティングなどがあります。

基本的に、`zeek`によって作成されるログは**pcap**ではありません。そのため、pcapに関する**情報**を解析するためには、**他のツール**を使用する必要があります。

### 接続情報
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

DNS（Domain Name System）は、インターネット上のドメイン名とIPアドレスの対応関係を管理するシステムです。DNS情報は、ネットワークトラフィックの中に含まれており、パケットキャプチャ（PCAP）ファイルを調査することで取得できます。

PCAPファイルを調査する際には、以下の手順に従うことが一般的です。

1. PCAPファイルを開きます。
2. DNSトラフィックを特定します。
3. DNSクエリとDNSレスポンスを分析します。
4. ドメイン名と関連するIPアドレスを特定します。

DNS情報の分析により、ネットワーク上で行われた通信の詳細を把握することができます。これにより、不正なアクティビティやセキュリティ上の問題を特定することができます。
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

[**RootedCON**](https://www.rootedcon.com/)は、**スペイン**で最も関連性の高いサイバーセキュリティイベントであり、**ヨーロッパ**でも最も重要なイベントの一つです。**技術的な知識の促進を使命**として、この会議は、あらゆる分野の技術とサイバーセキュリティの専門家のための活気ある交流の場です。

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>
