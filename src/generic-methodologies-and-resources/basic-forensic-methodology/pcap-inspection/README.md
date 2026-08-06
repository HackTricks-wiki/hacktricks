# Pcap調査

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** と **PCAPNG** についての注意: PCAPファイル形式には2つのバージョンがあります。**PCAPNGは新しい形式で、すべてのツールでサポートされているわけではありません**。一部のツールで使用するには、Wiresharkまたはその他の互換性のあるツールを使って、ファイルをPCAPNGからPCAPに変換する必要があります。

## pcap用オンラインツール

- pcapのヘッダーが**破損している**場合は、次を使って**修復**してみてください: [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- [**PacketTotal**](https://packettotal.com)でpcap内の**情報**を抽出し、**malware**を検索する
- [**www.virustotal.com**](https://www.virustotal.com)および[**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)を使って**悪意のある活動**を検索する
- [**https://apackets.com/**](https://apackets.com/)でブラウザーから**pcapを完全に分析**する

## 情報の抽出

以下のツールは、統計情報やファイルなどの抽出に役立ちます。

### Wireshark

> [!TIP]
> **PCAPを分析するなら、基本的にWiresharkの使い方を知っておく必要があります**

Wiresharkの便利なテクニックについては、次を参照してください:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

ブラウザーからpcapを分析します。

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(Linuxのみ)_は**pcap**を**分析**し、そこから情報を抽出できます。たとえば、Xplicoはpcapファイルから各メール（POP、IMAP、SMTPプロトコル）、すべてのHTTPコンテンツ、各VoIP通話（SIP）、FTP、TFTPなどを抽出します。

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
127.0.0.1:9876 に認証情報 _**xplico:xplico**_ でアクセスします。

次に、**new case** を作成し、その case 内に **new session** を作成して、**pcap** ファイルを **upload** します。

### NetworkMiner

Xplico と同様に、**pcap からオブジェクトを分析・抽出する**ための tool です。無料版を[**こちら**](https://www.netresec.com/?page=NetworkMiner)から**download**できます。**Windows**で動作します。\
この tool は、パケットから**分析されたその他の情報**を取得し、何が起きていたのかを**より迅速に**把握するためにも役立ちます。

### NetWitness Investigator

[**NetWitness Investigatorはこちらからdownload**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)できます（**Windowsで動作します**）。\
これは、パケットを**分析**し、**内部で何が起きているのか**を把握しやすい形に情報を整理する、もう1つの便利な tool です。

### [BruteShark](https://github.com/odedshimon/BruteShark)

- ユーザー名とパスワードを抽出して encoding する（HTTP、FTP、Telnet、IMAP、SMTP...）
- 認証 hash を抽出し、Hashcat を使用して crack する（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
- visual network diagram を構築する（Network nodes & users）
- DNS queries を抽出する
- すべての TCP および UDP Sessions を再構築する
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

pcap 内で**何か**を**探している**場合は、**ngrep**を使用できます。主なフィルターを使用した例を以下に示します。
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### カービング

一般的なカービング技術を使用すると、pcap からファイルや情報を抽出するのに役立ちます:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 認証情報の取得

[https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) などのツールを使用して、pcap またはライブインターフェースから認証情報を解析できます。

## Exploits/Malware の確認

### Suricata

**インストールとセットアップ**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcapを確認**
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) は、次の処理を行うツールです。

- PCAP File を読み込み、HTTP Streams を抽出する
- 圧縮された Streams を gzip で展開する
- すべてのファイルを yara でスキャンする
- report.txt を書き込む
- オプションでマッチしたファイルを Dir に保存する

### マルウェア解析

既知のマルウェアの fingerprint を見つけられるか確認します。


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) は、passive なオープンソースの network traffic analyzer です。多くの operator は、疑わしい、または悪意のある activity の調査を支援する Network Security Monitor (NSM) として Zeek を使用しています。Zeek は security domain 以外にも、performance measurement や troubleshooting など、幅広い traffic analysis tasks をサポートしています。

基本的に、`zeek` が作成する logs は **pcaps** ではありません。そのため、pcaps に関する **information** が含まれている logs を分析するには、**other tools** を使用する必要があります。

### Connections Info
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
## その他のpcap解析テクニック


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
