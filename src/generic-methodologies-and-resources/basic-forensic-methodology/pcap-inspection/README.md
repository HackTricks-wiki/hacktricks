# Pcap Inspection

> [!TIP]
> **PCAP** と **PCAPNG** は異なるキャプチャ形式です。**PCAPNG は PCAP の柔軟で拡張可能な後継形式**ですが、ツールによって対応状況が異なります。ツールが PCAPNG を読み込めない場合は、Wireshark またはその他の互換ツールを使用して PCAP に変換してください。<sup>[[1]](#references)[[18]](#references)</sup>

## pcap向けオンラインツール

- pcap のヘッダーが**壊れている**場合は、[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) を使用して**修復**してみてください。<sup>[[2]](#references)</sup>
- [**PacketTotal**](https://packettotal.com) で pcap 内の**情報**を抽出し、**malware**を検索します。<sup>[[19]](#references)</sup>
- [**www.virustotal.com**](https://www.virustotal.com) と [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) を使用して、**悪意のある活動**を検索します。<sup>[[3]](#references)[[4]](#references)</sup>
- [**https://apackets.com/**](https://apackets.com/) で、**ブラウザから pcap を完全に分析**できます。<sup>[[5]](#references)</sup>

## 情報の抽出

以下のツールは、統計情報やファイルなどの抽出に役立ちます。

### Wireshark

> [!TIP]
> **PCAP を分析する場合、基本的に Wireshark の使い方を知っておく必要があります**

Wireshark の tricks は以下で確認できます:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

ブラウザからの Pcap 分析。<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) は Unix 系の network-forensics ツールで、PCAP ファイルをデコードし、POP/IMAP/SMTP 経由のメール、HTTP コンテンツ、SIP VoIP 通話、FTP データ、TFTP データを抽出できます。<sup>[[6]](#references)</sup>

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
_**127.0.0.1:9876**_ に、認証情報 _**xplico:xplico**_ でアクセスします。

次に、**新しいケース**を作成し、ケース内に**新しいセッション**を作成して、**pcap** ファイルをアップロードします。

### NetworkMiner

Xplico と同様に、[**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) は PCAP トラフィックを解析し、ファイル、画像、メール、パスワードなどのアーティファクトを抽出するとともに、ホスト情報を集約します。無料版は主に Windows 向けです。<sup>[[7]](#references)</sup>

### NetWitness Investigator

[**NetWitness Investigator はこちらからダウンロードできます**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **（Windows で動作します）**。\
ベンダーは、この freeware を悪意のある活動のトリアージを目的としたインタラクティブなネットワークセッション解析ツールとして説明しており、現在は問い合わせフォーム経由でのアクセスを案内しています。<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark のドキュメントに記載されたモジュールは、HTTP、FTP、Telnet、IMAP、SMTP から認証情報を解析し、Kerberos、NTLM、CRAM-MD5、HTTP-Digest 認証ハッシュを Hashcat 用にエクスポートし、ネットワークノードとユーザーをマッピングし、DNS クエリを抽出し、TCP/UDP セッションを再構築し、ファイルをカービングできます。<sup>[[9]](#references)</sup>

### Capinfos

Wireshark の `capinfos` は、デフォルトでキャプチャファイルに関する詳細なレポートを出力します。<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep`は正規表現でパケットのpayloadを検索し、BPF filterを受け付けます。`-I`はpcap互換のcapture fileを読み込みます。<sup>[[11]](#references)</sup> この例では、これらの機能を組み合わせて、選択したトラフィック内のHTTP requestを検索します。
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

一般的な carving techniques を使用すると、pcap からファイルや情報を抽出するのに役立ちます:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 認証情報のキャプチャ

保存された PCAP ファイルまたは live interface から認証情報を parse するには、[PCredz](https://github.com/lgandx/PCredz) を使用できます。<sup>[[12]](#references)</sup>

## Exploits/Malware の確認

### Suricata

**インストールとセットアップ**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**pcap の確認**

Suricata の `-r` オプションは offline mode で PCAP を再生します。この例では、`-k none` が checksum checks を無効化し、`-v` が logging を増加させ、`-l` が log directory を選択します。<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) は PCAP ファイルから HTTP ストリームを処理し、gzip ストリームを任意で展開し、抽出したファイルを YARA でスキャンし、`report.txt` を書き込み、一致したファイルをディレクトリに保存できます。<sup>[[14]](#references)</sup>

### Malware Analysis

既知の malware の fingerprint を見つけられるか確認します。


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) は、Network Security Monitor (NSM) として、またパフォーマンス測定やトラブルシューティングを含む、より広範なトラフィック分析のために使用される、パッシブなオープンソースのネットワークトラフィックアナライザーです。<sup>[[15]](#references)</sup>

Zeek は PCAP ファイルではなく構造化されたログを生成するため、`zeek-cut` などのログ分析ツールを使用してこれらのログを調査します。<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

以下の例では、`zeek-cut` を使用して TSV ログから名前付きフィールドを選択し、その後、標準的な Unix ツールで接続を順位付けしてカウントします。RITA で Zeek ログを取り込み、長時間接続、beaconing、DNS-tunneling を分析することもできます。<sup>[[16]](#references)[[17]](#references)</sup>
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
## その他の pcap 分析テクニック


{{#ref}}
dnscat-exfiltration.md
{{#endref}}


{{#ref}}
wifi-pcap-analysis.md
{{#endref}}


{{#ref}}
usb-keystrokes.md
{{#endref}}

## References

- [1] [Wireshark User's Guide: キャプチャファイルを開く](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - オンライン pcap / pcapng 修復サービス](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 概要](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - 概要](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator Freeware](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark リポジトリ](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` マニュアル](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep ドキュメント](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz リポジトリ](https://github.com/lgandx/PCredz)
- [13] [Suricata コマンドラインオプション](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap リポジトリ](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek とは？](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek ログチュートリアル](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA リポジトリ](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` ドキュメント](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API の発表](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
