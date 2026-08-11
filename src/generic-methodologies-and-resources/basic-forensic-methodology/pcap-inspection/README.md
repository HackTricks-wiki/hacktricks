# PCAPの検査

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> **PCAP** と **PCAPNG** は異なるキャプチャ形式です。**PCAPNGはPCAPを継承した柔軟で拡張可能な形式**ですが、toolによって対応状況が異なります。toolがPCAPNGを読み取れない場合は、Wiresharkまたはその他の互換toolを使用してPCAPに変換してください。<sup>[[1]](#references)[[18]](#references)</sup>

## PCAP用のオンラインtool

- pcapのヘッダーが**破損している**場合は、[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)を使用して**修復**してみてください。<sup>[[2]](#references)</sup>
- [**PacketTotal**](https://packettotal.com)でpcap内の**情報**を抽出し、**malware**を検索します。<sup>[[19]](#references)</sup>
- [**www.virustotal.com**](https://www.virustotal.com)および[**www.hybrid-analysis.com**](https://www.hybrid-analysis.com)を使用して**悪意のある活動**を検索します。<sup>[[3]](#references)[[4]](#references)</sup>
- [**https://apackets.com/**](https://apackets.com/)で**ブラウザから完全なpcap解析**を行えます。<sup>[[5]](#references)</sup>

## 情報の抽出

以下のtoolは、統計情報やファイルなどの抽出に役立ちます。

### Wireshark

> [!TIP]
> **PCAPを解析する場合、基本的にWiresharkの使い方を知っておく必要があります**

Wiresharkのtipsについては、以下を参照してください:


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

ブラウザからpcapを解析します。<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico)はUnix系のnetwork-forensics toolであり、PCAPファイルをdecodeし、POP/IMAP/SMTP経由のemail、HTTP contents、SIP VoIP calls、FTP data、TFTP dataを抽出できます。<sup>[[6]](#references)</sup>

**Install**
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
_**127.0.0.1:9876**_ に認証情報 _**xplico:xplico**_ でアクセスします。

次に、**new case** を作成し、case 内に **new session** を作成して、**pcap** ファイルをアップロードします。

### NetworkMiner

Xplico と同様に、[**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) は PCAP トラフィックを解析し、ファイル、画像、メール、パスワードなどの artifact を抽出するとともに、host 情報を集約します。free edition は主に Windows 向けです。<sup>[[7]](#references)</sup>

### NetWitness Investigator

[**NetWitness Investigatorはこちらからダウンロードできます**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **（Windows で動作します）**。\
vendor は、この freeware を悪意のある活動の triage 用インタラクティブな network-session analysis tool と説明しており、現在は contact form 経由でのアクセスを案内しています。<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark の documented modules は、HTTP、FTP、Telnet、IMAP、SMTP から credentials を解析し、Hashcat 用に Kerberos、NTLM、CRAM-MD5、HTTP-Digest authentication hashes を export し、network nodes と users を map し、DNS queries を抽出し、TCP/UDP sessions を再構築し、files を carve できます。<sup>[[9]](#references)</sup>

### Capinfos

Wireshark の `capinfos` は、デフォルトで capture file の詳細な report を出力します。<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` は正規表現で packet payload を検索し、BPF filters を受け付けます。`-I` は pcap-compatible capture file を読み取ります。<sup>[[11]](#references)</sup> この例では、これらの機能を組み合わせて、選択した traffic 内の HTTP request を検索します。
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### Carving

一般的な carving 技術を使用すると、pcap からファイルや情報を抽出するのに役立ちます:


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 認証情報の取得

保存された PCAP ファイルまたはライブインターフェースから認証情報を解析するには、[PCredz](https://github.com/lgandx/PCredz) を使用できます。<sup>[[12]](#references)</sup>

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

Suricataの`-r`オプションはoffline modeでPCAPを再生します。この例では、`-k none`でchecksum checksを無効にし、`-v`でloggingを増やし、`-l`でlog directoryを指定しています。<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) は PCAP ファイルから HTTP ストリームを処理し、必要に応じて gzip ストリームを展開し、抽出したファイルを YARA でスキャンして `report.txt` に書き込み、一致したファイルをディレクトリに保存できます。<sup>[[14]](#references)</sup>

### Malware Analysis

既知の malware の fingerprint を見つけられるか確認します:


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) は、Network Security Monitor (NSM) として、またパフォーマンス測定やトラブルシューティングを含む、より広範なトラフィック分析のために使用される、passive な open-source のネットワークトラフィック analyzer です。<sup>[[15]](#references)</sup>

Zeek は PCAP ファイルではなく構造化されたログを生成するため、`zeek-cut` などの log-analysis tools を使用してそれらのログを調査します。<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

以下の例では、`zeek-cut` を使用して TSV ログから名前付きフィールドを選択し、その後、標準的な Unix tools で接続を順位付けしてカウントします。RITA は Zeek ログを取り込み、長時間接続、beaconing、DNS-tunneling の分析を行うこともできます。<sup>[[16]](#references)[[17]](#references)</sup>
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
- [8] [NetWitness Investigator 無料版](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark リポジトリ](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` マニュアル](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep ドキュメント](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz リポジトリ](https://github.com/lgandx/PCredz)
- [13] [Suricata コマンドラインオプション](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap リポジトリ](https://github.com/kevthehermit/YaraPcap)
- [15] [Zeek とは](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek ログチュートリアル](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA リポジトリ](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` ドキュメント](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API の発表](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
