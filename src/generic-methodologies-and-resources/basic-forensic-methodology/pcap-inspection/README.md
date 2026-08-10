# Pcap 检查

> [!TIP]
> **PCAP** 和 **PCAPNG** 是两种不同的捕获格式；**PCAPNG 是 PCAP 的灵活且可扩展的后继格式**，但不同工具对其支持程度有所不同。如果某个工具无法读取 PCAPNG，可以使用 Wireshark 或其他兼容工具将其转换为 PCAP。<sup>[[1]](#references)[[18]](#references)</sup>

## PCAP 在线工具

- 如果你的 pcap 文件头**损坏**，可以尝试使用以下工具进行**修复**：[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)。<sup>[[2]](#references)</sup>
- 在 [**PacketTotal**](https://packettotal.com) 中从 pcap 内提取**信息**并搜索**malware**。<sup>[[19]](#references)</sup>
- 使用 [**www.virustotal.com**](https://www.virustotal.com) 和 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) 搜索**恶意活动**。<sup>[[3]](#references)[[4]](#references)</sup>
- 在浏览器中进行 [**https://apackets.com/**](https://apackets.com/) 的 **pcap 全面分析**。<sup>[[5]](#references)</sup>

## 提取信息

以下工具可用于提取统计信息、文件等。

### Wireshark

> [!TIP]
> **如果你要分析 PCAP，基本上必须了解如何使用 Wireshark**

你可以在以下位置找到一些 Wireshark 技巧：


{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

在浏览器中进行 Pcap 分析。<sup>[[5]](#references)</sup>

### Xplico Framework

[**Xplico**](https://github.com/xplico/xplico) 是一个类 Unix 网络取证工具，可以解码 PCAP 文件，并提取通过 POP/IMAP/SMTP 传输的电子邮件、HTTP 内容、SIP VoIP 通话、FTP 数据和 TFTP 数据。<sup>[[6]](#references)</sup>

**安装**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
运行
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
使用凭据 _**xplico:xplico**_ 访问 _**127.0.0.1:9876**_

然后创建一个**新 case**，在该 case 中创建一个**新 session**，并**上传 pcap**文件。

### NetworkMiner

与 Xplico 类似，[**NetworkMiner**](https://www.netresec.com/?page=NetworkMiner) 会解析 PCAP 流量，以提取文件、图像、电子邮件和密码等 artifacts，并汇总主机信息；其免费版本主要面向 Windows。<sup>[[7]](#references)</sup>

### NetWitness Investigator

你可以[**从这里下载 NetWitness Investigator**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)**（可在 Windows 中运行）**。\
该厂商将此 freeware 描述为一种交互式 network-session analysis 工具，用于恶意活动 triage，目前通过联系表单提供访问权限。<sup>[[8]](#references)</sup>

### [BruteShark](https://github.com/odedshimon/BruteShark)

BruteShark 的文档化模块可以从 HTTP、FTP、Telnet、IMAP 和 SMTP 中解析 credentials，为 Hashcat 导出 Kerberos、NTLM、CRAM-MD5 和 HTTP-Digest authentication hashes，映射 network nodes 和 users，提取 DNS queries，重建 TCP/UDP sessions，并 carve files。<sup>[[9]](#references)</sup>

### Capinfos

Wireshark 的 `capinfos` 默认会为 capture file 打印一份详细报告。<sup>[[10]](#references)</sup>
```
capinfos capture.pcap
```
### Ngrep

`ngrep` 使用正则表达式搜索数据包有效载荷，并接受 BPF 过滤器；`-I` 读取与 pcap 兼容的捕获文件。<sup>[[11]](#references)</sup> 以下示例结合这些功能，在选定的流量中搜索 HTTP 请求。
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 文件雕刻

使用常见的文件雕刻技术有助于从 pcap 中提取文件和信息：


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 捕获凭据

你可以使用 [PCredz](https://github.com/lgandx/PCredz) 从存储的 PCAP 文件或实时接口中解析凭据。<sup>[[12]](#references)</sup>

## 检查 Exploits/Malware

### Suricata

**安装和设置**
```
apt-get install suricata
apt-get install oinkmaster
echo "url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz" >> /etc/oinkmaster.conf
oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules
```
**检查 pcap**

Suricata 的 `-r` 选项以离线模式重放 PCAP；在此示例中，`-k none` 禁用校验和检查，`-v` 增加日志详细程度，而 `-l` 选择日志目录。<sup>[[13]](#references)</sup>
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) 处理 PCAP 文件中的 HTTP 流，可选择解压 gzip 流，使用 YARA 扫描提取的文件，写入 `report.txt`，并可将匹配的文件保存到指定目录。<sup>[[14]](#references)</sup>

### Malware Analysis

检查是否能找到已知 malware 的任何指纹：


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) 是一种被动的开源网络流量分析器，可用作 Network Security Monitor (NSM)，也可用于更广泛的流量分析，包括性能测量和故障排除。<sup>[[15]](#references)</sup>

Zeek 生成结构化日志，而不是 PCAP 文件，因此应使用 `zeek-cut` 等日志分析工具检查这些日志。<sup>[[15]](#references)[[16]](#references)</sup>

### Connections Info

下面的示例使用 `zeek-cut` 从 TSV 日志中选择指定字段，然后使用标准 Unix 工具对连接进行排序和计数；RITA 也可以导入 Zeek 日志，用于长连接、beaconing 和 DNS-tunneling 分析。<sup>[[16]](#references)[[17]](#references)</sup>
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
### DNS 信息
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
## 其他 pcap 分析技巧


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

- [1] [Wireshark 用户指南：打开捕获文件](https://www.wireshark.org/docs/wsug_html_chunked/ChIOOpenSection.html)
- [2] [pcapfix - 在线 pcap / pcapng 修复服务](https://f00l.de/hacking/pcapfix.php)
- [3] [VirusTotal API v3 概览](https://docs.virustotal.com/reference/overview)
- [4] [Hybrid Analysis](https://www.hybrid-analysis.com/)
- [5] [A-Packets PCAP Analyzer](https://apackets.com/)
- [6] [Xplico - 关于](https://www.xplico.org/about)
- [7] [NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [8] [NetWitness Investigator 免费软件](https://www.netwitness.com/contact-us/netwitness-investigator-freeware/)
- [9] [BruteShark 仓库](https://github.com/odedshimon/BruteShark)
- [10] [Wireshark `capinfos` 手册](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [11] [ngrep 文档](https://ngrep.sourceforge.net/usage.html)
- [12] [PCredz 仓库](https://github.com/lgandx/PCredz)
- [13] [Suricata 命令行选项](https://docs.suricata.io/en/latest/command-line-options.html)
- [14] [YaraPcap 仓库](https://github.com/kevthehermit/YaraPcap)
- [15] [什么是 Zeek？](https://docs.zeek.org/en/master/about/what.html)
- [16] [Zeek 日志教程](https://docs.zeek.org/en/master/tutorial/logs.html)
- [17] [RITA 仓库](https://github.com/activecm/rita)
- [18] [Wireshark `editcap` 文档](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html)
- [19] [PacketTotal Upload API 公告](https://medium.com/packettotal/the-packettotal-upload-api-26f48e53f0ee)
{{#include ../../../banners/hacktricks-training.md}}
