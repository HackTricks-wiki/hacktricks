# Pcap 检查

{{#include ../../../banners/hacktricks-training.md}}

> [!TIP]
> 关于 **PCAP** 与 **PCAPNG** 的说明：PCAP 文件格式有两个版本；**PCAPNG 更新，但并非所有工具都支持**。你可能需要使用 Wireshark 或其他兼容工具将文件从 PCAPNG 转换为 PCAP，才能在某些其他工具中处理它。

## 用于 pcap 的在线工具

- 如果你的 pcap 文件头**损坏**，应尝试使用以下工具**修复**： [http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php)
- 在 [**PacketTotal**](https://packettotal.com) 中提取 pcap 内的**信息**并搜索**malware**
- 使用 [**www.virustotal.com**](https://www.virustotal.com) 和 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) 搜索**恶意活动**
- [**https://apackets.com/**](https://apackets.com/) 中的**浏览器内完整 pcap 分析**

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

在浏览器中进行 Pcap 分析。

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(仅限 linux)_ 可以**分析** **pcap** 并从中提取信息。例如，对于 pcap 文件，Xplico 可以提取每封电子邮件（POP、IMAP 和 SMTP 协议）、所有 HTTP 内容、每个 VoIP 通话（SIP）、FTP、TFTP 等。

**安装**
```bash
sudo bash -c 'echo "deb http://repo.xplico.org/ $(lsb_release -s -c) main" /etc/apt/sources.list'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 791C25CE
sudo apt-get update
sudo apt-get install xplico
```
**运行**
```
/etc/init.d/apache2 restart
/etc/init.d/xplico start
```
访问 _**127.0.0.1:9876**_，使用凭据 _**xplico:xplico**_

然后创建一个**新 case**，在该 case 中创建一个**新 session**，并**上传 pcap**文件。

### NetworkMiner

与 Xplico 一样，它是一个用于**分析和从 pcap 中提取对象**的工具。它提供免费版本，可从[**此处下载**](https://www.netresec.com/?page=NetworkMiner)。它适用于 **Windows**。\
该工具还可用于从数据包中获取经过**分析的其他信息**，从而以**更快的方式**了解发生了什么。

### NetWitness Investigator

你可以[**从此处下载 NetWitness Investigator**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware)，**（适用于 Windows）**。\
这是另一个有用的工具，可以**分析数据包**，并以有用的方式整理信息，从而**了解内部正在发生什么**。

### [BruteShark](https://github.com/odedshimon/BruteShark)

- 提取并编码用户名和密码（HTTP、FTP、Telnet、IMAP、SMTP...）
- 提取 authentication hashes，并使用 Hashcat 破解（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
- 构建可视化网络图（网络节点和用户）
- 提取 DNS queries
- 重建所有 TCP 和 UDP Sessions
- File Carving

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

如果你正在 **查找** pcap 中的 **某些内容**，可以使用 **ngrep**。以下是一个使用主要过滤器的示例：
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 文件雕刻

使用常见的 carving 技术可以从 pcap 中提取文件和信息：


{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 捕获凭据

你可以使用 [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) 等工具，从 pcap 或实时接口中解析凭据。

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
```
suricata -r packets.pcap -c /etc/suricata/suricata.yaml -k none -v -l log
```
### YaraPcap

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) 是一个工具，可以：

- 读取 PCAP File 并提取 Http Streams。
- 对任何压缩的 streams 进行 gzip 解压
- 使用 yara 扫描每个文件
- 写入 report.txt
- 可选地将匹配的文件保存到一个 Dir

### Malware Analysis

检查是否可以找到任何已知 malware 的特征：


{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) 是一个被动式、开源的网络流量分析器。许多 operator 使用 Zeek 作为 Network Security Monitor (NSM)，以支持对可疑或恶意活动的调查。Zeek 还支持 security domain 之外的广泛流量分析任务，包括性能测量和故障排除。

基本上，`zeek` 创建的日志并不是 **pcaps**。因此，你需要使用 **其他工具** 来分析包含有关 pcaps 的 **信息** 的日志。

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

{{#include ../../../banners/hacktricks-training.md}}
