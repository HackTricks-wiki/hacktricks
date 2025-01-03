# Pcap Inspection

{{#include ../../../banners/hacktricks-training.md}}

> [!NOTE]
> 关于 **PCAP** 与 **PCAPNG** 的说明：PCAP 文件格式有两个版本；**PCAPNG 是较新的，并不是所有工具都支持**。您可能需要使用 Wireshark 或其他兼容工具将文件从 PCAPNG 转换为 PCAP，以便在某些其他工具中使用。

## 在线工具用于 pcaps

- 如果您的 pcap 的 **头部**是 **损坏的**，您应该尝试使用：[http://f00l.de/hacking/**pcapfix.php**](http://f00l.de/hacking/pcapfix.php) **修复**它
- 在 [**PacketTotal**](https://packettotal.com) 中提取 **信息** 并搜索 **恶意软件**
- 使用 [**www.virustotal.com**](https://www.virustotal.com) 和 [**www.hybrid-analysis.com**](https://www.hybrid-analysis.com) 搜索 **恶意活动**
- 在 [**https://apackets.com/**](https://apackets.com/) 中 **从浏览器进行完整的 pcap 分析**

## 提取信息

以下工具对于提取统计信息、文件等非常有用。

### Wireshark

> [!NOTE]
> **如果您要分析 PCAP，您基本上必须知道如何使用 Wireshark**

您可以在以下位置找到一些 Wireshark 技巧：

{{#ref}}
wireshark-tricks.md
{{#endref}}

### [**https://apackets.com/**](https://apackets.com/)

从浏览器进行 pcap 分析。

### Xplico Framework

[**Xplico** ](https://github.com/xplico/xplico)_(仅限 linux)_ 可以 **分析** 一个 **pcap** 并从中提取信息。例如，从一个 pcap 文件中，Xplico 提取每封电子邮件（POP、IMAP 和 SMTP 协议）、所有 HTTP 内容、每个 VoIP 通话（SIP）、FTP、TFTP 等。

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
访问 _**127.0.0.1:9876**_，凭证为 _**xplico:xplico**_

然后创建一个 **新案例**，在案例中创建一个 **新会话** 并 **上传 pcap** 文件。

### NetworkMiner

像 Xplico 一样，它是一个 **分析和提取 pcaps 中对象** 的工具。它有一个免费版可以 **下载** [**这里**](https://www.netresec.com/?page=NetworkMiner)。它在 **Windows** 上工作。\
这个工具也有助于从数据包中获取 **其他信息分析**，以便能够更 **快速** 地了解发生了什么。

### NetWitness Investigator

您可以从 [**这里下载 NetWitness Investigator**](https://www.rsa.com/en-us/contact-us/netwitness-investigator-freeware) **（它在 Windows 上工作）**。\
这是另一个有用的工具，**分析数据包** 并以有用的方式整理信息，以 **了解内部发生的事情**。

### [BruteShark](https://github.com/odedshimon/BruteShark)

- 提取和编码用户名和密码（HTTP、FTP、Telnet、IMAP、SMTP...）
- 提取身份验证哈希并使用 Hashcat 破解它们（Kerberos、NTLM、CRAM-MD5、HTTP-Digest...）
- 构建可视化网络图（网络节点和用户）
- 提取 DNS 查询
- 重建所有 TCP 和 UDP 会话
- 文件雕刻

### Capinfos
```
capinfos capture.pcap
```
### Ngrep

如果您在 pcap 中**寻找**某些**东西**，可以使用**ngrep**。以下是使用主要过滤器的示例：
```bash
ngrep -I packets.pcap "^GET" "port 80 and tcp and host 192.168 and dst host 192.168 and src host 192.168"
```
### 切割

使用常见的切割技术可以从 pcap 中提取文件和信息：

{{#ref}}
../partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

### 捕获凭证

您可以使用工具如 [https://github.com/lgandx/PCredz](https://github.com/lgandx/PCredz) 从 pcap 或实时接口中解析凭证。

## 检查漏洞/恶意软件

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

[**YaraPCAP**](https://github.com/kevthehermit/YaraPcap) 是一个工具，可以

- 读取 PCAP 文件并提取 Http 流。
- gzip 解压任何压缩流
- 使用 yara 扫描每个文件
- 写入 report.txt
- 可选地将匹配的文件保存到目录

### 恶意软件分析

检查您是否可以找到已知恶意软件的任何指纹：

{{#ref}}
../malware-analysis.md
{{#endref}}

## Zeek

> [Zeek](https://docs.zeek.org/en/master/about.html) 是一个被动的开源网络流量分析器。许多操作员使用 Zeek 作为网络安全监控器 (NSM) 来支持对可疑或恶意活动的调查。Zeek 还支持广泛的流量分析任务，超出安全领域，包括性能测量和故障排除。

基本上，`zeek` 创建的日志不是 **pcaps**。因此，您需要使用 **其他工具** 来分析包含 **pcaps 信息** 的日志。

### 连接信息
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

​

{{#include ../../../banners/hacktricks-training.md}}
