# Wireshark技巧

{{#include ../../../banners/hacktricks-training.md}}

## 提升你的Wireshark技能

### 教程

以下教程非常适合学习一些酷炫的基本技巧：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**分析** --> **专家信息**_ 你将获得一个 **概述**，了解在 **分析** 的数据包中发生了什么：

![](<../../../images/image (256).png>)

**已解析地址**

在 _**统计 --> 已解析地址**_ 下，你可以找到Wireshark "已解析" 的多种 **信息**，如端口/传输到协议、MAC到制造商等。了解通信中涉及的内容是很有趣的。

![](<../../../images/image (893).png>)

**协议层次**

在 _**统计 --> 协议层次**_ 下，你可以找到通信中 **涉及的协议** 及其相关数据。

![](<../../../images/image (586).png>)

**对话**

在 _**统计 --> 对话**_ 下，你可以找到通信中的 **对话摘要** 及其相关数据。

![](<../../../images/image (453).png>)

**端点**

在 _**统计 --> 端点**_ 下，你可以找到通信中的 **端点摘要** 及其相关数据。

![](<../../../images/image (896).png>)

**DNS信息**

在 _**统计 --> DNS**_ 下，你可以找到捕获的DNS请求的统计信息。

![](<../../../images/image (1063).png>)

**I/O图**

在 _**统计 --> I/O图**_ 下，你可以找到 **通信图**。

![](<../../../images/image (992).png>)

### 过滤器

在这里你可以找到根据协议的Wireshark过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
其他有趣的过滤器：

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP和初始HTTPS流量
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP和初始HTTPS流量 + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP和初始HTTPS流量 + TCP SYN + DNS请求

### 搜索

如果你想在会话的 **数据包** 中 **搜索** **内容**，请按 _CTRL+f_。你可以通过右键点击并选择编辑列来添加新的层到主信息栏（编号、时间、源等）。

### 免费pcap实验室

**通过以下免费挑战进行练习：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 识别域名

你可以添加一个显示Host HTTP头的列：

![](<../../../images/image (639).png>)

以及一个添加来自发起HTTPS连接的服务器名称的列 (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## 识别本地主机名

### 从DHCP

在当前的Wireshark中，你需要搜索 `DHCP` 而不是 `bootp`

![](<../../../images/image (1013).png>)

### 从NBNS

![](<../../../images/image (1003).png>)

## 解密TLS

### 使用服务器私钥解密https流量

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

按 _编辑_ 并添加服务器和私钥的所有数据 (_IP、端口、协议、密钥文件和密码_)

### 使用对称会话密钥解密https流量

Firefox和Chrome都能够记录TLS会话密钥，这可以与Wireshark一起使用以解密TLS流量。这允许对安全通信进行深入分析。有关如何执行此解密的更多详细信息，请参阅[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)中的指南。

要检测此内容，请在环境中搜索变量 `SSLKEYLOGFILE`

共享密钥的文件看起来像这样：

![](<../../../images/image (820).png>)

要在Wireshark中导入此文件，请转到 _edit > preference > protocol > ssl > 并将其导入到 (Pre)-Master-Secret日志文件名中：

![](<../../../images/image (989).png>)

## ADB通信

从ADB通信中提取一个APK，其中APK被发送：
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{{#include ../../../banners/hacktricks-training.md}}
