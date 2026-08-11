# Wireshark 技巧

{{#include ../../../banners/hacktricks-training.md}}

## 提升 Wireshark 技能

### 教程

以下教程非常适合学习一些实用的基础技巧：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析的信息

**专家信息**

点击 _**Analyze** --> **Expert Information**_，即可查看已**分析**数据包中发生情况的**概览**：

![教程 - 分析的信息：点击 Analyze -- Expert Information，即可查看已分析数据包中发生情况的概览](<../../../images/image (256).png>)

**解析的地址**

在 _**Statistics --> Resolved Addresses**_ 下，可以找到 Wireshark "**解析**"出的各种**信息**，例如端口/传输层到协议、MAC 地址到制造商等。了解通信中涉及的对象非常有用。

![教程 - 分析的信息：在 Statistics -- Resolved Addresses 下，可以找到 Wireshark“解析”出的各种信息，例如端口/传输层到协议、MAC 地址到制造商等](<../../../images/image (893).png>)

**协议层次结构**

在 _**Statistics --> Protocol Hierarchy**_ 下，可以找到通信中**涉及**的**协议**及其相关数据。

![教程 - 分析的信息：在 Statistics -- Protocol Hierarchy 下，可以找到通信中涉及的协议及其相关数据](<../../../images/image (586).png>)

**会话**

在 _**Statistics --> Conversations**_ 下，可以找到通信中**会话的摘要**及其相关数据。

![教程 - 分析的信息：在 Statistics -- Conversations 下，可以找到通信中会话的摘要及其相关数据](<../../../images/image (453).png>)

**端点**

在 _**Statistics --> Endpoints**_ 下，可以找到通信中**端点的摘要**以及每个端点的相关数据。

![教程 - 分析的信息：在 Statistics -- Endpoints 下，可以找到通信中端点的摘要以及每个端点的相关数据](<../../../images/image (896).png>)

**DNS 信息**

在 _**Statistics --> DNS**_ 下，可以找到所捕获 DNS 请求的统计信息。

![教程 - 分析的信息：在 Statistics -- DNS 下，可以找到所捕获 DNS 请求的统计信息](<../../../images/image (1063).png>)

**I/O 图**

在 _**Statistics --> I/O Graph**_ 下，可以找到**通信图表**。

![教程 - 分析的信息：在 Statistics -- I/O Graph 下，可以找到通信图表](<../../../images/image (992).png>)

### 过滤器

你可以在这里根据协议查找 Wireshark 过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
在当前版本的 Wireshark 中，应使用 `tls.*`，而不是旧的 `ssl.*` 过滤器名称。<sup>[[1]](#references)</sup>\
其他有用的过滤器：

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS 流量
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS 流量 + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS 流量 + TCP SYN + DNS 请求
- `tls.handshake.extensions_server_name contains "example.com"`
- 即使无法解密 payload，也可以根据 ClientHello 中发送的 SNI 进行 Pivot
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- 快速区分经典 HTTPS、HTTP/2 和支持 HTTP/3 的会话
- `quic or http3`
- 查找现代 UDP/443 流量；如果只查看 TCP 会话，这些流量可能会被遗漏

### 搜索

如果要在会话数据包中**搜索**某些**内容**，请按下 _CTRL+f_。按下鼠标右键，然后选择编辑列，即可向主信息栏（No.、Time、Source 等）添加新的列。

### 跟踪多路复用的流

Wireshark 可以直接跟踪 `TLS`、`HTTP/2` 和 `QUIC` 流。其 HTTP/2 和 QUIC 对话框提供连接和子流选择器，有助于隔离共享同一低层连接的多路复用流。<sup>[[4]](#references)</sup>

### 免费 pcap 实验

**通过以下免费挑战进行练习：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 识别域名

你可以添加一列来显示 HTTP Host header：

![免费 pcap 实验 - 识别域名：你可以添加一列来显示 HTTP Host header](<../../../images/image (639).png>)

还可以添加一列，显示发起 HTTPS 连接的 Server name（**tls.handshake.type == 1**）：

![免费 pcap 实验 - 识别域名：还可以添加一列，显示发起 HTTPS 连接的 Server name（tls.handshake.type == 1）](<../../../images/image (408) (1).png>)

如果捕获内容大多经过加密，将这些字段添加为列可以显著加快 triage：

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4`（Wireshark 4.2+）

这样，即使 payload 本身仍处于加密状态，也可以根据 hostname、ALPN（`http/1.1`、`h2`、`h3` 等）和客户端指纹对会话进行聚类。对于已解密的 HTTP/2 和 HTTP/3 捕获，将 `http2.header.value` 或 `http3.headers.header.value` 添加为列也很有用，这样可以根据路径、权限以及其他有趣的 metadata 进行 Pivot。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## 识别本地主机名

### 从 DHCP 获取

在当前版本的 Wireshark 中，需要搜索 `DHCP`，而不是 `bootp`

![识别本地主机名 - 从 DHCP 获取：在当前版本的 Wireshark 中，需要搜索 DHCP，而不是 bootp](<../../../images/image (1013).png>)

### 从 NBNS 获取

![从 DHCP 获取 - 从 NBNS 获取：在当前版本的 Wireshark 中，需要搜索 DHCP，而不是 bootp](<../../../images/image (1003).png>)

## 解密 TLS

### 使用服务器私钥解密 https 流量

_编辑 > 首选项 > 协议 > tls >_

![解密 TLS - 使用服务器私钥解密 https 流量：使用服务器私钥解密 https 流量](<../../../images/image (1103).png>)

点击 _编辑_，然后添加服务器和私钥的所有信息（_IP、端口、协议、密钥文件和密码_）

此方法仅适用于数量有限的情况。对于当前的 TLS 1.3 / ECDHE 流量，下面的 session key log 方法通常是实际可行的选项。<sup>[[1]](#references)</sup>

### 使用对称 session key 解密 https 流量

Firefox 和 Chrome 都能够记录 TLS session key，这些密钥可与 Wireshark 一起用于解密 TLS 流量。这可以对安全通信进行深入分析。有关如何执行此解密的更多详细信息，请参阅 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) 上的指南。<sup>[[3]](#references)</sup> 这也是解密现代 TLS 1.3 和 QUIC/HTTP/3 capture 的常规方法。<sup>[[2]](#references)</sup>

要检测此情况，请在环境中搜索变量 `SSLKEYLOGFILE`

共享密钥文件如下所示：

![解密 https 流量 - 使用服务器私钥解密 https 流量：使用对称 session key 解密 https 流量：共享密钥文件如下所示](<../../../images/image (820).png>)

如果 capture 是 `pcapng`，请先检查其中是否已经包含嵌入式解密 secrets，再搜索主机文件系统：<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
To import this in wireshark go to \_edit > preferences > protocols > tls > and import it in (Pre)-Master-Secret log filename:

![使用 server private key 解密 https traffic - 使用 symmetric session keys 解密 https traffic: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

从发送 APK 的 ADB communication 中提取 APK：
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
## References

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [在 Wireshark 中解密和解析 HTTP/3 流量](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [使用 Wireshark 解密 TLS 浏览器流量——简单方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [跟踪协议流](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [显示过滤器参考：Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [显示过滤器参考：HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [显示过滤器参考：Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
