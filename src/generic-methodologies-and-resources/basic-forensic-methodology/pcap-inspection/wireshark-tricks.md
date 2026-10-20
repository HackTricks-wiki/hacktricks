# Wireshark 技巧

{{#include ../../../banners/hacktricks-training.md}}

## 提升 Wireshark 技能

### 教程

以下教程非常适合学习一些实用的基础技巧：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析信息

**专家信息**

点击 _**Analyze** --> **Expert Information**_，即可**概览**已**分析**的数据包中发生的情况：

![教程 - 分析信息：点击 Analyze -- Expert Information，即可概览已分析的数据包中发生的情况](<../../../images/image (256).png>)

**已解析地址**

在 _**Statistics --> Resolved Addresses**_ 中，可以查看 Wireshark "**解析**"出的各类**信息**，例如端口/传输层到协议、MAC 地址到制造商等。了解通信中涉及的内容很有帮助。

![教程 - 分析信息：在 Statistics -- Resolved Addresses 中，可以查看 Wireshark "解析"出的各类信息，例如端口/传输层到协议、MAC 地址到制造商等……](<../../../images/image (893).png>)

**协议层次结构**

在 _**Statistics --> Protocol Hierarchy**_ 中，可以查看通信中涉及的**协议**及相关数据。

![教程 - 分析信息：在 Statistics -- Protocol Hierarchy 中，可以查看通信中涉及的协议及相关数据](<../../../images/image (586).png>)

**会话**

在 _**Statistics --> Conversations**_ 中，可以查看通信中**会话的摘要**及相关数据。

![教程 - 分析信息：在 Statistics -- Conversations 中，可以查看通信中会话的摘要及相关数据](<../../../images/image (453).png>)

**端点**

在 _**Statistics --> Endpoints**_ 中，可以查看通信中**端点的摘要**及每个端点的相关数据。

![教程 - 分析信息：在 Statistics -- Endpoints 中，可以查看通信中端点的摘要及每个端点的相关数据](<../../../images/image (896).png>)

**DNS 信息**

在 _**Statistics --> DNS**_ 中，可以查看捕获到的 DNS 请求统计信息。

![教程 - 分析信息：在 Statistics -- DNS 中，可以查看捕获到的 DNS 请求统计信息](<../../../images/image (1063).png>)

**I/O 图表**

在 _**Statistics --> I/O Graph**_ 中，可以查看通信的**图表**。

![教程 - 分析信息：在 Statistics -- I/O Graph 中，可以查看通信的图表](<../../../images/image (992).png>)

### 过滤器

可以在此处按协议查找 Wireshark 过滤器：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
在当前版本的 Wireshark 中，请使用 `tls.*`，而不要使用旧的 `ssl.*` 过滤器名称。<sup>[[1]](#references)</sup>\
其他实用过滤器：

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP 和初始 HTTPS 流量
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP 和初始 HTTPS 流量 + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP 和初始 HTTPS 流量 + TCP SYN + DNS 请求
- `tls.handshake.extensions_server_name contains "example.com"`
  - 根据 ClientHello 中发送的 SNI 进行筛选，即使无法解密负载也适用
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - 快速区分传统 HTTPS、HTTP/2 和支持 HTTP/3 的会话
- `quic or http3`
  - 查找现代 UDP/443 流量，避免只检查 TCP 会话时遗漏这些流量

### 搜索

若要在会话的**数据包**中**搜索****内容**，请按 _CTRL+f_。按鼠标右键，然后选择编辑列，即可向主信息栏（No.、Time、Source 等）添加新列。

### 跟踪多路复用流

Wireshark 可以直接跟踪 `TLS`、`HTTP/2` 和 `QUIC` 流。其 HTTP/2 和 QUIC 对话框提供连接和子流选择器，可帮助隔离共享同一低层连接的多路复用流。<sup>[[4]](#references)</sup>

有会话密钥时，先确定请求的流 ID，然后跟踪该子流，而不是整个 TCP 或 UDP 会话。示例 `0,1` 表示选择 TCP 流 0 上的 HTTP/2 流 ID 1；对于 QUIC，则使用 `follow,quic,utf-8,<connection-number>,<stream-id>`。仅按五元组跟踪可能会混入互相独立的请求，或在 QUIC 连接迁移后遗漏该连接。<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### 免费 pcap 实验

**通过以下免费挑战进行练习：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 识别域名

你可以添加一列来显示 HTTP Host header：

![免费 pcap 实验 - 识别域名：你可以添加一列来显示 HTTP Host header](<../../../images/image (639).png>)

还可以添加一列，显示发起 HTTPS 连接时的 Server name（**tls.handshake.type == 1**）：

![免费 pcap 实验 - 识别域名：还可以添加一列，显示发起 HTTPS 连接时的 Server name（ tls.handshake.type == 1 ）](<../../../images/image (408) (1).png>)

如果捕获内容大多已加密，将这些字段添加为列可以大幅加快 triage：

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4`（Wireshark 4.2+）

即使载荷本身仍处于加密状态，这些字段也能让你按主机名、ALPN（`http/1.1`、`h2`、`h3` 等）和客户端指纹对会话进行分组。对于已解密的 HTTP/2 和 HTTP/3 捕获数据，将 `http2.header.value` 或 `http3.headers.header.value` 添加为列，并根据路径、authority 和其他有趣的元数据进行筛选，也很有用。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH：不要把外层 SNI 误认为源站

Encrypted ClientHello (ECH) 可以在可见的外层 SNI 中放置一个公开的伪装名称，同时加密内层名称。因此，仅根据 SNI 建立的域名清单可能会将 ECH 流量归因于错误的源站。仅凭 ECH 扩展并不能证明 ECH 已成功：客户端可能会发送 GREASE ECH 扩展。在 Wireshark 4.2+ 中，使用以下过滤器查找外层 ECH 提议，并将报告的 SNI 视为伪装名称候选，而非请求访问的网站。<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

如果你有匹配的客户端会话密钥，请检查解密后的 HTTP authority/Host，而不是根据外层 SNI 推断源站。没有密钥时，请检查其他捕获到的源站证据，例如明文 DNS，但不要将外层 SNI 等同于隐藏名称。<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## 识别本地主机名

### 从 DHCP 获取

在当前版本的 Wireshark 中，不要搜索 `bootp`，而应搜索 `DHCP`

![识别本地主机名 - 从 DHCP 获取：在当前版本的 Wireshark 中，不要搜索 bootp，而应搜索 DHCP](<../../../images/image (1013).png>)

### 从 NBNS 获取

![从 DHCP 获取 - 从 NBNS 获取：在当前版本的 Wireshark 中，不要搜索 bootp，而应搜索 DHCP](<../../../images/image (1003).png>)

## 解密 TLS

Wi-Fi 链路层解密与 TLS 会话解密是分开的；有关密钥和握手的前提条件，请参见 [Wi-Fi PCAP 分析](wifi-pcap-analysis.md)。

### 使用服务器私钥解密 https 流量

_edit > preferences > protocols > tls >_

![解密 TLS - 使用服务器私钥解密 https 流量：使用服务器私钥解密 https 流量](<../../../images/image (1103).png>)

点击 _Edit_，添加服务器和私钥的所有数据（_IP、Port、Protocol、Key file 和 password_）

此方法仅适用于有限的情况。对于当前的 TLS 1.3 / ECDHE 流量，通常实际可行的方法是下面介绍的会话密钥日志方法。<sup>[[1]](#references)</sup>

### 使用对称会话密钥解密 https 流量

Firefox 和 Chrome 都支持记录 TLS 会话密钥，这些密钥可用于通过 Wireshark 解密 TLS 流量。这使得对安全通信进行深入分析成为可能。有关如何执行此解密的详细信息，请参阅 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) 的指南。<sup>[[3]](#references)</sup> 这也是解密现代 TLS 1.3 和 QUIC/HTTP/3 捕获流量的常用方法。<sup>[[2]](#references)</sup>

要检测这种情况，请在环境中搜索变量 `SSLKEYLOGFILE`

共享密钥文件如下所示：

![使用服务器私钥解密 https 流量 - 使用对称会话密钥解密 https 流量：共享密钥文件如下所示](<../../../images/image (820).png>)

如果捕获文件是 `pcapng`，请先检查其中是否已包含嵌入的解密密钥，再搜索主机文件系统：<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

要将其导入 Wireshark，请转到 \_edit > preferences > protocols > tls >，然后将其导入 (Pre)-Master-Secret log filename：

![使用服务器私钥解密 https 流量 - 使用对称会话密钥解密 https 流量：editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB 通信

从发送了 APK 的 ADB 通信中提取 APK：

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

- [1] [Wireshark TLS 维基](https://wiki.wireshark.org/TLS)
- [2] [在 Wireshark 中解密并解析 HTTP/3 流量](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [使用 Wireshark 解密 TLS 浏览器流量——简单方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [跟踪协议流](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [显示过滤器参考：传输层安全协议](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [显示过滤器参考：超文本传输协议 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [显示过滤器参考：超文本传输协议第 3 版](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849：TLS 加密客户端问候](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark 手册](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
