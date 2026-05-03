# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Improve your Wireshark skills

### Tutorials

The following tutorials are amazing to learn some cool basic tricks:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

点击 _**Analyze** --> **Expert Information**_，你将获得对 **analyzed** 的数据包中正在发生什么的 **overview**：

![](<../../../images/image (256).png>)

**Resolved Addresses**

在 _**Statistics --> Resolved Addresses**_ 下，你可以找到一些由 wireshark “**resolved**” 的 **information**，比如 port/transport 到 protocol、MAC 到 manufacturer 等。了解通信中涉及了什么很有意思。

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

在 _**Statistics --> Protocol Hierarchy**_ 下，你可以找到通信中涉及的 **protocols** 以及它们的数据。

![](<../../../images/image (586).png>)

**Conversations**

在 _**Statistics --> Conversations**_ 下，你可以找到通信中 **conversations** 的 **summary** 以及它们的数据。

![](<../../../images/image (453).png>)

**Endpoints**

在 _**Statistics --> Endpoints**_ 下，你可以找到通信中 **endpoints** 的 **summary** 以及每个端点的数据。

![](<../../../images/image (896).png>)

**DNS info**

在 _**Statistics --> DNS**_ 下，你可以找到捕获到的 DNS request 的统计信息。

![](<../../../images/image (1063).png>)

**I/O Graph**

在 _**Statistics --> I/O Graph**_ 下，你可以找到通信的 **graph**。

![](<../../../images/image (992).png>)

### Filters

这里你可以找到按 protocol 划分的 wireshark filter: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
在当前 Wireshark 中使用 `tls.*` 代替旧的 `ssl.*` filter 名称。\
其他有趣的 filters：

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 和初始 HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- 即使无法解密 payload，也可以根据 ClientHello 中发送的 SNI 进行 pivot
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- 快速区分经典 HTTPS、HTTP/2 和 HTTP/3 capable sessions
- `quic or http3`
- 找出如果你只查看 TCP conversations 就会漏掉的现代 UDP/443 traffic

### Search

如果你想在 sessions 的 packets 中 **search** **content**，按 _CTRL+f_。你可以通过按右键然后 edit column，向主信息栏（No., Time, Source, etc.）添加新 layer。

### Following multiplexed streams

较新的 Wireshark 版本可以直接跟踪 `TLS`、`HTTP/2` 和 `QUIC` streams。在嘈杂的 capture 中，这通常比只使用 `Follow TCP Stream` 更快，尤其是在多个 request 共享同一连接时。

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

你可以添加一个显示 HTTP Host header 的 column：

![](<../../../images/image (639).png>)

以及一个添加来自初始 HTTPS connection 的 Server name 的 column（**tls.handshake.type == 1**）：

![](<../../../images/image (408) (1).png>)

如果 capture 主要是 encrypted，把这些字段作为 columns 添加会大幅加快 triage：

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

这可以让你按 hostname、ALPN（`http/1.1`、`h2`、`h3` 等）和 client fingerprint 对 sessions 进行聚类，即使 payload 本身仍然是 encrypted。对于已解密的 HTTP/2 和 HTTP/3 captures，添加 `http2.header.value` 或 `http3.headers.header.value` 作为 columns 也很有用，并按 paths、authorities 和其他有趣的 metadata 进行 pivot。
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Identifying local hostnames

### From DHCP

在当前 Wireshark 中，不是搜索 `bootp`，而是需要搜索 `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

按下 _Edit_ 并添加服务器和私钥的所有数据（_IP, Port, Protocol, Key file and password_）

这种方法只在少数情况下有效。对于当前的 TLS 1.3 / ECDHE 流量，下面的 session key log 方法通常才是实用选项。

### Decrypting https traffic with symmetric session keys

Firefox 和 Chrome 都具备记录 TLS session keys 的能力，这些 key 可与 Wireshark 一起用于解密 TLS 流量。这使得对安全通信进行深入分析成为可能。关于如何执行此解密的更多细节，可以在 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) 的指南中找到。这也是解密现代 TLS 1.3 和 QUIC/HTTP/3 captures 的常规方式。

要检测这一点，请在环境中搜索变量 `SSLKEYLOGFILE`

共享 keys 文件看起来会像这样：

![](<../../../images/image (820).png>)

如果 capture 是 `pcapng`，在去主机文件系统排查之前，先检查它是否已经包含嵌入的 decryption secrets：
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
要在 wireshark 中导入它，请转到 \_edit > preferences > protocols > tls > 然后将其导入到 (Pre)-Master-Secret log filename 中：

![](<../../../images/image (989).png>)

## ADB communication

从 APK 已被发送的 ADB communication 中提取一个 APK：
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
## 参考资料

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
