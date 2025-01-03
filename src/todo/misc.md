{{#include ../banners/hacktricks-training.md}}

在 ping 响应 TTL：\
127 = Windows\
254 = Cisco\
其他的是某些 Linux

$1$- md5\
$2$或 $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

如果你不知道某个服务背后是什么，尝试发起一个 HTTP GET 请求。

**UDP 扫描**\
nc -nv -u -z -w 1 \<IP> 160-16

一个空的 UDP 数据包被发送到特定端口。如果 UDP 端口是开放的，目标机器不会回复。如果 UDP 端口是关闭的，目标机器应该会发送一个 ICMP 端口不可达的数据包。\

UDP 端口扫描通常不可靠，因为防火墙和路由器可能会丢弃 ICMP\
数据包。这可能导致扫描中的假阳性，你会经常看到\
UDP 端口扫描显示被扫描机器上的所有 UDP 端口都是开放的。\
大多数端口扫描器不会扫描所有可用端口，通常有一个预设的“有趣端口”列表\
进行扫描。

# CTF - 技巧

在 **Windows** 中使用 **Winzip** 搜索文件。\
**备用数据流**：_dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Start with "_begin \<mode> \<filename>_" and weird chars\
**Xxencoding** --> Start with "_begin \<mode> \<filename>_" and B64\
\
**Vigenere** (频率分析) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (字符偏移) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> 使用空格和制表符隐藏消息

# Characters

%E2%80%AE => RTL字符 (反向书写有效载荷)

{{#include ../banners/hacktricks-training.md}}
