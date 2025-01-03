# Wifi Pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

## 检查 BSSID

当你收到一个主要流量为 Wifi 的捕获文件时，可以使用 WireShark 开始调查捕获中的所有 SSID，路径为 _Wireless --> WLAN Traffic_：

![](<../../../images/image (106).png>)

![](<../../../images/image (492).png>)

### 暴力破解

该屏幕的其中一列指示是否在 pcap 中**发现了任何认证**。如果是这种情况，你可以尝试使用 `aircrack-ng` 进行暴力破解：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例如，它将检索保护 PSK（预共享密钥）的 WPA 密码，这将在稍后解密流量时需要。

## 信标中的数据 / 侧信道

如果您怀疑 **数据在 Wifi 网络的信标中泄露**，可以使用以下过滤器检查网络的信标：`wlan contains <NAMEofNETWORK>`，或 `wlan.ssid == "NAMEofNETWORK"` 在过滤后的数据包中搜索可疑字符串。

## 在 Wifi 网络中查找未知 MAC 地址

以下链接将有助于查找 **在 Wifi 网络中发送数据的机器**：

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果您已经知道 **MAC 地址，可以通过添加检查将其从输出中移除**，例如：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

一旦您检测到 **在网络中通信的未知 MAC** 地址，可以使用 **过滤器**，例如：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` 来过滤其流量。请注意，ftp/http/ssh/telnet 过滤器在您解密流量时非常有用。

## 解密流量

编辑 --> 首选项 --> 协议 --> IEEE 802.11 --> 编辑

![](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
