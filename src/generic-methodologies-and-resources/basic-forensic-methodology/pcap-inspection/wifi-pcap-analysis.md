# Wifi Pcap 分析

## 检查 BSSID

在 Wireshark 中打开 Wi-Fi capture 后，选择 _Wireless → WLAN Traffic_，即可汇总 capture 中观察到的 wireless networks；每一行代表一个 wireless network。<sup>[[1]](#references)</sup>

![Wifi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 Wifi 的 capture，并使用 WireShark 时，可以通过 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (106).png>)

![Wifi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 Wifi 的 capture，并使用 WireShark 时，可以通过 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (492).png>)

### 暴力破解

对于 WPA/WPA2-PSK capture，`aircrack-ng` 需要一个可用的四次 EAPOL handshake，并使用 dictionary 测试候选 passphrase。使用 `-w` 提供 wordlist，使用 `-b` 指定目标 access point 的 BSSID：<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
如果候选项匹配，Aircrack-ng 会恢复预共享密钥；随后，在捕获文件和安全模式支持的情况下，可以将匹配的密码和 SSID 配置到 Wireshark 的 802.11 解密设置中。<sup>[[2]](#references)[[5]](#references)</sup>

## Beacon 中的数据 / Side Channel

如果你怀疑 **数据正在 beacon-side-channel 流量中泄漏**，可以从类似 `wlan contains "NAMEofNETWORK"` 或 `wlan.ssid == "NAMEofNETWORK"` 的显示过滤器开始，然后检查匹配帧中是否存在可疑字符串。第一种形式是广泛的字节搜索；第二种形式匹配 SSID 字段。<sup>[[3]](#references)[[4]](#references)</sup>

## 在 Wi-Fi 网络中查找未知 MAC 地址

Wireshark 将 `wlan.ta` 暴露为发送方地址，将 `wlan.addr` 暴露为硬件/MAC 地址；显示过滤器可以使用逻辑运算符组合这些字段：<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果你已经知道某些 **MAC 地址**，可以通过添加类似 `&& !(wlan.addr == 5c:51:88:31:a0:3b)` 的检查，将它们从输出中移除。

检测到网络内部正在通信的 **未知 MAC** 地址后，可以使用类似 `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` 的过滤器来缩小其流量范围。只有当 Wireshark 能够解析相应的已解密 payload 时，FTP、HTTP、SSH 和 Telnet 过滤器才有用。<sup>[[3]](#references)[[5]](#references)</sup>

## 解密流量

要在 Wireshark 中添加 802.11 解密密钥，请打开 _Edit → Preferences → Protocols → IEEE 802.11_，然后点击 _Decryption Keys_ 旁边的 _Edit_。<sup>[[5]](#references)</sup>

![在 Wi-Fi 网络中查找未知 MAC 地址 - 解密流量：检测到网络内部正在通信的未知 MAC 地址后，可以使用类似以下内容的过滤器：...](<../../../images/image (499).png>)

对于 WPA/WPA2，Wireshark 通常需要 EAPOL 四次握手以及匹配的密码/SSID；提供 transient key 可以避免握手要求。WPA3 的逐连接解密需要该连接的 PMK。<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide：WLAN 流量](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide：构建显示过滤器表达式](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference：IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide：IEEE 802.11 WLAN 解密密钥](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
