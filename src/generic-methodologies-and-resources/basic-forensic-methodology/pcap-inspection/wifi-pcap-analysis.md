# Wifi Pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

## 检查 BSSID

在 Wireshark 中打开 Wi-Fi capture 后，选择 _Wireless → WLAN Traffic_，即可汇总 capture 中观察到的无线网络；每一行代表一个无线网络。<sup>[[1]](#references)</sup>

![Wifi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 Wi-Fi 的 capture 时，可以使用 WireShark 从 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (106).png>)

![Wifi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 Wi-Fi 的 capture 时，可以使用 WireShark 从 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (492).png>)

### Brute Force

对于 WPA/WPA2-PSK capture，`aircrack-ng` 需要可用的四次握手 EAPOL handshake，并使用字典测试候选密码。使用 `-w` 指定字典文件，使用 `-b` 指定目标 access point 的 BSSID：<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

如果候选项匹配，Aircrack-ng 会恢复预共享密钥；当捕获文件和安全模式支持时，可以在 Wireshark 的 802.11 解密设置中配置匹配的密码和 SSID。<sup>[[2]](#references)[[5]](#references)</sup>

## Beacon 中的数据 / 侧信道

如果你怀疑 **数据正通过 beacon 侧信道流量泄露**，可以先使用 `wlan contains "NAMEofNETWORK"` 或 `wlan.ssid == "NAMEofNETWORK"` 这类显示过滤器，然后检查匹配的帧，寻找可疑字符串。第一种形式会广泛搜索字节；第二种会匹配 SSID 字段。<sup>[[3]](#references)[[4]](#references)</sup>

## 在 Wi-Fi 网络中查找未知 MAC 地址

Wireshark 将 `wlan.ta` 作为发送方地址，将 `wlan.addr` 作为硬件/MAC 地址；显示过滤器可以通过逻辑运算符组合这些字段：<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果你已知 **MAC 地址，可以通过添加 `&& !(wlan.addr == 5c:51:88:31:a0:3b)` 这类检查将它们从输出中排除**。

检测到网络内部通信的 **未知 MAC** 地址后，可以使用 `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` 这类过滤器来缩小流量范围。只有当 Wireshark 能够解析相应的解密后载荷时，FTP、HTTP、SSH 和 Telnet 过滤器才有用。<sup>[[3]](#references)[[5]](#references)</sup>

## 解密流量

要在 Wireshark 中添加 802.11 解密密钥，请打开 _编辑 → 首选项 → 协议 → IEEE 802.11_，然后点击 _解密密钥_ 旁边的 _编辑_。<sup>[[5]](#references)</sup>

![在 Wi-Fi 网络中查找未知 MAC 地址 - 解密流量：检测到网络内部通信的未知 MAC 地址后，可以使用如下过滤器：...](<../../../images/image (499).png>)

对于 WPA/WPA2，Wireshark 通常需要 EAPOL 四次握手以及匹配的密码/SSID；提供瞬态密钥可以省去握手要求。WPA3 的逐连接解密需要该连接的 PMK。<sup>[[5]](#references)</sup>

恢复 Wi-Fi 流量后，如需解密应用层 TLS，请参阅 [Wireshark 技巧](wireshark-tricks.md#decrypting-tls)。

## References

- [1] [Wireshark 用户指南：WLAN 流量](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark 用户指南：构建显示过滤器表达式](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark 显示过滤器参考：IEEE 802.11 无线 LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark 用户指南：IEEE 802.11 WLAN 解密密钥](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
