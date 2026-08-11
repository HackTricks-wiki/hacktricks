# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## Check BSSIDs

在 Wireshark 中打开 Wi-Fi capture 后，选择 _Wireless → WLAN Traffic_，即可汇总 capture 中观测到的 wireless networks；每一行代表一个 wireless network。<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Check BSSIDs：当你收到一个主要流量为 Wifi 的 capture，并使用 WireShark 打开它时，可以通过 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Check BSSIDs：当你收到一个主要流量为 Wifi 的 capture，并使用 WireShark 打开它时，可以通过 Wireless --... 开始调查 capture 中的所有 SSID](<../../../images/image (492).png>)

### Brute Force

对于 WPA/WPA2-PSK captures，`aircrack-ng` 需要一个可用的四次 EAPOL handshake，并使用 dictionary 测试候选 passphrases。使用 `-w` 提供 wordlist，使用 `-b` 指定 access point 的 BSSID：<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
如果候选项匹配，Aircrack-ng 会恢复预共享密钥；随后，当 capture 和 security mode 支持时，可以将匹配的 password 和 SSID 配置到 Wireshark 的 802.11 解密设置中。<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons / Side Channel 中的数据

如果怀疑 **data 正在 beacon-side-channel traffic 中被 leak**，可以从 `wlan contains "NAMEofNETWORK"` 或 `wlan.ssid == "NAMEofNETWORK"` 这样的 display filter 开始，然后检查匹配的 frames 中是否存在可疑字符串。第一种形式是 broad byte search；第二种形式匹配 SSID field。<sup>[[3]](#references)[[4]](#references)</sup>

## 在 Wi-Fi Network 中查找 Unknown MAC Addresses

Wireshark 将 `wlan.ta` 显示为 transmitter address，将 `wlan.addr` 显示为 hardware/MAC address；display filters 可以使用 logical operators 组合这些 fields：<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果已经知道某些 **MAC addresses，请将它们从 output 中移除**，方法是添加类似 `&& !(wlan.addr == 5c:51:88:31:a0:3b)` 的 checks。

检测到 **unknown MAC** addresses 在 network 内进行 communication 后，可以使用类似 `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` 的 filter 来缩小其 traffic 范围。只有当 Wireshark 能够 dissect 对应的 decrypted payload 时，FTP、HTTP、SSH 和 Telnet filters 才有用。<sup>[[3]](#references)[[5]](#references)</sup>

## 解密 Traffic

要在 Wireshark 中添加 802.11 decryption key，请打开 _Edit → Preferences → Protocols → IEEE 802.11_，然后点击 _Decryption Keys_ 旁边的 _Edit_。<sup>[[5]](#references)</sup>

![在 Wi-Fi Network 中查找 Unknown MAC Addresses - 解密 Traffic：检测到 unknown MAC addresses 在 network 内进行 communication 后，可以使用如下 filters：...](<../../../images/image (499).png>)

对于 WPA/WPA2，Wireshark 通常需要 EAPOL four-way handshake 以及匹配的 password/SSID；提供 transient key 可以避免 handshake 要求。WPA3 的 per-connection decryption 需要该 connection 的 PMK。<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide：WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide：构建 Display Filter Expressions](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference：IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide：IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
