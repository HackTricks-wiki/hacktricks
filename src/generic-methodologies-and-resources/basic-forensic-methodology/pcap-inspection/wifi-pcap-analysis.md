# WiFi Pcap 分析

{{#include ../../../banners/hacktricks-training.md}}

## 检查 BSSID

当你收到一个主要流量为 WiFi 的 capture，并使用 WireShark 时，可以通过 _Wireless --> WLAN Traffic_ 开始调查 capture 中的所有 SSID：

![WiFi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 WiFi 的 capture，并使用 WireShark 时，可以通过 Wireless --...](<../../../images/image (106).png>)

![WiFi Pcap 分析 - 检查 BSSID：当你收到一个主要流量为 WiFi 的 capture，并使用 WireShark 时，可以通过 Wireless --...](<../../../images/image (492).png>)

### Brute Force

该界面的其中一列会显示 **pcap 中是否发现了任何 authentication**。如果是这样，你可以尝试使用 `aircrack-ng` 对其进行 Brute force：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例如，它会获取保护 PSK（pre shared-key）的 WPA passphrase，之后解密流量时会需要该 passphrase。

## Beacons / Side Channel 中的数据

如果你怀疑 **数据正在被泄露到某个 Wifi 网络的 beacons 中**，可以使用类似以下的 filter 检查该网络的 beacons：`wlan contains <NAMEofNETWORK>`，或 `wlan.ssid == "NAMEofNETWORK"`，然后在过滤后的数据包中搜索可疑字符串。

## 在 Wifi 网络中查找未知 MAC 地址

以下链接有助于查找**在 Wifi 网络中发送数据的机器**：

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

如果你已经知道某些 **MAC addresses**，可以添加类似以下的检查，将它们从输出中移除：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

检测到在网络中通信的**未知 MAC**地址后，可以使用类似以下的 **filters** 过滤其流量：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`。请注意，如果已经解密流量，ftp/http/ssh/telnet filters 才有用。

## Decrypt Traffic

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![在 Wifi 网络中查找未知 MAC 地址 - Decrypt Traffic：检测到在网络中通信的未知 MAC 地址后，可以使用类似以下的 filters：...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
