# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## Check BSSIDs

WireSharkを使用してWifiの主要なトラフィックを含むキャプチャを受信した場合、_Wireless --> WLAN Traffic_を使用してキャプチャのすべてのSSIDを調査し始めることができます：

![](<../../../images/image (106).png>)

![](<../../../images/image (492).png>)

### Brute Force

その画面の列の1つは、**pcap内に認証が見つかったかどうか**を示しています。もしそうであれば、`aircrack-ng`を使用してブルートフォースを試みることができます：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例えば、PSK（事前共有キー）を保護するWPAパスフレーズを取得し、後でトラフィックを復号化するために必要です。

## ビーコン / サイドチャネルのデータ

**Wifiネットワークのビーコン内でデータが漏洩していると疑う場合**、次のようなフィルターを使用してネットワークのビーコンを確認できます: `wlan contains <NAMEofNETWORK>`、または `wlan.ssid == "NAMEofNETWORK"` でフィルタリングされたパケット内で疑わしい文字列を検索します。

## Wifiネットワーク内の未知のMACアドレスを見つける

次のリンクは、**Wifiネットワーク内でデータを送信しているマシンを見つける**のに役立ちます:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

**MACアドレスをすでに知っている場合は、出力からそれらを削除できます**。次のようなチェックを追加します: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**未知のMAC**アドレスを検出したら、次のような**フィルター**を使用できます: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` でそのトラフィックをフィルタリングします。ftp/http/ssh/telnetフィルターは、トラフィックを復号化している場合に便利です。

## トラフィックの復号化

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
