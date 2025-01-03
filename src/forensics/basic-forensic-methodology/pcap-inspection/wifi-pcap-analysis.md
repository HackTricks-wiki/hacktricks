{{#include ../../../banners/hacktricks-training.md}}

# BSSIDを確認する

WireSharkを使用してWifiの主なトラフィックをキャプチャした場合、_Wireless --> WLAN Traffic_でキャプチャのすべてのSSIDを調査し始めることができます：

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## ブルートフォース

その画面の列の1つは、**pcap内に認証が見つかったかどうか**を示しています。もしそうであれば、`aircrack-ng`を使用してブルートフォースを試みることができます：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例えば、PSK（事前共有キー）を保護するWPAパスフレーズを取得し、後でトラフィックを復号化するために必要です。

# ビーコン内のデータ / サイドチャネル

**Wifiネットワークのビーコン内でデータが漏洩していると疑う場合**、次のようなフィルターを使用してネットワークのビーコンを確認できます: `wlan contains <NAMEofNETWORK>`、または `wlan.ssid == "NAMEofNETWORK"` フィルタリングされたパケット内で疑わしい文字列を検索します。

# Wifiネットワーク内の不明なMACアドレスを見つける

次のリンクは、**Wifiネットワーク内でデータを送信しているマシンを見つけるのに役立ちます**:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

**MACアドレスが既にわかっている場合は、出力からそれらを削除できます**。次のようなチェックを追加します: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**不明なMAC**アドレスを検出したら、次のような**フィルター**を使用できます: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` トラフィックをフィルタリングします。ftp/http/ssh/telnetフィルターは、トラフィックを復号化した場合に便利です。

# トラフィックを復号化する

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
