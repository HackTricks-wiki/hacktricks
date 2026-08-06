# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDの確認

WireSharkを使用して、主なトラフィックがWifiであるcaptureを受け取った場合、_Wireless --> WLAN Traffic_ からcapture内のすべてのSSIDの調査を開始できます：

![Wifi Pcap Analysis - BSSIDの確認：WireSharkを使用して、主なトラフィックがWifiであるcaptureを受け取った場合、Wireless --... からcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSIDの確認：WireSharkを使用して、主なトラフィックがWifiであるcaptureを受け取った場合、Wireless --... からcapture内のすべてのSSIDの調査を開始できます](<../../../images/image (492).png>)

### Brute Force

この画面の列の1つには、**pcap内で認証が見つかったかどうか**が表示されます。見つかった場合は、`aircrack-ng`を使用してBrute forceを試行できます：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例えば、PSK（pre shared-key）を保護している WPA passphrase を取得できます。これは、後でトラフィックを復号するために必要です。

## Beacons / Side Channel 内のデータ

**Wifi network の beacons 内でデータが leak している**疑いがある場合は、次のような filter を使用して network の beacons を確認できます：`wlan contains <NAMEofNETWORK>` または `wlan.ssid == "NAMEofNETWORK"`。filter された packets 内で suspicious な文字列を検索します。

## A Wifi Network 内の Unknown MAC Addresses を見つける

次の link は、**Wifi Network 内でデータを送信している machines**を見つけるのに役立ちます。

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

既知の **MAC addresses を output から除外**したい場合は、次のような check を追加します：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

network 内で通信している **unknown MAC** addresses を検出したら、次のような **filters** を使用できます：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`。ftp/http/ssh/telnet filters は、トラフィックを decrypt 済みの場合に便利です。

## トラフィックを Decrypt する

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![A Wifi Network 内の Unknown MAC Addresses を見つける - トラフィックを Decrypt する：network 内で通信している unknown MAC addresses を検出したら、次のような filters を使用できます：...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
