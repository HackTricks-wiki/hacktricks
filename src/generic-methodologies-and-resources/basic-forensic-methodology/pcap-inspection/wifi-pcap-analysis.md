# Wi-Fi Pcap解析

{{#include ../../../banners/hacktricks-training.md}}

## BSSIDの確認

Wi-FiキャプチャをWiresharkで開き、_Wireless → WLAN Traffic_ を選択すると、キャプチャ内で確認されたワイヤレスネットワークの概要が表示されます。各行は1つのワイヤレスネットワークを表します。<sup>[[1]](#references)</sup>

![Wi-Fi Pcap解析 - BSSIDの確認: 主なトラフィックがWi-FiのキャプチャをWireSharkで受け取った場合、Wireless --...を使ってキャプチャ内のすべてのSSIDの調査を開始できます](<../../../images/image (106).png>)

![Wi-Fi Pcap解析 - BSSIDの確認: 主なトラフィックがWi-FiのキャプチャをWireSharkで受け取った場合、Wireless --...を使ってキャプチャ内のすべてのSSIDの調査を開始できます](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSKのキャプチャでは、`aircrack-ng`を使うために、使用可能な4-way EAPOL handshakeが必要です。`aircrack-ng`は辞書を使って候補のパスフレーズを試します。`-w`でwordlistを指定し、`-b`で対象のアクセスポイントのBSSIDを指定します。<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

候補が一致すると、Aircrack-ng は事前共有キーを復元します。一致したパスワードと SSID は、キャプチャとセキュリティモードが対応していれば、Wireshark の 802.11 復号設定に指定できます。<sup>[[2]](#references)[[5]](#references)</sup>

## Beacon / Side Channel のデータ

**Beacon の Side Channel トラフィックでデータが漏えいしている**疑いがある場合は、`wlan contains "NAMEofNETWORK"` や `wlan.ssid == "NAMEofNETWORK"` などの表示フィルターを使い、一致したフレームに不審な文字列がないか調べます。前者は幅広いバイト検索、後者は SSID フィールドとの一致を検索します。<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi ネットワーク内の未知の MAC アドレスを見つける

Wireshark では、`wlan.ta` は送信元アドレス、`wlan.addr` はハードウェア/MAC アドレスとして扱われます。表示フィルターでは、論理演算子を使ってこれらのフィールドを組み合わせられます。<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

既知の**MAC アドレスがある場合は、** `&& !(wlan.addr == 5c:51:88:31:a0:3b)` のような条件を追加して、出力から除外します。

ネットワーク内で通信している**未知の MAC** アドレスを検出したら、`wlan.addr == <MAC address> && (ftp || http || ssh || telnet)` のようなフィルターを使って、そのトラフィックを絞り込みます。FTP、HTTP、SSH、Telnet のフィルターが有効なのは、Wireshark が復号された対応ペイロードを解析できる場合に限られます。<sup>[[3]](#references)[[5]](#references)</sup>

## トラフィックを復号する

Wireshark に 802.11 復号キーを追加するには、_Edit → Preferences → Protocols → IEEE 802.11_ を開き、_Decryption Keys_ の横にある _Edit_ をクリックします。<sup>[[5]](#references)</sup>

![Wi-Fi ネットワーク内の未知の MAC アドレスを見つける - トラフィックを復号する: ネットワーク内で通信している未知の MAC アドレスを検出したら、次のようなフィルターを使用できます:...](<../../../images/image (499).png>)

WPA/WPA2 の場合、Wireshark で通常必要なのは EAPOL の4ウェイハンドシェイクと、一致するパスワード/SSID です。一時キーを指定すれば、ハンドシェイクは不要になります。WPA3 で接続ごとに復号するには、その接続の PMK が必要です。<sup>[[5]](#references)</sup>

Wi-Fi トラフィックの復元後にアプリケーション層の TLS を復号する方法については、[Wireshark tricks](wireshark-tricks.md#decrypting-tls) を参照してください。

## References

- [1] [Wireshark ユーザーガイド: WLAN トラフィック](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark ユーザーガイド: 表示フィルター式の作成](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark 表示フィルターリファレンス: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark ユーザーガイド: IEEE 802.11 WLAN 復号キー](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
