<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# BSSIDsをチェックする

WireSharkを使用してWifiの主要なトラフィックが含まれるキャプチャを受け取った場合、_Wireless --> WLAN Traffic_ でキャプチャのすべてのSSIDを調査することから始めることができます：

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## ブルートフォース

その画面の列の一つは、**pcap内に認証が見つかったかどうか**を示しています。その場合、`aircrack-ng`を使用してブルートフォースを試みることができます：
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
例えば、後でトラフィックを復号するために必要となる、PSK（プリシェアードキー）を保護するWPAパスフレーズを取得します。

# ビーコン/サイドチャネルのデータ

もし**Wifiネットワークのビーコン内でデータが漏洩している**と疑われる場合、以下のようなフィルタを使用してネットワークのビーコンをチェックできます：`wlan contains <NAMEofNETWORK>`、または `wlan.ssid == "NAMEofNETWORK"`。フィルタリングされたパケット内で怪しい文字列を探します。

# Wifiネットワーク内の未知のMACアドレスを見つける

以下のリンクは、**Wifiネットワーク内でデータを送信しているマシン**を見つけるのに役立ちます：

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

もし既知の**MACアドレス**を知っている場合、以下のようなチェックを追加することで出力からそれらを除外できます：`&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**未知のMAC**アドレスを検出したら、以下のような**フィルタ**を使用してそのトラフィックをフィルタリングできます：`wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`。ftp/http/ssh/telnetのフィルタは、トラフィックを復号した場合に有用です。

# トラフィックを復号する

編集 --> 環境設定 --> プロトコル --> IEEE 802.11--> 編集

![](<../../../.gitbook/assets/image (426).png>)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>
