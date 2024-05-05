# Wifi Pcap Analysis

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

## BSSIDの確認

WireSharkを使用してWifiの主要なトラフィックを含むキャプチャを受信した場合、キャプチャ内のすべてのSSIDを調査を開始することができます。_Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### ブルートフォース

その画面の列の1つは、**pcap内で認証情報が見つかったかどうか**を示しています。その場合、`aircrack-ng`を使用してブルートフォース攻撃を試みることができます。
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## ビーコン/サイドチャネル内のデータ

**Wifiネットワークのビーコン内でデータが漏洩している**と疑う場合は、次のようなフィルタを使用してネットワークのビーコンをチェックできます: `wlan contains <NAMEofNETWORK>`、または `wlan.ssid == "NAMEofNETWORK"`。フィルタされたパケット内で疑わしい文字列を検索します。

## Wifiネットワーク内の不明なMACアドレスを見つける

次のリンクは、**Wifiネットワーク内でデータを送信している機器を見つける**のに役立ちます:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

すでに**MACアドレスを知っている場合は、それらを出力から削除**するために、次のようなチェックを追加できます: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

ネットワーク内で通信している**不明なMAC**アドレスを検出したら、次のような**フィルタ**を使用できます: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`。ftp/http/ssh/telnetフィルタは、トラフィックを復号化済みの場合に有用です。

## トラフィックの復号化

編集 --> 設定 --> プロトコル --> IEEE 802.11 --> 編集

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
