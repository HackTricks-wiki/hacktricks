# Wiresharkのトリック

## Wiresharkのトリック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## Wiresharkスキルの向上

### チュートリアル

以下のチュートリアルは、いくつかのクールな基本的なトリックを学ぶために素晴らしいです：

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析情報

**エキスパート情報**

_Analyze_ --> _Expert Information_ をクリックすると、**解析された**パケットの**概要**が表示されます：

![](<../../../.gitbook/assets/image (570).png>)

**解決されたアドレス**

_Statistics_ --> _Resolved Addresses_ の下には、ポート/トランスポートからプロトコルへの変換、MACから製造元への変換など、wiresharkによって「解決された」いくつかの**情報**が表示されます。通信に関与しているものを知ることは興味深いです。

![](<../../../.gitbook/assets/image (571).png>)

**プロトコル階層**

_Statistics_ --> _Protocol Hierarchy_ の下には、通信に関与している**プロトコル**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (572).png>)

**会話**

_Statistics_ --> _Conversations_ の下には、通信の**会話の要約**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (573).png>)

**エンドポイント**

_Statistics_ --> _Endpoints_ の下には、通信の**エンドポイントの要約**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (575).png>)

**DNS情報**

_Statistics_ --> _DNS_ の下には、キャプチャされたDNSリクエストに関する統計情報が表示されます。

![](<../../../.gitbook/assets/image (577).png>)

**I/Oグラフ**

_Statistics_ --> _I/O Graph_ の下には、通信の**グラフ**が表示されます。

![](<../../../.gitbook/assets/image (574).png>)

### フィルター

ここでは、プロトコルに応じたwiresharkフィルターを見つけることができます：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルター：

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTPおよび初期のHTTPSトラフィック
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTPおよび初期のHTTPSトラフィック+ TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTPおよび初期のHTTPSトラフィック+ TCP SYN + DNSリクエスト

### 検索

セッションのパケット内の**コンテンツ**を**検索**する場合は、_CTRL+f_ を押します。右ボタンを押して、メイン情報バー（No.、Time、Sourceなど）に新しいレイヤーを追加することもできます。

練習：[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## ドメインの識別

Host HTTPヘッダーを表示する列を追加できます：

![](<../../../.gitbook/assets/image (403).png>)

また、初期化されたHTTPS接続のServer名を追加する列も追加できます（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)
## ローカルホスト名の特定

### DHCPから

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります。

![](<../../../.gitbook/assets/image (404).png>)

### NBNSから

![](<../../../.gitbook/assets/image (405).png>)

## TLSの復号化

### サーバーの秘密鍵を使用してhttpsトラフィックを復号化する

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

「編集」を押して、サーバーと秘密鍵のすべてのデータ（IP、ポート、プロトコル、キーファイル、パスワード）を追加します。

### 対称セッションキーを使用してhttpsトラフィックを復号化する

FirefoxとChromeの両方が、TLSトラフィックを暗号化するために使用される対称セッションキーをファイルに記録することをサポートしていることがわかりました。その後、Wiresharkをそのファイルに向けることで、復号化されたTLSトラフィックが表示されます。詳細はこちら：[https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します。

共有キーのファイルは次のようになります：

![](<../../../.gitbook/assets/image (99).png>)

これをWiresharkにインポートするには、\_edit > preference > protocol > ssl > に移動し、(Pre)-Master-Secret log filenameにインポートします。

![](<../../../.gitbook/assets/image (100).png>)

## ADB通信

APKが送信されたADB通信からAPKを抽出します。
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有する**には、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
