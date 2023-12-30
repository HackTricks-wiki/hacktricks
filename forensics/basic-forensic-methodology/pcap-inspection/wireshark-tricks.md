# Wiresharkのコツ

## Wiresharkのコツ

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **ハッキングのコツを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出してください。

</details>

## Wiresharkスキルを向上させる

### チュートリアル

以下のチュートリアルは、いくつかの基本的なコツを学ぶのに素晴らしいです:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析された情報

**エキスパート情報**

_**分析** --> **エキスパート情報**_ をクリックすると、分析されたパケットで何が起こっているかの**概要**が表示されます:

![](<../../../.gitbook/assets/image (570).png>)

**解決されたアドレス**

_**統計 --> 解決されたアドレス**_ の下で、Wiresharkによって「**解決された**」いくつかの**情報**を見つけることができます。例えば、ポート/トランスポートからプロトコル、MACから製造元などです。通信に何が関与しているかを知るのは興味深いです。

![](<../../../.gitbook/assets/image (571).png>)

**プロトコル階層**

_**統計 --> プロトコル階層**_ の下で、通信に**関与している** **プロトコル**とそれに関するデータを見つけることができます。

![](<../../../.gitbook/assets/image (572).png>)

**会話**

_**統計 --> 会話**_ の下で、通信の**会話の要約**とそれに関するデータを見つけることができます。

![](<../../../.gitbook/assets/image (573).png>)

**エンドポイント**

_**統計 --> エンドポイント**_ の下で、通信の**エンドポイントの要約**とそれぞれに関するデータを見つけることができます。

![](<../../../.gitbook/assets/image (575).png>)

**DNS情報**

_**統計 --> DNS**_ の下で、キャプチャされたDNSリクエストに関する統計を見つけることができます。

![](<../../../.gitbook/assets/image (577).png>)

**I/Oグラフ**

_**統計 --> I/Oグラフ**_ の下で、通信の**グラフ**を見つけることができます。

![](<../../../.gitbook/assets/image (574).png>)

### フィルタ

ここでは、プロトコルに応じたWiresharkフィルタを見つけることができます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルタ:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* HTTPと初期HTTPSトラフィック
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* HTTPと初期HTTPSトラフィック + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* HTTPと初期HTTPSトラフィック + TCP SYN + DNSリクエスト

### 検索

セッションの**パケット**内の**コンテンツ**を**検索**したい場合は、_CTRL+f_ を押します。メイン情報バー（No.、Time、Sourceなど）に新しいレイヤーを追加するには、右クリックしてから列の編集を行います。

実践: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## ドメインの特定

HTTPヘッダーのホストを表示する列を追加できます:

![](<../../../.gitbook/assets/image (403).png>)

そして、HTTPS接続を開始するサーバー名を追加する列（**ssl.handshake.type == 1**）:

![](<../../../.gitbook/assets/image (408) (1).png>)

## ローカルホスト名の特定

### DHCPから

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります

![](<../../../.gitbook/assets/image (404).png>)

### NBNSから

![](<../../../.gitbook/assets/image (405).png>)

## TLSの復号化

### サーバーの秘密鍵を使ったhttpsトラフィックの復号化

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

_Edit_ を押して、サーバーと秘密鍵のすべてのデータを追加します（_IP、Port、Protocol、Key file、password_）

### 対称セッションキーを使ったhttpsトラフィックの復号化

FirefoxとChromeは両方とも、TLSトラフィックを暗号化するために使用される対称セッションキーをファイルに記録する機能をサポートしています。そのファイルをWiresharkに指定すると、あら不思議！復号化されたTLSトラフィックが表示されます。詳細はこちら: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します

共有キーのファイルは次のようになります:

![](<../../../.gitbook/assets/image (99).png>)

これをWiresharkにインポートするには、_edit > preference > protocol > ssl >_ に行き、(Pre)-Master-Secret log filenameにインポートします:

![](<../../../.gitbook/assets/image (100).png>)

## ADB通信

ADB通信からAPKを抽出する場合、APKが送信されたところです:
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

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>
