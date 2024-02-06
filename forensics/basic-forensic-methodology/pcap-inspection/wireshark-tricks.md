# Wiresharkのトリック

## Wiresharkのトリック

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **会社をHackTricksで宣伝したい**または**HackTricksをPDFでダウンロードしたい場合は**[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**する
- **ハッキングトリックを共有するには**、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## Wiresharkスキルの向上

### チュートリアル

次のチュートリアルは、いくつかのクールな基本的なトリックを学ぶのに素晴らしいです：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析情報

**専門家情報**

_Analyze_ --> _Expert Information_をクリックすると、**分析された**パケットで何が起こっているかの**概要**が表示されます：

![](<../../../.gitbook/assets/image (570).png>)

**解決されたアドレス**

_Statistics_ --> _Resolved Addresses_の下には、wiresharkによって**解決された**ポート/トランスポートからプロトコル、MACから製造元など、いくつかの**情報**が表示されます。通信に関わるものを知ることは興味深いです。

![](<../../../.gitbook/assets/image (571).png>)

**プロトコル階層**

_Statistics_ --> _Protocol Hierarchy_の下には、通信に関与する**プロトコル**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (572).png>)

**会話**

_Statistics_ --> _Conversations_の下には、通信中の**会話の要約**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (573).png>)

**エンドポイント**

_Statistics_ --> _Endpoints_の下には、通信中の**エンドポイントの要約**とそれぞれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (575).png>)

**DNS情報**

_Statistics_ --> _DNS_の下には、キャプチャされたDNSリクエストに関する統計が表示されます。

![](<../../../.gitbook/assets/image (577).png>)

**I/Oグラフ**

_Statistics_ --> _I/O Graph_の下には、通信の**グラフ**が表示されます。

![](<../../../.gitbook/assets/image (574).png>)

### フィルター

ここでは、プロトコルに応じたWiresharkフィルターを見つけることができます：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルター：

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN + DNSリクエスト

### 検索

セッションのパケット内の**コンテンツ**を**検索**したい場合は、_CTRL+f_を押します。右ボタンを押してから列を編集することで、メイン情報バーに新しいレイヤーを追加できます（番号、時間、ソースなど）。

練習：[https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## ドメインの識別

Host HTTPヘッダーを表示する列を追加できます：

![](<../../../.gitbook/assets/image (403).png>)

および初期化HTTPS接続からサーバー名を追加する列（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)

## ローカルホスト名の識別

### DHCPから

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります

![](<../../../.gitbook/assets/image (404).png>)

### NBNSから

![](<../../../.gitbook/assets/image (405).png>)

## TLSの復号化

### サーバーの秘密鍵を使用してhttpsトラフィックを復号化する

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

_Edit_を押して、サーバーとプライベートキーのすべてのデータ（_IP、ポート、プロトコル、キーファイル、パスワード_）を追加します

### 対称セッションキーを使用してhttpsトラフィックを復号化する

FirefoxとChromeの両方が、TLSトラフィックを暗号化するために使用される対称セッションキーをファイルに記録するのをサポートしていることがわかりました。その後、Wiresharkをそのファイルに向けることで、復号化されたTLSトラフィックが表示されます。詳細はこちら：[https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
これを検出するには、環境内で`SSLKEYLOGFILE`変数を検索します

共有キーのファイルは次のようになります：

![](<../../../.gitbook/assets/image (99).png>)

Wiresharkにこれをインポートするには、\_edit > preference > protocol > ssl > に移動し、（Pre）-Master-Secretログファイル名にインポートします：

![](<../../../.gitbook/assets/image (100).png>)

## ADB通信

APKが送信されたADB通信からAPKを抽出します：
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

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**をフォローする。**
* **ハッキングトリックを共有するためにPRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **githubリポジトリに提出する。**

</details>
