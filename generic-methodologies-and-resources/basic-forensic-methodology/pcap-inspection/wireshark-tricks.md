# Wiresharkのトリック

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする
- **Hackingトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## Wiresharkスキルの向上

### チュートリアル

以下のチュートリアルは、いくつかのクールな基本的なトリックを学ぶのに素晴らしいです：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析された情報

**専門家情報**

_Analyze_ --> _Expert Information_をクリックすると、**分析された**パケットで何が起こっているかの**概要**が表示されます：

![](<../../../.gitbook/assets/image (253).png>)

**解決されたアドレス**

_Statistics_ --> _Resolved Addresses_の下には、wiresharkによって**解決された**ポート/トランスポートからプロトコル、MACから製造業者など、いくつかの**情報**が表示されます。通信に関わるものを知ることは興味深いです。

![](<../../../.gitbook/assets/image (890).png>)

**プロトコル階層**

_Statistics_ --> _Protocol Hierarchy_の下には、通信に関与する**プロトコル**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (583).png>)

**会話**

_Statistics_ --> _Conversations_の下には、通信中の**会話の要約**とそれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (450).png>)

**エンドポイント**

_Statistics_ --> _Endpoints_の下には、通信中の**エンドポイントの要約**とそれぞれに関するデータが表示されます。

![](<../../../.gitbook/assets/image (893).png>)

**DNS情報**

_Statistics_ --> _DNS_の下には、キャプチャされたDNSリクエストに関する統計が表示されます。

![](<../../../.gitbook/assets/image (1060).png>)

**I/Oグラフ**

_Statistics_ --> _I/O Graph_の下には、通信の**グラフ**が表示されます。

![](<../../../.gitbook/assets/image (989).png>)

### フィルタ

ここでは、プロトコルに応じたWiresharkフィルタを見つけることができます：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルタ：

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN + DNSリクエスト

### 検索

セッションのパケット内の**コンテンツ**を**検索**したい場合は、_CTRL+f_を押します。右ボタンを押してから列を編集することで、メイン情報バーに新しいレイヤーを追加できます（番号、時間、ソースなど）。

### 無料のpcapラボ

**無料のチャレンジで練習:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## ドメインの識別

Host HTTPヘッダーを表示する列を追加できます：

![](<../../../.gitbook/assets/image (635).png>)

そして、初期化HTTPS接続からサーバー名を追加する列を追加できます（**ssl.handshake.type == 1**）：

![](<../../../.gitbook/assets/image (408) (1).png>)

## ローカルホスト名の識別

### DHCPから

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります

![](<../../../.gitbook/assets/image (1010).png>)

### NBNSから

![](<../../../.gitbook/assets/image (1000).png>)

## TLSの復号化

### サーバーのプライベートキーを使用してhttpsトラフィックを復号化

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (1100).png>)

_Edit_を押して、サーバーとプライベートキーのすべてのデータ（_IP、ポート、プロトコル、キーファイル、パスワード_）を追加します

### 対称セッションキーを使用してhttpsトラフィックを復号化

FirefoxとChromeの両方には、TLSセッションキーを記録する機能があり、これをWiresharkで使用してTLSトラフィックを復号化できます。これにより、セキュアな通信の詳細な分析が可能になります。この復号化を実行する方法の詳細については、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)のガイドで見つけることができます。

これを検出するには、環境内で`SSLKEYLOGFILE`変数を検索します

共有キーのファイルは次のようになります：

![](<../../../.gitbook/assets/image (817).png>)

Wiresharkにこれをインポートするには、\_edit > preference > protocol > ssl > に移動し、（Pre）-Master-Secretログファイル名にインポートします：

![](<../../../.gitbook/assets/image (986).png>)
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
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}


<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したり、HackTricksをPDFでダウンロードしたり**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有する。

</details>
