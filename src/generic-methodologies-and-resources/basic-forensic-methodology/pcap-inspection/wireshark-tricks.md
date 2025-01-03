# Wiresharkのトリック

{{#include ../../../banners/hacktricks-training.md}}

## Wiresharkスキルの向上

### チュートリアル

以下のチュートリアルは、いくつかのクールな基本的なトリックを学ぶのに素晴らしいです：

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 分析された情報

**エキスパート情報**

_**Analyze** --> **Expert Information**_をクリックすると、**分析された**パケットで何が起こっているかの**概要**が得られます：

![](<../../../images/image (256).png>)

**解決されたアドレス**

_**Statistics --> Resolved Addresses**_の下には、wiresharkによって「**解決された**」いくつかの**情報**（ポート/トランスポートからプロトコル、MACから製造元など）を見つけることができます。通信に何が関与しているかを知るのは興味深いです。

![](<../../../images/image (893).png>)

**プロトコル階層**

_**Statistics --> Protocol Hierarchy**_の下には、通信に関与する**プロトコル**とそれに関するデータを見つけることができます。

![](<../../../images/image (586).png>)

**会話**

_**Statistics --> Conversations**_の下には、通信の**会話の要約**とそれに関するデータを見つけることができます。

![](<../../../images/image (453).png>)

**エンドポイント**

_**Statistics --> Endpoints**_の下には、通信の**エンドポイントの要約**とそれぞれに関するデータを見つけることができます。

![](<../../../images/image (896).png>)

**DNS情報**

_**Statistics --> DNS**_の下には、キャプチャされたDNSリクエストに関する統計を見つけることができます。

![](<../../../images/image (1063).png>)

**I/Oグラフ**

_**Statistics --> I/O Graph**_の下には、**通信のグラフ**を見つけることができます。

![](<../../../images/image (992).png>)

### フィルター

ここでは、プロトコルに応じたwiresharkフィルターを見つけることができます：[https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
他の興味深いフィルター：

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN + DNSリクエスト

### 検索

セッションの**パケット**内の**コンテンツ**を**検索**したい場合は、_CTRL+f_を押します。右ボタンを押してから列を編集することで、メイン情報バー（No.、Time、Sourceなど）に新しいレイヤーを追加できます。

### 無料のpcapラボ

**無料のチャレンジで練習する：** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## ドメインの特定

Host HTTPヘッダーを表示する列を追加できます：

![](<../../../images/image (639).png>)

そして、開始HTTPS接続からサーバー名を追加する列（**ssl.handshake.type == 1**）：

![](<../../../images/image (408) (1).png>)

## ローカルホスト名の特定

### DHCPから

現在のWiresharkでは、`bootp`の代わりに`DHCP`を検索する必要があります。

![](<../../../images/image (1013).png>)

### NBNSから

![](<../../../images/image (1003).png>)

## TLSの復号化

### サーバーの秘密鍵を使用したhttpsトラフィックの復号化

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

_サーバーと秘密鍵のすべてのデータ（_IP、Port、Protocol、Key file、password_）を追加するために_編集_を押します。

### 対称セッションキーを使用したhttpsトラフィックの復号化

FirefoxとChromeの両方は、TLSセッションキーをログに記録する機能があり、これを使用してWiresharkでTLSトラフィックを復号化できます。これにより、安全な通信の詳細な分析が可能になります。この復号化を実行する方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)のガイドにあります。

これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します。

共有キーのファイルは次のようになります：

![](<../../../images/image (820).png>)

これをwiresharkにインポートするには、_edit > preference > protocol > ssl >_に移動し、(Pre)-Master-Secretログファイル名にインポートします：

![](<../../../images/image (989).png>)

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
{{#include ../../../banners/hacktricks-training.md}}
