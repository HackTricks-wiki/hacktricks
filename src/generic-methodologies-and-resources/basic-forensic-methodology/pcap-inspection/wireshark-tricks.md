# Wiresharkの便利なテクニック

{{#include ../../../banners/hacktricks-training.md}}

## Wiresharkのスキルを向上させる

### Tutorials

以下のチュートリアルでは、便利な基本テクニックを学べます。

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 解析情報

**Expert Information**

_**Analyze** --> **Expert Information**_ をクリックすると、**解析**されたパケットで何が起きているかの**概要**を確認できます。

![チュートリアル - 解析情報: Analyze -- Expert Information をクリックすると、解析されたパケットで何が起きているかの概要を確認できます](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ では、wiresharkによって「**解決**」された情報を確認できます。たとえば、ポート／トランスポートからプロトコル、MACアドレスからメーカーなどです。通信に関係しているものを把握するうえで役立ちます。

![チュートリアル - 解析情報: Statistics -- Resolved Addresses では、wiresharkによって「解決」された情報を確認できます。たとえば、ポート／トランスポートからプロトコル、MACアドレスからメーカーなどです](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ では、通信に**関与している****プロトコル**と、それらに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Protocol Hierarchy では、通信に関与しているプロトコルと、それらに関するデータを確認できます](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ では、通信における**会話の概要**と、それらに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Conversations では、通信における会話の概要と、それらに関するデータを確認できます](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ では、通信における**エンドポイントの概要**と、それぞれに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Endpoints では、通信におけるエンドポイントの概要と、それぞれに関するデータを確認できます](<../../../images/image (896).png>)

**DNS情報**

_**Statistics --> DNS**_ では、キャプチャされたDNSリクエストに関する統計を確認できます。

![チュートリアル - 解析情報: Statistics -- DNS では、キャプチャされたDNSリクエストに関する統計を確認できます](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ では、**通信のグラフ**を確認できます。

![チュートリアル - 解析情報: Statistics -- I/O Graph では、通信のグラフを確認できます](<../../../images/image (992).png>)

### Filters

ここでは、プロトコル別のWiresharkフィルターを確認できます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
現在のWiresharkでは、古い`ssl.*`フィルター名ではなく`tls.*`を使用します。<sup>[[1]](#references)</sup>\
その他の便利なフィルター:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPSトラフィック + TCP SYN + DNSリクエスト
- `tls.handshake.extensions_server_name contains "example.com"`
- ペイロードを復号できない場合でも、ClientHelloで送信されたSNIを基準にPivotする
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- 従来のHTTPS、HTTP/2、HTTP/3対応セッションをすばやく分離する
- `quic or http3`
- TCPの会話だけを確認すると見落とす、最新のUDP/443トラフィックを検出する

### Search

セッションの**パケット**内の**コンテンツ**を**検索**するには、_CTRL+f_を押します。右クリックしてから列を編集することで、メイン情報バー（No.、Time、Sourceなど）に新しい列を追加できます。

### 多重化されたストリームの追跡

Wiresharkでは、`TLS`、`HTTP/2`、`QUIC`のストリームを直接追跡できます。HTTP/2およびQUICのダイアログには接続とサブストリームのセレクターがあり、同じ下位レベルの接続を共有する多重化ストリームを分離するのに役立ちます。<sup>[[4]](#references)</sup>

### 無料のpcapラボ

**無料のチャレンジで練習:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## ドメインの特定

HTTPのHostヘッダーを表示する列を追加できます。

![無料のpcapラボ - ドメインの特定: HTTPのHostヘッダーを表示する列を追加できます](<../../../images/image (639).png>)

また、開始されたHTTPS接続（**tls.handshake.type == 1**）のServer名を追加する列も設定できます。

![無料のpcapラボ - ドメインの特定: 開始されたHTTPS接続（tls.handshake.type == 1）のServer名を追加する列も設定できます](<../../../images/image (408) (1).png>)

キャプチャの大部分が暗号化されている場合、これらのフィールドを列として追加すると、トリアージを大幅に高速化できます。

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

これにより、ペイロード自体が暗号化されたままでも、ホスト名、ALPN（`http/1.1`、`h2`、`h3`など）、クライアントフィンガープリントによってセッションをクラスタリングできます。復号されたHTTP/2およびHTTP/3のキャプチャでは、`http2.header.value`または`http3.headers.header.value`を列として追加し、パス、authority、その他の興味深いメタデータを基準にPivotすることも有用です。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## ローカルホスト名の特定

### DHCP から

現在の Wireshark では、`bootp` の代わりに `DHCP` を検索する必要があります。

![ローカルホスト名の特定 - DHCP から: 現在の Wireshark では、bootp の代わりに DHCP を検索する必要があります](<../../../images/image (1013).png>)

### NBNS から

![DHCP から - NBNS から: 現在の Wireshark では、bootp の代わりに DHCP を検索する必要があります](<../../../images/image (1003).png>)

## TLS の復号

### server private key を使用した https トラフィックの復号

_edit > preferences > protocols > tls >_

![TLS の復号 - server private key を使用した https トラフィックの復号: server private key を使用した https トラフィックの復号](<../../../images/image (1103).png>)

_Edit_ を押し、server と private key のすべての情報（_IP, Port, Protocol, Key file and password_）を追加します。

この方法が機能するケースは限られています。現在の TLS 1.3 / ECDHE トラフィックでは、通常、以下の session key log method が実用的な選択肢です。<sup>[[1]](#references)</sup>

### symmetric session keys を使用した https トラフィックの復号

Firefox と Chrome はどちらも TLS session keys をログに記録する機能を備えており、Wireshark で TLS トラフィックを復号するために使用できます。これにより、secure communications を詳細に分析できます。この復号方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) の guide にあります。<sup>[[3]](#references)</sup> これは、modern TLS 1.3 および QUIC/HTTP/3 captures を復号する通常の方法でもあります。<sup>[[2]](#references)</sup>

これを検出するには、environment 内で変数 `SSLKEYLOGFILE` を検索します。

shared keys のファイルは次のようになります。

![server private key を使用した https トラフィックの復号 - symmetric session keys を使用した https トラフィックの復号: shared keys のファイルは次のようになります](<../../../images/image (820).png>)

capture が `pcapng` の場合は、host filesystem の調査を始める前に、embedded decryption secrets がすでに含まれているか確認します。<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
これを wireshark にインポートするには、\_edit > preferences > protocols > tls > に移動し、(Pre)-Master-Secret log filename にインポートします。

![サーバーの秘密鍵を使用した https トラフィックの復号 - 対称セッションキーを使用した https トラフィックの復号: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

APK が送信された ADB communication から APK を抽出します：
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
## References

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [WiresharkでHTTP/3トラフィックを復号および解析する](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wiresharkを使用したTLS Browserトラフィックの復号 – 簡単な方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protocol Streamsの追跡](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
