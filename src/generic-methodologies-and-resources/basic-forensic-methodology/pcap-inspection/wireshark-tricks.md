# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark のスキルを向上させる

### チュートリアル

基本的な便利なテクニックを学ぶのに役立つ、素晴らしいチュートリアルを紹介します。

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 解析情報

**エキスパート情報**

_**Analyze** --> **Expert Information**_ をクリックすると、**解析した**パケットで何が起きているのかを**概要**で確認できます。

![チュートリアル - 解析情報: Analyze -- Expert Information をクリックすると、解析したパケットで何が起きているのかを概要で確認できます](<../../../images/image (256).png>)

**名前解決されたアドレス**

_**Statistics --> Resolved Addresses**_ では、ポート/トランスポートからプロトコルへの対応や、MACアドレスからメーカーへの対応など、Wiresharkによって「**名前解決**」されたさまざまな**情報**を確認できます。通信に関係するものを把握するのに役立ちます。

![チュートリアル - 解析情報: Statistics -- Resolved Addresses では、ポート/トランスポートからプロトコルへの対応や、MACアドレスからメーカーへの対応など、Wiresharkによって「名前解決」されたさまざまな情報を確認できます。](<../../../images/image (893).png>)

**プロトコル階層**

_**Statistics --> Protocol Hierarchy**_ では、通信に**関与する****プロトコル**と、それらに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Protocol Hierarchy では、通信に関与するプロトコルと、それらに関するデータを確認できます](<../../../images/image (586).png>)

**会話**

_**Statistics --> Conversations**_ では、通信における**会話の概要**と、それらに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Conversations では、通信における会話の概要と、それらに関するデータを確認できます](<../../../images/image (453).png>)

**エンドポイント**

_**Statistics --> Endpoints**_ では、通信における**エンドポイントの概要**と、各エンドポイントに関するデータを確認できます。

![チュートリアル - 解析情報: Statistics -- Endpoints では、通信におけるエンドポイントの概要と、各エンドポイントに関するデータを確認できます](<../../../images/image (896).png>)

**DNS情報**

_**Statistics --> DNS**_ では、キャプチャしたDNSリクエストに関する統計情報を確認できます。

![チュートリアル - 解析情報: Statistics -- DNS では、キャプチャしたDNSリクエストに関する統計情報を確認できます](<../../../images/image (1063).png>)

**I/Oグラフ**

_**Statistics --> I/O Graph**_ では、**通信のグラフ**を確認できます。

![チュートリアル - 解析情報: Statistics -- I/O Graph では、通信のグラフを確認できます](<../../../images/image (992).png>)

### フィルター

プロトコル別のWiresharkフィルターはこちらで確認できます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
現在のWiresharkでは、古いフィルター名`ssl.*`の代わりに`tls.*`を使用します。<sup>[[1]](#references)</sup>\
その他の便利なフィルター:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTPおよびHTTPSの初期トラフィック
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTPおよびHTTPSの初期トラフィック + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTPおよびHTTPSの初期トラフィック + TCP SYN + DNSリクエスト
- `tls.handshake.extensions_server_name contains "example.com"`
  - ペイロードを復号できない場合でも、ClientHelloで送信されたSNIをPivotする
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - 従来のHTTPS、HTTP/2、HTTP/3対応セッションをすばやく切り分ける
- `quic or http3`
  - TCPの会話だけを調べていると見逃す、最新のUDP/443トラフィックを見つける

### 検索

セッションの**パケット**内の**コンテンツ**を**検索**するには、_CTRL+f_ を押します。メインの情報バー（No.、Time、Sourceなど）を右クリックして列の編集を選択すると、列を追加できます。

### 多重化されたストリームを追跡する

Wiresharkでは、`TLS`、`HTTP/2`、`QUIC`のストリームを直接追跡できます。HTTP/2およびQUICのダイアログには、接続とサブストリームのセレクターがあり、同じ下位レベルの接続を共有する多重化ストリームを個別に確認できます。<sup>[[4]](#references)</sup>

セッションキーを利用できる場合は、まずリクエストのストリームIDを特定し、TCPまたはUDPの会話全体ではなく、そのサブストリームを追跡します。`0,1`の例では、TCPストリーム0上のHTTP/2ストリームID 1を選択します。QUICの場合は`follow,quic,utf-8,<connection-number>,<stream-id>`を使用します。5タプルだけを基準に追跡すると、独立したリクエストが混在したり、接続移行後のQUIC接続を見逃したりすることがあります。<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### 無料のpcapラボ

**無料のチャレンジで練習する:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## ドメインの特定

HTTPのHostヘッダーを表示する列を追加できます:

![無料のpcapラボ - ドメインの特定: HTTPのHostヘッダーを表示する列を追加できます](<../../../images/image (639).png>)

また、HTTPS接続の開始時に送信されるServer name（**tls.handshake.type == 1**）を表示する列も追加できます:

![無料のpcapラボ - ドメインの特定: HTTPS接続の開始時に送信されるServer name（ tls.handshake.type == 1 ）を表示する列も追加できます](<../../../images/image (408) (1).png>)

キャプチャの大部分が暗号化されている場合、これらのフィールドを列として追加すると、トリアージを大幅に効率化できます:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

これにより、payload自体が暗号化されたままでも、ホスト名、ALPN（`http/1.1`、`h2`、`h3`など）、クライアントフィンガープリントでセッションをクラスタリングできます。復号済みのHTTP/2およびHTTP/3キャプチャでは、`http2.header.value`または`http3.headers.header.value`を列として追加し、パス、authority、その他の興味深いメタデータを軸に調べるのも有用です。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: 外側のSNIを接続先と取り違えない

Encrypted ClientHello（ECH）は、内側の名前を暗号化しつつ、外側から見えるSNIに公開用のカバー名を設定できます。そのため、SNIだけを使ったドメイン一覧では、ECHトラフィックの接続先を誤って特定する可能性があります。ECH拡張があるだけでは、ECHが成功した証拠にはなりません。クライアントはGREASE ECH拡張を送信することがあるためです。Wireshark 4.2以降では、次のフィルターを使って外側のECHオファーを探し、表示されたSNIは要求されたサイトではなく、カバー候補として扱ってください。<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

対応するクライアントセッションキーがある場合は、外側のSNIからオリジンを推測せず、復号したHTTP authority/Hostを調べてください。キーがない場合は、平文のDNSなど、キャプチャに含まれる他のオリジンの証拠を確認してください。ただし、外側のSNIを隠された名前と同一視しないでください。<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## ローカルホスト名の特定

### DHCPから

現在のWiresharkでは、`bootp`ではなく`DHCP`を検索する必要があります。

![ローカルホスト名の特定 - DHCPから: 現在のWiresharkでは、bootpではなくDHCPを検索する必要があります](<../../../images/image (1013).png>)

### NBNSから

![DHCPから - NBNSから: 現在のWiresharkでは、bootpではなくDHCPを検索する必要があります](<../../../images/image (1003).png>)

## TLSの復号

Wi-Fiのリンク層の復号とTLSセッションの復号は別の処理です。鍵とハンドシェイクの前提条件については、[Wi-Fi PCAP analysis](wifi-pcap-analysis.md)を参照してください。

### サーバーの秘密鍵を使ったHTTPSトラフィックの復号

_編集 > 設定 > プロトコル > tls >_

![TLSの復号 - サーバーの秘密鍵を使ったHTTPSトラフィックの復号: サーバーの秘密鍵を使ったHTTPSトラフィックの復号](<../../../images/image (1103).png>)

_編集_を押し、サーバーと秘密鍵の情報をすべて追加します（_IP、ポート、プロトコル、鍵ファイル、パスワード_）。

この方法が使えるのは、限られたケースのみです。現在のTLS 1.3 / ECDHEトラフィックでは、通常、以下のセッション鍵ログを使う方法が現実的な選択肢です。<sup>[[1]](#references)</sup>

### 対称セッション鍵を使ったHTTPSトラフィックの復号

FirefoxとChromeはどちらもTLSセッション鍵をログに記録できます。この鍵をWiresharkで使うと、TLSトラフィックを復号できます。これにより、セキュアな通信を詳細に分析できます。この復号方法の詳細については、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)のガイドを参照してください。<sup>[[3]](#references)</sup> これは、最新のTLS 1.3やQUIC/HTTP/3のキャプチャを復号する際にも標準的な方法です。<sup>[[2]](#references)</sup>

これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します。

共有鍵のファイルは次のようになります。

![サーバーの秘密鍵を使ったHTTPSトラフィックの復号 - 対称セッション鍵を使ったHTTPSトラフィックの復号: 共有鍵のファイルは次のようになります](<../../../images/image (820).png>)

キャプチャが`pcapng`の場合、ホストのファイルシステムを調べる前に、復号用の秘密情報がすでに埋め込まれていないか確認してください。<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Wiresharkでこれをインポートするには、\_編集 > 設定 > プロトコル > TLS > に移動し、(Pre)-Master-Secret log filename にインポートします:

![サーバーの秘密鍵を使ったHTTPS通信の復号 - 対称セッションキーを使ったHTTPS通信の復号: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB通信

APKが送信されたADB通信からAPKを抽出します:

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
- [2] [WiresharkでHTTP/3トラフィックを復号して解析する](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [WiresharkでブラウザーのTLSトラフィックを復号する簡単な方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [プロトコルストリームを追跡する](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TSharkマニュアル](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
