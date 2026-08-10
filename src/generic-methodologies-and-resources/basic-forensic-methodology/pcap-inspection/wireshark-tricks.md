# Wireshark tricks

## Wireshark skillsを向上させる

### Tutorials

以下のtutorialsでは、基本的な便利なtricksを学べます。

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 解析された情報

**Expert Information**

_**Analyze** --> **Expert Information**_をクリックすると、**解析された**packetで何が起きているかの**概要**を確認できます。

![Tutorials - 解析された情報: Analyze -- Expert Informationをクリックすると、解析されたpacketで何が起きているかの概要を確認できます](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_では、port/transportからprotocol、MACからmanufacturerへの変換など、wiresharkによって「**resolved**」されたさまざまな**情報**を確認できます。通信に何が関与しているかを把握するうえで役立ちます。

![Tutorials - 解析された情報: Statistics -- Resolved Addressesでは、port/transportからprotocol、MACからmanufacturerへの変換など、wiresharkによって「resolved」されたさまざまな情報を確認できます](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_では、通信に**関与している****protocols**と、それらに関するデータを確認できます。

![Tutorials - 解析された情報: Statistics -- Protocol Hierarchyでは、通信に関与しているprotocolsと、それらに関するデータを確認できます](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_では、通信中の**conversationsの概要**と、それらに関するデータを確認できます。

![Tutorials - 解析された情報: Statistics -- Conversationsでは、通信中のconversationsの概要と、それらに関するデータを確認できます](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_では、通信中の**endpointsの概要**と、それぞれに関するデータを確認できます。

![Tutorials - 解析された情報: Statistics -- Endpointsでは、通信中のendpointsの概要と、それぞれに関するデータを確認できます](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_では、captureされたDNS requestに関する統計を確認できます。

![Tutorials - 解析された情報: Statistics -- DNSでは、captureされたDNS requestに関する統計を確認できます](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_では、**通信のgraph**を確認できます。

![Tutorials - 解析された情報: Statistics -- I/O Graphでは、通信のgraphを確認できます](<../../../images/image (992).png>)

### Filters

protocolに応じたwireshark filterは、こちらで確認できます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
現在のWiresharkでは、古い`ssl.*` filter nameの代わりに`tls.*`を使用します。<sup>[[1]](#references)</sup>\
その他の興味深いfilter:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTPおよび初期HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- payloadをdecryptできない場合でも、ClientHelloで送信されたSNIをpivotする
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- classic HTTPS、HTTP/2、HTTP/3対応のsessionを素早く分離する
- `quic or http3`
- TCP conversationsだけを確認した場合に見落とす、最新のUDP/443 trafficを見つける

### Search

sessionの**packets**内にある**content**を**search**するには、_CTRL+f_を押します。右クリックしてからedit columnを選択すると、main information bar（No.、Time、Sourceなど）に新しいlayerを追加できます。

### multiplexed streamsを追跡する

Wiresharkでは、`TLS`、`HTTP/2`、`QUIC`のstreamsを直接追跡できます。HTTP/2およびQUICのdialogではconnectionとsubstreamのselectorが表示されるため、同じ下位levelのconnectionを共有するmultiplexed streamsを分離するのに役立ちます。<sup>[[4]](#references)</sup>

### 無料のpcap labs

**次の無料challengeでpracticeしてください:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domainsを特定する

HTTP Host headerを表示するcolumnを追加できます。

![Free pcap labs - Domainsを特定する: HTTP Host headerを表示するcolumnを追加できます](<../../../images/image (639).png>)

また、開始HTTPS connection（**tls.handshake.type == 1**）からServer nameを追加するcolumnも設定できます。

![Free pcap labs - Domainsを特定する: 開始HTTPS connection（tls.handshake.type == 1）からServer nameを追加するcolumn](<../../../images/image (408) (1).png>)

captureの大部分がencryptedの場合、これらのfieldをcolumnとして追加するとtriageを大幅に高速化できます。

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

これにより、payload自体がencryptedのままでも、hostname、ALPN（`http/1.1`、`h2`、`h3`など）、client fingerprintによってsessionをcluster化できます。decrypted HTTP/2およびHTTP/3 captureでは、`http2.header.value`または`http3.headers.header.value`をcolumnとして追加し、path、authority、その他の興味深いmetadataをpivotすることも有用です。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## ローカルホスト名の特定

### DHCPから

現在のWiresharkでは、`bootp`ではなく`DHCP`を検索する必要があります。

![ローカルホスト名の特定 - DHCPから: 現在のWiresharkでは、bootpではなくDHCPを検索する必要があります](<../../../images/image (1013).png>)

### NBNSから

![DHCPから - NBNSから: 現在のWiresharkでは、bootpではなくDHCPを検索する必要があります](<../../../images/image (1003).png>)

## TLSの復号

### server private keyを使用したhttpsトラフィックの復号

_edit > preferences > protocols > tls >_

![TLSの復号 - server private keyを使用したhttpsトラフィックの復号: server private keyを使用したhttpsトラフィックの復号](<../../../images/image (1103).png>)

_Edit_を押し、serverとprivate keyのすべての情報（_IP、Port、Protocol、Key file、password_）を追加します。

この方法は、限られたケースでのみ機能します。現在のTLS 1.3 / ECDHEトラフィックでは、通常、以下のsession key log方式が実用的な選択肢です。<sup>[[1]](#references)</sup>

### 対称session keyを使用したhttpsトラフィックの復号

FirefoxとChromeはどちらもTLS session keyをログに記録する機能を備えており、WiresharkでTLSトラフィックを復号するために使用できます。これにより、secure communicationsを詳細に分析できます。この復号方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)のガイドで確認できます。<sup>[[3]](#references)</sup>これは、modern TLS 1.3およびQUIC/HTTP/3のcaptureを復号する通常の方法でもあります。<sup>[[2]](#references)</sup>

これを検出するには、環境内で変数`SSLKEYLOGFILE`を検索します。

共有keyのファイルは次のようになります。

![server private keyを使用したhttpsトラフィックの復号 - 対称session keyを使用したhttpsトラフィックの復号: 共有keyのファイルは次のようになります](<../../../images/image (820).png>)

captureが`pcapng`の場合は、host filesystemを調べる前に、すでに復号secretが埋め込まれていないか確認します。<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
これを wireshark にインポートするには、\_edit > preferences > protocols > tls > に移動し、(Pre)-Master-Secret log filename にインポートします:

![server private key を使用した https トラフィックの復号 - symmetric session keys を使用した https トラフィックの復号: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB通信

APK が送信された ADB communication から APK を抽出します:
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
- [3] [WiresharkでブラウザのTLSトラフィックを復号する - 簡単な方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Protocol Streamsを追跡する](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
