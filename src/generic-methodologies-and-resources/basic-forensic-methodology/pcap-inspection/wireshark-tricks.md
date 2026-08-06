# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark のスキルを向上させる

### Tutorials

以下の Tutorials では、便利な基本的 tricks を学べます。

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 解析された情報

**Expert Information**

_**Analyze** --> **Expert Information**_ をクリックすると、**解析された** packets で何が起きているかの **overview** を確認できます。

![Tutorials - 解析された情報: Analyze -- Expert Information をクリックすると、解析された packets で何が起きているかの overview を確認できます](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ では、port/transport から protocol への対応付けや、MAC から manufacturer の特定など、wireshark によって "**resolved**" された複数の **information** を確認できます。通信に何が関与しているかを把握するうえで役立ちます。

![Tutorials - 解析された情報: Statistics -- Resolved Addresses では、port/transport から protocol への対応付けや、MAC から...など、wireshark によって「resolved」された複数の information を確認できます](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ では、通信に **involved** している **protocols** と、それらに関する data を確認できます。

![Tutorials - 解析された情報: Statistics -- Protocol Hierarchy では、通信に involved している protocols と、それらに関する data を確認できます](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ では、通信における **conversations の summary** と、それらに関する data を確認できます。

![Tutorials - 解析された情報: Statistics -- Conversations では、通信における conversations の summary と、それらに関する data を確認できます](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ では、**endpoints の summary** と、それぞれに関する data を確認できます。

![Tutorials - 解析された情報: Statistics -- Endpoints では、endpoints の summary と、それぞれに関する data を確認できます](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ では、capture された DNS request に関する statistics を確認できます。

![Tutorials - 解析された情報: Statistics -- DNS では、capture された DNS request に関する statistics を確認できます](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ では、**通信の graph** を確認できます。

![Tutorials - 解析された情報: Statistics -- I/O Graph では、通信の graph を確認できます](<../../../images/image (992).png>)

### Filters

protocol に応じた wireshark filter は、こちらで確認できます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
現在の Wireshark では、古い `ssl.*` filter names の代わりに `tls.*` を使用します。\
その他の興味深い filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP および初期 HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP および初期 HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP および初期 HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- payload を decrypt できない場合でも、ClientHello で送信された SNI を pivot
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- classic HTTPS、HTTP/2、HTTP/3 対応 sessions をすばやく分離
- `quic or http3`
- TCP conversations だけを確認すると見落とす modern UDP/443 traffic を検索

### Search

sessions の **packets** 内にある **content** を **search** するには、_CTRL+f_ を押します。右ボタンを押してから edit column を選択すると、main information bar（No.、Time、Source など）に新しい layers を追加できます。

### multiplexed streams の追跡

最近の Wireshark versions では、`TLS`、`HTTP/2`、`QUIC` streams を直接追跡できます。noisy captures では、これは通常、`Follow TCP Stream` だけを使用するより高速です。特に、複数の requests が同じ connection を共有している場合に有効です。

### 無料の pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains の特定

Host HTTP header を表示する column を追加できます:

![Free pcap labs - Domains の特定: Host HTTP header を表示する column を追加できます](<../../../images/image (639).png>)

また、initiating HTTPS connection（**tls.handshake.type == 1**）から Server name を追加する column も設定できます:

![Free pcap labs - Domains の特定: initiating HTTPS connection（ tls.handshake.type == 1 ）から Server name を追加する column](<../../../images/image (408) (1).png>)

capture の大部分が encrypted の場合、これらの fields を columns として追加すると triage を大幅に高速化できます:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

これにより、payload 自体が encrypted のままでも、hostname、ALPN（`http/1.1`、`h2`、`h3` など）、client fingerprint に基づいて sessions を cluster できます。decrypted HTTP/2 および HTTP/3 captures では、`http2.header.value` または `http3.headers.header.value` を columns として追加し、paths、authorities、その他の興味深い metadata を pivot することも有用です。<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## ローカルホスト名の特定

### DHCPから

現在の Wireshark では、`bootp` の代わりに `DHCP` を検索する必要があります。

![ローカルホスト名の特定 - DHCPから: 現在の Wireshark では、bootp の代わりに DHCP を検索する必要があります](<../../../images/image (1013).png>)

### NBNSから

![DHCPから - NBNSから: 現在の Wireshark では、bootp の代わりに DHCP を検索する必要があります](<../../../images/image (1003).png>)

## TLSの復号

### server private keyを使用したhttpsトラフィックの復号

_edit > preferences > protocols > tls >_

![TLSの復号 - server private keyを使用したhttpsトラフィックの復号: server private keyを使用したhttpsトラフィックの復号](<../../../images/image (1103).png>)

_Edit_ を押し、serverとprivate keyのすべての情報（_IP、Port、Protocol、Key file、password_）を追加します。

この方法が機能するケースは限られています。現在の TLS 1.3 / ECDHE トラフィックでは、通常、以下の session key log method が実用的な選択肢です。<sup>[[1]](#references)</sup>

### symmetric session keysを使用したhttpsトラフィックの復号

Firefox と Chrome はどちらも TLS session keys をログに記録する機能を備えており、これを Wireshark で TLS トラフィックの復号に使用できます。これにより、secure communications を詳細に分析できます。この復号方法の詳細は、[Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) の guide に記載されています。<sup>[[3]](#references)</sup> これは、modern TLS 1.3 および QUIC/HTTP/3 captures を復号する通常の方法でもあります。<sup>[[2]](#references)</sup>

これを検出するには、environment 内で変数 `SSLKEYLOGFILE` を検索します。

shared keys のファイルは次のようになります。

![server private keyを使用したhttpsトラフィックの復号 - symmetric session keysを使用したhttpsトラフィックの復号: shared keys のファイルは次のようになります](<../../../images/image (820).png>)

capture が `pcapng` の場合は、host filesystem を調査する前に、すでに embedded decryption secrets が含まれているか確認します。<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
これを wireshark にインポートするには、\_edit > preferences > protocols > tls > に移動し、(Pre)-Master-Secret log filename にインポートします:

![server private key を使用した https traffic の復号 - symmetric session keys を使用した https traffic の復号: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

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
## 参考文献

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [WiresharkでHTTP/3トラフィックを復号および解析する](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [WiresharkでTLS Browser Trafficを復号する - 簡単な方法！](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
