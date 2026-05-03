# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark スキルを向上させる

### Tutorials

以下の tutorials は、いくつかの便利な基本テクニックを学ぶのに最適です:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_ をクリックすると、**解析**されたパケットで何が起きているかの**概要**を確認できます:

![](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ の下では、wireshark によって "**resolved**" された複数の**情報**を確認できます。たとえば port/transport から protocol への変換、MAC から manufacturer への変換などです。通信に何が関与しているかを知るのに役立ちます。

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ の下では、通信に**関与**している **protocols** と、それらに関する data を確認できます。

![](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ の下では、通信内の **conversations の要約** と、それらに関する data を確認できます。

![](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ の下では、通信内の **endpoints の要約** と、それぞれに関する data を確認できます。

![](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ の下では、キャプチャされた DNS request に関する statistics を確認できます。

![](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ の下では、**通信の graph** を確認できます。

![](<../../../images/image (992).png>)

### Filters

protocol ごとの wireshark filter はここで確認できます: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
現在の Wireshark では、古い `ssl.*` filter 名の代わりに `tls.*` を使います。\
その他の興味深い filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP と最初の HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP と最初の HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP と最初の HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- ペイロードを復号できない場合でも、ClientHello で送信された SNI を起点に pivot する
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- 従来の HTTPS、HTTP/2、HTTP/3 対応セッションを素早く分離する
- `quic or http3`
- TCP conversations だけを確認していると見逃す modern な UDP/443 traffic を見つける

### Search

session の **packets** 内の **content** を**検索**したい場合は _CTRL+f_ を押します。メインの information bar (No., Time, Source, etc.) に新しい layers を追加するには、右ボタンを押してから edit column を選びます。

### Following multiplexed streams

最近の Wireshark では、`TLS`、`HTTP/2`、`QUIC` streams を直接 follow できます。ノイズの多い capture では、特に複数の request が同じ connection を共有している場合、`Follow TCP Stream` だけを使うより通常はこちらのほうが速いです。

### Free pcap labs

**以下の free challenges で練習できます:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Host HTTP header を表示する column を追加できます:

![](<../../../images/image (639).png>)

また、開始された HTTPS connection (**tls.handshake.type == 1**) から Server name を追加する column もあります:

![](<../../../images/image (408) (1).png>)

capture の大半が encrypted なら、これらの fields を column として追加すると triage がかなり速くなります:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

これにより、payload 自体が encrypted のままでも、hostname、ALPN (`http/1.1`, `h2`, `h3`, など)、client fingerprint で session を cluster できます。復号済みの HTTP/2 と HTTP/3 capture では、`http2.header.value` または `http3.headers.header.value` を column として追加し、paths、authorities、その他の興味深い metadata を起点に pivot するのも有用です。
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## ローカルホスト名の識別

### DHCPから

現在の Wireshark では `bootp` の代わりに `DHCP` を検索する必要があります

![](<../../../images/image (1013).png>)

### NBNSから

![](<../../../images/image (1003).png>)

## TLSの復号

### サーバーの秘密鍵で https traffic を復号する

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

_Edit_ を押して、サーバーと秘密鍵のすべてのデータ（_IP, Port, Protocol, Key file and password_）を追加します

この方法は限られたケースでしか機能しません。現在の TLS 1.3 / ECDHE traffic では、通常は下の session key log method が実用的な選択肢です。

### 対称 session keys で https traffic を復号する

Firefox と Chrome の両方に TLS session keys をログ出力する機能があり、Wireshark で TLS traffic を復号するために使えます。これにより、secure communications の詳細な分析が可能になります。この復号を行う方法の詳細は [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/) のガイドで確認できます。これは、modern TLS 1.3 と QUIC/HTTP/3 captures を復号するための通常の方法でもあります。

これを検出するには、環境内で変数 `SSLKEYLOGFILE` を検索します

共有鍵のファイルは次のようになります:

![](<../../../images/image (820).png>)

キャプチャが `pcapng` の場合、ホストの filesystem を調べる前に、すでに埋め込まれた decryption secrets を含んでいるか確認してください:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
wiresharkでこれをインポートするには、\_edit > preferences > protocols > tls > に移動し、(Pre)-Master-Secret log filename にインポートします:

![](<../../../images/image (989).png>)

## ADB communication

APKが送信されたADB communicationからAPKを抽出する:
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

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
