# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark skills 향상

### Tutorials

다음 tutorials는 유용한 기본 tricks를 배우는 데 매우 좋습니다:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 분석된 정보

**Expert Information**

_**Analyze** --> **Expert Information**_을 클릭하면 **분석된** 패킷에서 어떤 일이 발생하고 있는지 **개요**를 확인할 수 있습니다:

![Tutorials - 분석된 정보: Analyze -- Expert Information을 클릭하면 분석된 패킷에서 어떤 일이 발생하고 있는지 개요를 확인할 수 있습니다](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_에서 port/transport를 protocol로, MAC을 제조업체로 변환하는 등 wireshark가 "**resolved**"한 여러 **정보**를 확인할 수 있습니다. 통신에 어떤 항목이 관련되어 있는지 파악하는 데 유용합니다.

![Tutorials - 분석된 정보: Statistics -- Resolved Addresses에서 port/transport를 protocol로, MAC을 제조업체로 변환하는 등 wireshark가 " resolved "한 여러 정보를 확인할 수 있습니다](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_에서 통신에 **관련된** **protocols** 및 해당 protocol에 대한 데이터를 확인할 수 있습니다.

![Tutorials - 분석된 정보: Statistics -- Protocol Hierarchy에서 통신에 관련된 protocols 및 해당 protocol에 대한 데이터를 확인할 수 있습니다](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_에서 통신의 **conversations 요약** 및 해당 conversations에 대한 데이터를 확인할 수 있습니다.

![Tutorials - 분석된 정보: Statistics -- Conversations에서 통신의 conversations 요약 및 해당 conversations에 대한 데이터를 확인할 수 있습니다](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_에서 통신의 **endpoints 요약** 및 각 endpoint에 대한 데이터를 확인할 수 있습니다.

![Tutorials - 분석된 정보: Statistics -- Endpoints에서 통신의 endpoints 요약 및 각 endpoint에 대한 데이터를 확인할 수 있습니다](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_에서 캡처된 DNS request에 대한 통계를 확인할 수 있습니다.

![Tutorials - 분석된 정보: Statistics -- DNS에서 캡처된 DNS request에 대한 통계를 확인할 수 있습니다](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_에서 **통신 그래프**를 확인할 수 있습니다.

![Tutorials - 분석된 정보: Statistics -- I/O Graph에서 통신 그래프를 확인할 수 있습니다](<../../../images/image (992).png>)

### Filters

protocol에 따른 wireshark filter는 다음에서 확인할 수 있습니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
현재 Wireshark에서는 이전의 `ssl.*` filter name 대신 `tls.*`를 사용합니다.<sup>[[1]](#references)</sup>\
그 외 유용한 filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- payload를 decrypt할 수 없더라도 ClientHello에서 전송된 SNI를 기준으로 pivot
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- classic HTTPS, HTTP/2 및 HTTP/3 capable session을 빠르게 분리
- `quic or http3`
- TCP conversations만 검토할 경우 놓치게 되는 modern UDP/443 traffic 찾기

### Search

session의 **packets** 내부에서 **content**를 **search**하려면 _CTRL+f_를 누릅니다. 오른쪽 버튼을 누른 다음 edit column을 선택하면 main information bar(No., Time, Source 등)에 새로운 layers를 추가할 수 있습니다.

### Following multiplexed streams

Wireshark는 `TLS`, `HTTP/2`, `QUIC` streams를 직접 follow할 수 있습니다. HTTP/2 및 QUIC dialogs는 connection 및 substream selectors를 제공하므로, 동일한 lower-level connection을 공유하는 multiplexed streams를 분리하는 데 도움이 됩니다.<sup>[[4]](#references)</sup>

### Free pcap labs

**다음 free challenges로 practice하세요:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Domains 식별

HTTP Host header를 표시하는 column을 추가할 수 있습니다:

![Free pcap labs - Domains 식별: HTTP Host header를 표시하는 column을 추가할 수 있습니다](<../../../images/image (639).png>)

그리고 initiating HTTPS connection(**tls.handshake.type == 1**)에서 Server name을 추가하는 column도 사용할 수 있습니다:

![Free pcap labs - Domains 식별: initiating HTTPS connection( tls.handshake.type == 1 )에서 Server name을 추가하는 column도 사용할 수 있습니다](<../../../images/image (408) (1).png>)

capture가 대부분 encrypted 상태라면 이 fields를 columns로 추가하면 triage 속도를 크게 높일 수 있습니다:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

이를 통해 payload 자체가 encrypted 상태로 유지되더라도 hostname, ALPN(`http/1.1`, `h2`, `h3` 등) 및 client fingerprint를 기준으로 sessions를 cluster할 수 있습니다. decrypted HTTP/2 및 HTTP/3 captures의 경우 `http2.header.value` 또는 `http3.headers.header.value`를 columns로 추가하고 paths, authorities 및 기타 유용한 metadata를 기준으로 pivot하는 것도 유용합니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## 로컬 호스트 이름 식별

### DHCP에서

최신 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![로컬 호스트 이름 식별 - DHCP에서: 최신 Wireshark에서는 bootp 대신 DHCP를 검색해야 합니다.](<../../../images/image (1013).png>)

### NBNS에서

![DHCP에서 - NBNS에서: 최신 Wireshark에서는 bootp 대신 DHCP를 검색해야 합니다.](<../../../images/image (1003).png>)

## TLS 복호화

### server private key를 사용한 https traffic 복호화

_edit > preferences > protocols > tls >_

![TLS 복호화 - server private key를 사용한 https traffic 복호화: server private key를 사용한 https traffic 복호화](<../../../images/image (1103).png>)

_Edit_를 누르고 server의 모든 정보와 private key (_IP, Port, Protocol, Key file 및 password_)를 추가합니다.

이 방법은 제한된 수의 경우에만 작동합니다. 최신 TLS 1.3 / ECDHE traffic에서는 일반적으로 아래의 session key log 방법이 실용적인 선택입니다.<sup>[[1]](#references)</sup>

### symmetric session keys를 사용한 https traffic 복호화

Firefox와 Chrome 모두 TLS session keys를 log할 수 있으며, 이를 Wireshark에서 TLS traffic을 복호화하는 데 사용할 수 있습니다. 이를 통해 secure communications를 심층적으로 분석할 수 있습니다. 이 복호화를 수행하는 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 guide에서 확인할 수 있습니다.<sup>[[3]](#references)</sup> 이는 최신 TLS 1.3 및 QUIC/HTTP/3 captures를 복호화하는 일반적인 방법이기도 합니다.<sup>[[2]](#references)</sup>

이를 감지하려면 environment 내부에서 `SSLKEYLOGFILE` 변수를 검색합니다.

shared keys 파일은 다음과 같은 형태입니다.

![server private key를 사용한 https traffic 복호화 - symmetric session keys를 사용한 https traffic 복호화: shared keys 파일은 다음과 같은 형태입니다.](<../../../images/image (820).png>)

capture가 `pcapng`인 경우 host filesystem을 조사하기 전에 이미 embedded decryption secrets가 포함되어 있는지 확인합니다.<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Wireshark에서 가져오려면 \_edit > preferences > protocols > tls > 로 이동한 다음 (Pre)-Master-Secret log filename에 가져옵니다:

![Decrypting https traffic with server private key - Decrypting https traffic with symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB 통신

APK가 전송된 ADB 통신에서 APK 추출:
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

- [1] [Wireshark TLS 위키](https://wiki.wireshark.org/TLS)
- [2] [Wireshark에서 HTTP/3 트래픽 복호화 및 파싱](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Wireshark로 TLS 브라우저 트래픽 복호화하기 - 쉬운 방법!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [프로토콜 스트림 추적](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Display Filter Reference: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Display Filter Reference: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Display Filter Reference: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
