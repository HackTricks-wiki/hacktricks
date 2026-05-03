# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark 기술 향상하기

### Tutorials

다음 Tutorials는 몇 가지 멋진 기본 trick을 배우는 데 아주 좋습니다:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

_**Analyze** --> **Expert Information**_을 클릭하면 **analyzed**된 패킷들에서 일어나는 일에 대한 **개요**를 볼 수 있습니다:

![](<../../../images/image (256).png>)

**Resolved Addresses**

_**Statistics --> Resolved Addresses**_ 아래에서 wireshark가 "resolved"한 여러 **정보**를 찾을 수 있습니다. 예를 들어 port/transport를 protocol로, MAC을 제조사로 매핑한 것 등이 있습니다. 통신에 무엇이 관련되어 있는지 파악하는 데 유용합니다.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

_**Statistics --> Protocol Hierarchy**_ 아래에서 통신에 **포함된** **protocols**와 그에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (586).png>)

**Conversations**

_**Statistics --> Conversations**_ 아래에서 통신 내 **conversations 요약**과 그에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (453).png>)

**Endpoints**

_**Statistics --> Endpoints**_ 아래에서 통신 내 **endpoints 요약**과 각 항목에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (896).png>)

**DNS info**

_**Statistics --> DNS**_ 아래에서 캡처된 DNS request에 대한 통계를 찾을 수 있습니다.

![](<../../../images/image (1063).png>)

**I/O Graph**

_**Statistics --> I/O Graph**_ 아래에서 **통신 graph**를 찾을 수 있습니다.

![](<../../../images/image (992).png>)

### Filters

프로tocol별 wireshark filter는 여기에서 찾을 수 있습니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
현재 Wireshark에서는 예전 `ssl.*` filter 이름 대신 `tls.*`를 사용합니다.\
다른 흥미로운 filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- payload를 복호화할 수 없더라도 ClientHello에서 전송된 SNI를 기준으로 pivot
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- classic HTTPS, HTTP/2 및 HTTP/3 지원 session을 빠르게 분리
- `quic or http3`
- TCP conversations만 검토하면 놓치게 될 최신 UDP/443 traffic 찾기

### Search

**packets** 안의 **content**를 **search**하고 싶다면 _CTRL+f_를 누르세요. 오른쪽 버튼을 누른 다음 edit column을 선택하면 main information bar(No., Time, Source, etc.)에 새로운 layers를 추가할 수 있습니다.

### Following multiplexed streams

최근 Wireshark 버전은 `TLS`, `HTTP/2`, `QUIC` streams를 직접 따라갈 수 있습니다. 잡음이 많은 capture에서는 여러 request가 같은 connection을 공유할 때 특히 `Follow TCP Stream`만 사용하는 것보다 보통 더 빠릅니다.

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

HTTP header의 Host를 보여주는 column을 추가할 수 있습니다:

![](<../../../images/image (639).png>)

그리고 시작 HTTPS connection(**tls.handshake.type == 1**)에서 Server name을 추가하는 column도 만들 수 있습니다:

![](<../../../images/image (408) (1).png>)

capture가 대부분 암호화되어 있다면, 이 필드들을 column으로 추가하는 것만으로 triage 속도가 크게 빨라집니다:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

이렇게 하면 payload 자체가 암호화된 상태여도 hostname, ALPN(`http/1.1`, `h2`, `h3`, etc.) 및 client fingerprint 기준으로 session을 클러스터링할 수 있습니다. 복호화된 HTTP/2 및 HTTP/3 capture에서는 `http2.header.value` 또는 `http3.headers.header.value`를 column으로 추가하고 paths, authorities 및 기타 흥미로운 metadata를 기준으로 pivot하는 것도 유용합니다.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## 로컬 hostname 식별

### DHCP에서

현재 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![](<../../../images/image (1013).png>)

### NBNS에서

![](<../../../images/image (1003).png>)

## TLS 복호화

### 서버 private key로 https traffic 복호화

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

_Edit_를 누르고 서버와 private key의 모든 데이터(_IP, Port, Protocol, Key file and password_)를 추가합니다.

이 방법은 제한된 경우에만 동작합니다. 현재의 TLS 1.3 / ECDHE traffic에서는 아래의 session key log 방법이 보통 실용적인 옵션입니다.

### 대칭 session key로 https traffic 복호화

Firefox와 Chrome은 모두 TLS session key를 기록할 수 있으며, 이를 Wireshark와 함께 사용해 TLS traffic을 복호화할 수 있습니다. 이를 통해 secure communications를 심층 분석할 수 있습니다. 이 복호화를 수행하는 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 가이드를 참고할 수 있습니다. 이것은 또한 최신 TLS 1.3 및 QUIC/HTTP/3 capture를 복호화하는 일반적인 방법입니다.

이를 탐지하려면 환경 변수 `SSLKEYLOGFILE`을 검색하세요.

공유 key 파일은 다음처럼 보입니다:

![](<../../../images/image (820).png>)

capture가 `pcapng`라면, host filesystem을 조사하기 전에 이미 embedded decryption secrets를 포함하고 있는지 확인하세요:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
wireshark에서 이를 가져오려면 \_edit > preferences > protocols > tls > 로 이동한 다음 (Pre)-Master-Secret log filename에 가져오세요:

![](<../../../images/image (989).png>)

## ADB communication

APK가 전송된 ADB communication에서 APK를 추출하세요:
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
