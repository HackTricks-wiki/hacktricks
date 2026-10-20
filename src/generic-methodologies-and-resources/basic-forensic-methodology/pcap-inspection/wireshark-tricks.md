# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark 실력 향상

### 튜토리얼

기본적인 유용한 요령을 배우기에 좋은 튜토리얼은 다음과 같습니다.

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 분석 정보

**전문가 정보**

_**Analyze** --> **Expert Information**_을 클릭하면 **분석한** 패킷에서 발생한 일을 **개괄적으로** 확인할 수 있습니다.

![튜토리얼 - 분석 정보: Analyze -- Expert Information을 클릭하면 분석한 패킷에서 발생한 일을 개괄적으로 확인할 수 있습니다](<../../../images/image (256).png>)

**확인된 주소**

_**Statistics --> Resolved Addresses**_에서 포트/전송 계층을 프로토콜에 연결하거나 MAC 주소로 제조업체를 확인하는 등 Wireshark가 "**확인한**" 여러 **정보**를 볼 수 있습니다. 통신에 어떤 요소가 포함되는지 파악하는 데 유용합니다.

![튜토리얼 - 분석 정보: Statistics -- Resolved Addresses에서 포트/전송 계층을 프로토콜에 연결하거나 MAC 주소로 제조업체를 확인하는 등 Wireshark가 " 확인한 " 여러 정보를 볼 수 있습니다...](<../../../images/image (893).png>)

**프로토콜 계층 구조**

_**Statistics --> Protocol Hierarchy**_에서 통신에 **관여하는** **프로토콜**과 각 프로토콜에 관한 데이터를 볼 수 있습니다.

![튜토리얼 - 분석 정보: Statistics -- Protocol Hierarchy에서 통신에 관여하는 프로토콜과 각 프로토콜에 관한 데이터를 볼 수 있습니다](<../../../images/image (586).png>)

**대화**

_**Statistics --> Conversations**_에서 통신의 **대화 요약**과 관련 데이터를 볼 수 있습니다.

![튜토리얼 - 분석 정보: Statistics -- Conversations에서 통신의 대화 요약과 관련 데이터를 볼 수 있습니다](<../../../images/image (453).png>)

**엔드포인트**

_**Statistics --> Endpoints**_에서 통신의 **엔드포인트 요약**과 각 엔드포인트에 관한 데이터를 볼 수 있습니다.

![튜토리얼 - 분석 정보: Statistics -- Endpoints에서 통신의 엔드포인트 요약과 각 엔드포인트에 관한 데이터를 볼 수 있습니다](<../../../images/image (896).png>)

**DNS 정보**

_**Statistics --> DNS**_에서 캡처한 DNS 요청에 관한 통계를 확인할 수 있습니다.

![튜토리얼 - 분석 정보: Statistics -- DNS에서 캡처한 DNS 요청에 관한 통계를 확인할 수 있습니다](<../../../images/image (1063).png>)

**I/O 그래프**

_**Statistics --> I/O Graph**_에서 통신 **그래프를** 확인할 수 있습니다.

![튜토리얼 - 분석 정보: Statistics -- I/O Graph에서 통신 그래프를 확인할 수 있습니다](<../../../images/image (992).png>)

### 필터

프로토콜별 Wireshark 필터는 여기에서 확인할 수 있습니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
현재 Wireshark에서는 기존 `ssl.*` 필터 이름 대신 `tls.*`를 사용합니다.<sup>[[1]](#references)</sup>\
그 밖의 유용한 필터:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP 및 초기 HTTPS 트래픽
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP 및 초기 HTTPS 트래픽 + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP 및 초기 HTTPS 트래픽 + TCP SYN + DNS 요청
- `tls.handshake.extensions_server_name contains "example.com"`
  - 페이로드를 복호화할 수 없을 때도 ClientHello에 포함된 SNI를 기준으로 탐색
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - 기존 HTTPS, HTTP/2, HTTP/3을 지원하는 세션을 빠르게 구분
- `quic or http3`
  - TCP 대화만 검토할 경우 놓칠 수 있는 최신 UDP/443 트래픽 찾기

### 검색

세션의 **패킷** 안에서 **콘텐츠를** **검색**하려면 _CTRL+f_를 누릅니다. 마우스 오른쪽 버튼을 누른 다음 열 편집을 선택하면 기본 정보 표시줄(No., Time, Source 등)에 새 열을 추가할 수 있습니다.

### 다중화된 스트림 따라가기

Wireshark에서는 `TLS`, `HTTP/2`, `QUIC` 스트림을 직접 따라갈 수 있습니다. HTTP/2 및 QUIC 대화상자에는 연결 및 하위 스트림 선택기가 있어, 같은 하위 계층 연결을 공유하는 다중화된 스트림을 분리하는 데 도움이 됩니다.<sup>[[4]](#references)</sup>

세션 키를 사용할 수 있다면 먼저 요청의 스트림 ID를 확인한 다음, 전체 TCP 또는 UDP 대화 대신 해당 하위 스트림을 따라가세요. `0,1` 예시는 TCP 스트림 0의 HTTP/2 스트림 ID 1을 선택합니다. QUIC에서는 `follow,quic,utf-8,<connection-number>,<stream-id>`를 사용합니다. 5-튜플만 따라가면 서로 독립적인 요청이 섞이거나 마이그레이션 후 QUIC 연결을 놓칠 수 있습니다.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### 무료 pcap 실습

**다음 사이트의 무료 challenge로 연습하세요:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 도메인 식별

Host HTTP 헤더를 표시하는 열을 추가할 수 있습니다:

![무료 pcap 실습 - 도메인 식별: Host HTTP 헤더를 표시하는 열을 추가할 수 있습니다](<../../../images/image (639).png>)

HTTPS 연결을 시작하는 패킷의 Server name을 표시하는 열도 추가할 수 있습니다 (**tls.handshake.type == 1**):

![무료 pcap 실습 - 도메인 식별: HTTPS 연결을 시작하는 패킷의 Server name을 표시하는 열도 추가할 수 있습니다 ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

캡처의 대부분이 암호화되어 있다면 이 필드들을 열로 추가하면 triage 속도를 크게 높일 수 있습니다:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

이렇게 하면 payload 자체가 계속 암호화된 상태여도 세션을 hostname, ALPN(`http/1.1`, `h2`, `h3` 등), client fingerprint별로 그룹화할 수 있습니다. 복호화된 HTTP/2 및 HTTP/3 캡처에서는 `http2.header.value` 또는 `http3.headers.header.value`를 열로 추가하고 path, authority 및 기타 흥미로운 metadata를 기준으로 피벗하는 것도 유용합니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: outer SNI를 origin으로 오인하지 말 것

Encrypted ClientHello (ECH)는 공개용 cover name을 표시되는 outer SNI에 넣고 inner name은 암호화할 수 있습니다. 따라서 SNI만으로 도메인 목록을 만들면 ECH 트래픽이 잘못된 origin에 귀속될 수 있습니다. ECH extension이 있다는 사실만으로 ECH가 성공했다고 단정할 수는 없습니다. 클라이언트가 GREASE ECH extension을 보낼 수도 있기 때문입니다. Wireshark 4.2+에서는 다음 필터를 사용해 outer ECH offer를 찾고, 보고된 SNI는 요청한 사이트가 아니라 cover 후보로 취급하세요.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

일치하는 client session keys가 있다면, outer SNI로 origin을 추론하지 말고 복호화된 HTTP authority/Host를 확인하세요. 키가 없다면 평문 DNS와 같은 캡처된 다른 origin 증거를 확인하되, outer SNI를 숨겨진 이름과 동일시하지 마세요.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## 로컬 호스트 이름 식별

### DHCP에서

현재 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![로컬 호스트 이름 식별 - DHCP에서: 현재 Wireshark에서는 bootp 대신 DHCP를 검색해야 합니다](<../../../images/image (1013).png>)

### NBNS에서

![DHCP에서 - NBNS에서: 현재 Wireshark에서는 bootp 대신 DHCP를 검색해야 합니다](<../../../images/image (1003).png>)

## TLS 복호화

Wi-Fi 링크 계층 복호화는 TLS 세션 복호화와 별개입니다. 키와 핸드셰이크 관련 사전 조건은 [Wi-Fi PCAP 분석](wifi-pcap-analysis.md)을 참고하세요.

### 서버 private key로 https 트래픽 복호화

_편집 > 기본 설정 > 프로토콜 > tls >_

![TLS 복호화 - 서버 private key로 https 트래픽 복호화: 서버 private key로 https 트래픽 복호화](<../../../images/image (1103).png>)

_편집_을 누르고 서버 정보와 private key의 모든 데이터를 추가합니다(_IP, Port, Protocol, Key file 및 password_).

이 방법은 제한된 경우에만 작동합니다. 최신 TLS 1.3 / ECDHE 트래픽에서는 아래의 세션 키 로그 방식이 일반적으로 실용적인 선택입니다.<sup>[[1]](#references)</sup>

### 대칭 세션 키로 https 트래픽 복호화

Firefox와 Chrome은 모두 TLS 세션 키를 로그로 기록하는 기능이 있으며, 이 키를 Wireshark에서 사용해 TLS 트래픽을 복호화할 수 있습니다. 이를 통해 보안 통신을 심층 분석할 수 있습니다. 이 복호화 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 가이드에서 확인할 수 있습니다.<sup>[[3]](#references)</sup> 최신 TLS 1.3 및 QUIC/HTTP/3 캡처를 복호화할 때도 일반적으로 이 방법을 사용합니다.<sup>[[2]](#references)</sup>

이를 감지하려면 환경에서 `SSLKEYLOGFILE` 변수를 검색합니다.

공유 키 파일은 다음과 같은 형식입니다.

![서버 private key로 https 트래픽 복호화 - 대칭 세션 키로 https 트래픽 복호화: 공유 키 파일은 다음과 같은 형식입니다](<../../../images/image (820).png>)

캡처가 `pcapng` 형식인 경우, 호스트 파일 시스템을 살펴보기 전에 캡처에 복호화용 비밀 정보가 이미 포함되어 있는지 확인합니다.<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Wireshark에서 가져오려면 \_편집 > 환경 설정 > 프로토콜 > TLS > 로 이동한 다음 (Pre)-Master-Secret log filename에 가져옵니다:

![서버 개인 키로 HTTPS 트래픽 복호화 - 대칭 세션 키로 HTTPS 트래픽 복호화: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB 통신

APK가 전송된 ADB 통신에서 APK를 추출합니다:

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
- [3] [Wireshark로 TLS 브라우저 트래픽 복호화하기 – 쉬운 방법!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [프로토콜 스트림 따라가기](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [디스플레이 필터 참조: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [디스플레이 필터 참조: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [디스플레이 필터 참조: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: TLS 암호화 Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [TShark 설명서](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
