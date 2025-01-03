# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Wireshark 기술 향상

### 튜토리얼

다음 튜토리얼은 멋진 기본 기술을 배우기에 훌륭합니다:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### 분석된 정보

**전문가 정보**

_**Analyze** --> **Expert Information**_을 클릭하면 패킷 **분석**에서 발생하는 일에 대한 **개요**를 볼 수 있습니다:

![](<../../../images/image (256).png>)

**해결된 주소**

_**Statistics --> Resolved Addresses**_ 아래에서 wireshark에 의해 "**해결된**" 여러 **정보**를 찾을 수 있습니다. 예를 들어 포트/전송 프로토콜, MAC에서 제조사 등입니다. 통신에 관련된 내용을 아는 것은 흥미롭습니다.

![](<../../../images/image (893).png>)

**프로토콜 계층**

_**Statistics --> Protocol Hierarchy**_ 아래에서 통신에 **관련된** **프로토콜**과 그에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (586).png>)

**대화**

_**Statistics --> Conversations**_ 아래에서 통신의 **대화 요약**과 그에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (453).png>)

**엔드포인트**

_**Statistics --> Endpoints**_ 아래에서 통신의 **엔드포인트 요약**과 각 엔드포인트에 대한 데이터를 찾을 수 있습니다.

![](<../../../images/image (896).png>)

**DNS 정보**

_**Statistics --> DNS**_ 아래에서 캡처된 DNS 요청에 대한 통계를 찾을 수 있습니다.

![](<../../../images/image (1063).png>)

**I/O 그래프**

_**Statistics --> I/O Graph**_ 아래에서 **통신 그래프**를 찾을 수 있습니다.

![](<../../../images/image (992).png>)

### 필터

여기에서 프로토콜에 따라 wireshark 필터를 찾을 수 있습니다: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
기타 흥미로운 필터:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽 + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP 및 초기 HTTPS 트래픽 + TCP SYN + DNS 요청

### 검색

세션의 **패킷** 내에서 **내용**을 **검색**하려면 _CTRL+f_를 누르십시오. 오른쪽 버튼을 눌러 새 레이어를 주 정보 바(No., Time, Source 등)에 추가할 수 있습니다.

### 무료 pcap 실습

**무료 챌린지로 연습하세요:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## 도메인 식별

Host HTTP 헤더를 보여주는 열을 추가할 수 있습니다:

![](<../../../images/image (639).png>)

그리고 시작 HTTPS 연결에서 서버 이름을 추가하는 열(**ssl.handshake.type == 1**)을 추가할 수 있습니다:

![](<../../../images/image (408) (1).png>)

## 로컬 호스트 이름 식별

### DHCP에서

현재 Wireshark에서는 `bootp` 대신 `DHCP`를 검색해야 합니다.

![](<../../../images/image (1013).png>)

### NBNS에서

![](<../../../images/image (1003).png>)

## TLS 복호화

### 서버 개인 키로 https 트래픽 복호화

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

_서버와 개인 키의 모든 데이터를 추가하려면_ _Edit_를 누르십시오 (_IP, Port, Protocol, Key file 및 password_)

### 대칭 세션 키로 https 트래픽 복호화

Firefox와 Chrome 모두 TLS 세션 키를 기록할 수 있는 기능이 있으며, 이를 사용하여 Wireshark에서 TLS 트래픽을 복호화할 수 있습니다. 이를 통해 보안 통신에 대한 심층 분석이 가능합니다. 이 복호화를 수행하는 방법에 대한 자세한 내용은 [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)의 가이드에서 확인할 수 있습니다.

이를 감지하려면 환경 내에서 변수 `SSLKEYLOGFILE`을 검색하십시오.

공유 키 파일은 다음과 같이 보일 것입니다:

![](<../../../images/image (820).png>)

이 파일을 wireshark에 가져오려면 \_edit > preference > protocol > ssl > (Pre)-Master-Secret 로그 파일 이름에 가져오십시오:

![](<../../../images/image (989).png>)

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
{{#include ../../../banners/hacktricks-training.md}}
