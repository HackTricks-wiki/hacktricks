{{#include ../../../banners/hacktricks-training.md}}

# BSSID 확인

WireShark를 사용하여 주된 트래픽이 Wifi인 캡처를 수신하면 _Wireless --> WLAN Traffic_을 통해 캡처의 모든 SSID를 조사할 수 있습니다:

![](<../../../images/image (424).png>)

![](<../../../images/image (425).png>)

## 무차별 대입

해당 화면의 열 중 하나는 **pcap 내에서 인증이 발견되었는지 여부**를 나타냅니다. 만약 그렇다면 `aircrack-ng`를 사용하여 무차별 대입을 시도할 수 있습니다:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
예를 들어, PSK(사전 공유 키)를 보호하는 WPA 비밀번호를 검색하여 나중에 트래픽을 복호화하는 데 필요합니다.

# 비콘 / 사이드 채널의 데이터

**Wifi 네트워크의 비콘 내부에서 데이터가 유출되고 있다고 의심되는 경우** 다음과 같은 필터를 사용하여 네트워크의 비콘을 확인할 수 있습니다: `wlan contains <NAMEofNETWORK>` 또는 `wlan.ssid == "NAMEofNETWORK"` 필터링된 패킷 내에서 의심스러운 문자열을 검색합니다.

# Wifi 네트워크에서 알 수 없는 MAC 주소 찾기

다음 링크는 **Wifi 네트워크 내에서 데이터를 전송하는 기계**를 찾는 데 유용합니다:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 **MAC 주소를 알고 있다면 출력에서 제거할 수 있습니다** 다음과 같은 체크를 추가하여: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

네트워크 내에서 통신하는 **알 수 없는 MAC** 주소를 감지한 후, 다음과 같은 **필터**를 사용할 수 있습니다: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` 트래픽을 필터링합니다. ftp/http/ssh/telnet 필터는 트래픽을 복호화한 경우에 유용합니다.

# 트래픽 복호화

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![](<../../../images/image (426).png>)

{{#include ../../../banners/hacktricks-training.md}}
