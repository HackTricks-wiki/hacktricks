# Wifi Pcap Analysis

{{#include ../../../banners/hacktricks-training.md}}

## BSSID 확인

WireShark를 사용하여 주요 트래픽이 Wifi인 capture를 받으면 _Wireless --> WLAN Traffic_을 통해 capture의 모든 SSID 조사를 시작할 수 있습니다:

![Wifi Pcap Analysis - BSSID 확인: WireShark를 사용하여 주요 트래픽이 Wifi인 capture를 받으면 Wireless --...를 통해 capture의 모든 SSID 조사를 시작할 수 있습니다](<../../../images/image (106).png>)

![Wifi Pcap Analysis - BSSID 확인: WireShark를 사용하여 주요 트래픽이 Wifi인 capture를 받으면 Wireless --...를 통해 capture의 모든 SSID 조사를 시작할 수 있습니다](<../../../images/image (492).png>)

### Brute Force

해당 화면의 열 중 하나는 **pcap 내부에서 인증이 발견되었는지 여부**를 나타냅니다. 인증이 발견된 경우 `aircrack-ng`를 사용하여 Brute force를 시도할 수 있습니다:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
예를 들어 PSK(pre shared-key)를 보호하는 WPA passphrase를 가져오며, 이는 나중에 트래픽을 복호화하는 데 필요합니다.

## Beacons / Side Channel의 데이터

**데이터가 WiFi 네트워크의 비콘 내부에서 leak되고 있다고 의심되는 경우**, 다음과 같은 filter를 사용하여 네트워크의 비콘을 확인할 수 있습니다: `wlan contains <NAMEofNETWORK>` 또는 `wlan.ssid == "NAMEofNETWORK"`. 필터링된 패킷에서 의심스러운 문자열을 검색합니다.

## WiFi 네트워크에서 알 수 없는 MAC 주소 찾기

다음 링크는 **WiFi 네트워크 내부에서 데이터를 전송하는 machine**을 찾는 데 유용합니다:

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 알고 있는 **MAC 주소는 다음과 같은 check를 추가하여 output에서 제거할 수 있습니다**: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

네트워크 내부에서 통신하는 **알 수 없는 MAC** 주소를 탐지했다면 다음과 같은 **filter**를 사용하여 해당 트래픽을 필터링할 수 있습니다: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)`. 트래픽을 복호화한 경우 ftp/http/ssh/telnet filter가 유용하다는 점에 유의하세요.

## 트래픽 복호화

Edit --> Preferences --> Protocols --> IEEE 802.11--> Edit

![WiFi 네트워크에서 알 수 없는 MAC 주소 찾기 - 트래픽 복호화: 네트워크 내부에서 통신하는 알 수 없는 MAC 주소를 탐지했다면 다음과 같은 filter를 사용하여 해당 트래픽을 필터링할 수 있습니다...](<../../../images/image (499).png>)

{{#include ../../../banners/hacktricks-training.md}}
