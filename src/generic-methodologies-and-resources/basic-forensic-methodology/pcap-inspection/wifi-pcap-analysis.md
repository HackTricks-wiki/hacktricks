# Wifi Pcap 분석

## BSSID 확인

Wireshark에서 Wi-Fi 캡처를 연 상태로 _Wireless → WLAN Traffic_을 선택하면 캡처에서 관찰된 wireless networks를 요약할 수 있습니다. 각 행은 하나의 wireless network를 나타냅니다.<sup>[[1]](#references)</sup>

![Wifi Pcap 분석 - BSSID 확인: WireShark를 사용해 주요 트래픽이 Wifi인 캡처를 받으면 Wireless --...를 통해 캡처의 모든 SSID 조사를 시작할 수 있습니다.](<../../../images/image (106).png>)

![Wifi Pcap 분석 - BSSID 확인: WireShark를 사용해 주요 트래픽이 Wifi인 캡처를 받으면 Wireless --...를 통해 캡처의 모든 SSID 조사를 시작할 수 있습니다.](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK captures의 경우 `aircrack-ng`는 사용 가능한 four-way EAPOL handshake를 필요로 하며 dictionary를 사용해 후보 passphrase를 테스트합니다. `-w`를 사용해 wordlist를 지정하고 `-b`를 사용해 access point의 BSSID를 대상으로 지정합니다.<sup>[[2]](#references)</sup>
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
후보가 일치하면 Aircrack-ng가 pre-shared key를 복구합니다. 그런 다음 캡처와 보안 모드가 지원하는 경우, 일치하는 password와 SSID를 Wireshark의 802.11 decryption 설정에 구성할 수 있습니다.<sup>[[2]](#references)[[5]](#references)</sup>

## Beacons / Side Channel의 데이터

**데이터가 beacon-side-channel traffic에서 leak되고 있다고 의심되는 경우**, `wlan contains "NAMEofNETWORK"` 또는 `wlan.ssid == "NAMEofNETWORK"`와 같은 display filter로 시작한 다음, 일치하는 프레임에서 의심스러운 문자열을 검사합니다. 첫 번째 형식은 광범위한 byte search이고, 두 번째 형식은 SSID 필드와 일치합니다.<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi Network에서 알 수 없는 MAC 주소 찾기

Wireshark는 `wlan.ta`를 transmitter address로, `wlan.addr`를 hardware/MAC address로 노출합니다. display filter는 logical operator를 사용하여 이러한 필드를 결합할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 **MAC addresses를 알고 있다면**, `&& !(wlan.addr == 5c:51:88:31:a0:3b)`와 같은 검사를 추가하여 해당 주소를 output에서 제거합니다.

Network 내부에서 통신하는 **알 수 없는 MAC** addresses를 탐지했다면, `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`과 같은 filter를 사용하여 해당 traffic의 범위를 좁힙니다. FTP, HTTP, SSH 및 Telnet filter는 Wireshark가 해당 decrypted payload를 dissect할 수 있을 때만 유용합니다.<sup>[[3]](#references)[[5]](#references)</sup>

## Traffic Decrypt

Wireshark에 802.11 decryption key를 추가하려면 _Edit → Preferences → Protocols → IEEE 802.11_을 열고 _Decryption Keys_ 옆의 _Edit_을 클릭합니다.<sup>[[5]](#references)</sup>

![Wi-Fi Network에서 알 수 없는 MAC 주소 찾기 - Traffic Decrypt: Network 내부에서 통신하는 알 수 없는 MAC 주소를 탐지했다면 다음과 같은 filter를 사용할 수 있습니다:...](<../../../images/image (499).png>)

WPA/WPA2의 경우 Wireshark에는 일반적으로 EAPOL four-way handshake와 일치하는 password/SSID가 필요합니다. transient key를 제공하면 handshake 요구 사항을 피할 수 있습니다. WPA3 per-connection decryption에는 해당 connection의 PMK가 필요합니다.<sup>[[5]](#references)</sup>

## References

- [1] [Wireshark User's Guide: WLAN Traffic](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark User's Guide: Display Filter Expression 작성](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter Reference: IEEE 802.11 wireless LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark User's Guide: IEEE 802.11 WLAN Decryption Keys](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
