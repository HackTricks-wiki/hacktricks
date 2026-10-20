# Wifi Pcap 분석

{{#include ../../../banners/hacktricks-training.md}}

## BSSID 확인

Wireshark에서 Wi-Fi 캡처를 연 상태로 _Wireless → WLAN Traffic_을 선택하면 캡처에서 관찰된 무선 네트워크를 요약해서 볼 수 있습니다. 각 행은 하나의 무선 네트워크를 나타냅니다.<sup>[[1]](#references)</sup>

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (106).png>)

![Wifi Pcap Analysis - Check BSSIDs: When you receive a capture whose principal traffic is Wifi using WireShark you can start investigating all the SSIDs of the capture with Wireless --...](<../../../images/image (492).png>)

### Brute Force

WPA/WPA2-PSK 캡처의 경우, `aircrack-ng`는 사용 가능한 4-way EAPOL handshake가 있어야 하며 사전을 사용해 후보 passphrase를 테스트합니다. `-w`로 wordlist를 지정하고 `-b`로 대상 access point의 BSSID를 지정합니다.<sup>[[2]](#references)</sup>

```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```

후보가 일치하면 Aircrack-ng가 pre-shared key를 복구합니다. 캡처와 보안 모드가 지원되는 경우, 일치하는 비밀번호와 SSID를 Wireshark의 802.11 복호화 설정에 입력할 수 있습니다.<sup>[[2]](#references)[[5]](#references)</sup>

## 비콘 / Side Channel의 데이터

**beacon-side-channel 트래픽에서 데이터가 유출되고 있다고 의심된다면**, `wlan contains "NAMEofNETWORK"` 또는 `wlan.ssid == "NAMEofNETWORK"`와 같은 display filter를 적용한 다음, 일치하는 프레임에서 의심스러운 문자열을 확인하세요. 첫 번째 필터는 넓은 범위의 바이트 검색이고, 두 번째 필터는 SSID 필드와 일치하는 항목을 찾습니다.<sup>[[3]](#references)[[4]](#references)</sup>

## Wi-Fi 네트워크에서 알 수 없는 MAC 주소 찾기

Wireshark에서 `wlan.ta`는 송신자 주소로, `wlan.addr`는 하드웨어/MAC 주소로 제공됩니다. display filter에서 논리 연산자를 사용해 이 필드들을 조합할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>

- `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

이미 **MAC 주소를 알고 있다면**, `&& !(wlan.addr == 5c:51:88:31:a0:3b)`와 같은 조건을 추가해 출력에서 해당 주소를 제외하세요.

네트워크 내부에서 통신하는 **알 수 없는 MAC** 주소를 발견했다면, `wlan.addr == <MAC address> && (ftp || http || ssh || telnet)`과 같은 필터를 사용해 해당 트래픽의 범위를 좁히세요. FTP, HTTP, SSH, Telnet 필터는 Wireshark가 해당 복호화된 페이로드를 디섹션할 수 있는 경우에만 유용합니다.<sup>[[3]](#references)[[5]](#references)</sup>

## 트래픽 복호화

Wireshark에 802.11 복호화 키를 추가하려면 _Edit → Preferences → Protocols → IEEE 802.11_을 열고 _Decryption Keys_ 옆의 _Edit_을 클릭하세요.<sup>[[5]](#references)</sup>

![Wi-Fi 네트워크에서 알 수 없는 MAC 주소 찾기 - 트래픽 복호화: 네트워크 내부에서 통신하는 알 수 없는 MAC 주소를 발견했다면 다음과 같은 필터를 사용할 수 있습니다:...](<../../../images/image (499).png>)

WPA/WPA2의 경우 Wireshark에는 일반적으로 EAPOL 4-way handshake와 일치하는 비밀번호/SSID가 필요합니다. transient key를 제공하면 handshake가 없어도 됩니다. WPA3에서 연결별 복호화를 하려면 해당 연결의 PMK가 필요합니다.<sup>[[5]](#references)</sup>

Wi-Fi 트래픽을 복구한 뒤 애플리케이션 계층 TLS 트래픽을 복호화하려면 [Wireshark tricks](wireshark-tricks.md#decrypting-tls)를 참조하세요.

## References

- [1] [Wireshark 사용자 가이드: WLAN 트래픽](https://www.wireshark.org/docs/wsug_html_chunked/ChWirelessWLANTraffic.html)
- [2] [Aircrack-ng](https://www.aircrack-ng.org/doku.php?id=aircrack-ng)
- [3] [Wireshark 사용자 가이드: Display Filter 표현식 작성](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)
- [4] [Wireshark Display Filter 참조: IEEE 802.11 무선 LAN](https://www.wireshark.org/docs/dfref/w/wlan.html)
- [5] [Wireshark 사용자 가이드: IEEE 802.11 WLAN 복호화 키](https://www.wireshark.org/docs/wsug_html_chunked/Ch80211Keys.html)
{{#include ../../../banners/hacktricks-training.md}}
