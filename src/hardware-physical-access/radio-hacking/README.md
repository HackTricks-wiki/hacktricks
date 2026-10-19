# Radio 해킹

{{#include ../../banners/hacktricks-training.md}}

Radio 보안 테스트는 기기가 무선 신호를 송신하고 수신하며 해석하는 방식을 살펴봅니다. 소프트웨어 정의 라디오(SDR)를 사용하면 신호를 찾고, 동위상/직교(I/Q) 샘플을 기록하고, 특정 프로토콜 전용 하드웨어에 의존하지 않고 복조와 디코딩을 테스트할 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 작업 흐름은 주파수 대역과 채널 폭을 확인하고, 알려진 기기 동작을 여러 번 캡처해 신호를 비교한 다음, 변조 방식과 패킷 구조를 파악하는 것입니다. replay 또는 송신 테스트는 격리된 환경에서, 사용 권한이 있는 주파수와 장비로만 수행하세요. 이 섹션의 페이지에서는 RFID, NFC, sub-GHz radio, infrared, BLE 및 관련 도구를 다룹니다.<sup>[[1]](#references)</sup>

## 관련 인터페이스 찾기

- 출입 배지나 접촉식 키라면 [RFID/NFC 태그 유형 및 공격](pentesting-rfid.md), [Proxmark3 작업 흐름](proxmark-3.md), 또는 [iButton 및 1-Wire 키](ibutton.md)부터 살펴보세요. [Flipper Zero 가이드](flipper-zero/README.md)에는 인터페이스별 동작으로 연결되는 링크가 있습니다.
- 원격 제어 신호라면 [sub-GHz RF 및 rolling code](sub-ghz-rf.md) 또는 [infrared 프로토콜 및 공격](infrared.md)을 사용하세요.
- 주변 기기와 센서라면 [BLE 광고, GATT 및 mesh 테스트](pentesting-ble-bluetooth-low-energy.md) 또는 [LPWAN/LoRaWAN 보안](low-power-wide-area-network.md)을 살펴보세요.
- 캡처한 RF 신호나 알 수 없는 RF 신호라면 [SigDigger 신호 분석](../hardware-hacking/radio.md#sigdigger) 또는 [FISSURE 프레임워크](fissure-the-rf-framework.md)를 사용하세요.
- 위성 터미널 다운링크는 [VSAT 순방향 링크 신호 주입](vsat-forward-link-injection.md)을 참조하세요.



## References

- [1] [Great Scott Gadgets - HackRF를 이용한 소프트웨어 정의 라디오](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
