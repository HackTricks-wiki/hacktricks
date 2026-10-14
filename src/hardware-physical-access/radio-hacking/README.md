# 라디오 해킹

{{#include ../../banners/hacktricks-training.md}}

라디오 보안 테스트에서는 기기가 무선 신호를 송수신하고 해석하는 방식을 살펴봅니다. 소프트웨어 정의 라디오(SDR)를 사용하면 신호를 찾고, 동위상/직교(I/Q) 샘플을 기록하고, 특정 프로토콜 전용 하드웨어를 준비하지 않고도 복조 및 디코딩을 테스트할 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 작업 흐름은 주파수 대역과 채널 폭을 확인하고, 기기의 알려진 동작을 여러 번 캡처해 결과 신호를 비교한 다음, 변조 방식과 패킷 구조를 파악하는 것입니다. 재생 또는 송신 테스트는 격리된 환경에서, 권한이 있는 주파수와 장비로만 수행하세요. 이 섹션에서는 RFID, NFC, sub-GHz 라디오, 적외선, BLE 및 관련 도구를 다룹니다.<sup>[[1]](#references)</sup>

## 관련 인터페이스 찾기

- 출입 배지나 접촉식 키라면 [RFID/NFC 태그 유형 및 공격](pentesting-rfid.md), [Proxmark3 작업 흐름](proxmark-3.md) 또는 [iButton 및 1-Wire 키](ibutton.md)부터 살펴보세요. [Flipper Zero 가이드](flipper-zero/README.md)에는 인터페이스별 작업 링크가 있습니다.
- 리모컨 신호라면 [sub-GHz RF 및 롤링 코드](sub-ghz-rf.md) 또는 [적외선 프로토콜 및 공격](infrared.md)을 사용하세요.
- 근처의 기기와 센서라면 [BLE 광고, GATT 및 메시 테스트](pentesting-ble-bluetooth-low-energy.md) 또는 [LPWAN/LoRaWAN 보안](low-power-wide-area-network.md)을 살펴보세요.
- 캡처한 RF 신호나 출처를 모르는 RF 신호라면 [SigDigger 신호 분석](../hardware-hacking/radio.md#sigdigger) 또는 [FISSURE 프레임워크](fissure-the-rf-framework.md)를 사용하세요.

## References

- [1] [Great Scott Gadgets - HackRF를 이용한 소프트웨어 정의 라디오](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
