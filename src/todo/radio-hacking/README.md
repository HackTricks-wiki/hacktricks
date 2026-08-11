# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

무선 보안 testing은 장치가 무선 신호를 전송하고, 수신하며, 해석하는 방식을 조사합니다. Software-defined radio (SDR)는 신호의 위치를 찾고, 동상/직교(in-phase/quadrature, I/Q) 샘플을 기록하며, 프로토콜별 하드웨어를 사용하지 않고 복조와 디코딩을 testing하는 데 도움을 줄 수 있습니다.<sup>[[1]](#references)</sup>

실용적인 workflow는 주파수 대역과 채널 폭을 식별하고, 알려진 장치 동작을 여러 번 capture한 다음, 그 결과로 생성된 신호를 비교하고, 변조 방식과 packet 구조를 파악하는 것입니다. replay 또는 transmission은 격리된 환경에서, 그리고 사용 권한이 있는 주파수와 장비에 대해서만 testing하십시오. 이 section의 페이지에서는 RFID, NFC, sub-GHz radio, infrared, BLE 및 관련 tools를 다룹니다.<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - HackRF를 사용한 소프트웨어 정의 라디오](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
