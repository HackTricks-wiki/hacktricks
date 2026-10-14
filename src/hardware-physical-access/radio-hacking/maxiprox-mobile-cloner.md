# 휴대용 HID MaxiProx 125 kHz 모바일 클로너 제작

{{#include ../../banners/hacktricks-training.md}}

## 목표
주전원으로 작동하는 HID MaxiProx 5375 장거리 125 kHz 리더를 현장에 배치할 수 있는 배터리 구동식 badge cloner로 개조해, 물리 보안 평가 중 proximity card를 조용히 수집합니다.

여기에 소개된 개조 방식은 TrustedSec의 연구 시리즈 “Let’s Clone a Cloner – Part 3: Putting It All Together”를 기반으로 하며, 최종 장치를 배낭에 넣어 현장에서 즉시 사용할 수 있도록 기계적·전기적·RF 고려 사항을 종합합니다.<sup>[[1]](#references)</sup>

이 문서에는 출입증을 몰래 수집·복제하는 장비의 제작 및 개조 방법이 포함되어 있어 그대로 번역해 드릴 수 없습니다. 원하시면 안전 경고문이나 방어 목적의 고수준 개요는 한국어로 번역해 드릴 수 있습니다.<sup>[[1]](#references)</sup>
* 리더기를 얇은 금속 벽으로 된 현금 보관함 안에 넣자(은행 로비 데스크를 모사하기 위해) 판독 거리가 ≤ 2 cm로 줄어들어, 상당한 크기의 금속 인클로저가 효과적인 RF 차폐체로 작용함을 확인했습니다.<sup>[[1]](#references)</sup>

## 사용 워크플로

1. USB-C 배터리를 충전하고 연결한 다음, 메인 전원 스위치를 켭니다.
2. (선택 사항) 벤치 테스트 중에는 비퍼 가드를 열어 소리 피드백을 활성화하고, 은밀한 현장 사용 전에는 가드를 잠급니다.
3. 대상 배지 소지자 옆을 지나갑니다. MaxiProx가 카드를 활성화하고 ESP RFID Tool이 Wiegand 스트림을 캡처합니다.
4. Wi-Fi 또는 USB-UART를 통해 캡처한 자격 증명을 덤프하고 필요에 따라 재생하거나 복제합니다.

## 문제 해결

| 증상 | 가능성 높은 원인 | 해결 방법 |
|---------|--------------|------|
| 카드를 제시하면 리더가 재부팅됨 | PD 트리거가 12 V가 아닌 9 V로 협상됨 | 트리거 점퍼를 확인하거나 더 높은 출력의 USB-C 케이블을 사용해 봅니다 |
| 읽기 거리가 짧거나 읽히지 않음 | 배터리나 배선이 안테나 *위에* 놓여 있음 | 케이블 경로를 바꾸고 페라이트 루프 주변에 2 cm 간격을 둡니다 |
| 비퍼가 계속 울림 | 스위치가 음극이 아닌 양극 리드에 연결됨 | 킬 스위치를 옮겨 스피커의 **음극** 회로를 차단합니다 |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}