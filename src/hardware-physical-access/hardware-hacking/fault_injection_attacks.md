# 결함 주입 공격

{{#include ../../banners/hacktricks-training.md}}

결함 주입은 하드웨어 보안 분야에서 흔히 **glitching**이라고 불리며, 장치가 작동하는 동안 의도적으로 교란해 잘못된 연산을 수행하게 하는 기법입니다. 유용한 결함은 명령어를 건너뛰거나, 데이터를 손상시키거나, 보안 검사를 우회하거나, 비밀 정보를 알아내는 데 사용할 수 있는 잘못된 암호화 출력을 생성할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 기법으로는 공급 전압이나 클럭을 조작하거나, 전자기 간섭을 주입하거나, 광학 또는 레이저 자극을 사용하는 방법이 있습니다.<sup>[[1]](#references)</sup> 각 기법의 정밀도와 침습성은 다르지만, 성공적인 테스트에는 대체로 반복 가능한 트리거와 타이밍, 펄스 폭, 강도에 대한 체계적인 조정이 필요합니다. 안정적인 기준 상태에서 시작해 재설정과 잘못된 출력을 따로 기록하고, 한 번에 하나의 매개변수만 변경하세요.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi 외 - 의도적 전자기 간섭 기반 비침습 트리거 없는 결함 주입 방법](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer 문서 - 캡처 하드웨어 개요 및 비교](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
