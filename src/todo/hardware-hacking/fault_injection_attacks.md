# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection은 hardware-security 분야에서 흔히 **glitching**이라고 불리며, 기기가 작동하는 동안 의도적으로 교란하여 잘못된 연산을 수행하도록 만드는 기법입니다. 유용한 fault는 명령어를 건너뛰거나, 데이터를 손상시키거나, 보안 검사를 우회하거나, 비밀 정보를 도출할 수 있는 잘못된 cryptographic output을 생성할 수 있습니다.<sup>[[1]](#references)</sup>

일반적인 기법은 공급 전압이나 clock을 조작하거나, electromagnetic interference를 주입하거나, optical 또는 laser stimulation을 사용하는 방식입니다.<sup>[[1]](#references)</sup> 정밀도와 침습성에는 차이가 있지만, 성공적인 테스트를 위해서는 일반적으로 반복 가능한 trigger와 timing, pulse width, intensity를 체계적으로 변경하는 작업이 필요합니다. 안정적인 baseline에서 시작하고, reset과 malformed output을 별도로 기록하며, 한 번에 하나의 parameter만 변경하십시오.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - 의도적인 electromagnetic interference에 기반한 비침습적 trigger-free Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware 개요 및 비교](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
