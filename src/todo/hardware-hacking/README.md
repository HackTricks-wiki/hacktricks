# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1)은 장치의 I/O 핀 주변에 배치된 셀을 통해 boundary-scan 테스트를 지원합니다. 많은 프로세서는 동일한 Test Access Port (TAP)를 통해 vendor-specific debug 기능도 제공합니다. boundary scan과 CPU debugging은 JTAG의 서로 관련된 용도이며, 동의어는 아닙니다.<sup>[[1]](#references)</sup>

JTAG 표준은 **boundary scan을 수행하기 위한 특정 명령**을 정의하며, 다음을 포함합니다.

- **BYPASS**는 1비트 우회 레지스터를 선택하여 scan chain의 다른 장치에 최소한의 오버헤드로 접근할 수 있게 합니다.
- **SAMPLE/PRELOAD**는 정상 작동 중 핀 값을 캡처하고, 다른 명령을 실행하기 전에 boundary-scan 레지스터에 값을 미리 로드할 수 있습니다.
- **EXTEST**는 핀 상태를 설정하고 읽습니다.

다음과 같은 다른 명령도 지원할 수 있습니다.

- 장치 식별을 위한 **IDCODE**
- 장치 내부 테스트를 위한 **INTEST**

JTAGulator와 같은 도구를 사용할 때 이러한 명령을 접할 수 있습니다.

### The Test Access Port

**Test Access Port (TAP)**는 컴포넌트의 JTAG test logic에 접근할 수 있게 합니다. 네 개의 신호가 필요하며 `TRST`는 선택 사항입니다.<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK는 TAP controller가 단일 동작을 수행하는 빈도, 즉 state machine에서 다음 상태로 이동하는 빈도를 정의하는 **clock**입니다.
- Test mode select (**TMS**) input TMS는 **finite state machine**을 제어합니다. clock의 각 주기마다 장치의 JTAG TAP controller는 TMS 핀의 전압을 확인합니다. 전압이 특정 임계값보다 낮으면 신호를 low로 간주하고 0으로 해석하며, 특정 임계값보다 높으면 신호를 high로 간주하고 1로 해석합니다.
- Test data input (**TDI**)는 선택된 TAP 레지스터로 serial instruction 또는 test data를 shift합니다. IEEE 1149.1은 TAP transfer 동작을 정의하며, vendor는 optional instruction과 debug register를 정의합니다.
- Test data output (**TDO**) TDO는 **chip에서 data를 내보내는** 핀입니다.
- Test reset (**TRST**) input 선택 사항인 TRST는 finite state machine을 **정상적인 알려진 상태**로 reset합니다. 또는 TMS를 5개의 연속된 clock cycle 동안 1로 유지하면 TRST 핀이 수행하는 것과 동일하게 reset이 실행되므로 TRST는 선택 사항입니다.

PCB에서 이러한 핀이 표시된 것을 찾을 수 있는 경우도 있습니다. 다른 경우에는 직접 **찾아야** 할 수 있습니다.

### Identifying JTAG pins

JTAG port를 감지하기 위한 빠르고 목적에 특화된 옵션은 비교적 고가인 **JTAGulator**이며, UART pinout도 식별할 수 있습니다.<sup>[[2]](#references)</sup>

JTAGulator에는 보드의 test point에 연결할 수 있는 **24개 채널**이 있습니다. **IDCODE** 및 **BYPASS** scan을 사용해 후보 핀 조합을 열거하고, 감지된 JTAG 신호에 해당하는 채널을 보고합니다.

JTAG pinout을 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino-compatible microcontroller에 로드한 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용할 때는 먼저 enumeration에 사용할 probing microcontroller 핀을 정의합니다. pinout을 확인한 다음 해당 핀을 대상 보드의 후보 test point에 연결합니다.<sup>[[3]](#references)</sup>

JTAG 핀을 식별하는 **세 번째 방법**은 알려진 footprint가 있는지 **PCB를 검사하는 것**입니다. 일부 보드는 **Tag-Connect** footprint를 노출하지만, Tag-Connect는 JTAG, SWD, UART 또는 다른 interface를 전달할 수 있는 connector system이므로, 이것만으로 해당 핀이 JTAG이라는 증거가 되지는 않습니다. 그런 다음 컴포넌트 datasheet와 continuity measurement를 통해 실제 신호를 식별할 수 있습니다.<sup>[[5]](#references)</sup>

## SDW

SWD는 Arm의 2핀 packet-based debug interface입니다.<sup>[[4]](#references)</sup>

이 interface는 data에 양방향 **SWDIO**를 사용하고 clock에 **SWCLK**를 사용합니다. 많은 장치는 공유 핀에서 SWD와 JTAG 간 선택을 허용하는 **Serial Wire/JTAG Debug Port (SWJ-DP)**를 구현합니다.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 working group — JTAG 및 boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator 문서](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG 핀 열거](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — 다중 장치 시스템을 위한 낮은 핀 수의 Debug Interface](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Debug 및 programming cable footprint](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
