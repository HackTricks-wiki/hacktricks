# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

물리적으로 접근할 수 있는 장치라면, 먼저 보드나 신호에 노출된 인터페이스부터 확인하세요. [UART serial consoles](uart.md), [JTAG/SWD debug access](jtag.md), [I²C](i2c.md), [SPI flash](spi.md) 버스를 살펴보세요. [Side-channel analysis](side_channel_analysis.md)와 [fault injection](fault_injection_attacks.md)은 각각 다른 측정 및 glitching 작업을 다루며, [radio signal analysis](radio.md)는 무선 진입점을 다룹니다. 도구를 연결하기 전에 대상의 전기적 레벨과 관련 장에 설명된 제한 사항을 확인하세요.

## JTAG

JTAG (IEEE 1149.1)는 장치의 I/O 핀 주변에 배치된 셀을 통해 boundary-scan 테스트를 지원합니다. 많은 프로세서는 동일한 Test Access Port (TAP)를 통해 벤더별 디버그 기능도 제공합니다. boundary scan과 CPU 디버깅은 JTAG의 서로 연관된 용도이지, 같은 의미는 아닙니다.<sup>[[1]](#references)</sup>

JTAG 표준은 **boundary scan을 수행하기 위한 특정 명령**을 정의하며, 여기에는 다음이 포함됩니다.

- **BYPASS**는 1비트 bypass register를 선택하여 scan chain의 다른 장치에 최소한의 오버헤드로 접근할 수 있게 합니다.
- **SAMPLE/PRELOAD**는 정상 작동 중 핀 값을 캡처하고, 다른 명령을 실행하기 전에 boundary-scan register에 값을 미리 설정할 수 있습니다.
- **EXTEST**는 핀 상태를 설정하고 읽습니다.

다음과 같은 다른 명령도 지원할 수 있습니다.

- 장치를 식별하는 **IDCODE**
- 장치 내부 테스트를 위한 **INTEST**

JTAGulator 같은 도구를 사용할 때 이러한 명령을 접할 수 있습니다.

### Test Access Port

**Test Access Port (TAP)**는 구성 요소의 JTAG 테스트 로직에 접근할 수 있게 합니다. 네 개의 신호가 필요하며 `TRST`는 선택 사항입니다.<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK는 TAP controller가 단일 동작을 얼마나 자주 수행할지 정의하는 **clock**입니다. 다시 말해, 상태 머신에서 다음 상태로 이동하는 주기를 결정합니다.
- Test mode select (**TMS**) input TMS는 **finite state machine**을 제어합니다. clock의 각 주기마다 장치의 JTAG TAP controller는 TMS 핀의 전압을 확인합니다. 전압이 특정 임계값보다 낮으면 신호를 low로 보고 0으로 해석하며, 특정 임계값보다 높으면 high로 보고 1로 해석합니다.
- Test data input (**TDI**)는 직렬 명령 또는 테스트 데이터를 선택된 TAP register로 shift합니다. IEEE 1149.1은 TAP 전송 동작을 정의하고, 벤더는 선택적 명령 및 debug register를 정의합니다.
- Test data output (**TDO**)는 **칩에서 데이터를 내보내는** 핀입니다.
- Test reset (**TRST**) input 선택 사항인 TRST는 finite state machine을 **정상 상태로 초기화**합니다. 또는 TMS를 5회 연속 clock 주기 동안 1로 유지해도 TRST 핀을 사용하는 것과 같은 방식으로 초기화할 수 있으므로 TRST는 선택 사항입니다.

때로는 PCB에 표시된 핀을 찾을 수 있습니다. 그렇지 않은 경우에는 핀을 **찾아야** 할 수도 있습니다.

### JTAG 핀 식별

JTAG 포트를 감지하는 빠르고 목적에 맞게 설계됐지만 비교적 고가인 옵션은 **JTAGulator**입니다. UART 핀아웃도 식별할 수 있습니다.<sup>[[2]](#references)</sup>

이 장치에는 보드의 테스트 지점에 연결할 수 있는 **24개 채널**이 있습니다. **IDCODE** 및 **BYPASS** scan을 사용해 핀 조합 후보를 열거하고, 감지된 JTAG 신호에 해당하는 채널을 표시합니다.

JTAG 핀아웃을 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino 호환 마이크로컨트롤러에 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 올려 사용하는 것입니다.

**JTAGenum**을 사용하려면 먼저 열거에 사용할 프로빙 마이크로컨트롤러 핀을 지정합니다. 핀아웃을 확인한 다음, 해당 핀을 대상 보드의 후보 테스트 지점에 연결하세요.<sup>[[3]](#references)</sup>

JTAG 핀을 식별하는 **세 번째 방법**은 **PCB를 살펴보고** 알려진 footprint가 있는지 확인하는 것입니다. 일부 보드에는 **Tag-Connect** footprint가 노출되어 있습니다. 다만 Tag-Connect는 JTAG, SWD, UART 또는 다른 인터페이스를 연결할 수 있는 커넥터 시스템이므로, 그 자체만으로 해당 핀이 JTAG라는 증거가 되지는 않습니다. 구성 요소의 datasheet와 연속성 측정을 통해 실제 신호를 식별할 수 있습니다.<sup>[[5]](#references)</sup>

## SDW

SWD는 Arm의 2핀 패킷 기반 디버그 인터페이스입니다.<sup>[[4]](#references)</sup>

이 인터페이스는 데이터에 양방향 **SWDIO**, clock에 **SWCLK**를 사용합니다. 여러 장치에서 공유 핀으로 SWD와 JTAG를 선택할 수 있도록 **Serial Wire/JTAG Debug Port (SWJ-DP)**를 구현합니다.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 작업 그룹 — JTAG 및 boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator 문서](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG 핀 열거](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — 다중 장치 시스템을 위한 저핀 수 디버그 인터페이스](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — 디버그 및 프로그래밍 케이블 footprint](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
