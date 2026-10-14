# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

기기에 물리적으로 접근할 수 있다면, 먼저 보드에서 노출된 인터페이스나 신호를 살펴보세요. [UART 시리얼 콘솔](uart.md), [JTAG/SWD 디버그 액세스](jtag.md), [I²C](i2c.md), [SPI 플래시](spi.md) 버스가 이에 해당합니다. [사이드 채널 분석](side_channel_analysis.md)과 [결함 주입](fault_injection_attacks.md)은 서로 다른 측정 및 글리칭 작업에 사용되며, [무선 신호 분석](radio.md)은 무선 진입점을 다룹니다. 대상별 RFID/NFC, sub-GHz, 적외선, BLE, LoRaWAN, iButton 절차는 [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md)를 참고하세요. 도구를 연결하기 전에 대상의 전기적 레벨과 해당 장에 설명된 제한 사항을 확인하세요.

## JTAG

JTAG(IEEE 1149.1)은 기기의 I/O 핀 주변에 배치된 셀을 통해 boundary-scan 테스트를 지원합니다. 많은 프로세서는 동일한 Test Access Port(TAP)를 통해 제조업체별 디버그 기능도 제공합니다. Boundary scan과 CPU 디버깅은 JTAG의 서로 연관된 용도이지, 같은 의미는 아닙니다.<sup>[[1]](#references)</sup>

JTAG 표준은 **boundary scan을 수행하기 위한 특정 명령**을 정의하며, 여기에는 다음이 포함됩니다.

- **BYPASS**는 1비트 우회 레지스터를 선택하여 scan chain의 다른 기기에 최소한의 오버헤드로 접근할 수 있게 합니다.
- **SAMPLE/PRELOAD**는 정상 작동 중 핀 값을 캡처하고, 다른 명령을 실행하기 전에 boundary-scan 레지스터에 값을 미리 로드할 수 있습니다.
- **EXTEST**는 핀 상태를 설정하고 읽습니다.

다음과 같은 다른 명령도 지원할 수 있습니다.

- 기기를 식별하는 **IDCODE**
- 기기 내부 테스트를 위한 **INTEST**

JTAGulator 같은 도구를 사용할 때 이러한 명령을 접할 수 있습니다.

### Test Access Port

**Test Access Port(TAP)**는 구성 요소의 JTAG 테스트 로직에 접근할 수 있게 합니다. 네 개의 신호가 필요하며 `TRST`는 선택 사항입니다.<sup>[[1]](#references)</sup>

- Test clock input (**TCK**) TCK는 TAP 컨트롤러가 단일 동작을 수행하는 빈도(즉, 상태 머신의 다음 상태로 이동하는 빈도)를 결정하는 **클록**입니다.
- Test mode select (**TMS**) input TMS는 **유한 상태 머신**을 제어합니다. 클록의 각 주기마다 기기의 JTAG TAP 컨트롤러는 TMS 핀의 전압을 확인합니다. 전압이 특정 임계값보다 낮으면 신호를 low로 간주해 0으로 해석하고, 임계값보다 높으면 high로 간주해 1로 해석합니다.
- Test data input (**TDI**)는 선택된 TAP 레지스터로 명령 또는 테스트 데이터를 직렬로 입력합니다. IEEE 1149.1은 TAP의 데이터 전송 동작을 정의하며, 선택적 명령과 디버그 레지스터는 제조업체가 정의합니다.
- Test data output (**TDO**)는 **칩에서 데이터를 출력하는** 핀입니다.
- Test reset (**TRST**) input 선택 사항인 TRST는 유한 상태 머신을 **정상 상태로 초기화**합니다. 또는 TMS를 5회 연속 클록 주기 동안 1로 유지해도 TRST 핀을 사용하는 것과 같은 방식으로 초기화할 수 있으므로 TRST는 선택 사항입니다.

PCB에 핀 표시가 되어 있는 경우도 있습니다. 표시가 없다면 핀을 **찾아야** 할 수 있습니다.

### JTAG 핀 식별

JTAG 포트를 빠르게 탐지하도록 특수 제작된 방법 중 비교적 비싼 옵션은 **JTAGulator**입니다. 이 도구는 UART 핀 배열도 식별할 수 있습니다.<sup>[[2]](#references)</sup>

이 도구에는 보드의 테스트 포인트에 연결할 수 있는 **24개 채널**이 있습니다. **IDCODE** 및 **BYPASS** 스캔을 사용해 후보 핀 조합을 나열하고, 탐지된 JTAG 신호에 해당하는 채널을 보고합니다.

JTAG 핀 배열을 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino 호환 마이크로컨트롤러에서 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용하려면 먼저 열거에 사용할 프로빙 마이크로컨트롤러 핀을 지정합니다. 핀 배열을 확인한 다음, 해당 핀을 대상 보드의 후보 테스트 포인트에 연결하세요.<sup>[[3]](#references)</sup>

JTAG 핀을 식별하는 **세 번째 방법**은 **PCB를 검사**하여 알려진 풋프린트를 찾는 것입니다. 일부 보드에는 **Tag-Connect** 풋프린트가 있습니다. 단, Tag-Connect는 JTAG, SWD, UART 또는 다른 인터페이스에 사용할 수 있는 커넥터 시스템이므로, 그 자체만으로 해당 핀이 JTAG임을 증명하지는 않습니다. 구성 요소 데이터시트와 연속성 측정을 통해 실제 신호를 확인할 수 있습니다.<sup>[[5]](#references)</sup>

## SDW

SWD는 Arm의 2핀 패킷 기반 디버그 인터페이스입니다.<sup>[[4]](#references)</sup>

이 인터페이스는 데이터용 양방향 **SWDIO**와 클록용 **SWCLK**를 사용합니다. 많은 기기는 공유 핀에서 SWD와 JTAG 중 하나를 선택할 수 있는 **Serial Wire/JTAG Debug Port(SWJ-DP)**를 구현합니다.<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 작업 그룹 — JTAG 및 boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator 문서](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Arduino JTAG 핀 열거](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — 다중 기기 시스템을 위한 저핀 수 디버그 인터페이스](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — 디버그 및 프로그래밍 케이블 풋프린트](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
