# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG를 사용하면 boundary scan을 수행할 수 있습니다. Boundary scan은 각 핀에 대한 embedded boundary-scan cells 및 registers를 포함한 특정 회로를 분석합니다.

JTAG standard는 **boundary scan을 수행하기 위한 특정 commands**를 정의하며, 다음을 포함합니다.

- **BYPASS**는 다른 chip을 통과해야 하는 overhead 없이 특정 chip을 테스트할 수 있도록 합니다.
- **SAMPLE/PRELOAD**는 device가 정상적인 functioning mode일 때 device로 들어오고 나가는 data를 sample합니다.
- **EXTEST**는 pin states를 설정하고 읽습니다.

다음과 같은 다른 commands도 지원할 수 있습니다.

- device 식별을 위한 **IDCODE**
- device 내부 테스트를 위한 **INTEST**

JTAGulator와 같은 tool을 사용할 때 이러한 instructions를 접하게 될 수 있습니다.

### The Test Access Port

Boundary scan에는 네 개의 wire로 구성된 **Test Access Port (TAP)** 테스트가 포함됩니다. TAP는 component에 내장된 **JTAG test support** functions에 대한 access를 제공하는 general-purpose port입니다. TAP는 다음 다섯 가지 signals를 사용합니다.

- Test clock input (**TCK**) TCK는 TAP controller가 single action을 수행하는 빈도, 즉 state machine에서 다음 state로 jump하는 방식을 정의하는 **clock**입니다.
- Test mode select (**TMS**) input TMS는 **finite state machine**을 제어합니다. clock의 각 beat에서 device의 JTAG TAP controller는 TMS pin의 voltage를 확인합니다. voltage가 특정 threshold보다 낮으면 signal은 low로 간주되어 0으로 해석되고, voltage가 특정 threshold보다 높으면 signal은 high로 간주되어 1로 해석됩니다.
- Test data input (**TDI**) TDI는 **scan cells를 통해 chip으로 data를 보내는** pin입니다. JTAG는 이 pin을 통한 communication protocol을 정의하지 않으므로 각 vendor가 이를 정의해야 합니다.
- Test data output (**TDO**) TDO는 **chip에서 data를 내보내는** pin입니다.
- Test reset (**TRST**) input 선택 사항인 TRST는 finite state machine을 **정상적으로 알려진 state로** reset합니다. 또는 TMS를 5회의 연속 clock cycle 동안 1로 유지하면 TRST pin과 동일하게 reset이 실행되므로 TRST는 선택 사항입니다.

때로는 PCB에 이러한 pins가 표시되어 있는 것을 확인할 수 있습니다. 다른 경우에는 **직접 찾아야** 할 수 있습니다.

### Identifying JTAG pins

JTAG ports를 감지하는 가장 빠르지만 가장 비싼 방법은 이 목적을 위해 특별히 제작된 device인 **JTAGulator**를 사용하는 것입니다(다만 **UART pinouts도 감지할 수 있습니다**).

JTAGulator에는 board의 pins에 연결할 수 있는 **24개 channels**가 있습니다. 그런 다음 **BF attack**을 수행하여 가능한 모든 combinations에 **IDCODE** 및 **BYPASS** boundary scan commands를 전송합니다. response를 받으면 각 JTAG signal에 해당하는 channel을 표시합니다.

JTAG pinouts를 식별하는 더 저렴하지만 훨씬 느린 방법은 Arduino-compatible microcontroller에 로드한 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)을 사용하는 것입니다.

**JTAGenum**을 사용하려면 먼저 enumeration에 사용할 **probing device의 pins를 정의**해야 합니다. 해당 device의 pinout diagram을 참조한 후, 이 pins를 target device의 test points에 연결해야 합니다.

JTAG pins를 식별하는 **세 번째 방법**은 PCB에서 pinouts 중 하나를 **inspect하는 것**입니다. 경우에 따라 PCB가 편리하게 **Tag-Connect interface**를 제공할 수 있으며, 이는 board에 JTAG connector도 있다는 명확한 indication입니다. 해당 interface가 어떻게 생겼는지는 [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)에서 확인할 수 있습니다. 또한 **PCB의 chipsets datasheets**를 inspect하면 JTAG interfaces를 가리키는 pinout diagrams를 발견할 수 있습니다.

## SDW

SWD는 debugging을 위해 설계된 ARM-specific protocol입니다.

SWD interface에는 **두 개의 pins**가 필요합니다. 하나는 bidirectional **SWDIO** signal로, JTAG의 **TDI 및 TDO pins와 clock**에 해당하며, 다른 하나는 JTAG의 **TCK**에 해당하는 **SWCLK**입니다. 많은 devices가 **Serial Wire 또는 JTAG Debug Port (SWJ-DP)**를 지원합니다. 이는 SWD probe 또는 JTAG probe를 target에 연결할 수 있게 하는 combined JTAG 및 SWD interface입니다.

{{#include ../../banners/hacktricks-training.md}}
