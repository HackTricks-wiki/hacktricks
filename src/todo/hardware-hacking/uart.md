# UART

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

UART는 직렬 프로토콜로, 구성 요소 간에 데이터를 한 번에 한 비트씩 전송합니다. 반면, 병렬 통신 프로토콜은 여러 채널을 통해 데이터를 동시에 전송합니다. 일반적인 직렬 프로토콜에는 RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express 및 USB가 포함됩니다.

일반적으로 UART가 유휴 상태일 때 라인은 높은 상태(논리 1 값)로 유지됩니다. 그런 다음 데이터 전송의 시작을 신호하기 위해 송신기는 수신기에 시작 비트를 전송하며, 이 동안 신호는 낮은 상태(논리 0 값)로 유지됩니다. 다음으로 송신기는 실제 메시지를 포함하는 5~8개의 데이터 비트를 전송하고, 그 뒤에 선택적 패리티 비트와 하나 또는 두 개의 정지 비트(논리 1 값)를 전송합니다. 오류 검사용으로 사용되는 패리티 비트는 실제로는 거의 보이지 않습니다. 정지 비트(또는 비트)는 전송의 끝을 나타냅니다.

가장 일반적인 구성은 8N1이라고 부릅니다: 8개의 데이터 비트, 패리티 없음, 1개의 정지 비트. 예를 들어, 문자 C 또는 ASCII에서 0x43을 8N1 UART 구성으로 전송하고자 한다면, 다음 비트를 전송합니다: 0(시작 비트); 0, 1, 0, 0, 0, 0, 1, 1(0x43의 이진 값), 그리고 0(정지 비트).

![](<../../images/image (764).png>)

UART와 통신하기 위한 하드웨어 도구:

- USB-직렬 어댑터
- CP2102 또는 PL2303 칩이 있는 어댑터
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 다목적 도구

### UART 포트 식별

UART에는 4개의 포트가 있습니다: **TX**(전송), **RX**(수신), **Vcc**(전압), 및 **GND**(접지). PCB에 **`TX`** 및 **`RX`** 문자가 **표기된** 4개의 포트를 찾을 수 있을 것입니다. 그러나 표시가 없다면, **멀티미터** 또는 **로직 분석기**를 사용하여 직접 찾아야 할 수도 있습니다.

**멀티미터**와 장치 전원이 꺼진 상태에서:

- **GND** 핀을 식별하려면 **연속성 테스트** 모드를 사용하고, 검은색 리드를 접지에 놓고 빨간색 리드로 테스트하여 멀티미터에서 소리가 날 때까지 테스트합니다. PCB에서 여러 GND 핀을 찾을 수 있으므로 UART에 해당하는 핀을 찾았는지 여부는 확실하지 않을 수 있습니다.
- **VCC 포트**를 식별하려면 **DC 전압 모드**로 설정하고 20V로 설정합니다. 검은색 프로브를 접지에 놓고 빨간색 프로브를 핀에 놓습니다. 장치를 켭니다. 멀티미터가 3.3V 또는 5V의 일정한 전압을 측정하면 Vcc 핀을 찾은 것입니다. 다른 전압이 측정되면 다른 포트로 다시 시도합니다.
- **TX** **포트**를 식별하려면, **DC 전압 모드**를 20V로 설정하고 검은색 프로브를 접지에 놓고 빨간색 프로브를 핀에 놓고 장치를 켭니다. 전압이 몇 초 동안 변동하다가 Vcc 값으로 안정화되면 TX 포트를 찾은 것입니다. 이는 전원이 켜질 때 일부 디버그 데이터를 전송하기 때문입니다.
- **RX 포트**는 나머지 3개 포트와 가장 가까운 포트로, 전압 변동이 가장 적고 모든 UART 핀 중에서 가장 낮은 전체 값을 가집니다.

TX와 RX 포트를 혼동해도 아무런 문제가 발생하지 않지만, GND와 VCC 포트를 혼동하면 회로가 손상될 수 있습니다.

일부 대상 장치에서는 제조업체가 RX 또는 TX 또는 두 개 모두를 비활성화하여 UART 포트를 비활성화합니다. 이 경우 회로 기판의 연결을 추적하고 일부 브레이크아웃 포인트를 찾는 것이 도움이 될 수 있습니다. UART가 감지되지 않고 회로가 끊어졌다는 것을 확인하는 강력한 힌트는 장치 보증을 확인하는 것입니다. 장치가 보증과 함께 배송된 경우, 제조업체는 일부 디버그 인터페이스(이 경우 UART)를 남겨두고, 따라서 UART를 분리했으며 디버깅 중에 다시 연결해야 합니다. 이러한 브레이크아웃 핀은 납땜하거나 점퍼 와이어로 연결할 수 있습니다.

### UART 전송 속도 식별

올바른 전송 속도를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 보고 데이터를 읽어보는 것**입니다. 수신한 데이터가 읽을 수 없다면, 데이터가 읽을 수 있을 때까지 다음 가능한 전송 속도로 전환합니다. USB-직렬 어댑터나 Bus Pirate와 같은 다목적 장치를 사용하여 이를 수행할 수 있으며, [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 도우미 스크립트와 함께 사용할 수 있습니다. 가장 일반적인 전송 속도는 9600, 38400, 19200, 57600 및 115200입니다.

> [!CAUTION]
> 이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 한다는 점에 유의하는 것이 중요합니다!

## CP210X UART to TTY 어댑터

CP210X 칩은 Serial Communication을 위해 NodeMCU(esp8266 포함)와 같은 많은 프로토타입 보드에서 사용됩니다. 이러한 어댑터는 상대적으로 저렴하며 대상의 UART 인터페이스에 연결하는 데 사용할 수 있습니다. 이 장치는 5개의 핀을 가지고 있습니다: 5V, GND, RXD, TXD, 3.3V. 손상을 방지하기 위해 대상이 지원하는 전압으로 연결해야 합니다. 마지막으로 어댑터의 RXD 핀을 대상의 TXD에, 어댑터의 TXD 핀을 대상의 RXD에 연결합니다.

어댑터가 감지되지 않는 경우, 호스트 시스템에 CP210X 드라이버가 설치되어 있는지 확인하십시오. 어댑터가 감지되고 연결되면 picocom, minicom 또는 screen과 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치를 나열하려면:
```
ls /dev/
```
UART 인터페이스와 기본적으로 상호작용하려면 다음 명령어를 사용하세요:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom의 경우, 다음 명령어를 사용하여 구성합니다:
```
minicom -s
```
`Serial port setup` 옵션에서 baudrate 및 장치 이름과 같은 설정을 구성합니다.

구성이 완료되면 `minicom` 명령을 사용하여 UART 콘솔을 시작합니다.

## Arduino UNO R3를 통한 UART (탈착 가능한 Atmel 328p 칩 보드)

UART Serial to USB 어댑터를 사용할 수 없는 경우, Arduino UNO R3를 빠른 해킹으로 사용할 수 있습니다. Arduino UNO R3는 일반적으로 어디서나 구할 수 있으므로 많은 시간을 절약할 수 있습니다.

Arduino UNO R3에는 보드 자체에 USB to Serial 어댑터가 내장되어 있습니다. UART 연결을 얻으려면 보드에서 Atmel 328p 마이크로컨트롤러 칩을 분리하기만 하면 됩니다. 이 해킹은 Atmel 328p가 보드에 납땜되지 않은 Arduino UNO R3 변형에서 작동합니다(여기서는 SMD 버전이 사용됨). Arduino의 RX 핀(디지털 핀 0)을 UART 인터페이스의 TX 핀에 연결하고 Arduino의 TX 핀(디지털 핀 1)을 UART 인터페이스의 RX 핀에 연결합니다.

마지막으로, Serial Console을 얻기 위해 Arduino IDE를 사용하는 것이 좋습니다. 메뉴의 `tools` 섹션에서 `Serial Console` 옵션을 선택하고 UART 인터페이스에 따라 baud rate를 설정합니다.

## Bus Pirate

이 시나리오에서는 프로그램의 모든 출력을 Serial Monitor로 전송하는 Arduino의 UART 통신을 스니핑할 것입니다.
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## UART 콘솔을 통한 펌웨어 덤프

UART 콘솔은 런타임 환경에서 기본 펌웨어와 작업할 수 있는 훌륭한 방법을 제공합니다. 그러나 UART 콘솔 접근이 읽기 전용인 경우 많은 제약이 있을 수 있습니다. 많은 임베디드 장치에서 펌웨어는 EEPROM에 저장되고 휘발성 메모리를 가진 프로세서에서 실행됩니다. 따라서 원래 펌웨어가 제조 중 EEPROM 내부에 있기 때문에 펌웨어는 읽기 전용으로 유지되며, 새로운 파일은 휘발성 메모리로 인해 손실될 수 있습니다. 따라서 임베디드 펌웨어 작업 시 펌웨어 덤프는 귀중한 노력입니다.

이를 수행하는 방법은 여러 가지가 있으며, SPI 섹션에서는 다양한 장치를 사용하여 EEPROM에서 직접 펌웨어를 추출하는 방법을 다룹니다. 그러나 물리적 장치와 외부 상호작용을 통한 펌웨어 덤프는 위험할 수 있으므로 먼저 UART를 통해 펌웨어 덤프를 시도하는 것이 좋습니다.

UART 콘솔에서 펌웨어를 덤프하려면 먼저 부트로더에 접근해야 합니다. 많은 인기 있는 공급업체는 Linux를 로드하기 위해 uboot(유니버설 부트로더)를 부트로더로 사용합니다. 따라서 uboot에 접근하는 것이 필요합니다.

부트로더에 접근하려면 UART 포트를 컴퓨터에 연결하고 모든 Serial Console 도구를 사용하며 장치의 전원 공급 장치를 분리합니다. 설정이 완료되면 Enter 키를 누르고 유지합니다. 마지막으로 장치에 전원 공급 장치를 연결하고 부팅을 시작합니다.

이렇게 하면 uboot의 로딩이 중단되고 메뉴가 제공됩니다. uboot 명령을 이해하고 도움말 메뉴를 사용하여 목록을 나열하는 것이 좋습니다. 이는 `help` 명령일 수 있습니다. 서로 다른 공급업체가 서로 다른 구성을 사용하므로 각 구성을 개별적으로 이해하는 것이 필요합니다.

일반적으로 펌웨어를 덤프하는 명령은:
```
md
```
"메모리 덤프"를 의미합니다. 이는 화면에 메모리(EEPROM 내용)를 덤프합니다. 메모리 덤프를 캡처하기 위해 절차를 시작하기 전에 Serial Console 출력을 기록하는 것이 권장됩니다.

마지막으로, 로그 파일에서 모든 불필요한 데이터를 제거하고 파일을 `filename.rom`으로 저장한 다음 binwalk를 사용하여 내용을 추출합니다:
```
binwalk -e <filename.rom>
```
이것은 헥스 파일에서 발견된 서명에 따라 EEPROM의 가능한 내용을 나열합니다.

하지만 uboot가 사용되고 있더라도 항상 잠금 해제가 되어 있는 것은 아니라는 점에 유의해야 합니다. Enter 키가 아무런 반응을 보이지 않으면 Space 키와 같은 다른 키를 확인하십시오. 부트로더가 잠겨 있고 중단되지 않으면 이 방법은 작동하지 않습니다. uboot가 장치의 부트로더인지 확인하려면 장치 부팅 중 UART 콘솔의 출력을 확인하십시오. 부팅 중에 uboot가 언급될 수 있습니다.

{{#include ../../banners/hacktricks-training.md}}
