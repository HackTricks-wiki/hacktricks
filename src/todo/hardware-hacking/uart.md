# UART

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

UART는 serial protocol로, component 간에 한 번에 1bit씩 data를 전송합니다. 이와 대조적으로 parallel communication protocol은 여러 channel을 통해 data를 동시에 전송합니다. 일반적인 serial protocol에는 RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, USB 등이 있습니다.

일반적으로 UART가 idle state일 때 line은 high(logical 1 value)로 유지됩니다. 그런 다음 data transfer의 시작을 알리기 위해 transmitter가 receiver로 start bit를 전송하며, 이때 signal은 low(logical 0 value)로 유지됩니다. 다음으로 transmitter는 실제 message를 포함하는 5~8개의 data bit를 전송하고, configuration에 따라 optional parity bit와 하나 또는 두 개의 stop bit(logical 1 value)를 전송합니다. Error checking에 사용되는 parity bit는 실제 환경에서 거의 사용되지 않습니다. Stop bit(또는 stop bits)는 transmission의 끝을 나타냅니다.

가장 일반적인 configuration을 8N1이라고 합니다. 이는 8개의 data bit, parity 없음, 1개의 stop bit를 의미합니다. 예를 들어 8N1 UART configuration에서 character C 또는 ASCII의 0x43을 전송하려면 다음 bit를 전송합니다: 0(start bit); 0, 1, 0, 0, 0, 0, 1, 1(0x43의 binary 값); 그리고 0(stop bit).

![UART: 가장 일반적인 configuration을 8N1이라고 합니다. 이는 8개의 data bit, parity 없음, 1개의 stop bit를 의미합니다. 예를 들어 8N1 UART configuration에서 character C 또는 ASCII의 0x43을 전송하려면 다음 bit를 전송합니다](<../../images/image (764).png>)

UART와 통신하기 위한 hardware tool:

- USB-to-serial adapter
- CP2102 또는 PL2303 chip이 장착된 adapter
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 multipurpose tool

### UART Port 식별

UART에는 **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), **GND**(Ground)의 4개 port가 있습니다. PCB에 **`TX`** 및 **`RX`** 문자가 **표기된** 4개의 port를 찾을 수 있을 수도 있습니다. 하지만 표시가 없다면 **multimeter** 또는 **logic analyzer**를 사용하여 직접 찾아야 할 수 있습니다.

장치의 전원이 꺼진 상태에서 **multimeter**를 사용합니다.

- **GND** pin을 식별하려면 **Continuity Test** mode를 사용합니다. 검은색 probe를 ground에 연결하고 빨간색 probe로 테스트하여 multimeter에서 소리가 날 때까지 확인합니다. PCB에서 여러 GND pin을 찾을 수 있으므로, UART에 속한 pin을 찾았을 수도 있고 아닐 수도 있습니다.
- **VCC port**를 식별하려면 **DC voltage mode**를 설정하고 voltage를 20 V로 설정합니다. 검은색 probe를 ground에 연결하고 빨간색 probe를 pin에 연결합니다. 장치의 전원을 켭니다. multimeter가 3.3 V 또는 5 V 중 하나의 일정한 voltage를 측정하면 Vcc pin을 찾은 것입니다. 다른 voltage가 측정되면 다른 port로 다시 시도합니다.
- **TX** **port**를 식별하려면 **DC voltage mode**를 사용하고 voltage를 최대 20 V로 설정한 뒤, 검은색 probe를 ground에 연결하고 빨간색 probe를 pin에 연결한 다음 장치의 전원을 켭니다. voltage가 몇 초 동안 변동한 후 Vcc 값으로 안정화되면 TX port일 가능성이 높습니다. 전원을 켤 때 장치가 일부 debug data를 전송하기 때문입니다.
- **RX port**는 나머지 3개 port와 가장 가까운 port이며, 모든 UART pin 중 voltage fluctuation과 전체 voltage 값이 가장 낮습니다.

TX와 RX port를 혼동해도 아무 일도 일어나지 않지만, GND와 VCC port를 혼동하면 circuit을 손상시킬 수 있습니다.

일부 target device에서는 manufacturer가 RX 또는 TX, 혹은 둘 다 비활성화하여 UART port를 disable합니다. 이 경우 circuit board의 connection을 추적하여 breakout point를 찾는 것이 도움이 될 수 있습니다. UART가 detection되지 않고 circuit이 끊어졌는지 확인하는 강력한 단서는 device warranty를 확인하는 것입니다. device가 일부 warranty와 함께 출하되었다면 manufacturer는 일부 debug interface(이 경우 UART)를 남겨두므로, debug 시 UART를 다시 연결할 수 있도록 UART를 분리했을 것입니다. 이러한 breakout pin은 soldering 또는 jumper wire로 연결할 수 있습니다.

### UART Baud Rate 식별

올바른 baud rate를 식별하는 가장 쉬운 방법은 **TX pin의 output을 확인하고 data를 읽어보는 것**입니다. 수신한 data를 읽을 수 없다면 data를 읽을 수 있을 때까지 다음 가능한 baud rate로 변경합니다. USB-to-serial adapter 또는 Bus Pirate와 같은 multipurpose device를 [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 helper script와 함께 사용할 수 있습니다. 가장 일반적인 baud rate는 9600, 38400, 19200, 57600, 115200입니다.

> [!CAUTION]
> 이 protocol에서는 한 device의 TX를 다른 device의 RX에 연결해야 한다는 점에 유의해야 합니다!

## CP210X UART to TTY Adapter

CP210X Chip은 Serial Communication을 위한 NodeMCU(esp8266 포함)와 같은 여러 prototyping board에서 사용됩니다. 이러한 adapter는 비교적 저렴하며 target의 UART interface에 연결하는 데 사용할 수 있습니다. device에는 5V, GND, RXD, TXD, 3.3V의 5개 pin이 있습니다. 손상을 방지하려면 target이 지원하는 voltage로 연결해야 합니다. 마지막으로 Adapter의 RXD pin을 target의 TXD에 연결하고, Adapter의 TXD pin을 target의 RXD에 연결합니다.

adapter가 detection되지 않는 경우 host system에 CP210X driver가 설치되어 있는지 확인합니다. adapter가 detection되고 연결되면 picocom, minicom 또는 screen과 같은 tool을 사용할 수 있습니다.

Linux/MacOS system에 연결된 device를 나열하려면:
```
ls /dev/
```
UART interface와 기본적으로 상호작용하려면 다음 명령을 사용하세요:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom의 경우 다음 명령을 사용하여 구성합니다:
```
minicom -s
```
`Serial port setup` 옵션에서 baudrate 및 device name과 같은 설정을 구성합니다.

구성이 완료되면 `minicom` 명령을 사용하여 UART Console을 시작합니다.

## Arduino UNO R3를 통한 UART (분리 가능한 Atmel 328p Chip 보드)

UART Serial to USB adapters를 사용할 수 없는 경우, 간단한 hack을 통해 Arduino UNO R3를 사용할 수 있습니다. Arduino UNO R3는 일반적으로 어디서나 구할 수 있으므로 많은 시간을 절약할 수 있습니다.

Arduino UNO R3에는 보드 자체에 USB to Serial adapter가 내장되어 있습니다. UART connection을 얻으려면 보드에서 Atmel 328p microcontroller chip을 뽑기만 하면 됩니다. 이 hack은 Atmel 328p가 보드에 납땜되어 있지 않은 Arduino UNO R3 variants에서 작동합니다(SMD version이 사용된 보드). Arduino의 RX pin(Digital Pin 0)을 UART Interface의 TX pin에 연결하고, Arduino의 TX pin(Digital Pin 1)을 UART interface의 RX pin에 연결합니다.

마지막으로 Serial Console을 사용하려면 Arduino IDE를 사용하는 것이 좋습니다. 메뉴의 `tools` section에서 `Serial Console` option을 선택하고 UART interface에 맞게 baud rate를 설정합니다.

## Bus Pirate

이 시나리오에서는 프로그램의 모든 출력을 Serial Monitor로 전송하는 Arduino의 UART communication을 sniff합니다.
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
## UART Console로 Firmware Dump하기

UART Console은 runtime environment에서 underlying firmware를 다룰 수 있는 훌륭한 방법을 제공합니다. 하지만 UART Console access가 read-only인 경우 여러 가지 제약이 발생할 수 있습니다. 많은 embedded device에서는 firmware가 EEPROM에 저장되고 volatile memory를 사용하는 processor에서 실행됩니다. 따라서 manufacturing 과정에서 사용된 original firmware가 EEPROM 자체에 들어 있고 volatile memory로 인해 새 파일은 손실되므로, firmware는 read-only로 유지됩니다. 이런 이유로 embedded firmware를 다룰 때 firmware를 dump하는 것은 매우 중요한 작업입니다.

이를 수행하는 방법은 다양하며, SPI section에서는 여러 device를 사용해 EEPROM에서 직접 firmware를 extract하는 방법을 다룹니다. 하지만 physical device와 external interaction을 사용한 firmware dumping은 위험할 수 있으므로, 먼저 UART를 사용해 firmware를 dump해 보는 것이 좋습니다.

UART Console에서 firmware를 dump하려면 먼저 bootloader에 access해야 합니다. 많은 유명 vendor는 Linux를 load하기 위한 bootloader로 uboot (Universal Bootloader)를 사용합니다. 따라서 uboot에 access하는 것이 필요합니다.

bootloader를 시작하기 위해 UART port를 computer에 연결하고, Serial Console tool을 사용한 다음 device의 power supply를 분리해 둡니다. setup이 준비되면 Enter Key를 누른 상태로 유지합니다. 마지막으로 device에 power supply를 연결하고 boot되도록 둡니다.

이렇게 하면 uboot의 loading이 중단되고 menu가 표시됩니다. uboot commands를 이해하고 help menu를 사용해 command 목록을 확인하는 것이 좋습니다. 이를 위한 command는 `help`일 수 있습니다. vendor마다 서로 다른 configuration을 사용하므로 각각을 별도로 이해해야 합니다.

일반적으로 firmware를 dump하는 command는 다음과 같습니다:
```
md
```
이는 "memory dump"를 의미합니다. 화면에 메모리(EEPROM Content)를 dump합니다. 메모리 dump를 캡처할 수 있도록 절차를 시작하기 전에 Serial Console 출력을 log하는 것이 좋습니다.

마지막으로 log file에서 불필요한 데이터를 모두 제거하고 파일을 `filename.rom`으로 저장한 다음 binwalk를 사용하여 내용을 추출합니다:
```
binwalk -e <filename.rom>
```
이는 hex 파일에서 확인된 signature에 따라 EEPROM의 가능한 contents를 나열합니다.

다만 uboot가 사용되고 있더라도 항상 unlock되어 있는 것은 아니라는 점에 유의해야 합니다. Enter 키를 눌러도 아무 동작이 없다면 Space 키 등 다른 키를 확인하세요. bootloader가 lock되어 중단되지 않는 경우에는 이 방법이 작동하지 않습니다. uboot가 해당 device의 bootloader인지 확인하려면 device가 booting되는 동안 UART Console의 output을 확인하세요. booting 중 uboot가 언급될 수 있습니다.

{{#include ../../banners/hacktricks-training.md}}
