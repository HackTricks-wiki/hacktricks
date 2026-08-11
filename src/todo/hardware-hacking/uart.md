# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART는 공유 클록 없이 프레임화된 비트 스트림을 전송하는 비동기식 serial interface입니다. logic-level UART와 RS-232를 혼동하지 마세요. RS-232는 서로 다른, 흔히 음수인 전압 레벨을 사용하며 transceiver가 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

일반적으로 UART가 idle 상태일 때 라인은 high(논리 1 값)로 유지됩니다. 그런 다음 data transfer의 시작을 알리기 위해 transmitter가 receiver로 start bit를 전송하며, 이때 signal은 low(논리 0 값)로 유지됩니다. 다음으로 transmitter는 실제 message를 포함하는 5~8개의 data bit를 전송하고, configuration에 따라 optional parity bit와 1~2개의 stop bit(논리 1 값)를 전송합니다. error checking에 사용되는 parity bit는 실제로는 거의 사용되지 않습니다. stop bit(또는 bit들)는 transmission의 끝을 나타냅니다.

가장 일반적인 configuration은 8N1입니다. 즉, 8개의 data bit, parity 없음, 1개의 stop bit입니다. UART는 least-significant data bit부터 전송하므로 ASCII `C`(`0x43`)는 다음과 같이 전송됩니다: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: 가장 일반적인 configuration을 8N1이라고 합니다. 8개의 data bit, parity 없음, 1개의 stop bit입니다. 예를 들어 ASCII에서 문자 C 또는 0x43을 8N1 UART로 전송하려는 경우](<../../images/image (764).png>)

UART와 통신하기 위한 hardware tools:

- USB-to-serial adapter
- CP2102 또는 PL2303 chip이 장착된 adapter
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 multipurpose tool

### Identifying UART Ports

일반적인 debug header에는 **TX**, **RX**, **GND**가 노출되며, **Vcc/Vref** pin, reset 또는 flow-control pin이 추가로 노출될 수도 있습니다. Vcc는 UART signal이 아니며, 일반적으로 voltage reference로만 사용해야 합니다. board의 schematic과 current requirements를 알고 있는 경우가 아니라면 power source로 연결하지 마세요.<sup>[[2]](#references)[[3]](#references)</sup>

device의 **전원을 끄고** 연결을 해제한 상태에서 시작하세요.

- 이미 알고 있는 ground plane, connector shield 또는 supply ground를 기준으로 continuity mode에서 **GND**를 식별합니다. 전원이 켜진 board에서는 절대로 continuity/resistance mode를 사용하지 마세요.
- target의 전원을 켜기 전에 DC-voltage mode로 전환합니다. ground를 기준으로 후보 pin을 측정하여 logic voltage를 식별합니다. 일정한 rail은 Vcc/Vref일 수 있으므로, 안전하게 연결할 수 있다고 가정하지 마세요.
- boot 중 logic analyzer 또는 oscilloscope로 후보 pin을 관찰합니다. **TX**는 일반적으로 high 상태로 idle하며 framed data의 burst를 보여줍니다. multimeter는 평균적인 fluctuation을 표시할 수 있지만 framing 또는 baud rate를 검증할 수는 없습니다.
- **RX**는 idle 상태로 유지될 수 있으며, TX 옆에 있다는 이유만으로 안전하게 식별할 수 없습니다. PCB를 trace하거나 SoC datasheet를 참조하거나, RX를 drive하기 전에 high-impedance analyzer를 사용하세요.

TX와 RX를 서로 바꾸면 일반적으로 통신이 되지 않습니다. power, ground 또는 signal level을 혼동하면 target 또는 adapter가 영구적으로 손상될 수 있습니다. 먼저 ground를 연결하고 **receive-only**로 시작하세요(target TX를 adapter RX에 연결).

제조업체는 header를 생략하거나, series resistor를 실장하지 않거나, firmware에서 console을 비활성화하거나, TX만 노출할 수 있습니다. 주변 test pad와 resistor footprint를 SoC까지 trace하고 electrical level을 확인한 후에만 임시 high-impedance connection을 추가하세요. warranty가 존재한다고 해서 접근 가능한 UART가 반드시 존재하는 것은 아닙니다.

### Identifying the UART Baud Rate

올바른 baud rate를 식별하는 가장 쉬운 방법은 **TX pin의 output을 확인하고 data를 읽어보는 것**입니다. 수신한 data를 읽을 수 없다면 data를 읽을 수 있을 때까지 다음 가능한 baud rate로 변경합니다. USB-to-serial adapter 또는 Bus Pirate와 같은 multipurpose device를 helper script와 함께 사용할 수 있습니다. 예: [baudrate.py](https://github.com/devttys0/baudrate/). 가장 일반적인 baud rate는 9600, 38400, 19200, 57600 및 115200입니다.

> [!CAUTION]
> 이 protocol에서는 한 device의 TX를 다른 device의 RX에 연결해야 한다는 점에 유의하세요!

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridge는 많은 prototyping board와 저가형 adapter에서 사용됩니다. 일반적인 module은 GND, RXD 및 TXD와 함께 supply pin을 노출하지만, header와 I/O level은 서로 다릅니다. board design 또는 data sheet에서 실제 voltage를 확인하세요. 일반적으로 GND, adapter RX를 target TX에 연결하고, receive-only 검증을 완료한 후 adapter TX를 target RX에 연결합니다. 해당 target에 의도적으로 전원을 공급하고 target이 이를 견딜 수 있다는 것을 알고 있는 경우가 아니라면 adapter의 5 V/3.3 V supply pin을 연결하지 마세요.<sup>[[3]](#references)</sup>

adapter가 detect되지 않는 경우 host system에 CP210X driver가 설치되어 있는지 확인하세요. adapter가 detect되고 연결되면 picocom, minicom 또는 screen과 같은 tool을 사용할 수 있습니다.

Linux/MacOS system에 연결된 device를 나열하려면:
```
ls /dev/
```
UART 인터페이스와 기본적으로 상호 작용하려면 다음 명령을 사용합니다:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom은 다음 명령을 사용하여 구성합니다:
```
minicom -s
```
`Serial port setup` 옵션에서 baudrate 및 device name과 같은 설정을 구성합니다.

구성 후 `minicom`을 실행하여 UART console을 엽니다.

## Arduino UNO R3를 통한 UART(분리 가능한 Atmel 328p Chip 보드)

UART Serial to USB adapter를 사용할 수 없는 경우, 간단한 hack으로 Arduino UNO R3를 사용할 수 있습니다. Arduino UNO R3는 일반적으로 어디서나 구할 수 있으므로 많은 시간을 절약할 수 있습니다.

Arduino UNO R3에는 보드 자체에 USB to Serial adapter가 내장되어 있습니다. UART connection을 얻으려면 보드에서 Atmel 328p microcontroller chip을 뽑기만 하면 됩니다. 이 hack은 Atmel 328p가 보드에 납땜되지 않은 Arduino UNO R3 variant(SMD version이 사용된 경우)에서 작동합니다. Arduino의 RX pin(Digital Pin 0)을 UART Interface의 TX pin에 연결하고, Arduino의 TX pin(Digital Pin 1)을 UART interface의 RX pin에 연결합니다.

Arduino IDE의 **Serial Monitor** 또는 target baud rate로 설정한 전용 terminal을 사용합니다. Classic Uno R3 serial signal은 5 V logic이므로, 3.3 V 또는 더 낮은 voltage의 target에 연결하기 전에 level shifter 또는 divider를 사용합니다.

## Bus Pirate

다음 transcript는 UART output을 monitor하기 위해 legacy Bus Pirate firmware interface를 사용합니다. 최신 Bus Pirate firmware는 `m uart`, `{`/`}`, `monitor` 또는 `bridge`와 같은 command를 사용하므로, 설치된 version의 documentation을 확인하세요.<sup>[[2]](#references)</sup>
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
## UART Console을 사용한 Firmware 덤프

UART Console은 부팅 로그에 대한 runtime access와 경우에 따라 bootloader 또는 operating-system shell에 대한 access를 제공합니다. 읽기 전용 Console에서도 memory maps, flash drivers, boot arguments, partition layouts 및 firmware versions가 노출됩니다. Firmware는 SPI NOR/NAND, eMMC 또는 다른 device에 존재할 수 있으며, 일반적으로 EEPROM에서 직접 실행되지는 않습니다. 또한 mounted persistent filesystem에 기록된 파일이 reboot 시 반드시 사라지는 것도 아닙니다.

여러 acquisition 경로가 있으며, SPI section에서는 external flash에서 직접 읽는 방법을 다룹니다. bootloader가 이미 안전한 read command를 제공하는 경우 Console-assisted acquisition이 덜 침습적일 수 있지만, boot interruption이나 flash command는 availability에 영향을 줄 수 있으므로 원래 상태를 기록하고 write/erase operation은 피해야 합니다.

Console-assisted firmware dumping은 흔히 bootloader를 interrupt하는 것부터 시작합니다. 많은 embedded Linux device가 **Das U-Boot**를 사용하지만, proprietary bootloader를 사용하거나 interactive Console을 비활성화한 device도 있습니다.

interactive bootloader를 테스트하려면 target의 전원이 꺼진 상태에서 UART receive path와 terminal을 연결하고 logging을 시작한 다음 전원을 켭니다. 표시되는 autoboot prompt를 따르십시오. build에 따라 interruption에는 key 하나, 짧은 sequence가 필요할 수 있으며, interruption 자체가 완전히 비활성화되어 있을 수도 있습니다.

interruption에 성공하면 `help`, `printenv` 및 read-only discovery command를 사용하여 address에 access하기 전에 해당 vendor의 memory 및 storage layout을 파악합니다.

U-Boot에서 `md`는 자동으로 “EEPROM”을 표시하는 것이 아니라 **addressable memory**를 표시합니다. 먼저 `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables 및 boot logs와 같은 board-specific command를 사용하여 올바른 mapped address를 식별하거나 flash region을 RAM으로 load합니다. 그런 다음 알려진 range를 byte 단위로 표시합니다:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
시작하기 전에 시리얼 출력을 기록합니다. `md.b` 출력에는 주소와 ASCII 열이 포함되어 있으므로 원시 ROM 이미지가 아니라 텍스트 표현입니다.

주소와 ASCII 열을 제거하고 16진수 바이트 필드만 연결한 다음, 이를 바이너리로 디코딩합니다(예: `xxd -r -p`). 분석하기 전에 예상 바이트 수를 확인하고 hash를 기록합니다:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk는 재구성된 바이너리에서 알려진 시그니처를 식별합니다. 콘솔이 데이터를 안정적으로 전송하지 못할 때는 적절한 SPI/eMMC/NAND 인터페이스를 통한 직접적인 플래시 읽기가 일반적으로 더 빠르고 오류가 적습니다.

U-Boot는 중단 기능을 비활성화하거나, vendor-specific 키 시퀀스를 요구하거나, 메모리/플래시 명령을 잠글 수 있습니다. 문자를 무작정 전송하지 말고 autoboot 프롬프트와 boot log를 따르십시오. 콘솔을 중단할 수 없다면 boot log를 보존하고 비침습적인 firmware 획득 경로로 전환하십시오.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART - Microchip PIC32 제품군 레퍼런스 매뉴얼 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits - Bus Pirate 문서 - UART 모드 및 전기적 한계](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet - Silicon Labs - CP2102C 데이터시트](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command - U-Boot 문서 - `md` 메모리 표시 명령](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
