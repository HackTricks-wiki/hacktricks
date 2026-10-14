# UART

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

UART는 공통 클럭 없이 프레임으로 구성된 비트 스트림을 전송하는 비동기 직렬 인터페이스입니다. 로직 레벨 UART를 RS-232와 혼동하지 마세요. RS-232는 전압 레벨이 다르며(종종 음전압 사용), 트랜시버가 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

일반적으로 UART가 유휴 상태일 때 라인은 high(논리값 1)로 유지됩니다. 데이터 전송의 시작을 알리기 위해 송신기는 수신기에 start bit를 보내며, 이때 신호는 low(논리값 0)로 유지됩니다. 다음으로 송신기는 실제 메시지가 포함된 5~8개의 데이터 비트를 보낸 뒤, 설정에 따라 선택적 parity bit와 하나 또는 두 개의 stop bit(논리값 1)를 보냅니다. 오류 확인에 사용되는 parity bit는 실제로 거의 사용되지 않습니다. Stop bit는 전송이 끝났음을 나타냅니다.

가장 일반적인 설정은 8N1입니다. 데이터 비트 8개, parity 없음, stop bit 1개를 의미합니다. UART는 데이터의 최하위 비트부터 전송하므로 ASCII `C`(`0x43`)는 다음과 같이 전송됩니다. start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: 가장 일반적인 설정은 8N1이며 데이터 비트 8개, parity 없음, stop bit 1개를 의미합니다. 예를 들어 ASCII에서 문자 C 또는 0x43을 8N1 UART로 전송한다고 가정해 보겠습니다](<../../images/image (764).png>)

UART 통신에 사용하는 하드웨어 도구:

- USB-to-serial 어댑터
- CP2102 또는 PL2303 칩이 장착된 어댑터
- Bus Pirate, Adafruit FT232H, Shikra, Attify Badge와 같은 다목적 도구

### UART 포트 식별

일반적인 디버그 헤더에는 **TX**, **RX**, **GND**가 있으며, **Vcc/Vref** 핀, reset 또는 flow-control 핀이 추가로 있을 수 있습니다. Vcc는 UART 신호가 아니며, 보드의 회로도와 전류 요구 사항을 알고 있는 경우가 아니라면 일반적으로 전원이 아닌 전압 기준으로만 사용해야 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

먼저 장치의 **전원을 끄고** 연결을 해제합니다.

- continuity 모드에서 알려진 ground plane, 커넥터 실드 또는 전원 ground를 기준으로 **GND**를 식별합니다. 전원이 켜진 보드에서는 continuity/resistance 모드를 절대 사용하지 마세요.
- 대상 장치의 전원을 켜기 전에 DC 전압 모드로 전환합니다. 후보 핀과 ground 사이의 전압을 측정해 로직 전압을 식별합니다. 일정한 전압 레일은 Vcc/Vref일 수 있으므로, 안전하게 연결할 수 있다고 단정하지 마세요.
- 부팅 중 로직 분석기나 오실로스코프로 후보 핀을 관찰합니다. **TX**는 보통 유휴 상태에서 high이며, 프레임으로 구성된 데이터가 버스트 형태로 나타납니다. 멀티미터는 평균적인 변동을 보여줄 수 있지만 프레이밍이나 baud rate를 확인할 수는 없습니다.
- **RX**는 유휴 상태로 유지될 수 있으므로 TX 옆에 있다는 이유만으로 안전하게 식별할 수 없습니다. PCB 회로를 추적하거나 SoC 데이터시트를 참조하거나, 입력 임피던스가 높은 분석기를 사용한 뒤 신호를 보내세요.

TX와 RX를 서로 바꿔 연결하면 일반적으로 통신이 되지 않습니다. 전원, ground 또는 신호 레벨을 혼동하면 대상 장치나 어댑터가 영구적으로 손상될 수 있습니다. 먼저 ground를 연결하고 **수신 전용**으로 시작하세요(대상 TX를 어댑터 RX에 연결).

제조업체는 헤더를 생략하거나 직렬 저항을 실장하지 않거나 펌웨어에서 콘솔을 비활성화하거나 TX만 노출할 수 있습니다. 주변 테스트 패드와 저항 패턴을 따라 SoC까지 회로를 추적하고, 전기적 레벨을 확인한 뒤에만 임시로 입력 임피던스가 높은 연결을 추가하세요. 보증이 있다고 해서 접근 가능한 UART가 반드시 존재하는 것은 아닙니다.

### UART Baud Rate 식별

올바른 baud rate를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어보는 것**입니다. 수신한 데이터가 읽을 수 없다면 데이터가 읽힐 때까지 다음 baud rate로 바꿔가며 시도하세요. USB-to-serial 어댑터나 Bus Pirate 같은 다목적 장치와 [baudrate.py](https://github.com/devttys0/baudrate/) 같은 보조 스크립트를 함께 사용할 수 있습니다. 가장 일반적인 baud rate는 9600, 38400, 19200, 57600, 115200입니다.

> [!CAUTION]
> 이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 한다는 점에 유의하세요!

## CP210X UART to TTY 어댑터

CP210x USB-to-UART 브리지는 여러 프로토타이핑 보드와 저가형 어댑터에서 볼 수 있습니다. 일반적인 모듈은 GND, RXD, TXD와 함께 전원 핀을 노출하지만, 헤더 구성과 I/O 레벨은 제품마다 다릅니다. 보드 설계나 데이터시트를 통해 실제 전압을 확인하세요. 보통 GND와 어댑터 RX를 대상 TX에 연결하고, 수신 전용으로 검증한 뒤 어댑터 TX를 대상 RX에 연결합니다. 대상 장치에 의도적으로 전원을 공급하는 경우가 아니라면 어댑터의 5 V/3.3 V 전원 핀을 연결하지 마세요.<sup>[[3]](#references)</sup>

어댑터가 감지되지 않으면 호스트 시스템에 CP210X 드라이버가 설치되어 있는지 확인하세요. 어댑터가 감지되어 연결되면 picocom, minicom, screen과 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치를 나열하려면:

```
ls /dev/
```

UART 인터페이스와 기본적으로 상호작용하려면 다음 명령을 사용하세요:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom의 경우, 다음 명령을 사용해 설정합니다:

```
minicom -s
```

`Serial port setup` 옵션에서 baud rate와 장치 이름 등의 설정을 구성합니다.

설정한 후 `minicom`을 실행해 UART 콘솔을 엽니다.

## Arduino UNO R3를 통한 UART (Atmel 328p 칩을 분리할 수 있는 보드)

UART Serial to USB 어댑터를 사용할 수 없는 경우, Arduino UNO R3를 간단한 hack으로 활용할 수 있습니다. Arduino UNO R3는 대개 어디서나 구할 수 있어 시간을 크게 절약할 수 있습니다.

Arduino UNO R3에는 USB to Serial 어댑터가 보드에 내장되어 있습니다. UART 연결을 위해 보드에서 Atmel 328p 마이크로컨트롤러 칩을 빼면 됩니다. 이 방법은 Atmel 328p가 보드에 납땜되지 않은 Arduino UNO R3 변형 모델에서 작동합니다(SMD 버전은 이 방식으로 사용됩니다). Arduino의 RX 핀(디지털 핀 0)을 UART 인터페이스의 TX 핀에 연결하고, Arduino의 TX 핀(디지털 핀 1)을 UART 인터페이스의 RX 핀에 연결합니다.

Arduino IDE의 **Serial Monitor** 또는 전용 터미널을 대상 baud rate에 맞춰 사용합니다. 클래식 Uno R3의 시리얼 신호는 5 V 로직이므로, 3.3 V 또는 그보다 낮은 전압의 대상 장치에 연결하기 전에 레벨 시프터나 분압기를 사용하세요.

## Bus Pirate

다음 transcript는 UART 출력을 모니터링하기 위해 레거시 Bus Pirate 펌웨어 인터페이스를 사용합니다. 최신 Bus Pirate 펌웨어에서는 `m uart`, `{`/`}`, `monitor` 또는 `bridge`와 같은 명령을 사용합니다. 설치된 버전의 문서를 참고하세요.<sup>[[2]](#references)</sup>

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

UART console은 부팅 로그와 때로는 bootloader 또는 운영체제 shell에 런타임으로 접근할 수 있게 해줍니다. 읽기 전용 console에서도 메모리 맵, flash 드라이버, boot 인수, partition 레이아웃, firmware 버전을 확인할 수 있습니다. Firmware는 SPI NOR/NAND, eMMC 또는 다른 장치에 저장될 수 있습니다. 일반적으로 EEPROM에서 직접 실행되는 것은 아니며, 마운트된 영구 파일 시스템에 기록한 파일이 재부팅 후 반드시 사라지는 것도 아닙니다.

여러 가지 획득 방법이 있으며, SPI 섹션에서는 외부 flash에서 직접 읽는 방법을 다룹니다. bootloader에 안전한 읽기 명령이 이미 있다면 console을 이용한 획득이 덜 침습적일 수 있지만, boot를 중단하거나 flash 명령을 실행하면 가용성에 영향을 줄 수 있으므로 원래 상태를 기록하고 쓰기/삭제 작업은 피하세요.

Console을 이용한 firmware 덤프는 흔히 bootloader를 중단하는 것으로 시작합니다. 많은 임베디드 Linux 장치가 **Das U-Boot**를 사용하지만, 다른 장치는 독점 bootloader를 사용하거나 대화형 console을 비활성화합니다.

대화형 bootloader를 확인하려면 대상 장치의 전원이 꺼진 상태에서 UART 수신 경로와 터미널을 연결하고, 로깅을 시작한 다음 전원을 켭니다. 표시되는 autoboot 프롬프트에 따라 중단하세요. 빌드에 따라 키 입력이나 짧은 키 시퀀스가 필요할 수 있으며, 중단 기능이 완전히 비활성화되어 있을 수도 있습니다.

중단에 성공하면 주소에 접근하기 전에 `help`, `printenv` 및 읽기 전용 탐색 명령을 사용해 해당 vendor의 메모리 및 저장 장치 레이아웃을 파악하세요.

U-Boot에서 `md`는 **주소 지정 가능한 메모리**를 표시하며, 자동으로 “EEPROM”을 표시하는 것은 아닙니다. 먼저 `mtd list`, `sf probe`, `mmc info`, `part list`와 같은 보드별 명령, 환경 변수 및 boot 로그를 사용해 올바르게 매핑된 주소를 확인하거나 flash 영역을 RAM에 로드하세요. 그런 다음 알려진 범위를 바이트 단위로 표시합니다:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

시작하기 전에 serial 출력을 기록하세요. `md.b` 출력에는 주소와 ASCII 열이 포함되어 있으므로, raw ROM 이미지가 아니라 텍스트 표현입니다.

주소와 ASCII 열을 제거하고 16진수 바이트 필드만 연결한 다음, 이를 바이너리로 디코딩하세요(예: `xxd -r -p`). 분석 전에 예상 바이트 수를 확인하고 해시를 기록하세요:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk는 재구성된 바이너리에서 알려진 시그니처를 식별합니다. 콘솔을 통해 데이터를 안정적으로 전송할 수 없다면, 적절한 SPI/eMMC/NAND 인터페이스를 통해 플래시를 직접 읽는 편이 일반적으로 더 빠르고 오류가 적습니다.

U-Boot에서는 중단 기능을 비활성화하거나, 공급업체별 키 입력 순서를 요구하거나, 메모리/플래시 명령을 잠글 수 있습니다. 문자를 무작정 전송하지 말고 autoboot 프롬프트와 부팅 로그를 확인하세요. 콘솔에서 부팅을 중단할 수 없다면 부팅 로그를 보존하고 비침습적인 펌웨어 획득 방법을 사용하세요.

## References

- [1] [Microchip PIC32 제품군 레퍼런스 매뉴얼 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate 문서 - UART 모드 및 전기적 제한](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C 데이터시트](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot 문서 - `md` 메모리 표시 명령](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
