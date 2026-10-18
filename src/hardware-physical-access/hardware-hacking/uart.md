# UART

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

UART는 공통 클럭 없이 프레임으로 구성된 비트 스트림을 전송하는 비동기 직렬 인터페이스입니다. logic-level UART와 RS-232를 혼동하지 마세요. RS-232는 전압 레벨이 다르며, 흔히 음전압을 사용하고 트랜시버가 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

일반적으로 UART가 유휴 상태일 때 회선은 high(논리값 1)로 유지됩니다. 데이터 전송을 시작하려면 송신기가 수신기에 시작 비트를 보내며, 이때 신호는 low(논리값 0)로 유지됩니다. 다음으로 송신기는 실제 메시지를 담은 데이터 비트 5~8개를 보낸 뒤, 설정에 따라 선택적 패리티 비트와 정지 비트 1~2개(논리값 1)를 보냅니다. 오류 확인에 사용하는 패리티 비트는 실제로는 거의 볼 수 없습니다. 정지 비트는 전송이 끝났음을 나타냅니다.

가장 일반적인 설정은 8N1입니다. 데이터 비트 8개, 패리티 없음, 정지 비트 1개를 뜻합니다. UART는 최하위 데이터 비트를 먼저 보내므로 ASCII `C`(`0x43`)는 다음과 같이 전송됩니다. 시작 `0`; 데이터 `1, 1, 0, 0, 0, 0, 1, 0`; 정지 `1`.<sup>[[1]](#references)</sup>

![UART: 가장 일반적인 설정인 8N1은 데이터 비트 8개, 패리티 없음, 정지 비트 1개를 뜻합니다. 예를 들어 ASCII에서 문자 C 또는 0x43을 8N1 UART로 보내려는 경우](<../../images/image (764).png>)

UART 통신에 사용하는 하드웨어 도구:

- USB-시리얼 어댑터
- CP2102 또는 PL2303 칩이 탑재된 어댑터
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge 같은 다목적 도구

### UART 포트 식별

일반적인 디버그 헤더에는 **TX**, **RX**, **GND**가 있습니다. **Vcc/Vref** 핀, 리셋 핀 또는 흐름 제어 핀이 추가로 있을 수도 있습니다. Vcc는 UART 신호가 아니며, 보드 회로도와 전류 요구 사항을 알고 있지 않다면 전원으로 연결하지 말고 전압 기준으로만 사용해야 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

장치의 **전원을 끄고** 연결을 분리한 상태에서 시작하세요.

- 연속성 모드로 알려진 접지면, 커넥터 실드 또는 전원 접지를 기준 삼아 **GND**를 식별합니다. 전원이 켜진 보드에는 연속성/저항 모드를 사용하지 마세요.
- 대상 장치에 전원을 공급하기 전에 멀티미터를 DC 전압 모드로 전환합니다. 후보 핀과 접지 사이의 전압을 측정해 logic 전압을 식별합니다. 일정하게 유지되는 전원 레일은 Vcc/Vref일 수 있으므로 안전하게 연결할 수 있다고 단정하지 마세요.
- 부팅 중 로직 애널라이저나 오실로스코프로 후보 핀을 관찰합니다. **TX**는 보통 유휴 상태에서 high이며, 프레임 데이터가 연속해서 나타납니다. 멀티미터는 평균적인 전압 변화를 보여줄 수 있지만 프레이밍이나 baud rate를 확인할 수는 없습니다.
- **RX**는 유휴 상태를 유지할 수 있으며, TX 옆에 있다는 이유만으로 안전하게 식별할 수 없습니다. PCB 회로를 추적하거나 SoC 데이터시트를 확인하거나, 입력 임피던스가 높은 애널라이저를 사용한 뒤에 신호를 인가하세요.

TX와 RX를 서로 바꿔 연결하면 보통 통신이 되지 않습니다. 전원, 접지 또는 신호 레벨을 혼동하면 대상 장치나 어댑터가 영구적으로 손상될 수 있습니다. 먼저 접지를 연결하고, **수신 전용**으로 시작하세요(대상 장치 TX를 어댑터 RX에 연결).

제조업체는 헤더를 생략하거나 직렬 저항을 미실장 상태로 두거나 펌웨어에서 콘솔을 비활성화할 수 있으며, TX만 노출할 수도 있습니다. 근처의 테스트 패드와 저항 풋프린트를 따라 SoC까지 회로를 추적하고 전기적 레벨을 확인한 뒤에만 임시 고임피던스 연결을 추가하세요. 보증이 제공된다고 해서 접근 가능한 UART가 반드시 존재하는 것은 아닙니다.

### UART Baud Rate 식별

올바른 baud rate를 식별하는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어 보는 것**입니다. 수신한 데이터를 읽을 수 없다면 읽을 수 있을 때까지 다음 baud rate를 시도하세요. USB-시리얼 어댑터나 Bus Pirate 같은 다목적 장치를 도우미 스크립트(예: [baudrate.py](https://github.com/devttys0/baudrate/))와 함께 사용할 수 있습니다. 가장 일반적인 baud rate는 9600, 38400, 19200, 57600, 115200입니다.

> [!CAUTION]
> 이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 합니다!

### SCPI로 부팅 시 UART 캡처 자동화

부팅 출력이 짧거나 TX 패드가 아직 확인되지 않았다면, 전원 공급 장치와 오실로스코프를 수동으로 조작하는 대신 전원을 반복해서 켜는 과정을 자동화하세요. 전류 제한 기능이 있는 프로그래밍 가능 전원 공급 장치를 검증된 대상 장치의 전원 입력에 연결합니다. 공통 접지를 사용하고 입력 임피던스가 높은 오실로스코프 입력으로 각 후보 TX 패드를 측정하되, 패드에 신호를 인가하지 마세요.<sup>[[5]](#references)</sup>

VISA는 시리얼 또는 Ethernet 계측기 세션을 열고, SCPI는 출력, 트리거, 파형 읽기를 제어합니다.<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa`와 `pyvisa-py`를 설치하세요(시리얼 VISA 리소스에는 `pyserial`도 필요). `ResourceManager('@py')`는 Python 백엔드를 명시적으로 선택합니다.<sup>[[5]](#references)[[7]](#references)</sup> 리소스 문자열과 명령은 사용하는 계측기에서 지원하는 값으로 바꾸세요.<sup>[[5]](#references)</sup>

Rigol MSO5000 예제에서는 보드에 전원을 공급하기 전에 단일 하강 에지 트리거를 설정합니다. 유휴 상태에서 high인 UART TX는 시작 비트에서 처음으로 low로 떨어집니다.<sup>[[5]](#references)</sup> 측정한 유휴 레벨과 low 레벨 사이에 트리거 임계값을 설정하고, 관심 있는 부팅 구간을 포함하도록 시간축을 설정하세요.<sup>[[5]](#references)[[6]](#references)</sup> 연속 캡처에서 `:TRIG:HOLD`를 사용하면 반복 에지를 억제할 수 있지만, 단일 캡처가 실제로 완료되었는지 확인하는 절차를 대신할 수는 없습니다.<sup>[[5]](#references)</sup> 다음 예제는 한 번의 부팅을 캡처하고 부호 없는 바이트 샘플과 스케일링 메타데이터를 모두 저장합니다. 시간 초과가 발생하면 무한정 기다리는 대신 대상 장치의 전원을 끕니다.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA 전원 켜기 및 단일 캡처 UART 파형 수집</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

패드 조사에서는 프로브를 옮긴 뒤 단일 캡처를 반복하거나, 전원 공급 세션을 열린 상태로 유지하면서 부팅 대기 시간과 전원 차단 간격을 두고 출력을 켰다 끄세요. 전원을 켤 때마다 스코프를 다시 준비해 각 파일이 하나의 부팅과 하나의 패드에 대응하도록 하세요.<sup>[[5]](#references)</sup>

Rigol 프리앰블 형식은 `<format>,<type>,<points>,<count>,<xincrement>,...`입니다.<sup>[[6]](#references)</sup> **세 번째** 값은 포인트 수이며, 문서에서 설명한 것처럼 샘플링 레이트가 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup> 해당 예시에서 `25,000,000` 포인트와 `xincrement = 2e-8`초는 샘플링 레이트가 25 MSa/s가 아니라 `1 / xincrement = 50,000,000` 샘플/초임을 뜻합니다.<sup>[[5]](#references)[[6]](#references)</sup> 프리앰블을 바이너리 파일과 함께 보관하고 읽은 길이가 `<points>`와 일치하는지 확인하세요. 가이드에는 대용량 레코드에 대한 분할/일괄 읽기 방법이 설명되어 있습니다.<sup>[[6]](#references)</sup>

캡처한 신호를 디코딩하려면 PulseView에서 `capture.bin`을 **Raw Analog Data Without Header**로 가져오고, 부호 없는 8비트(`U8`) 값을 선택한 다음 `xincrement`에서 계산한 샘플링 레이트를 입력하세요.<sup>[[5]](#references)[[6]](#references)</sup> 아날로그 채널에 **Logic via Threshold**를 적용하고, 낮은 샘플 값과 높은 샘플 값 사이의 임계값을 선택하세요.<sup>[[5]](#references)</sup> 깨끗한 시작 비트의 폭을 측정해 보드레이트를 추정한 다음(57,600 baud에서 약 17.36 µs), PulseView의 UART 디코더를 적용하고 여러 프레임이 일관되게 디코딩되는지 확인하세요.<sup>[[5]](#references)</sup> 하강 에지만으로는 해당 패드가 UART라고 단정할 수 없습니다.

## CP210X UART-대-TTY 어댑터

CP210x USB-to-UART 브리지는 여러 프로토타이핑 보드와 저가형 어댑터에서 볼 수 있습니다. 일반적인 모듈은 GND, RXD, TXD와 함께 전원 핀을 제공하지만, 헤더와 I/O 레벨은 제품마다 다릅니다. 보드 설계나 데이터시트에서 실제 전압을 확인하세요. 보통 GND와 어댑터 RX를 대상 TX에 연결하고, 수신 전용 검증을 마친 뒤 어댑터 TX를 대상 RX에 연결하면 됩니다. 대상 장치에 전원을 공급하려는 의도가 없고 해당 장치가 전압을 견딜 수 있는지 확인되지 않았다면 어댑터의 5 V/3.3 V 전원 핀을 연결하지 마세요.<sup>[[3]](#references)</sup>

어댑터가 감지되지 않으면 호스트 시스템에 CP210X 드라이버가 설치되어 있는지 확인하세요. 어댑터가 감지되고 연결되면 picocom, minicom 또는 screen 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치를 나열하려면:

```
ls /dev/
```

UART 인터페이스와 기본적으로 상호 작용하려면 다음 명령을 사용하세요:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom의 경우 다음 명령을 사용해 설정합니다:

```
minicom -s
```

baudrate 및 device name과 같은 설정을 `Serial port setup` 옵션에서 구성합니다.

구성한 후 `minicom`을 실행해 UART 콘솔을 엽니다.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

UART Serial to USB 어댑터를 사용할 수 없는 경우, 간단한 hack으로 Arduino UNO R3를 사용할 수 있습니다. Arduino UNO R3는 어디서나 쉽게 구할 수 있으므로 시간을 크게 절약할 수 있습니다.

Arduino UNO R3에는 USB to Serial 어댑터가 보드 자체에 내장되어 있습니다. UART에 연결하려면 보드에서 Atmel 328p 마이크로컨트롤러 칩을 뽑기만 하면 됩니다. 이 hack은 Atmel 328p가 보드에 납땜되지 않은 Arduino UNO R3 변형 모델에서 작동합니다(SMD 버전에는 납땜되어 있습니다). Arduino의 RX 핀(Digital Pin 0)을 UART 인터페이스의 TX 핀에 연결하고, Arduino의 TX 핀(Digital Pin 1)을 UART 인터페이스의 RX 핀에 연결합니다.

Arduino IDE의 **Serial Monitor** 또는 대상 baud rate에 맞춘 전용 터미널을 사용합니다. 일반적인 Uno R3의 serial 신호는 5 V 로직이므로, 3.3 V 또는 그보다 낮은 전압의 대상 장치에 연결하기 전에 level shifter나 분압기를 사용합니다.

## Bus Pirate

다음 transcript는 UART 출력을 모니터링하기 위해 legacy Bus Pirate firmware 인터페이스를 사용합니다. 최신 Bus Pirate firmware에서는 `m uart`, `{`/`}`, `monitor` 또는 `bridge`와 같은 명령을 사용합니다. 설치된 버전에 맞는 문서를 참고하세요.<sup>[[2]](#references)</sup>

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

## UART Console을 사용한 펌웨어 덤프

UART console은 부팅 로그와 때로는 bootloader 또는 운영체제 shell에 런타임으로 접근할 수 있게 해 줍니다. 읽기 전용 console에서도 메모리 맵, flash 드라이버, 부팅 인수, 파티션 레이아웃, 펌웨어 버전을 확인할 수 있습니다. 펌웨어는 SPI NOR/NAND, eMMC 또는 다른 장치에 저장될 수 있습니다. 일반적으로 EEPROM에서 직접 실행되지는 않으며, 마운트된 영구 파일 시스템에 기록한 파일이 재부팅 후 반드시 사라지는 것도 아닙니다.

데이터를 확보하는 방법은 여러 가지가 있으며, 외부 flash를 직접 읽는 방법은 SPI 섹션에서 다룹니다. bootloader에 안전한 읽기 명령이 이미 있다면 console을 이용한 확보가 덜 침습적일 수 있습니다. 하지만 부팅을 중단하거나 flash 명령을 실행하면 가용성에 영향을 줄 수 있으므로, 원래 상태를 기록하고 쓰기/삭제 작업은 피하세요.

console을 이용한 펌웨어 덤프는 bootloader의 부팅을 중단하는 것부터 시작하는 경우가 많습니다. 많은 embedded Linux 장치가 **Das U-Boot**를 사용하지만, 다른 장치는 proprietary bootloader를 사용하거나 대화형 console을 비활성화합니다.

대화형 bootloader가 있는지 확인하려면 대상 장치의 전원이 꺼진 상태에서 UART 수신 경로와 terminal을 연결하고, 로깅을 시작한 다음 전원을 켭니다. 화면에 표시되는 자동 부팅 프롬프트에 따르세요. 빌드에 따라 중단하려면 키 하나 또는 짧은 키 입력 시퀀스가 필요할 수 있으며, 아예 비활성화되어 있을 수도 있습니다.

중단에 성공하면 `help`, `printenv` 및 읽기 전용 탐색 명령을 사용해 주소에 접근하기 전에 해당 제조사의 메모리 및 저장소 레이아웃을 파악하세요.

U-Boot에서 `md`는 **주소 지정 가능한 메모리**를 표시하며, 자동으로 “EEPROM”을 표시하는 것은 아닙니다. 먼저 `mtd list`, `sf probe`, `mmc info`, `part list`와 같은 보드별 명령, 환경 변수, 부팅 로그를 사용해 올바른 매핑 주소를 찾거나 flash 영역을 RAM에 로드하세요. 그런 다음 바이트 단위로 지정된 범위를 표시합니다:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

시작하기 전에 시리얼 출력을 기록하세요. `md.b` 출력에는 주소와 ASCII 열이 포함되어 있으므로, 이는 원시 ROM 이미지가 아니라 텍스트 표현입니다.

주소와 ASCII 열을 제거하고 16진수 바이트 필드만 연결한 다음, 이를 바이너리로 디코딩하세요(예: `xxd -r -p` 사용). 분석 전에 예상 바이트 수를 확인하고 해시를 기록하세요:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk는 재구성된 바이너리에서 알려진 시그니처를 식별합니다. 콘솔을 통해 데이터를 안정적으로 전송할 수 없다면, 적절한 SPI/eMMC/NAND 인터페이스를 통한 직접 플래시 읽기가 대개 더 빠르고 오류도 적습니다.

U-Boot는 중단 기능을 비활성화하거나, 벤더별 키 시퀀스를 요구하거나, 메모리/플래시 명령을 잠글 수 있습니다. 문자를 무작정 전송하지 말고 autoboot 프롬프트와 부팅 로그를 확인하세요. 콘솔에서 중단할 수 없다면 부팅 로그를 보관하고 비침습적인 펌웨어 획득 경로를 이용하세요.

## References

- [1] [Microchip PIC32 제품군 참조 설명서 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate 문서 - UART 모드 및 전기적 한계](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C 데이터시트](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot 문서 - `md` 메모리 표시 명령](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — 리버스 엔지니어를 위한 SCPI 및 하드웨어 계측, 1부](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 프로그래밍 가이드](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — 백엔드 구성](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
