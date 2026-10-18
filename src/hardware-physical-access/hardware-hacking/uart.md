# UART

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

UART는 공통 클럭 없이 프레임으로 구성된 비트 스트림을 전송하는 비동기 직렬 인터페이스입니다. 논리 레벨 UART를 RS-232와 혼동하지 마세요. RS-232는 전압 레벨이 다르고, 보통 음전압을 사용하며 트랜시버가 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

일반적으로 UART가 유휴 상태일 때 라인은 높음(논리값 1)으로 유지됩니다. 그런 다음 데이터 전송이 시작됨을 알리기 위해 송신기가 수신기로 시작 비트를 보내며, 이때 신호는 낮음(논리값 0)으로 유지됩니다. 이어서 송신기는 실제 메시지가 담긴 5~8개의 데이터 비트를 보내고, 설정에 따라 선택적인 패리티 비트와 1개 또는 2개의 정지 비트(논리값 1)를 보냅니다. 오류 검사용 패리티 비트는 실제로는 거의 사용되지 않습니다. 정지 비트는 전송이 끝났음을 나타냅니다.

가장 일반적인 설정은 8N1입니다. 데이터 비트 8개, 패리티 없음, 정지 비트 1개를 의미합니다. UART는 데이터의 최하위 비트를 먼저 전송하므로 ASCII `C`(`0x43`)는 시작 비트 `0`, 데이터 비트 `1, 1, 0, 0, 0, 0, 1, 0`, 정지 비트 `1` 순으로 전송됩니다.<sup>[[1]](#references)</sup>

![UART: 가장 일반적인 설정인 8N1은 데이터 비트 8개, 패리티 없음, 정지 비트 1개를 의미합니다. 예를 들어 ASCII에서 문자 C 또는 0x43을 8N1 UART로 보내려는 경우](<../../images/image (764).png>)

UART 통신에 사용할 수 있는 하드웨어 도구:

- USB-직렬 어댑터
- CP2102 또는 PL2303 칩이 탑재된 어댑터
- Bus Pirate, Adafruit FT232H, Shikra 또는 Attify Badge와 같은 다목적 도구

### UART 포트 식별

일반적인 디버그 헤더에는 **TX**, **RX**, **GND**가 있습니다. **Vcc/Vref** 핀, 리셋 핀 또는 흐름 제어 핀이 추가로 있을 수도 있습니다. Vcc는 UART 신호가 아니며, 보드 회로도와 전류 요구 사항을 확인한 경우가 아니라면 일반적으로 전원으로 연결하지 말고 전압 기준으로만 사용해야 합니다.<sup>[[2]](#references)[[3]](#references)</sup>

먼저 장치의 **전원을 끄고** 연결을 해제합니다.

- 연속성 모드를 사용해 알려진 접지면, 커넥터 실드 또는 전원 접지를 기준으로 **GND**를 식별합니다. 전원이 켜진 보드에서는 연속성/저항 모드를 절대 사용하지 마세요.
- 대상 장치의 전원을 켜기 전에 멀티미터를 DC 전압 모드로 전환합니다. 후보 핀과 접지 사이의 전압을 측정해 논리 전압을 식별합니다. 안정적인 전압 레일이 Vcc/Vref일 수 있지만, 연결해도 안전하다고 단정하지 마세요.
- 부팅 중 로직 애널라이저나 오실로스코프로 후보 핀을 관찰합니다. **TX**는 보통 유휴 상태에서 높음이며, 프레임 데이터가 연속적으로 나타납니다. 멀티미터는 평균적인 변동을 표시할 수 있지만 프레이밍이나 baud rate를 검증할 수는 없습니다.
- **RX**는 유휴 상태를 유지할 수 있으며, TX 옆에 있다는 이유만으로 안전하게 식별할 수는 없습니다. PCB 배선을 추적하거나 SoC 데이터시트를 확인하거나, 신호를 인가하기 전에 고임피던스 애널라이저를 사용하세요.

TX와 RX를 서로 바꿔 연결하면 보통 통신이 되지 않습니다. 전원, 접지 또는 신호 레벨을 잘못 연결하면 대상 장치나 어댑터가 영구적으로 손상될 수 있습니다. 먼저 접지를 연결하고, **수신 전용**으로 시작하세요(대상 장치 TX를 어댑터 RX에 연결).

제조업체는 헤더를 생략하거나, 직렬 저항을 실장하지 않거나, 펌웨어에서 콘솔을 비활성화하거나, TX만 노출할 수 있습니다. 근처 테스트 패드와 저항 풋프린트를 SoC까지 추적하고, 전기적 레벨을 확인한 후에만 임시 고임피던스 연결을 추가하세요. 보증이 있다는 사실만으로 접근 가능한 UART가 반드시 존재한다고 볼 수는 없습니다.

### 낮은 전압으로 보이는 TX 패드 확인

초기 오실로스코프 캡처에서 TX라고 표시된 패드가 계속 낮게 보인다고 해서 UART가 없다고 단정할 수는 없습니다. 대상 장치의 논리 전압과 공통 접지를 확인한 후, 약한 풀업(문서의 예에서는 **10 kΩ을 3.3 V에 연결**)을 적용하고 버튼을 누르거나 장치를 부팅하면서 다시 캡처해 보세요. 대상 장치의 검증된 논리 전원 레일만 사용하세요. 알 수 없거나 능동적으로 구동되는 신호에 풀업을 연결하지 마세요. 프레임 전이가 나타나면 패드를 직렬 어댑터에 수신 전용으로 연결하기 전에 가장 짧고 깨끗한 비트 주기를 측정해 baud rate를 추정하세요. 이 방법으로 예시에서는 115200 baud의 버튼 이벤트 로그를 복구했지만, 펌웨어 덤프는 얻지 못했습니다.<sup>[[8]](#references)</sup>

### UART Baud Rate 식별

올바른 baud rate를 찾는 가장 쉬운 방법은 **TX 핀의 출력을 확인하고 데이터를 읽어 보는 것**입니다. 수신한 데이터를 읽을 수 없다면 데이터가 읽힐 때까지 다음 baud rate를 시도하세요. USB-직렬 어댑터나 Bus Pirate 같은 다목적 장치에 [baudrate.py](https://github.com/devttys0/baudrate/)와 같은 보조 스크립트를 함께 사용할 수 있습니다. 가장 일반적인 baud rate는 9600, 38400, 19200, 57600, 115200입니다.

> [!CAUTION]
> 이 프로토콜에서는 한 장치의 TX를 다른 장치의 RX에 연결해야 한다는 점을 기억하세요!

### SCPI를 이용한 부팅 시 UART 캡처 자동화

부팅 출력이 짧거나 TX 패드가 아직 확인되지 않았다면, 전원 공급 장치와 오실로스코프를 수동으로 조작하는 대신 전원을 반복해서 켜는 작업을 자동화하세요. 전류 제한 기능이 있는 프로그래밍 가능 전원 공급 장치를 대상 장치의 검증된 전원 입력에 연결합니다. 각 후보 TX 패드는 공통 접지를 사용해 고임피던스 오실로스코프 입력으로 프로브하세요. 패드에 신호를 인가하지 마세요.<sup>[[5]](#references)</sup>

VISA는 직렬 또는 Ethernet 장비 세션을 열고, SCPI는 출력, 트리거 및 파형 판독을 제어합니다.<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa`와 `pyvisa-py`를 설치하세요(직렬 VISA 리소스에는 `pyserial`도 설치). `ResourceManager('@py')`는 Python 백엔드를 명시적으로 선택합니다.<sup>[[5]](#references)[[7]](#references)</sup> 사용 중인 장비에서 지원하는 리소스 문자열과 명령으로 바꾸세요.<sup>[[5]](#references)</sup>

Rigol MSO5000 예시에서는 보드에 전원을 공급하기 전에 단일 하강 에지 트리거를 설정합니다. 유휴 상태에서 높음인 UART TX는 시작 비트에서 처음으로 하강합니다.<sup>[[5]](#references)</sup> 측정한 유휴 레벨과 낮은 레벨 사이에 트리거 임계값을 설정하고, 관심 있는 부팅 구간을 포착하도록 시간축을 설정하세요.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD`는 연속 캡처에서 반복되는 에지를 억제할 수 있지만, 단일 캡처가 실제로 완료되었는지 확인하는 일을 대신하지는 않습니다.<sup>[[5]](#references)</sup> 다음 코드는 부팅 한 번을 캡처하고 부호 없는 바이트 샘플과 스케일링 메타데이터를 모두 저장합니다. 시간 초과가 발생하면 무한정 기다리는 대신 대상 장치의 전원을 끕니다.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA 전원 켜기 및 단일 캡처 UART 파형 캡처</summary>

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

pad survey를 위해 probe를 옮긴 후 single-shot capture를 반복하거나, supply session을 열린 상태로 유지하고 boot dwell과 off interval을 두고 출력을 cycling하세요. 전원을 켤 때마다 scope를 다시 arm하여 각 파일이 하나의 boot와 하나의 pad에 대응하도록 하세요.<sup>[[5]](#references)</sup>

Rigol preamble은 `<format>,<type>,<points>,<count>,<xincrement>,...` 형식입니다.<sup>[[6]](#references)</sup> **세 번째** 값은 points의 개수이며, article에 명시된 것처럼 sample rate가 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup> 예시에서 `25,000,000` points와 `xincrement = 2e-8` seconds는 `1 / xincrement = 50,000,000` samples/second를 의미하며, 25 MSa/s가 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup> preamble을 binary file과 함께 보관하고 read length가 `<points>`와 일치하는지 확인하세요. guide에는 대용량 record를 위한 segmented/batched read가 설명되어 있습니다.<sup>[[6]](#references)</sup>

캡처한 신호를 decode하려면 PulseView에서 `capture.bin`을 **Raw Analog Data Without Header**로 import하고, unsigned 8-bit (`U8`) 값을 선택한 후 `xincrement`에서 계산한 sample rate를 입력하세요.<sup>[[5]](#references)[[6]](#references)</sup> 아날로그 채널에 **Logic via Threshold**를 적용하고, low와 high sample 값 사이의 threshold를 선택하세요.<sup>[[5]](#references)</sup> 깨끗한 start-bit 폭을 측정해 baud rate를 추정한 다음(57,600 baud에서 약 17.36 µs), PulseView의 UART decoder를 적용하고 여러 frame이 일관되게 decode되는지 확인하세요.<sup>[[5]](#references)</sup> falling edge만으로 pad가 UART라고 단정할 수는 없습니다.

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridge는 많은 prototyping board와 저렴한 adapter에서 볼 수 있습니다. 일반적인 module에는 GND, RXD, TXD와 함께 supply pin이 있지만, header와 I/O level은 제품마다 다릅니다. board design이나 data sheet를 확인해 실제 voltage를 확인하세요. 보통 GND와 adapter RX를 target TX에 연결하고, receive-only 검증을 마친 후 adapter TX를 target RX에 연결하면 됩니다. 해당 전압을 견딜 수 있다고 확인된 target에 의도적으로 전원을 공급하는 경우가 아니라면 adapter의 5 V/3.3 V supply pin을 연결하지 마세요.<sup>[[3]](#references)</sup>

adapter가 감지되지 않는다면 host system에 CP210X driver가 설치되어 있는지 확인하세요. adapter가 감지되고 연결되면 picocom, minicom 또는 screen 같은 도구를 사용할 수 있습니다.

Linux/MacOS 시스템에 연결된 장치를 나열하려면:

```
ls /dev/
```

UART 인터페이스와 기본적으로 상호작용하려면 다음 명령을 사용하세요:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom을 설정하려면 다음 명령을 사용하세요:

```
minicom -s
```

`Serial port setup` 옵션에서 baudrate 및 device name과 같은 설정을 구성합니다.

구성이 끝나면 `minicom`을 실행해 UART 콘솔을 엽니다.

## Arduino UNO R3를 통한 UART (Atmel 328p 칩을 분리할 수 있는 보드)

UART Serial to USB 어댑터를 사용할 수 없다면 간단한 방법으로 Arduino UNO R3를 사용할 수 있습니다. Arduino UNO R3는 어디서나 흔히 구할 수 있으므로 시간을 많이 절약할 수 있습니다.

Arduino UNO R3에는 보드 자체에 USB to Serial 어댑터가 내장되어 있습니다. UART 연결을 사용하려면 보드에서 Atmel 328p 마이크로컨트롤러 칩을 뽑기만 하면 됩니다. 이 방법은 Atmel 328p가 보드에 납땜되지 않은 Arduino UNO R3 변형 모델에서 사용할 수 있습니다(해당 모델에는 SMD 버전이 사용됩니다). Arduino의 RX 핀(Digital Pin 0)을 UART 인터페이스의 TX 핀에 연결하고, Arduino의 TX 핀(Digital Pin 1)을 UART 인터페이스의 RX 핀에 연결합니다.

Arduino IDE의 **Serial Monitor** 또는 전용 터미널을 대상 baud rate에 맞춰 사용합니다. 기본 Uno R3의 직렬 신호는 5 V 로직이므로, 3.3 V 또는 더 낮은 전압의 대상에 연결하기 전에 레벨 시프터나 분압기를 사용합니다.

## Bus Pirate

다음 transcript에서는 UART 출력을 모니터링하기 위해 레거시 Bus Pirate 펌웨어 인터페이스를 사용합니다. 최신 Bus Pirate 펌웨어에서는 `m uart`, `{`/`}`, `monitor` 또는 `bridge`와 같은 명령을 사용합니다. 설치된 버전에 해당하는 문서를 참조하세요.<sup>[[2]](#references)</sup>

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

## UART 콘솔을 이용한 펌웨어 덤프

UART 콘솔은 부팅 로그에 대한 런타임 접근을 제공하며, 경우에 따라 부트로더나 운영체제 셸에도 접근할 수 있습니다. 읽기 전용 콘솔에서도 메모리 맵, 플래시 드라이버, 부팅 인수, 파티션 레이아웃, 펌웨어 버전을 확인할 수 있습니다. 펌웨어는 SPI NOR/NAND, eMMC 또는 다른 장치에 저장될 수 있습니다. 일반적으로 EEPROM에서 직접 실행되는 것은 아니며, 마운트된 영구 파일 시스템에 기록한 파일이 재부팅 후 반드시 사라지는 것도 아닙니다.

펌웨어를 획득하는 방법은 여러 가지이며, SPI 절에서는 외부 플래시에서 직접 읽는 방법을 다룹니다. 부트로더에 안전한 읽기 명령이 이미 있다면 콘솔을 이용한 획득 방식이 덜 침습적일 수 있습니다. 하지만 부팅을 중단하거나 플래시 명령을 실행하면 가용성에 영향을 줄 수 있으므로, 원래 상태를 기록하고 쓰기/삭제 작업은 피해야 합니다.

콘솔을 이용한 펌웨어 덤프는 부트로더의 부팅을 중단하는 것부터 시작하는 경우가 많습니다. 많은 임베디드 Linux 장치는 **Das U-Boot**을 사용하지만, 독점 부트로더를 사용하거나 대화형 콘솔을 비활성화한 장치도 있습니다.

대화형 부트로더가 있는지 확인하려면 대상 장치의 전원이 꺼진 상태에서 UART 수신 경로와 터미널을 연결하고, 로깅을 시작한 다음 전원을 켭니다. 화면에 표시되는 autoboot 안내에 따르세요. 빌드에 따라 키 하나나 짧은 키 입력 시퀀스가 필요할 수 있으며, 중단 기능이 완전히 비활성화되어 있을 수도 있습니다.

부팅 중단에 성공하면 `help`, `printenv` 및 읽기 전용 탐색 명령을 사용해 주소에 접근하기 전에 해당 벤더의 메모리 및 저장소 레이아웃을 파악하세요.

U-Boot에서 `md`는 **주소 지정 가능한 메모리**를 표시하며, 자동으로 “EEPROM”을 표시하는 것은 아닙니다. 먼저 `mtd list`, `sf probe`, `mmc info`, `part list`와 같은 보드별 명령, 환경 변수, 부팅 로그를 사용해 올바른 매핑 주소를 식별하거나 플래시 영역을 RAM에 로드하세요. 그런 다음 알려진 범위를 바이트 단위로 표시합니다:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

시작하기 전에 시리얼 출력을 기록합니다. `md.b` 출력에는 주소와 ASCII 열이 포함되어 있으므로, 원시 ROM 이미지가 아니라 텍스트 표현입니다.

주소와 ASCII 열을 제거하고 16진수 바이트 필드만 이어 붙인 다음, 바이너리로 디코딩합니다(예: `xxd -r -p`). 분석하기 전에 예상 바이트 수를 확인하고 해시를 기록합니다:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk은 재구성된 바이너리에서 알려진 시그니처를 식별합니다. 콘솔을 통해 데이터를 안정적으로 전송할 수 없다면, 적절한 SPI/eMMC/NAND 인터페이스로 플래시를 직접 읽는 편이 대개 더 빠르고 오류가 적습니다.

U-Boot는 중단을 비활성화하거나, 제조업체별 키 시퀀스를 요구하거나, 메모리/플래시 명령을 잠글 수 있습니다. 문자를 무작정 전송하지 말고 autoboot 프롬프트와 부팅 로그를 확인하세요. 콘솔을 중단할 수 없다면 부팅 로그를 보관하고 비침습적인 펌웨어 획득 방법을 사용하세요.

## References

- [1] [Microchip PIC32 제품군 참조 설명서 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate 문서 - UART 모드 및 전기적 한계](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C 데이터 시트](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot 문서 - `md` 메모리 표시 명령](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — 리버스 엔지니어를 위한 SCPI 및 하드웨어 계측, 1부](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 프로그래밍 가이드](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — 백엔드 구성](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — 하드웨어 해킹 기초 다지기 2부](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
