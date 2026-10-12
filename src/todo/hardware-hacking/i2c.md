# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate를 연결하기 전에 대상 장치의 전압, 핀 배열, 풀업 구성, 공통 접지를 확인하세요. 버스를 스니핑하기 위해 대상 장치에 전원이 공급되는 상태에서 Bus Pirate의 전원 공급 장치를 활성화하지 마세요. 두 전원 공급 장치가 서로 간섭해 하드웨어가 손상될 수 있습니다. 아래 로그는 특정 장치인 Bus Pirate v3/community-firmware의 예시이며, 어디에나 적용할 수 있는 배선 방법이 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirate가 작동하는지 테스트하려면 +5V를 VPU에, 3.3V를 ADC에 연결하고 Bus Pirate에 접속한 다음(예: Tera Term 사용) `~` 명령을 입력합니다:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

이전 명령줄에서 오류가 0개 발견되었다고 표시된 것을 볼 수 있습니다. 기기를 구매한 후나 firmware를 플래싱한 후 정상 작동하는지 확인하는 데 매우 유용합니다.

Bus Pirate에 연결하려면 문서를 참고하세요:

![명령 사용 - 스페이스바 누르기: Bus Pirate에 연결하려면 문서를 참고하세요](<../../images/image (484).png>)

이 경우 대상은 24C256 계열 I²C EEPROM입니다. 부품마다 지원하는 공급 전압이 다르므로 정확한 접미사와 데이터시트를 확인하세요.<sup>[[3]](#references)</sup>

![명령 사용 - 스페이스바 누르기: 이 경우 EPROM에 연결합니다: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus Pirate와 통신하기 위해 Tera Term을 사용해 Bus Pirate의 COM 포트에 연결하고 Setup --> Serial Port --> Speed를 115200으로 설정했습니다.\
다음 통신 내용에서 Bus Pirate를 I²C 통신에 맞게 설정하고 메모리에 쓰고 읽는 방법을 확인할 수 있습니다(주석은 "#"을 사용해 표시합니다. 통신 내용에는 주석이 포함되어 있지 않습니다):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

이 시나리오에서는 arduino와 앞서 언급한 EPROM 사이의 I2C 통신을 sniff합니다. 두 장치 모두와 통신한 다음, bus pirate를 SCL, SDA 및 GND 핀에 연결하면 됩니다:

![이전에 설정한 주소 0x69에서 20B 읽기 - Sniffer: 이 시나리오에서는 arduino와 앞서 언급한 EPROM 사이의 I2C 통신을 sniff합니다. 두 장치 모두와 통신한 다음 bus pirate를...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## 블랙박스 I2C 프로토콜 재구성

### 동작 중인 핀에서 버스 식별하기

주변 장치에 핀아웃이나 데이터시트가 없으면, 원래 호스트가 작동하는 동안 고임피던스 로직 분석기로 수동 관찰을 시작합니다. 공통 접지와 안전한 로직 레벨을 확인한 뒤, 일정한 핀은 전원 레일, 접지 또는 풀업된 신호일 가능성이 있는 것으로 분류하고 활성 라인을 일반적인 버스와 비교합니다. UART는 비동기식으로 독립된 TX/RX를 사용하고, 일반적인 SPI는 보통 클록, 칩 선택 신호, 별도의 데이터 방향을 노출하며, I2C는 일정한 클록과 양방향 데이터 라인 하나를 사용합니다. 이후 I2C 디코딩을 통해 7비트 대상 주소, 읽기/쓰기 방향, ACK/NACK, 반복되는 페이로드를 확인할 수 있습니다.<sup>[[2]](#references)[[4]](#references)</sup>

정상적인 교환을 여러 차례 캡처하고 디코딩된 바이트와 원시 타이밍을 모두 보존합니다. 반복 프레임은 이후 직렬화기를 검증하는 데 유용한 알려진 정답 테스트가 되며, 요청 간 차이를 비교하면 opcode, 인덱스, 오프셋, 길이, 시퀀스 또는 체크섬 필드로 추정되는 항목을 찾을 수 있습니다.<sup>[[4]](#references)</sup>

### 호스트 펌웨어에서 프레이밍 복구하기

주변 장치 펌웨어에 접근할 수 없다면 **호스트** 펌웨어를 추출하고 I2C 장치를 여는 컴포넌트를 찾습니다. 주변 장치 이름, `/dev/i2c-`, 명령 빌더, 응답 파서, 재설정/초기화 루틴, 체크섬 함수와 관련된 문자열과 심볼을 검색합니다. 각 빌더에서 함수 이름으로 형식을 추측하지 말고 정확한 필드 오프셋, 상수, 허용되는 인수 크기, 페이로드 길이, 체크섬 범위, 체크섬 바이트 순서, 반환 프레임 길이를 기록합니다.<sup>[[4]](#references)</sup>

`crc16_ccitt`라는 체크섬 함수 이름만으로는 프리셋을 정하기에 충분하지 않습니다. 시프트 방향, 테이블 인덱스 바이트, 테이블에 반영된 다항식, 초기 레지스터 값, 입력/출력 비트 반전, 최종 XOR/반전, 직렬화기의 와이어 바이트 순서를 확인해야 합니다. 예를 들어, 역방향 다항식 `0x8408`을 기반으로 한 오른쪽 시프트 방식의 로우 바이트 테이블을 사용하고, `0xFFFF`로 초기화한 뒤 끝에서 보수 처리한다면 **CRC-16/X-25 (IBM-SDLC)**입니다. 무결성 검증을 통과해 명령 파서까지 테스트 케이스를 전달하려면 올바른 체크섬이 필요한 경우가 많습니다.<sup>[[4]](#references)</sup>

형식을 재구성한 뒤 공개 코드에서 특징적인 심볼 이름과 상수를 검색합니다. MJA1 사례에서는 별도로 찾은 SDK 래퍼가 명령 ID, 인수 검증, 응답 정의, 미러링된 CRC 구현을 확인해 주었습니다. 이러한 소스는 검증 자료로 사용하고, 정확한 대상 바이너리와 와이어상의 바이트 순서를 확인하는 절차를 대체하는 용도로 사용하지 마세요.<sup>[[4]](#references)[[5]](#references)</sup>

### 루팅된 Linux 호스트에서 프레임 보내기

침해된 임베디드 Linux 호스트는 별도의 버스 컨트롤러를 추가하지 않고도 주변 장치를 테스트할 수 있습니다. 관련 어댑터를 열고 `I2C_SLAVE`로 7비트 주소를 선택한 다음, 전용 직렬화기로 생성한 프레임을 보냅니다. 변이 및 퍼징을 위해 원시 프레임 모드도 유지합니다.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

대상 CPU 및 libc와 호환되는 toolchain으로 cross-compile하고, test client의 analyzer trace를 정상 트래픽과 비교하세요. 표시되는 바이트가 같더라도 트랜잭션 경계, 쓰기/읽기 순서, 지연 시간, 주변 장치 상태가 중요할 수 있습니다.<sup>[[4]](#references)</sup>

### 응답 기반 opcode 열거

가장 짧은 유효 프레임과 체크섬을 알아낸 뒤, 전체 opcode 너비를 열거하고 프로토콜의 명시적인 **unsupported-command** 응답을 음성 기준으로 사용하세요. 잘못된 인수, 잘못된 상태, 문서화되지 않은 상태 코드처럼 다른 결과가 나오면 디코딩이 구현된 핸들러 또는 부분적으로 구현된 핸들러에 도달했음을 시사합니다. 이것만으로 악용 가능성이 입증되는 것은 아닙니다. 길이, 인수, 상태, 명령 시퀀스를 체계적으로 fuzzing할 후보로 우선순위를 지정하세요.<sup>[[4]](#references)</sup>

테스트로 주변 장치가 멈춘다면, 외부 컨트롤러에서 부팅 1회당 격리된 테스트 케이스 하나를 자동 실행하세요. SSH로 연결해 테스트 케이스를 실행하고, 원시 요청/응답과 타이밍을 저장한 다음 재부팅하거나 전원을 껐다 켜세요. 상태 확인이 정상으로 돌아올 때까지 기다린 뒤 다음 테스트를 진행하세요. 나중에 마이크로컨트롤러 제어 fixture로 구성 요소를 옮기면 결정론적인 초기화, 직접적인 전원 제어, 더 빠른 fuzzing이 가능합니다.<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate 문서 — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C 버스 사양 및 사용자 설명서](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C 직렬 EEPROM 데이터시트](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — 블랙박스 프로빙: Xiaomi MJA1 보안 칩의 보안 분석](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 암호화 래퍼](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
