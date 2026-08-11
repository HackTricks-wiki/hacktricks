# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate를 연결하기 전에 대상 전압, 핀아웃, pull-up 구성 및 공통 접지를 확인하세요. 단순히 sniff하기 위해 대상에 전원이 공급 중인 bus에서 Bus Pirate 전원 공급 장치를 활성화하지 마세요. 두 전원 공급 장치가 충돌하여 hardware가 손상될 수 있습니다. 아래 transcript는 device-specific Bus Pirate v3/community-firmware 예시이며, 보편적으로 적용되는 wiring recipe가 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirate가 작동하는지 테스트하려면 +5V를 VPU에 연결하고 3.3V를 ADC에 연결한 다음 bus pirate에 접속하세요(예: Tera Term 사용). 그리고 다음 명령 `~`을 사용하세요:
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
이전 명령줄에서 볼 수 있듯이 오류가 0개 발견되었다고 표시됩니다. 제품을 구매한 후 또는 firmware를 flashing한 후 정상적으로 작동하는지 확인하는 데 매우 유용합니다.

Bus Pirate에 연결하려면 다음 문서를 참고할 수 있습니다:

![명령 사용 - 스페이스 누르기: Bus Pirate에 연결하려면 다음 문서를 참고할 수 있습니다](<../../images/image (484).png>)

이 경우 대상은 24C256 계열 I²C EEPROM입니다. 부품마다 지원되는 공급 전압이 다르므로 정확한 suffix/datasheet를 확인하세요.<sup>[[3]](#references)</sup>

![명령 사용 - 스페이스 누르기: 이 경우 EPROM에 연결합니다: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus Pirate와 통신하기 위해 Tera Term을 사용해 Bus Pirate의 COM 포트에 연결하고 Setup --> Serial Port --> Speed를 115200으로 설정했습니다.\
다음 통신 내용에서 Bus Pirate를 I2C 통신에 맞게 준비하고 memory에 쓰고 읽는 방법을 확인할 수 있습니다(주석은 "#"을 사용해 표시했습니다. 통신 내용에는 해당 부분이 나타나지 않을 것으로 예상하세요):
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

이 시나리오에서는 arduino와 이전 EPROM 간의 I2C 통신을 sniff합니다. 두 장치가 서로 통신하도록 한 다음, bus pirate를 SCL, SDA 및 GND 핀에 연결하면 됩니다:

![이전에 구성한 주소 0x69에서 20B 읽기 - Sniffer: 이 시나리오에서는 arduino와 이전 EPROM 간의 I2C 통신을 sniff합니다. 두 장치가 서로 통신하도록 한 다음,...](<../../images/image (166).png>)
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
## References

- [1] [Bus Pirate 문서 — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus 사양 및 사용자 매뉴얼](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C serial EEPROM 데이터시트](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
{{#include ../../banners/hacktricks-training.md}}
