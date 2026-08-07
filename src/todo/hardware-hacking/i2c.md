# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

Bus Pirate가 작동하는지 테스트하려면 +5V를 VPU에 연결하고 3.3V를 ADC에 연결한 다음 Bus Pirate에 액세스합니다(예: Tera Term 사용). 그리고 다음 명령어 `~`을 사용합니다:
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
이전 명령줄에서 볼 수 있듯이 오류가 0개 발견되었다고 표시됩니다. 이는 구매 후 또는 firmware를 flashing한 후 정상적으로 작동하는지 확인하는 데 매우 유용합니다.

Bus Pirate에 연결하려면 docs를 따를 수 있습니다:

![명령 사용 - Space 누르기: Bus Pirate에 연결하려면 docs를 따를 수 있습니다](<../../images/image (484).png>)

이 경우 EPROM인 ATMEL901 24C256 PU27에 연결하겠습니다:

![명령 사용 - Space 누르기: 이 경우 EPROM인 ATMEL901 24C256 PU27에 연결하겠습니다](<../../images/image (964).png>)

Bus Pirate와 통신하기 위해 Tera Term을 사용했으며, Setup --> Serial Port --> Speed를 115200으로 설정하여 Bus Pirate의 COM 포트에 연결했습니다.\
다음 통신 내용에서 Bus Pirate가 I2C와 통신하도록 준비하는 방법과 memory에 쓰고 읽는 방법을 확인할 수 있습니다 (댓글은 "#"을 사용하여 표시되며, 통신 내용에는 해당 부분이 포함되지 않는다고 생각하면 됩니다):
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

#Notice how the VPU is in 5V becausethe EPROM needs 5V signals

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

# Select communication spped
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

# Note that each slave will have a write address and a read address
# 0xA0 ad 0xA1 in the previous case

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

이 시나리오에서는 arduino와 이전 EPROM 간의 I2C 통신을 sniff합니다. 두 장치가 서로 통신하도록 한 다음 bus pirate를 SCL, SDA 및 GND 핀에 연결하면 됩니다:

![이전에 구성한 주소 0x69에서 20B 읽기 - Sniffer: 이 시나리오에서는 arduino와 이전 EPROM 간의 I2C 통신을 sniff합니다. 두 장치가 서로 통신하도록 한 다음...](<../../images/image (166).png>)
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

# EVEN IF YOU ARE GOING TO SNIFF YOU NEED TO POWER ON!

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```
{{#include ../../banners/hacktricks-training.md}}
