# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate कनेक्ट करने से पहले target voltage, pinout, pull-up arrangement और common ground को verify करें। किसी live, target-powered bus को केवल sniff करने के लिए Bus Pirate power supplies enable न करें; दो power supplies आपस में contend कर सकती हैं और hardware को नुकसान पहुंचा सकती हैं। नीचे दिया गया transcript device-specific Bus Pirate v3/community-firmware example है, universal wiring recipe नहीं।<sup>[[1]](#references)[[2]](#references)</sup>

यह जांचने के लिए कि Bus Pirate काम कर रहा है, +5V को VPU से और 3.3V को ADC से कनेक्ट करें, फिर Bus Pirate को access करें (उदाहरण के लिए Tera Term का उपयोग करके) और `~` command का उपयोग करें:
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
जैसा कि आप पिछली command line में देख सकते हैं, इसमें 0 errors मिले। इसे खरीदने या firmware flash करने के बाद यह जानना बहुत उपयोगी है कि यह काम कर रहा है।

Bus pirate से connect करने के लिए आप docs का अनुसरण कर सकते हैं:

![कमांड का उपयोग करें - space दबाएँ: Bus pirate से connect करने के लिए आप docs का अनुसरण कर सकते हैं](<../../images/image (484).png>)

इस मामले में target 24C256-family का I²C EEPROM है। सटीक suffix/datasheet की पुष्टि करें, क्योंकि supported supply voltage part के अनुसार अलग-अलग हो सकता है।<sup>[[3]](#references)</sup>

![कमांड का उपयोग करें - space दबाएँ: इस मामले में मैं एक EPROM से connect करने जा रहा हूँ: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus pirate से बात करने के लिए मैंने pirate bus COM port से connected Tera Term का उपयोग किया, जिसमें Setup --> Serial Port --> Speed को 115200 पर सेट किया गया था।\
निम्न communication में आप देख सकते हैं कि bus pirate को I2C से बात करने के लिए कैसे तैयार किया जाता है और memory से कैसे write तथा read किया जाता है (Comments में "#" का उपयोग किया गया है; communication में इस भाग की अपेक्षा न करें):
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

इस scenario में हम arduino और पिछले EPROM के बीच I2C communication को sniff करने वाले हैं। आपको बस दोनों devices के बीच communication करना है और फिर bus pirate को SCL, SDA और GND pins से connect करना है:

![पहले configure किए गए address 0x69 से 20B पढ़ें - Sniffer: इस scenario में हम arduino और पिछले EPROM के बीच I2C communication को sniff करने वाले हैं। आपको बस...](<../../images/image (166).png>)
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

- [1] [Bus Pirate documentation — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus specification and user manual](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C serial EEPROM datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
{{#include ../../banners/hacktricks-training.md}}
