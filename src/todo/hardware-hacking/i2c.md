# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

Bus Pirate के काम करने की जांच करने के लिए, +5V को VPU से और 3.3V को ADC से जोड़ें और बस पायरेट तक पहुँचें (उदाहरण के लिए Tera Term का उपयोग करते हुए) और कमांड `~` का उपयोग करें:
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
जैसा कि आप पिछले कमांड लाइन में देख सकते हैं, इसमें कहा गया था कि 0 त्रुटियाँ मिलीं। यह जानना बहुत उपयोगी है कि यह काम कर रहा है, इसे खरीदने के बाद या फर्मवेयर फ्लैश करने के बाद।

बस पायरेट से कनेक्ट करने के लिए आप दस्तावेज़ों का पालन कर सकते हैं:

![](<../../images/image (484).png>)

इस मामले में मैं एक EPROM: ATMEL901 24C256 PU27 से कनेक्ट करने जा रहा हूँ:

![](<../../images/image (964).png>)

बस पायरेट से बात करने के लिए मैंने Tera Term का उपयोग किया, जो पायरेट बस COM पोर्ट से कनेक्ट किया गया था, सेटअप --> सीरियल पोर्ट --> 115200 की गति के साथ।\
निम्नलिखित संचार में आप देख सकते हैं कि बस पायरेट को I2C से बात करने के लिए कैसे तैयार किया जाए और मेमोरी से पढ़ने और लिखने का तरीका (टिप्पणियाँ "#" का उपयोग करके दिखाई देती हैं, संचार में उस भाग की अपेक्षा न करें):
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

इस परिदृश्य में, हम Arduino और पिछले EPROM के बीच I2C संचार को स्निफ़ करने जा रहे हैं, आपको बस दोनों उपकरणों के बीच संचार करना है और फिर बस पायरेट को SCL, SDA और GND पिनों से कनेक्ट करना है:

![](<../../images/image (166).png>)
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
