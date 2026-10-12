# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate को जोड़ने से पहले target voltage, pinout, pull-up arrangement और common ground की जाँच करें। केवल sniff करने के लिए live, target-powered bus पर Bus Pirate की power supplies enable न करें—दो power supplies एक-दूसरे से टकरा सकती हैं और hardware को नुकसान पहुँचा सकती हैं। नीचे दिया गया transcript, device-specific Bus Pirate v3/community-firmware का उदाहरण है, universal wiring recipe नहीं।<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirate काम कर रहा है या नहीं, यह जाँचने के लिए +5V को VPU से और 3.3V को ADC से जोड़ें, फिर Bus Pirate से कनेक्ट करें (उदाहरण के लिए Tera Term का उपयोग करके) और `~` command चलाएँ:

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

जैसा कि आप पिछली कमांड लाइन में देख सकते हैं, इसमें बताया गया कि 0 त्रुटियाँ मिलीं। यह जानना बहुत उपयोगी है कि खरीदने या firmware flash करने के बाद यह काम कर रहा है।

bus pirate से कनेक्ट करने के लिए आप docs का पालन कर सकते हैं:

![कमांड का उपयोग करें - Space दबाएँ: bus pirate से कनेक्ट करने के लिए आप docs का पालन कर सकते हैं](<../../images/image (484).png>)

इस मामले में लक्ष्य 24C256-family I²C EEPROM है। सटीक suffix/datasheet की पुष्टि करें, क्योंकि समर्थित supply voltage अलग-अलग parts के अनुसार बदलता है।<sup>[[3]](#references)</sup>

![कमांड का उपयोग करें - Space दबाएँ: इस मामले में मैं एक EPROM से कनेक्ट करने जा रहा हूँ: ATMEL901 24C256 PU27](<../../images/image (964).png>)

bus pirate से बात करने के लिए मैंने Tera Term का उपयोग किया, जो pirate bus COM port से Setup --> Serial Port --> Speed of 115200 सेटिंग के साथ कनेक्ट था।\
नीचे दिए गए संचार में आप देख सकते हैं कि bus pirate को I2C पर बात करने के लिए कैसे तैयार करें और memory से कैसे लिखें और पढ़ें (टिप्पणियाँ "#" का उपयोग करके दिखाई गई हैं; संचार में उस हिस्से के होने की अपेक्षा न करें):

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

इस परिदृश्य में हम arduino और पिछले EPROM के बीच I2C communication को sniff करेंगे। आपको बस दोनों डिवाइसों के बीच communication करना है और फिर bus pirate को SCL, SDA और GND pins से connect करना है:

![पता 0x69 से पहले से configured 20B पढ़ें - Sniffer: इस परिदृश्य में हम arduino और पिछले EPROM के बीच I2C communication को sniff करेंगे। आपको बस...](<../../images/image (166).png>)

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

## Black-box I2C प्रोटोकॉल का पुनर्निर्माण

### लाइव पिनों से बस की पहचान करें

जब peripheral के पास pinout या datasheet न हो, तो मूल host के काम करते समय high-impedance logic analyzer से निष्क्रिय रूप से शुरुआत करें। साझा ground और सुरक्षित logic level स्थापित करने के बाद, स्थिर पिनों को संभावित power rails, grounds या pull-up signals के रूप में वर्गीकृत करें। फिर सक्रिय लाइनों की तुलना आम buses से करें: UART में asynchronous और स्वतंत्र दिशा वाले TX/RX होते हैं; पारंपरिक SPI में आम तौर पर clock, chip select और डेटा की अलग-अलग दिशाएँ होती हैं; I2C में नियमित clock और एक bidirectional data line होती है। इसके बाद I2C decode से 7-bit target addresses, read/write दिशा, ACK/NACK और बार-बार आने वाले payloads दिखने चाहिए।<sup>[[2]](#references)[[4]](#references)</sup>

कई वैध exchanges कैप्चर करें और decoded bytes के साथ raw timing भी सुरक्षित रखें। दोहराए गए frames बाद में serializers के लिए उपयोगी known-answer tests होते हैं, जबकि requests के बीच के बदलाव संभावित opcode, index, offset, length, sequence या checksum fields उजागर कर सकते हैं।<sup>[[4]](#references)</sup>

### Host firmware से framing का पता लगाएँ

अगर peripheral firmware तक पहुँच नहीं है, तो **host** firmware निकालें और उस component को खोजें जो I2C device खोलता है। Peripheral का नाम, `/dev/i2c-`, command builders, response parsers, reset/initialization routines और checksum functions के लिए strings और symbols खोजें। हर builder के लिए function names से format का अनुमान लगाने के बजाय, field offsets, constants, स्वीकार्य argument sizes, payload length, checksum coverage, checksum byte order और लौटाए गए frame length का सटीक रिकॉर्ड रखें।<sup>[[4]](#references)</sup>

`crc16_ccitt` नाम वाला checksum function किसी preset को चुनने के लिए पर्याप्त नहीं है। Shift direction, table index byte, table में दर्शाया गया polynomial, initial register, input/output reflection, final XOR/inversion और serializer का wire endianness निर्धारित करें। उदाहरण के लिए, reversed polynomial `0x8408` पर आधारित right-shifting low-byte table, जिसे `0xFFFF` से initialize करके अंत में complement किया जाता है, **CRC-16/X-25 (IBM-SDLC)** की पहचान करता है। Integrity validation पार करके command parser तक पहुँचने के लिए अक्सर सही checksum आवश्यक होता है।<sup>[[4]](#references)</sup>

Format का पुनर्निर्माण करने के बाद, public code में विशिष्ट symbol names और constants खोजें। MJA1 मामले में, स्वतंत्र रूप से मिला SDK wrapper command IDs, argument validation, response definitions और mirrored CRC implementation की पुष्टि करता था; ऐसे source का उपयोग validation के लिए करें, न कि exact target binary और wire पर byte order की जाँच के विकल्प के रूप में।<sup>[[4]](#references)[[5]](#references)</sup>

### Rooted Linux host से frames भेजें

Compromised embedded Linux host, कोई दूसरा bus controller जोड़े बिना peripheral को चलाकर जाँच सकता है। संबंधित adapter खोलें, `I2C_SLAVE` से 7-bit address चुनें और dedicated serializer से बना frame भेजें; mutation और fuzzing के लिए raw-frame mode भी बनाए रखें।<sup>[[4]](#references)</sup>

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

टार्गेट CPU और libc के साथ संगत toolchain से cross-compile करें, और test client के analyzer traces की तुलना वैध traffic से करें। Transaction boundaries, write/read का क्रम, delays और peripheral की स्थिति मायने रख सकती है, भले ही दिखाई देने वाले bytes मेल खाते हों।<sup>[[4]](#references)</sup>

### Response-guided opcode enumeration

सबसे छोटा मान्य frame और checksum ज्ञात हो जाने के बाद, opcode की पूरी चौड़ाई enumerate करें और protocol के स्पष्ट **unsupported-command** response को negative baseline के रूप में इस्तेमाल करें। कोई अलग परिणाम—जैसे invalid arguments, invalid state या undocumented status—संकेत देता है कि decoding किसी implemented या partially implemented handler तक पहुँची। इससे exploitability **साबित नहीं होती**; इस candidate को structured length, argument, state और command-sequence fuzzing के लिए प्राथमिकता दें।<sup>[[4]](#references)</sup>

अगर कोई test peripheral को wedge कर देता है, तो external controller से हर boot पर एक अलग case चलाने की प्रक्रिया automate करें: SSH से connect करें, case execute करें, raw request/response और timing save करें, reboot या power-cycle करें, health checks के ठीक होने की प्रतीक्षा करें, और फिर जारी रखें। बाद में component को microcontroller-controlled fixture में लगाने से deterministic resets, direct power control और तेज़ fuzzing मिल सकती है।<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate दस्तावेज़ — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus विनिर्देश और उपयोगकर्ता पुस्तिका](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C serial EEPROM की datasheet](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: Xiaomi के MJA1 Secure Chip का सुरक्षा विश्लेषण](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 cryptography wrapper](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
