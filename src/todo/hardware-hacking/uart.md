# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART एक serial protocol है, जिसका अर्थ है कि यह components के बीच data को एक समय में एक bit transfer करता है। इसके विपरीत, parallel communication protocols कई channels के माध्यम से data को एक साथ transmit करते हैं। सामान्य serial protocols में RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express और USB शामिल हैं।

आमतौर पर, UART के idle state में line को high (logical 1 value पर) रखा जाता है। इसके बाद, data transfer शुरू होने का संकेत देने के लिए transmitter receiver को एक start bit भेजता है, जिसके दौरान signal को low (logical 0 value पर) रखा जाता है। इसके बाद transmitter actual message वाले पांच से आठ data bits भेजता है, फिर configuration के आधार पर एक optional parity bit और एक या दो stop bits (logical 1 value के साथ) भेजे जाते हैं। Error checking के लिए उपयोग किया जाने वाला parity bit व्यवहार में बहुत कम दिखाई देता है। Stop bit (या bits) transmission के अंत का संकेत देते हैं।

हम सबसे सामान्य configuration को 8N1 कहते हैं: आठ data bits, no parity और एक stop bit। उदाहरण के लिए, यदि हम character C, या ASCII में 0x43, को 8N1 UART configuration में भेजना चाहते हैं, तो हम निम्नलिखित bits भेजेंगे: 0 (start bit); 0, 1, 0, 0, 0, 0, 1, 1 (binary में 0x43 की value), और 0 (stop bit)।

![UART: हम सबसे सामान्य configuration को 8N1 कहते हैं: आठ data bits, no parity और एक stop bit। उदाहरण के लिए, यदि हम character C, या ASCII में 0x43, को 8N1 UART configuration में भेजना चाहते हैं](<../../images/image (764).png>)

UART के साथ communicate करने के लिए hardware tools:

- USB-to-serial adapter
- CP2102 या PL2303 chips वाले adapters
- Multipurpose tool जैसे: Bus Pirate, Adafruit FT232H, Shikra या Attify Badge

### Identifying UART Ports

UART में 4 ports होते हैं: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) और **GND**(Ground)। हो सकता है कि आपको PCB पर **`TX`** और **`RX`** letters **written** के साथ 4 ports मिल जाएं। लेकिन यदि कोई indication नहीं है, तो आपको **multimeter** या **logic analyzer** का उपयोग करके उन्हें स्वयं खोजने की आवश्यकता हो सकती है।

Device को powered off रखते हुए **multimeter** के साथ:

- **GND** pin की पहचान करने के लिए **Continuity Test** mode का उपयोग करें, black lead को ground में लगाएं और red lead से तब तक test करें जब तक multimeter से sound न सुनाई दे। PCB पर कई GND pins मिल सकती हैं, इसलिए संभव है कि आपको UART से संबंधित pin मिली हो या नहीं।
- **VCC port** की पहचान करने के लिए **DC voltage mode** चुनें और voltage को 20 V तक set करें। Black probe को ground पर और red probe को pin पर लगाएं। Device को power on करें। यदि multimeter लगातार 3.3 V या 5 V का voltage measure करता है, तो आपको Vcc pin मिल गई है। यदि आपको अन्य voltages मिलते हैं, तो दूसरे ports के साथ फिर से प्रयास करें।
- **TX** **port** की पहचान करने के लिए **DC voltage mode** को 20 V तक set करें, black probe को ground पर और red probe को pin पर लगाएं, फिर device को power on करें। यदि voltage कुछ seconds तक fluctuate करता है और फिर Vcc value पर stabilize हो जाता है, तो संभवतः आपको TX port मिल गया है। ऐसा इसलिए होता है क्योंकि power on होने पर यह कुछ debug data भेजता है।
- **RX port** अन्य 3 ports के सबसे करीब वाला port होगा। इसमें सभी UART pins की तुलना में voltage fluctuation और overall value सबसे कम होती है।

आप TX और RX ports को आपस में confuse कर सकते हैं और कुछ नहीं होगा, लेकिन यदि आप GND और VCC port को confuse करते हैं, तो circuit fry हो सकता है।

कुछ target devices में manufacturer द्वारा UART port को RX या TX, अथवा दोनों को disable करके बंद किया जाता है। ऐसी स्थिति में circuit board में connections को trace करना और कोई breakout point ढूंढना उपयोगी हो सकता है। UART का detection न होने और circuit के टूटे होने की पुष्टि करने का एक मजबूत संकेत device की warranty को check करना है। यदि device warranty के साथ ship किया गया है, तो manufacturer कुछ debug interfaces (इस स्थिति में UART) छोड़ता है और इसलिए debugging के दौरान UART को disconnect करके फिर से attach करना आवश्यक होता है। इन breakout pins को soldering या jumper wires के माध्यम से connect किया जा सकता है।

### Identifying the UART Baud Rate

सही baud rate की पहचान करने का सबसे आसान तरीका **TX pin’s output को देखना और data को read करने का प्रयास करना** है। यदि आपको प्राप्त data readable नहीं है, तो अगले possible baud rate पर switch करें और ऐसा तब तक करें जब तक data readable न हो जाए। इसके लिए आप USB-to-serial adapter या Bus Pirate जैसे multipurpose device का उपयोग कर सकते हैं, साथ में [baudrate.py](https://github.com/devttys0/baudrate/) जैसी helper script का उपयोग करें। सबसे सामान्य baud rates 9600, 38400, 19200, 57600 और 115200 हैं।

> [!CAUTION]
> यह ध्यान रखना महत्वपूर्ण है कि इस protocol में आपको एक device के TX को दूसरे device के RX से connect करना होता है!

## CP210X UART to TTY Adapter

CP210X Chip का उपयोग NodeMCU (esp8266 के साथ) जैसे कई prototyping boards में Serial Communication के लिए किया जाता है। ये adapters अपेक्षाकृत सस्ते होते हैं और target के UART interface से connect करने के लिए उपयोग किए जा सकते हैं। Device में 5 pins होते हैं: 5V, GND, RXD, TXD, 3.3V। किसी भी damage से बचने के लिए voltage को target द्वारा supported voltage के अनुसार connect करना सुनिश्चित करें। अंत में Adapter के RXD pin को target के TXD से और Adapter के TXD pin को target के RXD से connect करें।

यदि adapter detect नहीं हो रहा है, तो सुनिश्चित करें कि host system में CP210X drivers installed हैं। Adapter detect और connect हो जाने के बाद picocom, minicom या screen जैसे tools का उपयोग किया जा सकता है।

Linux/MacOS systems से connected devices की list बनाने के लिए:
```
ls /dev/
```
UART interface के साथ basic interaction के लिए, निम्नलिखित command का उपयोग करें:
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom के लिए, इसे configure करने हेतु निम्न command का उपयोग करें:
```
minicom -s
```
`Serial port setup` option में baudrate और device name जैसी settings configure करें।

Configuration के बाद UART Console शुरू करने के लिए `minicom` command का उपयोग करें।

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

यदि UART Serial to USB adapters उपलब्ध न हों, तो Arduino UNO R3 का उपयोग एक quick hack के साथ किया जा सकता है। चूंकि Arduino UNO R3 आमतौर पर हर जगह उपलब्ध होता है, इससे काफी समय बचाया जा सकता है।

Arduino UNO R3 में board पर ही USB to Serial adapter built-in होता है। UART connection प्राप्त करने के लिए, board से Atmel 328p microcontroller chip को निकाल दें। यह hack Arduino UNO R3 के उन variants पर काम करता है जिनमें Atmel 328p board पर soldered नहीं होता (इसमें SMD version का उपयोग किया जाता है)। Arduino के RX pin (Digital Pin 0) को UART Interface के TX pin से और Arduino के TX pin (Digital Pin 1) को UART interface के RX pin से connect करें।

अंत में, Serial Console प्राप्त करने के लिए Arduino IDE का उपयोग करने की recommended है। Menu के `tools` section में `Serial Console` option चुनें और UART interface के अनुसार baud rate set करें।

## Bus Pirate

इस scenario में हम उस Arduino के UART communication को sniff करने जा रहे हैं, जो program के सभी prints Serial Monitor पर भेज रहा है।
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
## UART Console से Firmware Dump करना

UART Console runtime environment में underlying firmware के साथ काम करने का एक बेहतरीन तरीका प्रदान करता है। लेकिन जब UART Console access read-only हो, तो यह कई constraints उत्पन्न कर सकता है। कई embedded devices में firmware EEPROMs में stored होता है और उन processors पर execute होता है जिनमें volatile memory होती है। इसलिए firmware को read-only रखा जाता है, क्योंकि manufacturing के दौरान original firmware EEPROM के अंदर होता है और volatile memory के कारण कोई भी नई files खो जाती हैं। इसीलिए embedded firmwares के साथ काम करते समय firmware dump करना एक उपयोगी प्रयास है।

ऐसा करने के कई तरीके हैं और SPI section विभिन्न devices के माध्यम से सीधे EEPROM से firmware extract करने के methods को cover करता है। हालांकि, पहले UART के माध्यम से firmware dump करने का प्रयास करने की सलाह दी जाती है, क्योंकि physical devices और external interactions के साथ firmware dump करना risky हो सकता है।

UART Console से firmware dump करने के लिए पहले bootloaders का access प्राप्त करना आवश्यक है। कई popular vendors Linux load करने के लिए uboot (Universal Bootloader) को अपने bootloader के रूप में इस्तेमाल करते हैं। इसलिए uboot का access प्राप्त करना आवश्यक है।

Bootloader तक access प्राप्त करने के लिए UART port को computer से connect करें और किसी भी Serial Console tool का उपयोग करें, जबकि device की power supply disconnected हो। Setup तैयार होने के बाद, Enter Key दबाकर रखें। अंत में, device की power supply connect करें और उसे boot होने दें।

ऐसा करने से uboot को load होने से interrupt किया जाएगा और एक menu दिखाई देगा। uboot commands को समझने और उन्हें list करने के लिए help menu का उपयोग करने की सलाह दी जाती है। इसके लिए `help` command हो सकती है। चूंकि अलग-अलग vendors अलग-अलग configurations का उपयोग करते हैं, इसलिए प्रत्येक configuration को अलग से समझना आवश्यक है।

आमतौर पर, firmware dump करने की command होती है:
```
md
```
जिसका अर्थ "memory dump" है। यह memory (EEPROM Content) को screen पर dump करेगा। memory dump को capture करने के लिए procedure शुरू करने से पहले Serial Console output को log करना recommended है।

अंत में, log file से सभी अनावश्यक data हटा दें और file को `filename.rom` के रूप में store करें, फिर contents extract करने के लिए binwalk का उपयोग करें:
```
binwalk -e <filename.rom>
```
यह hex file में पाए गए signatures के अनुसार EEPROM की संभावित सामग्री सूचीबद्ध करेगा।

हालांकि, यह ध्यान रखना आवश्यक है कि uboot का उपयोग किए जाने पर भी यह हमेशा unlocked हो, ऐसा जरूरी नहीं है। यदि Enter Key कुछ नहीं करता है, तो Space Key आदि जैसी अलग-अलग keys आज़माएं। यदि bootloader locked है और interrupt नहीं होता है, तो यह method काम नहीं करेगा। यह जांचने के लिए कि uboot device का bootloader है या नहीं, device के boot होने के दौरान UART Console पर output देखें। Booting के दौरान इसमें uboot का उल्लेख हो सकता है।

{{#include ../../banners/hacktricks-training.md}}
