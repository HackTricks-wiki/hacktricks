# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART एक asynchronous serial interface है, जो shared clock के बिना bits की framed stream transfer करता है। Logic-level UART को RS-232 समझने की गलती न करें: RS-232 में अलग, अक्सर negative, voltage levels होते हैं और इसके लिए transceiver आवश्यक होता है।<sup>[[1]](#references)[[3]](#references)</sup>

आमतौर पर UART के idle state में line high (logical 1 value) रहती है। फिर data transfer शुरू होने का संकेत देने के लिए transmitter receiver को एक start bit भेजता है, जिसके दौरान signal low (logical 0 value) रहता है। इसके बाद transmitter actual message वाले पांच से आठ data bits भेजता है, फिर configuration के अनुसार एक optional parity bit और एक या दो stop bits (logical 1 value) भेजता है। Error checking के लिए उपयोग किया जाने वाला parity bit व्यवहार में बहुत कम दिखाई देता है। Stop bit (या bits) transmission के अंत का संकेत देते हैं।

सबसे सामान्य configuration 8N1 है: आठ data bits, no parity, और एक stop bit। UART सबसे कम महत्वपूर्ण data bit पहले भेजता है, इसलिए ASCII `C` (`0x43`) इस प्रकार transmit होता है: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`।<sup>[[1]](#references)</sup>

![UART: सबसे सामान्य configuration को 8N1 कहा जाता है: आठ data bits, no parity, और एक stop bit। उदाहरण के लिए, यदि हमें character C, या ASCII में 0x43, को 8N1 UART के माध्यम से भेजना हो](<../../images/image (764).png>)

UART के साथ communicate करने के लिए hardware tools:

- USB-to-serial adapter
- CP2102 या PL2303 chips वाले adapters
- Bus Pirate, Adafruit FT232H, Shikra, या Attify Badge जैसे multipurpose tools

### UART Ports की पहचान करना

एक सामान्य debug header में **TX**, **RX**, और **GND** होते हैं; इसमें **Vcc/Vref** pin, reset, या flow-control pins भी हो सकते हैं। Vcc UART signal नहीं है और सामान्यतः इसे केवल voltage reference के रूप में उपयोग करना चाहिए—power source के रूप में connect नहीं करना चाहिए—जब तक board का schematic और current requirements ज्ञात न हों।<sup>[[2]](#references)[[3]](#references)</sup>

Device को **powered off** और disconnected रखकर शुरुआत करें:

- किसी ज्ञात ground plane, connector shield, या supply ground के विरुद्ध continuity mode में **GND** पहचानें। Powered board पर continuity/resistance mode का कभी उपयोग न करें।
- Target को power देने से पहले DC-voltage mode पर switch करें। Logic voltage पहचानने के लिए candidate pins को ground के सापेक्ष measure करें। कोई steady rail Vcc/Vref हो सकती है; इसे connect करना सुरक्षित है, ऐसा न मानें।
- Boot के दौरान candidates को logic analyzer या oscilloscope से observe करें। **TX** सामान्यतः high पर idle रहता है और framed data के bursts दिखाता है। Multimeter average fluctuation दिखा सकता है, लेकिन framing या baud rate validate नहीं कर सकता।
- **RX** idle रह सकता है और केवल TX के पास होने के आधार पर इसे safely identify नहीं किया जा सकता। PCB trace करें, SoC datasheet देखें, या इसे drive करने से पहले high-impedance analyzer का उपयोग करें।

TX और RX को बदलने पर सामान्यतः communication नहीं होगा; power, ground, या signal levels को गलत connect करने से target या adapter को स्थायी रूप से damage हो सकता है। पहले ground connect करें और **receive-only** से शुरुआत करें (target TX को adapter RX से connect करें)।

Manufacturers header को हटा सकते हैं, series resistors को unpopulated छोड़ सकते हैं, firmware में console disable कर सकते हैं, या केवल TX expose कर सकते हैं। पास के test pads और resistor footprints को SoC तक trace करें और electrical level की पुष्टि करने के बाद ही temporary high-impedance connection जोड़ें। Warranty की मौजूदगी का अर्थ यह नहीं है कि accessible UART आवश्यक रूप से मौजूद होगा।

### UART Baud Rate की पहचान करना

सही baud rate पहचानने का सबसे आसान तरीका **TX pin के output को देखना और data पढ़ने का प्रयास करना** है। यदि प्राप्त data readable नहीं है, तो अगले संभावित baud rate पर switch करें और यह तब तक दोहराएं जब तक data readable न हो जाए। इसके लिए आप USB-to-serial adapter या Bus Pirate जैसे multipurpose device का उपयोग helper script, जैसे [baudrate.py](https://github.com/devttys0/baudrate/), के साथ कर सकते हैं। सबसे सामान्य baud rates 9600, 38400, 19200, 57600, और 115200 हैं।

> [!CAUTION]
> यह ध्यान रखना महत्वपूर्ण है कि इस protocol में आपको एक device के TX को दूसरे device के RX से connect करना होता है!

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridges कई prototyping boards और inexpensive adapters में पाए जाते हैं। सामान्य modules में GND, RXD, और TXD के साथ supply pins भी होते हैं, लेकिन उनके headers और I/O levels अलग-अलग हो सकते हैं। Board design या data sheet से actual voltage की पुष्टि करें। सामान्यतः केवल GND, adapter RX को target TX से, और—receive-only validation के बाद—adapter TX को target RX से connect करें। Adapter का 5 V/3.3 V supply pin तब तक connect न करें जब तक जानबूझकर ऐसे target को power न देना हो जो इसे tolerate करने के लिए ज्ञात हो।<sup>[[3]](#references)</sup>

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
`Serial port setup` विकल्प में baudrate और device name जैसी settings configure करें।

Configuration के बाद UART console खोलने के लिए `minicom` चलाएँ।

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

यदि UART Serial to USB adapters उपलब्ध नहीं हैं, तो Arduino UNO R3 को एक quick hack के साथ उपयोग किया जा सकता है। चूँकि Arduino UNO R3 आमतौर पर कहीं भी उपलब्ध होता है, इससे काफी समय बच सकता है।

Arduino UNO R3 में board पर ही USB to Serial adapter built-in होता है। UART connection प्राप्त करने के लिए, board से Atmel 328p microcontroller chip को निकाल दें। यह hack उन Arduino UNO R3 variants पर काम करता है जिनमें Atmel 328p board पर soldered नहीं होता (इसमें SMD version उपयोग किया जाता है)। Arduino के RX pin (Digital Pin 0) को UART Interface के TX pin से और Arduino के TX pin (Digital Pin 1) को UART interface के RX pin से connect करें।

Target baud rate पर Arduino IDE के **Serial Monitor** या किसी dedicated terminal का उपयोग करें। Classic Uno R3 serial signals 5 V logic होते हैं, इसलिए उन्हें 3.3 V या कम voltage वाले target से connect करने से पहले level shifter या divider का उपयोग करें।

## Bus Pirate

निम्न transcript UART output को monitor करने के लिए legacy Bus Pirate firmware interface का उपयोग करता है। Newer Bus Pirate firmware में `m uart`, `{`/`}`, `monitor` या `bridge` जैसे commands उपयोग किए जाते हैं; installed version के documentation से consult करें।<sup>[[2]](#references)</sup>
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
## UART Console से Firmware Dumping

एक UART console boot logs और कभी-कभी bootloader या operating-system shell तक runtime access प्रदान करता है। Read-only console भी memory maps, flash drivers, boot arguments, partition layouts और firmware versions प्रकट कर सकता है। Firmware SPI NOR/NAND, eMMC या किसी अन्य device में हो सकता है; इसे सामान्यतः EEPROM से execute नहीं किया जाता, और mounted persistent filesystem में लिखी गई files reboot पर आवश्यक रूप से गायब नहीं होतीं।

Acquisition के कई paths हैं, और SPI section external flash से direct reads को cover करता है। Console-assisted acquisition कम invasive हो सकता है, जब bootloader पहले से कोई safe read command प्रदान करता हो, लेकिन boot interruption या flash command availability को प्रभावित कर सकते हैं, इसलिए original state record करें और write/erase operations से बचें।

Console-assisted firmware dumping अक्सर bootloader को interrupt करने से शुरू होती है। कई embedded Linux devices **Das U-Boot** का उपयोग करते हैं, लेकिन अन्य proprietary bootloaders का उपयोग कर सकते हैं या interactive console को disable कर सकते हैं।

Interactive bootloader को test करने के लिए, target के unpowered होने पर UART receive path और terminal connect करें, logging शुरू करें और उसे power on करें। Display किए गए autoboot prompt का पालन करें; build के आधार पर interruption के लिए किसी key, short sequence की आवश्यकता हो सकती है या यह पूरी तरह disabled हो सकता है।

यदि interruption सफल हो, तो उस vendor के memory और storage layout को समझने के लिए addresses access करने से पहले `help`, `printenv` और read-only discovery commands का उपयोग करें।

U-Boot में `md` **addressable memory** प्रदर्शित करता है, अपने-आप “the EEPROM” नहीं। पहले सही mapped address की पहचान करने या किसी flash region को RAM में load करने के लिए board-specific commands जैसे `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables और boot logs का उपयोग करें। फिर किसी ज्ञात range को byte-by-byte display करें:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
शुरू करने से पहले serial output को log करें। `md.b` output में addresses और एक ASCII column होता है, इसलिए यह raw ROM image के बजाय एक textual representation है।

address और ASCII columns हटाएँ, केवल hexadecimal byte fields को concatenate करें, और उन्हें binary में decode करें (उदाहरण के लिए `xxd -r -p` के साथ)। Analysis से पहले अपेक्षित byte count verify करें और एक hash record करें:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk फिर से बनाए गए binary में ज्ञात signatures की पहचान करता है। जब console data को विश्वसनीय रूप से transfer नहीं कर पाता, तब उपयुक्त SPI/eMMC/NAND interface के माध्यम से direct flash read आमतौर पर अधिक तेज और कम error-prone होता है।

U-Boot interruption को disable कर सकता है, vendor-specific key sequence की आवश्यकता हो सकती है, या memory/flash commands को lock कर सकता है। Characters को बिना सोचे-समझे transmit करने के बजाय autoboot prompt और boot log का अनुसरण करें। यदि console को interrupt नहीं किया जा सकता, तो boot log सुरक्षित रखें और non-invasive firmware acquisition path अपनाएँ।

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
