# UART

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

UART एक asynchronous serial interface है, जो साझा clock के बिना bits की framed stream transfer करता है। Logic-level UART को RS-232 न समझें: RS-232 में अलग, अक्सर negative voltage levels का उपयोग होता है और इसके लिए transceiver की आवश्यकता होती है।<sup>[[1]](#references)[[3]](#references)</sup>

आमतौर पर, UART idle state में होने पर line high (logical 1 value पर) रहती है। फिर data transfer शुरू करने के लिए transmitter, receiver को start bit भेजता है; इस दौरान signal low (logical 0 value पर) रहता है। इसके बाद transmitter वास्तविक message वाले पाँच से आठ data bits भेजता है, जिनके बाद configuration के अनुसार एक optional parity bit और एक या दो stop bits (logical 1 value पर) आते हैं। Error checking के लिए इस्तेमाल होने वाला parity bit व्यवहार में बहुत कम दिखता है। Stop bit (या bits) transmission के अंत का संकेत देते हैं।

सबसे आम configuration 8N1 है: आठ data bits, no parity और एक stop bit। UART सबसे कम महत्वपूर्ण data bit पहले भेजता है, इसलिए ASCII `C` (`0x43`) इस तरह transmit होता है: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`।<sup>[[1]](#references)</sup>

![UART: सबसे आम configuration 8N1 है: आठ data bits, no parity और एक stop bit। उदाहरण के लिए, अगर हमें 8N1 UART में character C, या ASCII में 0x43, भेजना हो](<../../images/image (764).png>)

UART से communicate करने के लिए hardware tools:

- USB-to-serial adapter
- CP2102 या PL2303 chips वाले adapters
- Multipurpose tool, जैसे: Bus Pirate, Adafruit FT232H, Shikra या Attify Badge

### UART Ports की पहचान करना

एक typical debug header में **TX**, **RX** और **GND** होते हैं; इसमें **Vcc/Vref** pin, reset या flow-control pins भी हो सकते हैं। Vcc, UART signal नहीं है और इसे आम तौर पर सिर्फ voltage reference के रूप में इस्तेमाल करना चाहिए—power source के रूप में connect नहीं करना चाहिए—जब तक board की schematic और current requirements की जानकारी न हो।<sup>[[2]](#references)[[3]](#references)</sup>

शुरुआत में device को **बंद** और disconnected रखें:

- Continuity mode में किसी ज्ञात ground plane, connector shield या supply ground के साथ जाँच करके **GND** की पहचान करें। Powered board पर continuity/resistance mode का इस्तेमाल कभी न करें।
- Target को power देने से पहले DC-voltage mode चुनें। Logic voltage पहचानने के लिए candidate pins को ground के सापेक्ष मापें। स्थिर rail, Vcc/Vref हो सकती है; इसे connect करना सुरक्षित है, ऐसा न मानें।
- Boot के दौरान logic analyzer या oscilloscope से candidate pins देखें। **TX** आम तौर पर idle में high रहता है और framed data के bursts दिखाता है। Multimeter औसत fluctuation दिखा सकता है, लेकिन framing या baud rate की पुष्टि नहीं कर सकता।
- **RX** idle रह सकता है और सिर्फ TX के पास होने के आधार पर इसकी सुरक्षित पहचान नहीं की जा सकती। इसे drive करने से पहले PCB traces को follow करें, SoC datasheet देखें या high-impedance analyzer इस्तेमाल करें।

TX और RX को उलटने पर आम तौर पर communication नहीं होगा; power, ground या signal levels को गलत समझने से target या adapter को स्थायी नुकसान हो सकता है। पहले ground connect करें और शुरुआत **सिर्फ receive** करने से करें (target TX को adapter RX से connect करें)।

Manufacturers header को छोड़ सकते हैं, series resistors को unpopulated छोड़ सकते हैं, firmware में console disable कर सकते हैं या सिर्फ TX expose कर सकते हैं। पास के test pads और resistor footprints को SoC तक trace करें और electrical level की पुष्टि करने के बाद ही temporary high-impedance connection जोड़ें। Warranty होने का मतलब यह नहीं है कि UART उपलब्ध होगा।

### UART Baud Rate की पहचान करना

सही baud rate पहचानने का सबसे आसान तरीका **TX pin का output देखना और data पढ़ने की कोशिश करना** है। अगर आपको मिलने वाला data पढ़ने योग्य नहीं है, तो अगला संभावित baud rate आज़माएँ, जब तक data पढ़ने योग्य न हो जाए। इसके लिए USB-to-serial adapter या Bus Pirate जैसे multipurpose device के साथ [baudrate.py](https://github.com/devttys0/baudrate/) जैसी helper script इस्तेमाल कर सकते हैं। सबसे आम baud rates 9600, 38400, 19200, 57600 और 115200 हैं।

> [!CAUTION]
> ध्यान दें कि इस protocol में आपको एक device का TX दूसरे device के RX से connect करना होगा!

## CP210X UART से TTY Adapter

CP210x USB-to-UART bridges कई prototyping boards और सस्ते adapters में मिलते हैं। आम modules में GND, RXD और TXD के साथ supply pins भी होते हैं, लेकिन उनके headers और I/O levels अलग-अलग हो सकते हैं। Board design या data sheet से वास्तविक voltage की पुष्टि करें। आम तौर पर सिर्फ GND और adapter RX को target TX से connect करें; और receive-only validation के बाद adapter TX को target RX से connect करें। Adapter का 5 V/3.3 V supply pin तब तक connect न करें, जब तक आप जानबूझकर किसी ऐसे target को power न दे रहे हों जिसके इसके लिए सुरक्षित होने की पुष्टि हो।<sup>[[3]](#references)</sup>

अगर adapter detect नहीं होता है, तो host system में CP210X drivers install हैं, यह सुनिश्चित करें। Adapter detect और connect हो जाने के बाद picocom, minicom या screen जैसे tools इस्तेमाल किए जा सकते हैं।

Linux/MacOS systems से जुड़े devices की सूची देखने के लिए:

```
ls /dev/
```

UART इंटरफ़ेस के साथ बुनियादी इंटरैक्शन के लिए, निम्नलिखित कमांड का उपयोग करें:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom को configure करने के लिए, निम्नलिखित command का उपयोग करें:

```
minicom -s
```

`Serial port setup` विकल्प में baudrate और device name जैसी सेटिंग कॉन्फ़िगर करें।

कॉन्फ़िगरेशन के बाद, UART console खोलने के लिए `minicom` चलाएँ।

## Arduino UNO R3 के ज़रिए UART (हटाई जा सकने वाली Atmel 328p चिप वाले बोर्ड)

यदि UART Serial to USB adapters उपलब्ध न हों, तो Arduino UNO R3 को एक त्वरित हैक के तौर पर इस्तेमाल किया जा सकता है। चूँकि Arduino UNO R3 आमतौर पर कहीं भी उपलब्ध होता है, इससे काफी समय बच सकता है।

Arduino UNO R3 में बोर्ड पर ही USB to Serial adapter बना होता है। UART connection पाने के लिए, बस बोर्ड से Atmel 328p microcontroller chip निकाल दें। यह हैक Arduino UNO R3 के उन variants पर काम करता है जिनमें Atmel 328p बोर्ड पर soldered नहीं होता (इसमें SMD version इस्तेमाल किया जाता है)। Arduino के RX pin (Digital Pin 0) को UART Interface के TX pin से और Arduino के TX pin (Digital Pin 1) को UART interface के RX pin से जोड़ें।

Target baud rate पर Arduino IDE का **Serial Monitor** या कोई dedicated terminal इस्तेमाल करें। Classic Uno R3 के serial signals 5 V logic होते हैं, इसलिए उन्हें 3.3 V या उससे कम voltage वाले target से जोड़ने से पहले level shifter या divider इस्तेमाल करें।

## Bus Pirate

निम्न transcript UART output मॉनिटर करने के लिए legacy Bus Pirate firmware interface का इस्तेमाल करता है। नए Bus Pirate firmware में `m uart`, `{`/`}`, `monitor` या `bridge` जैसे commands इस्तेमाल होते हैं; इंस्टॉल किए गए version के documentation को देखें।<sup>[[2]](#references)</sup>

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

UART console boot logs और कभी-कभी bootloader या operating-system shell तक runtime access देता है। केवल पढ़ने योग्य console भी memory maps, flash drivers, boot arguments, partition layouts और firmware versions उजागर करता है। Firmware SPI NOR/NAND, eMMC या किसी अन्य डिवाइस में हो सकता है; यह आम तौर पर EEPROM से execute नहीं होता, और mounted persistent filesystem में लिखी गई files ज़रूरी नहीं कि reboot पर गायब हो जाएँ।

Firmware प्राप्त करने के कई तरीके हैं, और SPI section external flash से सीधे पढ़ने के बारे में बताता है। अगर bootloader पहले से कोई सुरक्षित read command देता है, तो console की मदद से firmware प्राप्त करना कम दखल देने वाला हो सकता है। लेकिन boot में रुकावट डालने या flash command चलाने से availability प्रभावित हो सकती है, इसलिए मूल स्थिति दर्ज करें और write/erase operations से बचें।

Console की मदद से firmware dump करने की शुरुआत अक्सर bootloader को रोकने से होती है। कई embedded Linux डिवाइस **Das U-Boot** का उपयोग करते हैं, लेकिन अन्य डिवाइस proprietary bootloaders का उपयोग कर सकते हैं या interactive console को disable कर सकते हैं।

Interactive bootloader जाँचने के लिए, target के बंद रहते हुए UART receive path और terminal कनेक्ट करें, logging शुरू करें और फिर डिवाइस को चालू करें। स्क्रीन पर दिखाए गए autoboot prompt का पालन करें; build के आधार पर, boot रोकने के लिए कोई key, छोटा sequence दबाना पड़ सकता है, या यह सुविधा पूरी तरह disabled हो सकती है।

अगर boot रोका जा सके, तो addresses access करने से पहले `help`, `printenv` और read-only discovery commands का उपयोग करके उस vendor के memory और storage layout को समझें।

U-Boot में `md` **addressable memory** दिखाता है, अपने-आप “EEPROM” नहीं। पहले सही mapped address पहचानने या flash region को RAM में load करने के लिए board-specific commands जैसे `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables और boot logs का उपयोग करें। फिर किसी ज्ञात range को byte-by-byte दिखाएँ:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

शुरू करने से पहले serial आउटपुट लॉग करें। `md.b` आउटपुट में पते और ASCII कॉलम होते हैं, इसलिए यह raw ROM image के बजाय एक टेक्स्टुअल प्रस्तुति है।

पते और ASCII कॉलम हटाएँ, केवल hexadecimal byte फ़ील्ड को जोड़ें, और उन्हें binary में डिकोड करें (उदाहरण के लिए, `xxd -r -p` से)। विश्लेषण से पहले अपेक्षित byte count सत्यापित करें और hash दर्ज करें:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk फिर पुनर्निर्मित बाइनरी में ज्ञात signatures की पहचान करता है। जब console विश्वसनीय रूप से डेटा स्थानांतरित नहीं कर सकता, तो उपयुक्त SPI/eMMC/NAND interface के माध्यम से सीधे flash read करना आमतौर पर तेज़ होता है और इसमें त्रुटियों की संभावना कम रहती है।

U-Boot interruption को disable कर सकता है, vendor-specific key sequence की आवश्यकता रख सकता है, या memory/flash commands को lock कर सकता है। बिना सोचे-समझे characters भेजने के बजाय autoboot prompt और boot log का अनुसरण करें। यदि console को interrupt नहीं किया जा सकता, तो boot log सुरक्षित रखें और firmware प्राप्त करने का non-invasive तरीका अपनाएँ।

## References

- [1] [Microchip PIC32 परिवार संदर्भ पुस्तिका - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate दस्तावेज़ीकरण - UART mode और विद्युत सीमाएँ](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C डेटा शीट](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot दस्तावेज़ीकरण - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
