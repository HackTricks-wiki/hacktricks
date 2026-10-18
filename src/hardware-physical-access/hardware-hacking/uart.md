# UART

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

UART एक asynchronous serial interface है, जो साझा clock के बिना bits की framed stream ट्रांसफर करता है। Logic-level UART को RS-232 न समझें: RS-232 में अलग, अक्सर negative voltage levels होते हैं और इसके लिए transceiver की आवश्यकता होती है।<sup>[[1]](#references)[[3]](#references)</sup>

आमतौर पर, UART idle state में होने पर line high (logical 1 value पर) रहती है। इसके बाद, data transfer शुरू होने का संकेत देने के लिए transmitter receiver को start bit भेजता है, जिसके दौरान signal low (logical 0 value पर) रहता है। फिर transmitter वास्तविक message वाले पाँच से आठ data bits भेजता है, जिसके बाद configuration के अनुसार एक optional parity bit और एक या दो stop bits (logical 1 value पर) भेजे जाते हैं। Error checking के लिए इस्तेमाल होने वाला parity bit व्यवहार में बहुत कम दिखाई देता है। Stop bit (या bits) transmission के अंत का संकेत देते हैं।

सबसे आम configuration 8N1 है: आठ data bits, parity नहीं और एक stop bit। UART सबसे कम महत्वपूर्ण data bit पहले भेजता है, इसलिए ASCII `C` (`0x43`) इस तरह ट्रांसमिट होता है: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`।<sup>[[1]](#references)</sup>

![UART: सबसे आम configuration को 8N1 कहते हैं: आठ data bits, parity नहीं और एक stop bit। उदाहरण के लिए, अगर हमें 8N1 UART में character C, या ASCII में 0x43, भेजना हो](<../../images/image (764).png>)

UART से communicate करने के लिए hardware tools:

- USB-to-serial adapter
- CP2102 या PL2303 chips वाले adapters
- Bus Pirate, Adafruit FT232H, Shikra या Attify Badge जैसे multipurpose tools

### UART पोर्ट की पहचान करना

एक सामान्य debug header में **TX**, **RX** और **GND** होते हैं; इसमें **Vcc/Vref** pin, reset या flow-control pins भी हो सकते हैं। Vcc, UART signal नहीं है और आम तौर पर इसका इस्तेमाल केवल voltage reference के रूप में किया जाना चाहिए—इसे power source के रूप में कनेक्ट नहीं करना चाहिए—जब तक कि board का schematic और current requirements ज्ञात न हों।<sup>[[2]](#references)[[3]](#references)</sup>

शुरुआत में device को **बंद** करें और उसका connection हटा दें:

- Continuity mode में किसी ज्ञात ground plane, connector shield या supply ground के मुकाबले **GND** की पहचान करें। Powered board पर continuity/resistance mode का इस्तेमाल कभी न करें।
- Target को power देने से पहले DC-voltage mode पर switch करें। Logic voltage की पहचान करने के लिए, candidate pins को ground के मुकाबले मापें। स्थिर rail, Vcc/Vref हो सकती है; यह न मानें कि इसे कनेक्ट करना सुरक्षित है।
- Boot के दौरान logic analyzer या oscilloscope से candidate pins को देखें। **TX** आम तौर पर idle में high रहता है और framed data के bursts दिखाता है। Multimeter औसत में उतार-चढ़ाव दिखा सकता है, लेकिन framing या baud rate की पुष्टि नहीं कर सकता।
- **RX** idle रह सकता है और केवल TX के पास होने के कारण सुरक्षित रूप से पहचाना नहीं जा सकता। PCB traces देखें, SoC datasheet देखें या इसे drive करने से पहले high-impedance analyzer इस्तेमाल करें।

TX और RX को आपस में बदलने पर आम तौर पर communication नहीं होता; power, ground या signal levels में भ्रम होने से target या adapter को स्थायी नुकसान हो सकता है। पहले ground कनेक्ट करें और **केवल receive** से शुरुआत करें (target TX को adapter RX से कनेक्ट करें)।

Manufacturers header को हटा सकते हैं, series resistors को न लगा सकते हैं, firmware में console को disable कर सकते हैं या केवल TX को expose कर सकते हैं। पास के test pads और resistor footprints से SoC तक trace करें और electrical level की पुष्टि करने के बाद ही temporary high-impedance connection जोड़ें। Warranty होने का मतलब यह नहीं कि सुलभ UART मौजूद होना चाहिए।

### Low दिखने वाले TX pad को फिर से प्राप्त करना

शुरुआती scope capture में labeled TX pad का low बने रहना, UART की संभावना खारिज करने के लिए पर्याप्त नहीं है। Target logic voltage और common ground की पुष्टि करने के बाद, weak pull-up लगाकर (दस्तावेज़ वाले उदाहरण में **10 kΩ से 3.3 V**) buttons दबाते समय या device boot करते समय capture फिर से करें। केवल target की verified logic rail का इस्तेमाल करें; pull-up को किसी अज्ञात या सक्रिय रूप से driven signal से कनेक्ट न करें। अगर framed transitions दिखाई दें, तो pad को serial adapter से केवल receive के लिए कनेक्ट करने से पहले सबसे छोटे साफ़ bit period को मापकर baud rate का अनुमान लगाएँ। इस तरीके से उदाहरण में 115200-baud के button-event logs मिले, लेकिन firmware dump नहीं मिला।<sup>[[8]](#references)</sup>

### UART Baud Rate की पहचान करना

सही baud rate की पहचान करने का सबसे आसान तरीका **TX pin का output देखना और data पढ़ने की कोशिश करना** है। अगर आपको मिला data पढ़ने योग्य नहीं है, तो अगली संभावित baud rate आज़माएँ, जब तक data पढ़ने योग्य न हो जाए। इसके लिए USB-to-serial adapter या Bus Pirate जैसा multipurpose device और [baudrate.py](https://github.com/devttys0/baudrate/) जैसी helper script इस्तेमाल कर सकते हैं। सबसे आम baud rates 9600, 38400, 19200, 57600 और 115200 हैं।

> [!CAUTION]
> ध्यान रखें कि इस protocol में एक device के TX को दूसरे device के RX से कनेक्ट करना ज़रूरी है!

### SCPI से Boot-Time UART Capture को स्वचालित करना

अगर boot output थोड़े समय के लिए ही दिखता है या TX pad अभी अज्ञात है, तो supply और oscilloscope को हाथ से चलाने के बजाय बार-बार startup को automate करें। Current-limited programmable supply को target के verified power input से कनेक्ट करें। हर candidate TX pad को shared ground के साथ high-impedance scope input से probe करें; pad को drive न करें।<sup>[[5]](#references)</sup>

VISA serial या Ethernet instrument sessions खोलता है, जबकि SCPI output, trigger और waveform readout को नियंत्रित करता है।<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa` और `pyvisa-py` (और serial VISA resources के लिए `pyserial`) install करें; `ResourceManager('@py')` स्पष्ट रूप से Python backend चुनता है।<sup>[[5]](#references)[[7]](#references)</sup> Resource strings और commands को इस्तेमाल हो रहे instruments द्वारा समर्थित विकल्पों से बदलें।<sup>[[5]](#references)</sup>

Rigol MSO5000 वाले उदाहरण में, board को power देने से पहले single falling-edge trigger arm करें: idle-high UART TX अपने start bit के लिए पहले low जाता है।<sup>[[5]](#references)</sup> Trigger threshold को मापे गए idle और low levels के बीच सेट करें और timebase को इच्छित boot interval कवर करने के लिए सेट करें।<sup>[[5]](#references)[[6]](#references)</sup> Continuous captures में `:TRIG:HOLD` बार-बार आने वाले edges को रोक सकता है, लेकिन इससे यह जाँचना ज़रूरी नहीं रहता कि single-shot capture वास्तव में पूरा हुआ या नहीं।<sup>[[5]](#references)</sup> नीचे दिया गया तरीका एक boot capture करके unsigned-byte samples और उनकी scaling metadata—दोनों को save करता है; timeout होने पर हमेशा इंतज़ार करने के बजाय target को power off कर देता है।<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA से power-on और single-shot UART waveform capture</summary>

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

पैड सर्वे के लिए, probe को दूसरी जगह ले जाने के बाद single-shot capture दोहराएँ, या supply session को खुला रखें और boot dwell तथा off interval के साथ उसका output cycle करें। हर power-on से पहले scope को फिर से arm करें, ताकि हर फ़ाइल एक boot और एक pad से संबंधित हो।<sup>[[5]](#references)</sup>

Rigol preamble का स्वरूप `<format>,<type>,<points>,<count>,<xincrement>,...` है।<sup>[[6]](#references)</sup> **तीसरी** value points की संख्या है, न कि sample rate, जैसा कि लेख में बताया गया है।<sup>[[5]](#references)[[6]](#references)</sup> इसके उदाहरण में, `25,000,000` points और `xincrement = 2e-8` seconds का अर्थ है `1 / xincrement = 50,000,000` samples/second, न कि 25 MSa/s।<sup>[[5]](#references)[[6]](#references)</sup> Preamble को binary file के साथ रखें और जाँचें कि read length `<points>` से मेल खाती है; बड़ी records के लिए guide segmented/batched reads का दस्तावेज़ देता है।<sup>[[6]](#references)</sup>

Captured signal को decode करने के लिए, PulseView में `capture.bin` को **Raw Analog Data Without Header** के रूप में import करें, unsigned 8-bit (`U8`) values चुनें, और `xincrement` से गणना की गई sample rate दर्ज करें।<sup>[[5]](#references)[[6]](#references)</sup> Analog channel पर **Logic via Threshold** लागू करें और low तथा high sample values के बीच का threshold चुनें।<sup>[[5]](#references)</sup> Baud rate का अनुमान लगाने के लिए साफ़ start-bit width मापें (57,600 baud के लिए लगभग 17.36 µs), फिर PulseView का UART decoder लागू करें और पुष्टि करें कि कई frames लगातार एक जैसे decode होते हैं।<sup>[[5]](#references)</sup> केवल falling edge से यह साबित नहीं होता कि कोई pad UART है।

## CP210X UART से TTY Adapter

CP210x USB-to-UART bridges कई prototyping boards और सस्ते adapters में मिलते हैं। आम modules में GND, RXD और TXD के साथ supply pins भी होते हैं, लेकिन उनके headers और I/O levels अलग-अलग हो सकते हैं। Board design या data sheet से वास्तविक voltage की पुष्टि करें। आमतौर पर केवल GND, adapter RX को target TX से और—receive-only validation के बाद—adapter TX को target RX से जोड़ें। Adapter का 5 V/3.3 V supply pin तब तक न जोड़ें, जब तक आप जानबूझकर ऐसे target को power न दे रहे हों जिसके बारे में पता हो कि वह इसे सह सकता है।<sup>[[3]](#references)</sup>

अगर adapter detect न हो, तो सुनिश्चित करें कि host system में CP210X drivers इंस्टॉल हैं। Adapter detect और connect हो जाने के बाद, picocom, minicom या screen जैसे tools इस्तेमाल किए जा सकते हैं।

Linux/MacOS systems से जुड़े devices की सूची देखने के लिए:

```
ls /dev/
```

UART interface के साथ बुनियादी इंटरैक्शन के लिए, निम्नलिखित कमांड का उपयोग करें:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom को configure करने के लिए, निम्न command का उपयोग करें:

```
minicom -s
```

`Serial port setup` विकल्प में baudrate और device name जैसी settings कॉन्फ़िगर करें।

कॉन्फ़िगरेशन के बाद, UART console खोलने के लिए `minicom` चलाएँ।

## Arduino UNO R3 के माध्यम से UART (हटाई जा सकने वाली Atmel 328p Chip वाले Boards)

यदि UART Serial to USB adapters उपलब्ध न हों, तो Arduino UNO R3 का इस्तेमाल एक त्वरित hack के रूप में किया जा सकता है। Arduino UNO R3 आम तौर पर कहीं भी उपलब्ध होता है, इसलिए इससे काफी समय बच सकता है।

Arduino UNO R3 में बोर्ड पर ही USB to Serial adapter बना होता है। UART connection पाने के लिए, बस बोर्ड से Atmel 328p microcontroller chip निकाल दें। यह hack Arduino UNO R3 के उन variants पर काम करता है जिनमें Atmel 328p को बोर्ड पर solder नहीं किया गया होता (इनमें SMD version का इस्तेमाल होता है)। Arduino के RX pin (Digital Pin 0) को UART Interface के TX pin से और Arduino के TX pin (Digital Pin 1) को UART interface के RX pin से जोड़ें।

Target baud rate पर Arduino IDE के **Serial Monitor** या किसी dedicated terminal का इस्तेमाल करें। Classic Uno R3 के serial signals 5 V logic के होते हैं, इसलिए उन्हें 3.3 V या उससे कम voltage वाले target से जोड़ने से पहले level shifter या divider का इस्तेमाल करें।

## Bus Pirate

नीचे दिया गया transcript UART output monitor करने के लिए legacy Bus Pirate firmware interface का इस्तेमाल करता है। नए Bus Pirate firmware में `m uart`, `{`/`}`, `monitor` या `bridge` जैसे commands इस्तेमाल होते हैं; इंस्टॉल किए गए version के लिए documentation देखें।<sup>[[2]](#references)</sup>

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

UART console boot logs और कभी-कभी bootloader या operating-system shell तक runtime access देता है। Read-only console से भी memory maps, flash drivers, boot arguments, partition layouts और firmware versions का पता चल सकता है। Firmware SPI NOR/NAND, eMMC या किसी अन्य device में हो सकता है; आम तौर पर इसे EEPROM से execute नहीं किया जाता, और mounted persistent filesystem पर लिखी गई files reboot के बाद ज़रूरी नहीं कि गायब हो जाएँ।

Firmware हासिल करने के कई तरीके हैं; SPI section में external flash से सीधे reads करने की जानकारी है। अगर bootloader में पहले से कोई सुरक्षित read command उपलब्ध हो, तो console की मदद से firmware हासिल करना कम invasive हो सकता है। लेकिन boot में रुकावट डालने या flash command चलाने से availability प्रभावित हो सकती है, इसलिए मूल स्थिति दर्ज करें और write/erase operations से बचें।

Console की मदद से firmware dump करने की शुरुआत अक्सर bootloader को interrupt करने से होती है। कई embedded Linux devices **Das U-Boot** का उपयोग करते हैं, लेकिन कुछ में proprietary bootloaders होते हैं या interactive console बंद होता है।

Interactive bootloader की जाँच के लिए, target के unpowered रहते हुए UART receive path और terminal connect करें, logging शुरू करें और फिर उसे power on करें। स्क्रीन पर दिखाए गए autoboot prompt के अनुसार चलें; build के आधार पर interruption के लिए कोई key या छोटा sequence दबाना पड़ सकता है, या यह पूरी तरह disabled हो सकता है।

अगर interruption सफल हो, तो addresses access करने से पहले `help`, `printenv` और read-only discovery commands का उपयोग करके vendor के memory और storage layout को समझें।

U-Boot में `md` **addressable memory** दिखाता है, न कि अपने-आप “EEPROM”। पहले board-specific commands जैसे `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables और boot logs का उपयोग करके सही mapped address का पता लगाएँ या flash region को RAM में load करें। फिर ज्ञात range को byte-by-byte दिखाएँ:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

शुरू करने से पहले serial output लॉग करें। `md.b` output में addresses और ASCII column होते हैं, इसलिए यह raw ROM image के बजाय एक textual representation है।

Address और ASCII columns हटाएँ, केवल hexadecimal byte fields को जोड़ें और उन्हें binary में decode करें (उदाहरण के लिए, `xxd -r -p` से)। Analysis से पहले अपेक्षित byte count की पुष्टि करें और hash रिकॉर्ड करें:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk फिर reconstructed binary में ज्ञात signatures की पहचान करता है। जब console विश्वसनीय रूप से data transfer नहीं कर सकता, तो उपयुक्त SPI/eMMC/NAND interface के माध्यम से सीधे flash read करना आमतौर पर तेज़ और त्रुटियों की संभावना कम करने वाला तरीका होता है।

U-Boot interruption को disable कर सकता है, vendor-specific key sequence की आवश्यकता रख सकता है, या memory/flash commands को lock कर सकता है। बिना सोचे-समझे characters भेजने के बजाय autoboot prompt और boot log का पालन करें। यदि console को interrupt नहीं किया जा सकता, तो boot log सुरक्षित रखें और firmware acquisition के non-invasive तरीके पर जाएँ।

## References

- [1] [Microchip PIC32 Family Reference Manual - UART परिवार संदर्भ मैनुअल - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits दस्तावेज़ीकरण - UART mode और electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet डेटा शीट](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command दस्तावेज़ीकरण - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI and Hardware Instrumentation for Reverse Engineers, Part 1 Reverse Engineers के लिए SCPI और Hardware Instrumentation, भाग 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 Programming Guide प्रोग्रामिंग गाइड](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configuring the backend backend को configure करना](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Brushing Up on Hardware Hacking Part 2 Hardware Hacking पर दोबारा अभ्यास, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
