# SPI

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

SPI (Serial Peripheral Interface) embedded systems में ICs (Integrated Circuits) के बीच कम दूरी के communication के लिए उपयोग किया जाने वाला Synchronous Serial Communication Protocol है। SPI Communication Protocol master-slave architecture का उपयोग करता है, जिसे Clock और Chip Select Signal द्वारा orchestrate किया जाता है। Master-slave architecture में एक master (आमतौर पर microprocessor) होता है, जो EEPROM, sensors, control devices आदि जैसे external peripherals को manage करता है; इन्हें slaves माना जाता है।

एक master से कई slaves connect किए जा सकते हैं, लेकिन slaves आपस में communicate नहीं कर सकते। Slaves को दो pins, clock और chip select, द्वारा administrate किया जाता है। SPI एक synchronous communication protocol है, इसलिए input और output pins clock signals का अनुसरण करते हैं। Chip select का उपयोग master द्वारा किसी slave को select करने और उसके साथ interact करने के लिए किया जाता है। जब chip select high होता है, तो slave device select नहीं होता, जबकि low होने पर chip select होता है और master slave के साथ interact करता है।

MOSI (Master Out, Slave In) और MISO (Master In, Slave Out) data भेजने और प्राप्त करने के लिए जिम्मेदार होते हैं। जब chip select low रखा जाता है, तब MOSI pin के माध्यम से slave device को data भेजा जाता है। Input data में slave device vendor की datasheet के अनुसार instructions, memory addresses या data शामिल होते हैं। Valid input मिलने पर MISO pin master को data transmit करने के लिए जिम्मेदार होती है। Output data, input समाप्त होने के ठीक अगले clock cycle में भेजा जाता है। MISO pins तब तक data transmit करती हैं जब तक data पूरी तरह transmit न हो जाए या master chip select pin को high न कर दे (ऐसी स्थिति में slave transmit करना बंद कर देगा और master उस clock cycle के बाद listen नहीं करेगा)।

## EEPROMs से Firmware Dump करना

Firmware dump करना firmware का analysis करने और उसमें vulnerabilities खोजने के लिए उपयोगी हो सकता है। कई बार firmware internet पर उपलब्ध नहीं होता या model number, version आदि जैसे विभिन्न factors में variations के कारण अप्रासंगिक होता है। इसलिए, physical device से सीधे firmware extract करना threats की hunting के दौरान अधिक specific होने में सहायक हो सकता है।

Serial Console प्राप्त करना उपयोगी हो सकता है, लेकिन कई बार files read-only होती हैं। विभिन्न कारणों से यह analysis को सीमित करता है। उदाहरण के लिए, packages भेजने और प्राप्त करने के लिए आवश्यक tools firmware में मौजूद नहीं होंगे। इसलिए binaries को reverse engineer करने के लिए extract करना feasible नहीं होता। इस कारण, पूरे firmware को system पर dump करना और analysis के लिए binaries extract करना बहुत सहायक हो सकता है।

इसके अलावा, red teaming और devices तक physical access प्राप्त करने के दौरान firmware dump करना files को modify करने या malicious files inject करने और फिर उन्हें memory में reflash करने में मदद कर सकता है, जिससे device में backdoor implant करना संभव हो सकता है। इसलिए, firmware dumping से कई संभावनाएं unlock की जा सकती हैं।

### CH341A EEPROM Programmer और Reader

यह device EEPROMs से firmwares dump करने और उन्हें firmware files के साथ reflash करने के लिए एक inexpensive tool है। Computer BIOS chips (जो केवल EEPROMs होते हैं) के साथ काम करने के लिए यह एक popular choice रहा है। यह device USB के माध्यम से connect होता है और शुरू करने के लिए minimal tools की आवश्यकता होती है। इसके अलावा, यह आमतौर पर task को जल्दी पूरा कर देता है, इसलिए physical device access में भी सहायक हो सकता है।

![drawing](../../images/board_image_ch341a.jpg)

EEPROM memory को CH341a Programmer से connect करें और device को computer में plug करें। यदि device detect नहीं हो रहा है, तो computer में drivers install करने का प्रयास करें। यह भी सुनिश्चित करें कि EEPROM proper orientation में connected हो (आमतौर पर VCC Pin को USB connector के विपरीत orientation में रखें), अन्यथा software chip को detect नहीं कर पाएगा। आवश्यकता होने पर diagram देखें:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

अंत में, firmware dump करने के लिए flashrom, G-Flash (GUI) आदि जैसे softwares का उपयोग करें। G-Flash एक minimal GUI tool है, जो fast है और EEPROM को automatically detect करता है। जब firmware को documentation के साथ अधिक tinkering किए बिना जल्दी extract करना हो, तब यह सहायक हो सकता है।

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump करने के बाद binary files पर analysis किया जा सकता है। strings, hexdump, xxd, binwalk आदि जैसे tools का उपयोग firmware के बारे में और पूरे file system के बारे में भी बहुत-सी information extract करने के लिए किया जा सकता है।

Firmware से contents extract करने के लिए binwalk का उपयोग किया जा सकता है। Binwalk hex signatures का analysis करता है और binary file में files की पहचान करता है तथा उन्हें extract करने में सक्षम है।
```
binwalk -e <filename>
```
यह उपयोग किए गए tools और configurations के अनुसार `.bin` या `.rom` हो सकता है।

> [!CAUTION]
> ध्यान दें कि firmware extraction एक नाजुक प्रक्रिया है और इसमें काफी patience की आवश्यकता होती है। किसी भी गलत handling से firmware corrupt हो सकता है या पूरी तरह erase हो सकता है, जिससे device unusable हो सकता है। firmware extract करने का प्रयास करने से पहले specific device का अध्ययन करने की सलाह दी जाती है।

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

ध्यान दें कि भले ही Pirate Bus का PINOUT SPI से connect करने के लिए **MOSI** और **MISO** के pins दर्शाता हो, कुछ SPIs pins को DI और DO के रूप में दर्शा सकते हैं। **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: ध्यान दें कि भले ही Pirate Bus का PINOUT SPI से connect करने के लिए MOSI और MISO के pins दर्शाता हो, कुछ SPIs pins को...](<../../images/image (360).png>)

Windows या Linux में flash memory का content dump करने के लिए आप [**`flashrom`**](https://www.flashrom.org/Flashrom) program का उपयोग करके कुछ इस तरह चला सकते हैं:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
