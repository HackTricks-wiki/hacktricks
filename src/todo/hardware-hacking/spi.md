# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

SPI (Serial Peripheral Interface) एक synchronous serial bus है, जिसका उपयोग आमतौर पर integrated circuits के बीच short-distance communication के लिए किया जाता है। एक controller clock प्रदान करता है और chip-select signal का उपयोग करके किसी peripheral, जैसे EEPROM, sensor या control device को चुनता है।<sup>[[1]](#references)</sup>

कई peripherals clock और data lines साझा कर सकते हैं, सामान्यतः प्रत्येक peripheral के लिए अलग chip-select के साथ। Controller transfers को व्यवस्थित करता है; peripherals सामान्यतः SPI bus पर एक-दूसरे से सीधे communicate नहीं करते। Chip-select polarity और timing device-specific होते हैं; active-low selection सामान्य है, लेकिन सार्वभौमिक नहीं। SPI discovery, addressing, commands या single maximum transfer length को define नहीं करता, इसलिए हमेशा target datasheet देखें।<sup>[[1]](#references)</sup>

MOSI/COPI controller-to-peripheral data ले जाता है और MISO/CIPO peripheral-to-controller data ले जाता है। दोनों दिशाओं में एक साथ shift किया जा सकता है। किसी command, address, dummy cycles और returned data के बीच संबंध peripheral द्वारा define किया जाता है, SPI द्वारा नहीं, और यह clock polarity तथा phase (modes 0–3) पर निर्भर करता है। यह न मानें कि input समाप्त होने के ठीक एक clock बाद output शुरू होता है।<sup>[[1]](#references)</sup>

## EEPROMs से Firmware Dump करना

Firmware dump करना उसके analysis और vulnerabilities खोजने में उपयोगी हो सकता है। सही image online उपलब्ध नहीं हो सकती या model, hardware revision अथवा version के अनुसार अलग हो सकती है, इसलिए उसे physical device से सीधे extract करने पर exact assessment target मिलता है।

Serial console सहायक हो सकता है, लेकिन उसका filesystem read-only हो सकता है और target में analysis tools मौजूद नहीं हो सकते, जिनमें test traffic भेजने/प्राप्त करने या binaries को सुविधाजनक रूप से extract करने के लिए आवश्यक utilities भी शामिल हैं। Offline image complete flash layout को सुरक्षित रखती है और running target को modify किए बिना filesystem extraction तथा reverse engineering की अनुमति देती है।

Authorized physical assessment के दौरान verified dump controlled modification और reflashing tests में भी सहायक हो सकता है। इसमें files बदलना या firmware-level persistence प्रदर्शित करने के लिए test payload/backdoor inject करना शामिल है। किसी भी write से पहले कई matching reads और original image सुरक्षित रखें: गलत voltage, chip selection, layout या image device को brick कर सकती है।

### CH341A EEPROM Programmer और Reader

यह कम लागत वाला USB tool compatible serial EEPROM और SPI flash devices को dump और reflash कर सकता है। इसका उपयोग आमतौर पर PC BIOS/UEFI firmware store करने वाली SPI NOR flash chips के साथ किया जाता है और time-limited physical access के दौरान यह सुविधाजनक होता है।

![drawing](../../images/board_image_ch341a.jpg)

Flash memory को CH341A से connect करें और फिर programmer को computer से connect करें। यदि programmer detect नहीं होता है, तो target chip की troubleshooting से पहले USB cable, OS permissions और उपयुक्त CH341A driver की जांच करें। Datasheets या meter की सहायता से chip का voltage, pin 1, adapter wiring और programmer output confirm करें—**VCC को USB connector के opposite रखने जैसे किसी rule पर निर्भर न रहें**। गलत orientation या 3.3/1.8 V part पर 5 V लागू करने से वह नष्ट हो सकता है। In-circuit reads भी fail हो सकते हैं, क्योंकि board का बाकी हिस्सा bus को load या power कर सकता है।<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip को read करने के लिए `flashrom` या G-Flash जैसे software का उपयोग करें। G-Flash एक minimal GUI है और compatible devices को auto-detect कर सकता है, जो quick acquisition के दौरान सुविधाजनक हो सकता है, लेकिन detected model और voltage को स्वयं confirm करें। Exact programmer और, आवश्यकता होने पर, exact chip model specify करें; dump को reliable मानने से पहले कम-से-कम दो reads करें और उनके hashes की तुलना करें।<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump करने के बाद binary files पर analysis किया जा सकता है। Firmware के साथ-साथ पूरे file system से भी बहुत-सी information extract करने के लिए strings, hexdump, xxd, binwalk आदि जैसे tools का उपयोग किया जा सकता है।

Initial triage के लिए Binwalk known signatures को scan कर सकता है और supported embedded content को extract कर सकता है:
```
binwalk -e <filename>
```
आउटपुट फ़ाइल में `.bin`, `.rom` या कोई अन्य extension हो सकता है; extension से format निर्धारित नहीं होता।

> [!CAUTION]
> ध्यान दें कि firmware extraction एक नाज़ुक प्रक्रिया है और इसमें बहुत धैर्य की आवश्यकता होती है। किसी भी गलत handling से firmware संभावित रूप से corrupt हो सकता है या पूरी तरह erase हो सकता है, जिससे device unusable हो सकता है। Firmware extract करने का प्रयास करने से पहले specific device का अध्ययन करने की सलाह दी जाती है।

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

कुछ datasheets target pins को `DI` और `DO` के रूप में label करती हैं: conventional single-data-line flash connection के लिए, controller **MOSI/COPI को DI से connect करता है** और controller **MISO/CIPO को DO से connect करता है**। Target datasheet को verify करें, क्योंकि dual/quad I/O parts अन्य modes में इन pins का पुनः उपयोग करते हैं।

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: ध्यान दें कि Pirate Bus के PINOUT में MOSI और MISO को SPI से connect करने के लिए pins होने के बावजूद, कुछ SPIs...](<../../images/image (360).png>)

Windows या Linux में आप flash memory का content dump करने के लिए [**`flashrom`**](https://www.flashrom.org/Flashrom) program का उपयोग कर सकते हैं, कुछ इस तरह:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
हालिया Bus Pirate documentation में वैकल्पिक `serialspeed` और `spispeed` parameters भी दिखाए गए हैं। यदि लंबे wires या in-circuit loading के कारण reads अस्थिर हों, तो conservatively शुरुआत करें।<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI Interface का परिचय](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer और read/write options](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
