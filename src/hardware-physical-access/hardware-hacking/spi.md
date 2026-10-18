# SPI

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

SPI (Serial Peripheral Interface) एक synchronous serial bus है, जिसका उपयोग आमतौर पर integrated circuits के बीच कम दूरी के communication के लिए किया जाता है। एक controller clock देता है और chip-select signal का उपयोग करके EEPROM, sensor या control device जैसे peripheral को चुनता है।<sup>[[1]](#references)</sup>

कई peripherals clock और data lines साझा कर सकते हैं; आमतौर पर हर peripheral के लिए अलग chip-select होता है। Controller transfers को orchestrate करता है; peripherals सामान्यतः SPI bus पर सीधे एक-दूसरे से communicate नहीं करते। Chip-select की polarity और timing device-specific होती है; active-low selection आम है, लेकिन सार्वभौमिक नहीं। SPI discovery, addressing, commands या transfer की एक निश्चित maximum length परिभाषित नहीं करता, इसलिए हमेशा target datasheet देखें।<sup>[[1]](#references)</sup>

MOSI/COPI controller-to-peripheral data और MISO/CIPO peripheral-to-controller data ले जाता है। दोनों दिशाओं में data एक साथ shift हो सकता है। Command, address, dummy cycles और लौटाए गए data के बीच का संबंध peripheral तय करता है—SPI नहीं—और यह clock polarity तथा phase (modes 0–3) पर निर्भर करता है। यह न मानें कि input खत्म होने के ठीक एक clock बाद output शुरू हो जाता है।<sup>[[1]](#references)</sup>

## EEPROMs से Firmware Dump करना

Firmware dump करना, उसका विश्लेषण करने और vulnerabilities खोजने में उपयोगी हो सकता है। सही image ऑनलाइन उपलब्ध न हो या model, hardware revision अथवा version के अनुसार अलग हो सकती है, इसलिए उसे सीधे physical device से extract करने पर assessment के लिए सटीक target मिलता है।

Serial console मदद कर सकता है, लेकिन उसका filesystem read-only हो सकता है और target पर analysis tools न हों—जिनमें test traffic भेजने/प्राप्त करने या binaries को आसानी से extract करने के लिए ज़रूरी utilities भी शामिल हैं। Offline image पूरा flash layout सुरक्षित रखती है और running target में बदलाव किए बिना filesystem extraction तथा reverse engineering की अनुमति देती है।

Authorized physical assessment के दौरान, verified dump नियंत्रित modification और reflashing tests में भी मदद कर सकता है। इसमें files बदलना या firmware-level persistence दिखाने के लिए test payload/backdoor inject करना शामिल है। किसी भी write से पहले कई मेल खाते reads और original image सुरक्षित रखें: गलत voltage, chip selection, layout या image device को brick कर सकती है।

### CH341A EEPROM Programmer और Reader

यह कम कीमत वाला USB tool compatible serial EEPROM और SPI flash devices को dump तथा reflash कर सकता है। इसका उपयोग आमतौर पर PC BIOS/UEFI firmware store करने वाली SPI NOR flash chips के साथ किया जाता है और time-limited physical access के दौरान यह सुविधाजनक है।

![drawing](../../images/board_image_ch341a.jpg)

Flash memory को CH341A से जोड़ें और फिर programmer को computer से connect करें। अगर programmer detect नहीं होता है, तो target chip की troubleshooting से पहले USB cable, OS permissions और उपयुक्त CH341A driver जाँचें। Datasheets या meter की मदद से chip का voltage, pin 1, adapter wiring और programmer output confirm करें—USB connector के उलट VCC रखने जैसे नियम पर **भरोसा न करें**। गलत orientation या 3.3/1.8 V part पर 5 V लगाने से chip खराब हो सकती है। In-circuit reads भी fail हो सकते हैं, क्योंकि board के बाकी हिस्से bus पर load डालते हैं या उसे power देते हैं।<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip को read करने के लिए `flashrom` या G-Flash जैसे software का उपयोग करें। G-Flash एक minimal GUI है और compatible devices को auto-detect कर सकता है, जो quick acquisition के दौरान सुविधाजनक हो सकता है; फिर भी detected model और voltage की खुद पुष्टि करें। Exact programmer और ज़रूरत पड़ने पर exact chip model specify करें; कम से कम दो reads करें और dump को reliable मानने से पहले उनके hashes की तुलना करें।<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump करने के बाद binary files का विश्लेषण किया जा सकता है। Firmware और पूरे file system के बारे में काफी जानकारी extract करने के लिए strings, hexdump, xxd, binwalk आदि जैसे tools इस्तेमाल किए जा सकते हैं।

शुरुआती triage के लिए, Binwalk ज्ञात signatures scan कर सकता है और समर्थित embedded content extract कर सकता है:

```
binwalk -e <filename>
```

Output file में `.bin`, `.rom` या कोई अन्य extension हो सकता है; extension से format निर्धारित नहीं होता।

> [!CAUTION]
> ध्यान दें कि firmware extraction एक नाज़ुक प्रक्रिया है और इसमें बहुत धैर्य की ज़रूरत होती है। किसी भी तरह की गलत हैंडलिंग से firmware corrupt हो सकता है या पूरी तरह erase भी हो सकता है, जिससे device अनुपयोगी हो सकता है। Firmware extract करने की कोशिश करने से पहले संबंधित device का अध्ययन करने की सलाह दी जाती है।

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

कुछ datasheets target pins को `DI` और `DO` नाम देते हैं: पारंपरिक single-data-line flash connection में, controller का **MOSI/COPI, DI से जुड़ता है** और controller का **MISO/CIPO, DO से जुड़ता है**। Target datasheet की पुष्टि करें, क्योंकि dual/quad I/O parts अन्य modes में इन्हीं pins का फिर से उपयोग करते हैं।

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: ध्यान दें कि Pirate Bus के PINOUT में SPI से जोड़ने के लिए MOSI और MISO pins दिए गए हैं, फिर भी कुछ SPIs...](<../../images/image (360).png>)

Windows या Linux में, flash memory की सामग्री dump करने के लिए [**`flashrom`**](https://www.flashrom.org/Flashrom) program का उपयोग इस तरह किया जा सकता है:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

हाल के Bus Pirate documentation में वैकल्पिक `serialspeed` और `spispeed` parameters भी दिखाए गए हैं। यदि लंबे wires या in-circuit loading के कारण reads अस्थिर हों, तो शुरुआत कम speed से करें।<sup>[[3]](#references)</sup>

### जब controller, flash bus साझा करता हो तब in-circuit reads

SOIC clip flash की supply को PCB के बाकी हिस्से तक पहुँचा सकता है। यदि MCU को power मिले और वह उसी chip को access करे, तो उसके SPI transfers बाहरी programmer के transfers से टकरा सकते हैं। इसलिए `No EEPROM/flash device found` का परिणाम इस बात का प्रमाण नहीं है कि flash मौजूद नहीं है या unsupported है। पहले pinout, voltage और contact जाँचें, फिर पता करें कि क्या on-board controller भी सक्रिय है।<sup>[[4]](#references)</sup>

यदि reset test pad उपलब्ध है, तो उसे सक्रिय करने से पहले meter से उसकी polarity और voltage की पुष्टि करें। MCU को reset में रखने से flash accessible रह सकती है और साथ ही प्रतिस्पर्धी SPI host रुक सकता है। विकल्प हैं chip को desolder करना या MCU के reads को passively रिकॉर्ड करना; इस तरीके से unread regions access नहीं किए जा सकते और न ही chip को write किया जा सकता है। साथ ही, अतिरिक्त probe wiring तेज़ bus में बाधा डाल सकती है। Oscillator या boot-mode intervention target-specific है; यह schematic और signals जाँचने का विकल्प नहीं है।<sup>[[4]](#references)</sup>

MCU को निष्क्रिय रखकर, enabled `spidev` interface वाला Raspberry Pi flashrom के `linux_spi` programmer के ज़रिए read कर सकता है। किसी दूसरे adapter के लिए `-p` बदलें। Read दोहराएँ और उस पर भरोसा करने से पहले hashes की तुलना करें; SFDP autodetection और सफल read से यह **साबित नहीं होता** कि किसी अन्यथा unsupported part पर erase, write या write-protect operations काम करते हैं।<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Logic analyzer से SPI flash reads को पुनर्निर्मित करना

जब active reading संभव न हो, तो boot या चुनी गई UI क्रिया के दौरान chip select, clock, controller-to-flash data और flash-to-controller data को capture करें। PulseView में पहले active chip-select interval और clock की पहचान करें, फिर flash pinout के अनुसार SPI decoder के data channels configure करें और जाँचें कि कोई संभावित command/address के बाद bytes लौट रहे हैं। Binary Decoder Output View का उपयोग करके **MISO/flash-output** bytes export करें और decoded read addresses सुरक्षित रखें, ताकि हर response को उसके संबंधित flash offset पर रखा जा सके। केवल menu-driven reads को capture करने से सिर्फ़ अनुरोधित regions मिलते हैं, पूरी flash image नहीं; addresses की जाँच किए बिना responses को ऐसे concatenate न करें, जैसे वे लगातार हों।<sup>[[4]](#references)</sup>

अगर dump में executable code के बजाय graphics दिखाई देते हैं, तो [raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash) जारी रखें।<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — SPI इंटरफ़ेस का परिचय](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI प्रोग्रामर और पढ़ने/लिखने के विकल्प](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — हार्डवेयर हैकिंग पर फिर से नज़र, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
