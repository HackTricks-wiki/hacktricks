# SPI

{{#include ../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

SPI (Serial Peripheral Interface) एक synchronous serial bus है, जिसका उपयोग आमतौर पर integrated circuits के बीच कम दूरी के संचार के लिए किया जाता है। कंट्रोलर clock देता है और chip-select signal का उपयोग करके EEPROM, sensor या control device जैसे peripheral को चुनता है।<sup>[[1]](#references)</sup>

कई peripherals clock और data lines साझा कर सकते हैं; आमतौर पर हर peripheral के लिए अलग chip-select होता है। कंट्रोलर transfers को नियंत्रित करता है; आमतौर पर peripherals SPI bus पर एक-दूसरे से सीधे संचार नहीं करते। Chip-select की polarity और timing डिवाइस के अनुसार अलग होती है; active-low selection आम है, लेकिन सार्वभौमिक नहीं। SPI में discovery, addressing, commands या एक अधिकतम transfer length निर्धारित नहीं है, इसलिए हमेशा target की datasheet देखें।<sup>[[1]](#references)</sup>

MOSI/COPI कंट्रोलर से peripheral तक data ले जाता है और MISO/CIPO peripheral से कंट्रोलर तक data ले जाता है। दोनों दिशाओं में एक साथ data shift हो सकता है। Command, address, dummy cycles और लौटाए गए data के बीच का संबंध peripheral द्वारा निर्धारित होता है—SPI द्वारा नहीं—और यह clock polarity और phase (modes 0–3) पर निर्भर करता है। यह न मानें कि input समाप्त होने के ठीक एक clock बाद output शुरू हो जाता है।<sup>[[1]](#references)</sup>

## EEPROMs से Firmware Dump करना

Firmware dump करना उसके विश्लेषण और vulnerabilities खोजने में उपयोगी हो सकता है। सही image ऑनलाइन उपलब्ध न हो या model, hardware revision अथवा version के अनुसार अलग हो सकती है। इसलिए उसे सीधे physical device से निकालने पर सटीक assessment target मिलता है।

Serial console मदद कर सकता है, लेकिन उसका filesystem read-only हो सकता है और target में analysis tools मौजूद न हों—जिनमें test traffic भेजने/प्राप्त करने या binaries आसानी से extract करने के लिए ज़रूरी utilities भी शामिल हैं। Offline image में पूरा flash layout सुरक्षित रहता है और running target में बदलाव किए बिना filesystem extraction और reverse engineering की जा सकती है।

Authorized physical assessment के दौरान, verified dump नियंत्रित modification और reflashing tests में भी मदद कर सकता है। इसमें firmware-level persistence दिखाने के लिए files बदलना या test payload/backdoor inject करना शामिल है। किसी भी write से पहले कई एक-जैसे reads और original image सुरक्षित रखें: गलत voltage, chip selection, layout या image डिवाइस को brick कर सकती है।

### CH341A EEPROM Programmer और Reader

यह कम कीमत वाला USB tool संगत serial EEPROM और SPI flash devices को dump और reflash कर सकता है। इसका उपयोग आमतौर पर PC BIOS/UEFI firmware स्टोर करने वाली SPI NOR flash chips के साथ किया जाता है और सीमित समय वाले physical access के दौरान यह सुविधाजनक है।

![drawing](../../images/board_image_ch341a.jpg)

Flash memory को CH341A से जोड़ें और फिर programmer को कंप्यूटर से जोड़ें। अगर programmer का पता ही नहीं चलता, तो target chip की जाँच करने से पहले USB cable, OS permissions और उपयुक्त CH341A driver जाँचें। Datasheets या meter की मदद से chip का voltage, pin 1, adapter wiring और programmer output की पुष्टि करें—VCC को USB connector के विपरीत तरफ रखने जैसे नियम पर **भरोसा न करें**। गलत दिशा में लगाने या 3.3/1.8 V वाले part पर 5 V देने से वह खराब हो सकता है। In-circuit reads भी fail हो सकते हैं, क्योंकि बाकी board bus पर load डाल सकता है या उसे power दे सकता है।<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip को read करने के लिए `flashrom` या G-Flash जैसे software का उपयोग करें। G-Flash एक minimal GUI है और संगत devices को auto-detect कर सकता है, जो त्वरित acquisition के दौरान सुविधाजनक है; फिर भी detected model और voltage की स्वयं पुष्टि करें। Programmer का सटीक नाम और, ज़रूरत पड़ने पर, chip का सटीक model दें; dump को भरोसेमंद मानने से पहले कम-से-कम दो reads करें और उनके hashes की तुलना करें।<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump करने के बाद, binary files का विश्लेषण किया जा सकता है। Firmware और पूरे file system के बारे में बहुत-सी जानकारी निकालने के लिए strings, hexdump, xxd, binwalk आदि tools का उपयोग किया जा सकता है।

शुरुआती जाँच के लिए, Binwalk ज्ञात signatures को scan कर सकता है और समर्थित embedded content extract कर सकता है:

```
binwalk -e <filename>
```

आउटपुट फ़ाइल में `.bin`, `.rom` या कोई अन्य एक्सटेंशन हो सकता है; एक्सटेंशन से फ़ाइल का फ़ॉर्मैट तय नहीं होता।

> [!CAUTION]
> ध्यान दें कि firmware निकालना एक नाज़ुक प्रक्रिया है और इसके लिए बहुत धैर्य की ज़रूरत होती है। लापरवाही से firmware corrupt हो सकता है या पूरी तरह मिट भी सकता है, जिससे डिवाइस अनुपयोगी हो सकता है। firmware निकालने की कोशिश करने से पहले उस विशिष्ट डिवाइस का अध्ययन करने की सलाह दी जाती है।

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

कुछ datasheet में target pins को `DI` और `DO` नाम दिया जाता है: पारंपरिक single-data-line flash connection में, controller का **MOSI/COPI, DI से** और controller का **MISO/CIPO, DO से** जुड़ता है। target datasheet ज़रूर जाँचें, क्योंकि dual/quad I/O पार्ट्स अन्य modes में उन्हीं pins का दोबारा उपयोग करते हैं।

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: ध्यान दें कि Pirate Bus के PINOUT में SPI से कनेक्ट करने के लिए MOSI और MISO pins दिए होने पर भी, कुछ SPIs...](<../../images/image (360).png>)

Windows या Linux में flash memory की सामग्री dump करने के लिए [**`flashrom`**](https://www.flashrom.org/Flashrom) प्रोग्राम का इस्तेमाल इस तरह किया जा सकता है:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

हाल के Bus Pirate documentation में optional `serialspeed` और `spispeed` parameters भी दिखाए गए हैं। अगर लंबे wires या circuit में लगे components के कारण reads अस्थिर हों, तो शुरुआत कम speed से करें।<sup>[[3]](#references)</sup>

### जब controller flash bus साझा करता हो, तब circuit में रहते हुए reads करना

SOIC clip flash की power को PCB के बाकी हिस्सों तक पहुँचा सकता है। अगर MCU powered हो और उसी chip को access करे, तो उसके SPI transfers बाहरी programmer के transfers से टकरा सकते हैं। इसलिए `No EEPROM/flash device found` परिणाम इस बात का प्रमाण नहीं है कि flash मौजूद नहीं है या unsupported है। पहले pinout, voltage और contact जाँचें, फिर पता करें कि क्या on-board controller भी active है।<sup>[[4]](#references)</sup>

अगर reset test pad उपलब्ध हो, तो उसे assert करने से पहले meter से उसकी polarity और voltage की पुष्टि करें। MCU को reset में रखने से flash accessible रह सकती है, जबकि प्रतिस्पर्धी SPI host रुक जाता है। अन्य विकल्प हैं chip को desolder करना या MCU के reads को passively record करना; दूसरे तरीके से unread regions access नहीं किए जा सकते और chip पर write भी नहीं किया जा सकता। अतिरिक्त probe wiring से तेज़ bus में बाधा आ सकती है। Oscillator या boot-mode में हस्तक्षेप target-specific होता है; यह schematic और signals जाँचने का विकल्प नहीं है।<sup>[[4]](#references)</sup>

MCU को inactive रखकर, enabled `spidev` interface वाला Raspberry Pi flashrom के `linux_spi` programmer से पढ़ सकता है। किसी दूसरे adapter के लिए `-p` बदलें। Read दोहराएँ और उस पर भरोसा करने से पहले hashes की तुलना करें; SFDP autodetection और सफल read से यह **साबित नहीं होता** कि किसी अन्यथा unsupported part पर erase, write या write-protect operations काम करते हैं।<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### लॉजिक एनालाइज़र से SPI flash reads का पुनर्निर्माण

जब सक्रिय रूप से read करना संभव न हो, तो boot के दौरान या UI की चुनी हुई कार्रवाई करते समय chip select, clock, controller-to-flash data और flash-to-controller data कैप्चर करें। PulseView में पहले सक्रिय chip-select interval और clock पहचानें, फिर flash pinout के अनुसार SPI decoder के data channels कॉन्फ़िगर करें और लौटाए गए bytes से पहले आने वाले command/address की पुष्टि करें। Binary Decoder Output View से **MISO/flash-output** bytes export करें और decoded read addresses सुरक्षित रखें, ताकि हर response को उसके संबंधित flash offset पर रखा जा सके। केवल menu-driven reads कैप्चर करने से सिर्फ़ अनुरोधित regions मिलते हैं, पूरी flash image नहीं; addresses जाँचे बिना responses को ऐसे concatenate न करें मानो वे लगातार हों।<sup>[[4]](#references)</sup>

अगर dump में executable code के बजाय graphics दिखाई देते हैं, तो [raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash) जारी रखें।<sup>[[4]](#references)</sup>

#### Scapy और mixed SPI/QSPI captures

बिना label वाले probes के लिए, response data से पहले opcode वाली line देखकर MOSI और MISO में अंतर करें, फिर flash datasheet से command की पुष्टि करें। Clock की अवधि से छोटी pulses, sampled bits के बजाय probe noise हो सकती हैं, और अतिरिक्त clip wiring से high-speed captures अविश्वसनीय हो सकते हैं।<sup>[[5]](#references)</sup>

Saleae का SPI CSV export, chip-select interval को सीमांकित करने के लिए `enable` और `disable` का उपयोग करता है; MOSI/MISO bytes `result` rows में होते हैं। Decode करने से पहले bytes को interval के अनुसार group करें; सभी MISO data को concatenate करने से transaction addresses खो जाते हैं।<sup>[[5]](#references)</sup> Scapy का `Packet`, MOSI header को `ByteEnumField` opcode और conditional address तथा dummy fields के साथ model कर सकता है। 24-bit NOR reads के लिए, `0x03` में opcode और तीन address bytes होते हैं, जबकि `0x0B` में एक dummy byte भी होता है। `len(req.self_build())` से modeled header की लंबाई मिलती है: single-lane read में, `miso[header_length:]` flash response होता है, जबकि header के बाद का MOSI controller-side don't-care data होता है।<sup>[[5]](#references)</sup> Responses को `0xFF` से भरी image में उनके decoded addresses पर रखें और covered offsets को अलग से track करें। किसी byte का दिखाई न देना इस बात का प्रमाण नहीं है कि flash में उस जगह `0xFF` था।<sup>[[5]](#references)[[6]](#references)</sup>

W25Q-शैली की `0x6B` (1-1-4) read में opcode और address के लिए एक lane का उपयोग होता है, लेकिन response data के लिए IO0–IO3 का। पहले वाले `/WP` और `/HOLD` pins पर activity, केवल तेज़ clock की तुलना में, quad-mode switch का अधिक ठोस प्रमाण है; single-lane analyzer quad response को गलत decode कर सकता है।<sup>[[5]](#references)</sup> उस phase को command की lane widths और dummy cycles के अनुसार configured QSPI analyzer से export करें, फिर single- और quad-lane reads को flash address के आधार पर merge करें।<sup>[[5]](#references)[[7]](#references)</sup> `spidump` दोनों export formats को auto-detect करता है, गलत lane width पर decoded reads को discard करता है और read coverage की रिपोर्ट देता है।<sup>[[6]](#references)</sup> इसकी repository से, dependencies install करने के बाद, captures को इस तरह merge करें:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

परिणाम एक विरल अवलोकन ही रहता है, पूरा chip dump नहीं।<sup>[[5]](#references)[[6]](#references)</sup> Writes को अलग से देखने के लिए `0x06` write-enable, `0x05` status polls, erase opcodes और `0x02` page-program commands का सहसंबंध करें। Page-program डेटा MOSI पर address के बाद आता है और केवल read से किए गए reconstruction में शामिल नहीं होता।<sup>[[5]](#references)</sup> परिणामी image का विश्लेषण [firmware analysis](../firmware-analysis/) से करें और read-coverage की जानकारी बनाए रखें।

## References

- [1] [Analog Devices — SPI Interface का परिचय](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer और read/write विकल्प](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate documentation — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Hardware Hacking पर दोबारा नज़र, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Hardware Reverse Engineering के लिए Scapy का विस्तार](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI trace capture और reconstruction](https://github.com/wrongbaud/spidump)
- [7] [Saleae Logic/KingstVIS के लिए QSPI Analyzer](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
