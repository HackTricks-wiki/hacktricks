# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## सुरक्षित pin hunting और hardware setup

- पहले multimeter से Vtref और GND की पहचान करें। कई adapters को I/O voltage सेट करने के लिए Vtref की ज़रूरत होती है।
- Level shifting: push-pull signals के लिए डिज़ाइन किए गए bidirectional level shifters को प्राथमिकता दें (JTAG lines open-drain नहीं होतीं)। JTAG के लिए auto-direction I2C shifters से बचें।
- उपयोगी adapters: FT2232H/FT232H boards (जैसे, Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (ESP32-Sx पर)। कम-से-कम TCK, TMS, TDI, TDO, GND और Vtref कनेक्ट करें; TRST और SRST वैकल्पिक हैं।

बिना दस्तावेज़ वाले header के लिए, **target को unpowered रखते हुए** multimeter से continuity जाँचकर किसी ज्ञात ground plane से जुड़े GND की पहचान करें। Voltage mode पर स्विच करके target को power देने के बाद, हर high pin को Vtref न मानें: high digital inputs भी meter पर वैसे ही दिख सकते हैं। संभावित rails को पास के decoupling capacitors तक trace करें और oscilloscope पर उनके power-up/power-down waveforms की तुलना करें। Capacitor जैसी धीमी rise या fall किसी supply/reference net का संकेत हो सकती है, लेकिन level-shifted probe कनेक्ट करने से पहले voltage और wiring की पुष्टि करें। PiFex पर, इसकी default 3.3 V setting की जगह `VCCA_IN` के ज़रिए बाहरी कम-voltage target reference चुना जा सकता है।<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** एक ऐसा tool है जिसे unknown JTAG pinouts को brute-force करने और instruction registers को enumerate करने के लिए Arduino-compatible MCU या प्रयोग के तौर पर Raspberry Pi पर load किया जा सकता है।<sup>[[3]](#references)</sup>

- Arduino: digital pins D2–D11 को अधिकतम 10 संदिग्ध JTAG pads/testpoints से और Arduino GND को target GND से कनेक्ट करें। जब तक आपको rail के सुरक्षित होने का पता न हो, target को अलग से power दें। 3.3 V logic को प्राथमिकता दें (जैसे, Arduino Due) या 1.8–3.3 V targets की जाँच करते समय level shifter/series resistors का इस्तेमाल करें।
- Raspberry Pi: Pi build में कम GPIOs इस्तेमाल किए जा सकते हैं (इसलिए scans धीमे होते हैं); मौजूदा pin map और सीमाओं के लिए repo देखें।

Flash करने के बाद, serial monitor को 115200 baud पर खोलें और मदद के लिए `h` भेजें। सामान्य प्रक्रिया:

- `l` false positives से बचने के लिए loopbacks खोजें
- `r` ज़रूरत पड़ने पर internal pull-ups टॉगल करें
- `s` TCK/TMS/TDI/TDO (और कभी-कभी TRST/SRST) के लिए scan करें
- `y` undocumented opcodes खोजने के लिए IR को brute-force करें
- `x` pin states का boundary-scan snapshot लें

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (774).png>)



अगर कोई valid TAP मिलता है, तो खोजे गए pins दिखाने वाली `FOUND!` से शुरू होने वाली lines दिखाई देंगी।

### JTAGenum के लिए सुरक्षा सुझाव

- हमेशा ground साझा करें और unknown pins को target Vtref से अधिक voltage कभी न दें। संदेह होने पर, संभावित pins पर 100–470 Ω series resistors लगाएँ।
- अगर device 4-wire JTAG की जगह SWD/SWJ इस्तेमाल करता है, तो JTAGenum उसे detect नहीं कर सकता; SWD tools या SWJ-DP को support करने वाला adapter आज़माएँ।

## go-jtagenum से GPIO pin discovery

Verified common ground और compatible I/O voltage वाले powered target पर, `go-jtagenum` Raspberry Pi GPIOs से संभावित JTAG signals enumerate कर सकता है। `-pins` JSON में labels, **GPIO numbers** से जुड़े होते हैं, physical header positions से नहीं।<sup>[[5]](#references)</sup> SSD उदाहरण में, पहले IDCODE scan ने बदलती हुई values की एक असंभव रूप से लंबी chain भी report की थी: केवल बदलती हुई candidate TDO line, valid TAP का प्रमाण नहीं है। BYPASS scan से संभावित नतीजे की दोबारा जाँच करें, जो TDI से one-bit bypass register होते हुए TDO तक एक ज्ञात bit pattern shift करता है।<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

उस बोर्ड के लिए, BYPASS ने `TCK=10`, `TMS=14`, `TDI=9`, और `TDO=15` की पुष्टि की; अतिरिक्त पिन केवल **संभावित** nTRST उम्मीदवार थे। अगर किसी उम्मीदवार से सभी शून्य या असंगत पैटर्न मिलता है, तो उसे कोई सिग्नल देने से पहले संपर्क, target power, pull-ups, और clock/reset delays जाँचें।<sup>[[4]](#references)[[5]](#references)</sup> टूल, मिले हुए मैपिंग को फिर से जाँचने के लिए `test_bypass` के साथ `-known-pins` भी स्वीकार करता है।<sup>[[5]](#references)</sup>

## UrJTAG के साथ अनदस्तावेजीकृत TAP की विशेषताएँ जानें

खोजा गया pinout, debugging के लिए आवश्यक instruction-register (IR) opcodes या data-register (DR) widths की पहचान नहीं करता। Raspberry Pi GPIO cable को सपोर्ट करने वाले UrJTAG build में, प्राप्त mapping सेट करें और `idcode`, फिर `detect`, और उसके बाद `discover` चलाएँ। SSD उदाहरण में एक TAP, चार-बिट IR, और अलग-अलग IR मानों के लिए अलग-अलग DR widths मिलीं। `-1` DR length या “TDO stuck at 0” उपयोग करने योग्य register definition नहीं है; उसे width देने के बजाय timing, wiring, और चुने गए instruction की जाँच करें।<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

यह TAP reconnaissance है, automatic CPU identification नहीं: प्राप्त IDCODE की तुलना device documentation और supported OpenOCD targets से करें। UrJTAG का local manufacturer database किसी अन्यथा valid ID को unknown के रूप में label कर सकता है।<sup>[[4]](#references)</sup>

## OpenOCD से पहला संपर्क (scan और IDCODE)

OpenOCD, JTAG/SWD के लिए de-facto OSS है। Supported adapter से आप chain scan कर सकते हैं और IDCODEs पढ़ सकते हैं:<sup>[[1]](#references)</sup>

- J‑Link के साथ generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 का built-in USB‑JTAG (बाहरी probe की आवश्यकता नहीं):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- अगर आपको "all ones/zeros" IDCODE मिले, तो wiring, power, Vtref और यह जाँचें कि port fuses/option bytes से locked तो नहीं है।
- Unknown chains को bring up करते समय manual TAP interaction के लिए OpenOCD के low-level `irscan`/`drscan` देखें।<sup>[[1]](#references)</sup>

## किसी undocumented target को OpenOCD में लाएँ

TAP ID और IR length पता चल जाने के बाद, **matching CPU architecture** के लिए OpenOCD की `cpu/`, `target/` और `board/` scripts देखें, फिर adapter और target के लिए अलग-अलग configurations बनाएँ।<sup>[[4]](#references)[[6]](#references)</sup> नीचे दिया गया Pi GPIO mapping और ARCv2 target tested SSD example है, universal JTAG configuration नहीं। इस device के लिए चुना गया ARC target और debug settings अनुमान थे, जो सफल रहे; किसी दूसरे board पर target की मापी गई ID, IR length, architecture और GPIO numbers का इस्तेमाल करें।<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

`openocd -f raspberrypi-io.cfg -f target.cfg` चलाएँ और memory पढ़ने से पहले पुष्टि करें कि TAP examination सफल है। उदाहरण में Telnet पोर्ट `4444` पर और GDB server `3333` पर खोला गया था; केवल पहचाना गया IDCODE यह साबित नहीं करता कि चुने गए CPU target की examination या debugging की जा सकती है।<sup>[[4]](#references)</sup> यदि adapter `adapter gpio` remapping की अनुमति देता है, तो Raspberry Pi GPIOs का breakout board पर JTAG लेबल वाले pins से जुड़ा होना ज़रूरी नहीं है।<sup>[[4]](#references)[[6]](#references)</sup>

## CPU को halt करना और memory/flash dump करना

TAP की पहचान हो जाने और target script चुन लिए जाने के बाद, आप core को halt करके memory regions या internal flash का dump ले सकते हैं। उदाहरण (target, base addresses और sizes के अनुसार बदलाव करें):<sup>[[1]](#references)</sup>

- init के बाद generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (उपलब्ध होने पर SBA को प्राथमिकता दें):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3 को OpenOCD helper के माध्यम से प्रोग्राम करें या पढ़ें:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Memory-Dumping के सुझाव

- लंबे dump से पहले memory की sanity-check करने के लिए `mdw/mdh/mdb` का उपयोग करें।
- Multi-device chains के लिए, non-targets पर BYPASS सेट करें या ऐसी board file का उपयोग करें जो सभी TAPs को परिभाषित करती हो।

Undocumented memory map के लिए, SSD research में पहचाने जा सकने वाले controller strings खोजने हेतु 1 MiB dump की जाँच की गई, फिर `$pc`, disassembly और registers का निरीक्षण करने के लिए OpenOCD के ज़रिए architecture-capable GDB का उपयोग किया गया। उन live addresses से दूसरे region dump को दिशा मिली, जिसकी जाँच ARC-capable Ghidra build में matching instructions से की गई। केवल strings से plausibility की जाँच होती है; वे इस बात का प्रमाण नहीं हैं कि image पूरी है या सही ढंग से mapped है।<sup>[[4]](#references)</sup> व्यापक static-analysis चरणों के लिए [firmware analysis](../firmware-analysis/) देखें।

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU debug access लॉक होने पर भी boundary-scan उपलब्ध हो सकता है। UrJTAG/OpenOCD के साथ आप यह कर सकते हैं:<sup>[[1]](#references)</sup>
- सिस्टम चलते समय pin states का snapshot लेने के लिए SAMPLE का उपयोग करें (bus activity खोजें, pin mapping की पुष्टि करें)।
- Pins drive करने के लिए EXTEST का उपयोग करें (जैसे, MCU के ज़रिए external SPI flash lines को bit-bang करके उसे offline पढ़ें, यदि board wiring इसकी अनुमति देती हो)।

FT2232x adapter के साथ न्यूनतम UrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
आपको boundary register के bit ordering को जानने के लिए device BSDL चाहिए। ध्यान रखें कि कुछ vendors production में boundary-scan cells को lock कर देते हैं।

## आधुनिक targets और टिप्पणियाँ

- ESP32‑S3/C3 में native USB‑JTAG bridge शामिल है; OpenOCD किसी external probe के बिना सीधे USB पर communicate कर सकता है। प्रारंभिक जांच और dumps के लिए यह बहुत सुविधाजनक है।<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) को OpenOCD व्यापक रूप से support करता है; जब core को सुरक्षित रूप से halt नहीं किया जा सकता, तो memory access के लिए SBA को प्राथमिकता दें।
- कई MCUs में debug authentication और lifecycle states लागू होते हैं। यदि JTAG काम करता हुआ न लगे, लेकिन power सही हो, तो संभव है कि device को fuse करके closed state में रखा गया हो या उसे authenticated probe की आवश्यकता हो।

## Defenses और hardening (असली devices में क्या अपेक्षा करें)

- Production में JTAG/SWD को स्थायी रूप से disable या lock करें (उदाहरण के लिए, STM32 RDP level 2, PAD JTAG को disable करने वाले ESP eFuses, NXP/Nordic APPROTECT/DPAP)।
- Manufacturing access बनाए रखते हुए authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM द्वारा प्रबंधित challenge-response) आवश्यक करें।
- आसानी से पहुँचने वाले test pads न रखें; test vias को भीतर दबाएँ, TAP को अलग करने के लिए resistors हटाएँ/लगाएँ, और keying वाले connectors या pogo-pin fixtures का उपयोग करें।
- Power-on debug lock: secure boot लागू करने वाले शुरुआती ROM के पीछे TAP को रखें।

## References

- [1] [OpenOCD User’s Guide – JTAG Commands और configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD का उपयोग)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-आधारित JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Raspberry Pi के साथ JTAG Hacking](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG enumeration](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD User’s Guide — Debug Adapter Configuration](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
