# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** एक ऐसा tool है जिसे unknown JTAG pinouts को brute-force करने और instruction registers enumerate करने के लिए Arduino-compatible MCU या प्रयोग के तौर पर Raspberry Pi पर load किया जा सकता है।<sup>[[3]](#references)</sup>

- Arduino: digital pins D2–D11 को अधिकतम 10 संभावित JTAG pads/testpoints से, और Arduino GND को target GND से जोड़ें। जब तक आपको यह न पता हो कि rail सुरक्षित है, target को अलग से power दें। 3.3 V logic को प्राथमिकता दें (जैसे Arduino Due), या 1.8–3.3 V targets की जाँच करते समय level shifter/series resistors का उपयोग करें।
- Raspberry Pi: Pi build में कम GPIOs उपयोग किए जा सकते हैं (इसलिए scans धीमे होते हैं); मौजूदा pin map और सीमाओं के लिए repo देखें।

Flash करने के बाद, serial monitor को 115200 baud पर खोलें और मदद के लिए `h` भेजें। सामान्य प्रक्रिया:

- `l` false positives से बचने के लिए loopbacks खोजें
- `r` ज़रूरत पड़ने पर internal pull-ups को toggle करें
- `s` TCK/TMS/TDI/TDO (और कभी-कभी TRST/SRST) के लिए scan करें
- `y` undocumented opcodes खोजने के लिए IR को brute-force करें
- `x` pin states का boundary-scan snapshot लें

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (774).png>)



अगर कोई valid TAP मिलता है, तो खोजे गए pins दिखाने वाली `FOUND!` से शुरू होने वाली lines दिखाई देंगी।

### JTAGenum सुरक्षा संबंधी सुझाव

- हमेशा ground साझा करें, और unknown pins को कभी भी target Vtref से अधिक voltage न दें। संदेह होने पर, संभावित pins पर 100–470 Ω series resistors लगाएँ।
- अगर device 4-wire JTAG के बजाय SWD/SWJ का उपयोग करता है, तो JTAGenum उसे detect नहीं कर सकता; SWD tools या SWJ‑DP को support करने वाला adapter आज़माएँ।

## अधिक सुरक्षित pin hunting और hardware setup

- पहले multimeter से Vtref और GND पहचानें। कई adapters को I/O voltage सेट करने के लिए Vtref की ज़रूरत होती है।
- Level shifting: push-pull signals के लिए बने bidirectional level shifters को प्राथमिकता दें (JTAG lines open-drain नहीं होतीं)। JTAG के लिए auto-direction I2C shifters से बचें।
- उपयोगी adapters: FT2232H/FT232H boards (जैसे Tigard), CMSIS-DAP, J‑Link, ST‑LINK (vendor-specific), ESP‑USB‑JTAG (ESP32‑Sx पर)। कम-से-कम TCK, TMS, TDI, TDO, GND और Vtref जोड़ें; TRST और SRST वैकल्पिक हैं।

## OpenOCD से पहला संपर्क (scan और IDCODE)

OpenOCD, JTAG/SWD के लिए de-facto OSS है। Supported adapter से आप chain scan कर सकते हैं और IDCODEs पढ़ सकते हैं:<sup>[[1]](#references)</sup>

- J‑Link के साथ सामान्य उदाहरण:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 का अंतर्निहित USB‑JTAG (बाहरी probe की आवश्यकता नहीं):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- अगर "all ones/zeros" IDCODE मिले, तो wiring, power, Vtref और जाँचें कि port fuses/option bytes से locked तो नहीं है।
- अज्ञात chains को शुरू करते समय manual TAP interaction के लिए OpenOCD के low-level `irscan`/`drscan` देखें।<sup>[[1]](#references)</sup>

## CPU को रोकना और memory/flash dump करना

TAP की पहचान हो जाने और target script चुन लिए जाने के बाद, आप core को रोक सकते हैं और memory regions या internal flash dump कर सकते हैं। उदाहरण (target, base addresses और sizes को समायोजित करें):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, OpenOCD helper के ज़रिए प्रोग्राम करें या पढ़ें:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Memory-Dumping Tips

- लंबा dump करने से पहले memory की sanity-check के लिए `mdw/mdh/mdb` का उपयोग करें।
- Multi-device chains के लिए, non-targets पर BYPASS सेट करें या ऐसी board file का उपयोग करें जो सभी TAPs को define करती हो।

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU debug access locked होने पर भी, boundary-scan exposed हो सकता है। UrJTAG/OpenOCD से आप:<sup>[[1]](#references)</sup>
- सिस्टम चलते समय pin states का snapshot लेने के लिए SAMPLE का उपयोग कर सकते हैं (bus activity ढूँढें और pin mapping की पुष्टि करें)।
- Pins drive करने के लिए EXTEST का उपयोग कर सकते हैं (उदाहरण के लिए, अगर board wiring अनुमति देती है तो MCU के ज़रिए external SPI flash lines को bit-bang करके उसे offline पढ़ें)।

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
डिवाइस का BSDL आवश्यक है, ताकि boundary register bit ordering पता चल सके। ध्यान रखें कि कुछ vendors production में boundary-scan cells को lock कर देते हैं।

## Modern targets और notes

- ESP32‑S3/C3 में native USB‑JTAG bridge शामिल है; OpenOCD बिना external probe के सीधे USB के ज़रिए संचार कर सकता है। Triage और dumps के लिए बहुत सुविधाजनक।<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) को OpenOCD में व्यापक समर्थन प्राप्त है; जब core को सुरक्षित रूप से halt नहीं किया जा सकता, तो memory access के लिए SBA को प्राथमिकता दें।
- कई MCUs में debug authentication और lifecycle states लागू होते हैं। अगर power सही होने पर भी JTAG काम न करे, तो हो सकता है कि device को fuse करके closed state में रखा गया हो या authenticated probe की आवश्यकता हो।

## Defenses और hardening (वास्तविक devices पर क्या अपेक्षा करें)

- Production में JTAG/SWD को स्थायी रूप से disable या lock करें (जैसे, STM32 RDP level 2, PAD JTAG को disable करने वाले ESP eFuses, NXP/Nordic APPROTECT/DPAP)।
- Manufacturing access बनाए रखते हुए authenticated debug आवश्यक करें (ARMv8.2‑A ADIv6 Debug Authentication, OEM द्वारा प्रबंधित challenge-response)।
- आसानी से पहुँचने वाले test pads न रखें; test vias को भीतर दबाएँ, TAP को अलग करने के लिए resistors हटाएँ/लगाएँ, और keying वाले connectors या pogo-pin fixtures का उपयोग करें।
- Power-on debug lock: secure boot लागू करने वाले शुरुआती ROM के पीछे TAP को रखें।

## References

- [1] [OpenOCD User’s Guide – JTAG Commands और configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD का उपयोग)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-आधारित JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
