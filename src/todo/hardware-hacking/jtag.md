# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** एक ऐसा tool है जिसे आप Arduino-compatible MCU या प्रयोगात्मक रूप से Raspberry Pi पर load कर सकते हैं, ताकि अज्ञात JTAG pinouts को brute-force किया जा सके और instruction registers को enumerate किया जा सके।<sup>[[3]](#references)</sup>

- Arduino: digital pins D2–D11 को अधिकतम 10 संदिग्ध JTAG pads/testpoints से connect करें, और Arduino GND को target GND से connect करें। Target को अलग से power दें, जब तक आपको यह सुनिश्चित न हो कि rail सुरक्षित है। 3.3 V logic को प्राथमिकता दें (जैसे Arduino Due), या 1.8–3.3 V targets की probing करते समय level shifter/series resistors का उपयोग करें।
- Raspberry Pi: Pi build में कम usable GPIOs होते हैं (इसलिए scans धीमे होते हैं); वर्तमान pin map और constraints के लिए repo देखें।

Flash करने के बाद, serial monitor को 115200 baud पर खोलें और सहायता के लिए `h` भेजें। सामान्य flow:

- `l` false positives से बचने के लिए loopbacks खोजें
- `r` आवश्यकता होने पर internal pull‑ups को toggle करें
- `s` TCK/TMS/TDI/TDO (और कभी-कभी TRST/SRST) के लिए scan करें
- `y` undocumented opcodes खोजने के लिए IR को brute-force करें
- `x` pin states का boundary-scan snapshot लें

![JTAG - JTAGenum: x pin states का boundary‑scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin states का boundary‑scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin states का boundary‑scan snapshot](<../../images/image (774).png>)



यदि कोई valid TAP मिलता है, तो आपको `FOUND!` से शुरू होने वाली lines दिखाई देंगी, जो discovered pins को दर्शाती हैं।

### JTAGenum Safety Tips

- हमेशा ground साझा करें और unknown pins को target Vtref से अधिक voltage पर कभी drive न करें। संदेह होने पर candidate pins पर 100–470 Ω series resistors लगाएं।
- यदि device 4‑wire JTAG के बजाय SWD/SWJ का उपयोग करता है, तो JTAGenum उसे detect नहीं कर सकता; SWD tools या SWJ‑DP support करने वाले adapter को आज़माएं।

## सुरक्षित pin hunting और hardware setup

- सबसे पहले multimeter से Vtref और GND की पहचान करें। कई adapters को I/O voltage set करने के लिए Vtref की आवश्यकता होती है।
- Level shifting: push‑pull signals के लिए designed bidirectional level shifters को प्राथमिकता दें (JTAG lines open‑drain नहीं होती हैं)। JTAG के लिए auto‑direction I2C shifters का उपयोग न करें।
- उपयोगी adapters: FT2232H/FT232H boards (जैसे Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (vendor‑specific), ESP‑USB‑JTAG (ESP32‑Sx पर)। कम से कम TCK, TMS, TDI, TDO, GND और Vtref connect करें; TRST और SRST वैकल्पिक हैं।

## OpenOCD से पहली contact (scan और IDCODE)

OpenOCD JTAG/SWD के लिए de‑facto OSS है। Supported adapter के साथ आप chain को scan कर सकते हैं और IDCODEs पढ़ सकते हैं:<sup>[[1]](#references)</sup>

- J‑Link के साथ generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 में built-in USB‑JTAG (किसी external probe की आवश्यकता नहीं):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### नोट्स

- यदि आपको "all ones/zeros" IDCODE मिलता है, तो wiring, power, Vtref की जांच करें और सुनिश्चित करें कि port fuses/option bytes द्वारा locked न हो।
- अज्ञात chains को bring up करते समय manual TAP interaction के लिए OpenOCD के low-level `irscan`/`drscan` देखें।<sup>[[1]](#references)</sup>

## CPU को halt करना और memory/flash dump करना

TAP के recognized होने और target script चुने जाने के बाद, आप core को halt करके memory regions या internal flash को dump कर सकते हैं। उदाहरण (target, base addresses और sizes को समायोजित करें):<sup>[[1]](#references)</sup>

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
- ESP32‑S3, OpenOCD helper के माध्यम से program या read करें:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Memory-Dumping के सुझाव

- लंबे dumps से पहले memory की sanity-check करने के लिए `mdw/mdh/mdb` का उपयोग करें।
- Multi-device chains के लिए, non-targets पर BYPASS सेट करें या ऐसी board file का उपयोग करें जो सभी TAPs को define करती हो।

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU debug access locked होने पर भी, boundary-scan exposed हो सकता है। UrJTAG/OpenOCD के साथ आप:<sup>[[1]](#references)</sup>
- SAMPLE का उपयोग system के चलने के दौरान pin states का snapshot लेने के लिए करें (bus activity खोजें, pin mapping की पुष्टि करें)।
- EXTEST का उपयोग pins को drive करने के लिए करें (उदाहरण के लिए, MCU के माध्यम से external SPI flash lines को bit-bang करके offline पढ़ें, यदि board wiring इसकी अनुमति देती हो)।

FT2232x adapter के साथ Minimal UrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
डिवाइस BSDL की आवश्यकता boundary register bit ordering जानने के लिए होती है। सावधान रहें कि कुछ vendors production में boundary-scan cells को lock कर देते हैं।

## Modern targets और notes

- ESP32‑S3/C3 में native USB‑JTAG bridge शामिल होता है; OpenOCD external probe के बिना सीधे USB के माध्यम से communicate कर सकता है। Triage और dumps के लिए बहुत सुविधाजनक।<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) को OpenOCD द्वारा व्यापक रूप से support किया जाता है; जब core को सुरक्षित रूप से halt नहीं किया जा सकता हो, तो memory access के लिए SBA को प्राथमिकता दें।
- कई MCUs debug authentication और lifecycle states लागू करते हैं। यदि power सही होने के बावजूद JTAG काम नहीं करता, तो device closed state में fused हो सकता है या authenticated probe की आवश्यकता हो सकती है।

## Defenses और hardening (real devices पर क्या अपेक्षा करें)

- Production में JTAG/SWD को permanently disable या lock करें (जैसे, STM32 RDP level 2, ESP eFuses जो PAD JTAG को disable करते हैं, NXP/Nordic APPROTECT/DPAP)।
- Manufacturing access बनाए रखते हुए authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM‑managed challenge‑response) आवश्यक करें।
- आसान test pads को route न करें; test vias को bury करें, TAP को isolate करने के लिए resistors को remove/populate करें, और keying या pogo‑pin fixtures वाले connectors का उपयोग करें।
- Power‑on debug lock: secure boot लागू करने वाले early ROM के पीछे TAP को gate करें।

## References

- [1] [OpenOCD User’s Guide – JTAG Commands और configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-based JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
