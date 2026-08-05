# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) एक tool है जिसे आप Arduino-compatible MCU या (प्रयोगात्मक रूप से) Raspberry Pi पर load कर सकते हैं, ताकि unknown JTAG pinouts को brute-force किया जा सके और instruction registers को भी enumerate किया जा सके।

- Arduino: digital pins D2–D11 को अधिकतम 10 suspected JTAG pads/testpoints से connect करें, और Arduino GND को target GND से connect करें। जब तक आपको rail के सुरक्षित होने का पता न हो, target को अलग से power दें। 3.3 V logic (जैसे Arduino Due) को प्राथमिकता दें या 1.8–3.3 V targets की probing करते समय level shifter/series resistors का उपयोग करें।
- Raspberry Pi: Pi build में कम usable GPIOs होते हैं (इसलिए scans धीमे होते हैं); current pin map और constraints के लिए repo देखें।

Flash करने के बाद, serial monitor को 115200 baud पर खोलें और help के लिए `h` भेजें। सामान्य flow:

- `l` false positives से बचने के लिए loopbacks खोजें
- `r` आवश्यकता होने पर internal pull-ups को toggle करें
- `s` TCK/TMS/TDI/TDO (और कभी-कभी TRST/SRST) के लिए scan करें
- `y` undocumented opcodes खोजने के लिए IR को brute-force करें
- `x` pin states का boundary-scan snapshot लें

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x pin states का boundary-scan snapshot](<../../images/image (774).png>)



यदि valid TAP मिलता है, तो आपको `FOUND!` से शुरू होने वाली lines दिखाई देंगी, जो discovered pins को indicate करती हैं।

Tips
- हमेशा ground share करें और unknown pins को target Vtref से अधिक voltage पर कभी drive न करें। संदेह होने पर candidate pins पर 100–470 Ω series resistors लगाएं।
- यदि device 4-wire JTAG के बजाय SWD/SWJ का उपयोग करता है, तो JTAGenum उसे detect नहीं कर सकता; SWD tools या SWJ-DP को support करने वाले adapter को आज़माएं।

## अधिक सुरक्षित pin hunting और hardware setup

- पहले multimeter से Vtref और GND identify करें। कई adapters को I/O voltage set करने के लिए Vtref की आवश्यकता होती है।
- Level shifting: push-pull signals के लिए design किए गए bidirectional level shifters को प्राथमिकता दें (JTAG lines open-drain नहीं होतीं)। JTAG के लिए auto-direction I2C shifters का उपयोग न करें।
- Useful adapters: FT2232H/FT232H boards (जैसे Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (ESP32-Sx पर)। कम से कम TCK, TMS, TDI, TDO, GND और Vtref connect करें; TRST और SRST optional हैं।

## OpenOCD से first contact (scan और IDCODE)

OpenOCD JTAG/SWD के लिए de-facto OSS है। Supported adapter के साथ आप chain को scan कर सकते हैं और IDCODEs read कर सकते हैं:

- J-Link के साथ generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 में built-in USB‑JTAG (किसी external probe की आवश्यकता नहीं):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
नोट्स
- यदि आपको "all ones/zeros" IDCODE मिलता है, तो wiring, power, Vtref की जांच करें और सुनिश्चित करें कि port fuses/option bytes द्वारा locked न हो।
- अज्ञात chains को bring up करते समय manual TAP interaction के लिए OpenOCD के low-level `irscan`/`drscan` देखें।<sup>[[1]](#references)</sup>

## CPU को halt करना और memory/flash dump करना

एक बार TAP की पहचान हो जाने और target script चुने जाने के बाद, आप core को halt कर सकते हैं और memory regions या internal flash का dump ले सकते हैं। उदाहरण (target, base addresses और sizes को समायोजित करें):

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
- ESP32‑S3, OpenOCD helper के माध्यम से program या read करें:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
सुझाव
- लंबे dumps से पहले memory को sanity-check करने के लिए `mdw/mdh/mdb` का उपयोग करें।
- multi-device chains के लिए, non-targets पर BYPASS सेट करें या ऐसी board file का उपयोग करें जो सभी TAPs को define करती हो।

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU debug access लॉक होने पर भी boundary-scan exposed हो सकता है। UrJTAG/OpenOCD के साथ आप:
- सिस्टम के चलने के दौरान pin states का snapshot लेने के लिए SAMPLE का उपयोग कर सकते हैं (bus activity खोजें, pin mapping की पुष्टि करें)।
- pins drive करने के लिए EXTEST का उपयोग कर सकते हैं (उदाहरण के लिए, MCU के माध्यम से external SPI flash lines को bit-bang करके offline पढ़ें, यदि board wiring इसकी अनुमति देती हो)।

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
BSDL में boundary register bit ordering जानना आवश्यक है। सावधान रहें कि कुछ vendors production में boundary-scan cells को lock कर देते हैं।

## आधुनिक targets और notes

- ESP32-S3/C3 में native USB-JTAG bridge शामिल होता है; OpenOCD किसी external probe के बिना सीधे USB के माध्यम से communicate कर सकता है। Triage और dumps के लिए बहुत सुविधाजनक।<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) को OpenOCD द्वारा व्यापक रूप से support किया जाता है; जब core को सुरक्षित रूप से halt नहीं किया जा सकता हो, तो memory access के लिए SBA को प्राथमिकता दें।
- कई MCUs debug authentication और lifecycle states लागू करते हैं। यदि power सही होने के बावजूद JTAG काम नहीं करता, तो device को closed state में fuse किया गया हो सकता है या authenticated probe की आवश्यकता हो सकती है।

## Defenses और hardening (वास्तविक devices पर क्या अपेक्षित है)

- Production में JTAG/SWD को permanently disable या lock करें (जैसे, STM32 RDP level 2, JTAG को disable करने वाले ESP eFuses, NXP/Nordic APPROTECT/DPAP)।
- Manufacturing access बनाए रखते हुए authenticated debug आवश्यक करें (ARMv8.2-A ADIv6 Debug Authentication, OEM-managed challenge-response)।
- आसान test pads को route न करें; test vias को bury करें, TAP को isolate करने के लिए resistors को remove/populate करें, और keying वाले connectors या pogo-pin fixtures का उपयोग करें।
- Power-on debug lock: secure boot लागू करने वाले early ROM के पीछे TAP को gate करें।

## References

- [1] [OpenOCD User's Guide - JTAG Commands और configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
