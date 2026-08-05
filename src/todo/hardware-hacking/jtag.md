# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) ni tool unayoweza kupakia kwenye MCU inayooana na Arduino au (kwa majaribio) Raspberry Pi ili kufanya brute-force ya mpangilio wa pini za JTAG usiojulikana na hata kuorodhesha instruction registers.

- Arduino: unganisha digital pins D2–D11 kwenye hadi pads/testpoints 10 za JTAG zinazoshukiwa, na Arduino GND kwenye GND ya target. Wasilia target kwa chanzo tofauti isipokuwa kama unajua rail ni salama. Pendelea logic ya 3.3 V (kwa mfano, Arduino Due) au tumia level shifter/series resistors unapochunguza targets za 1.8–3.3 V.
- Raspberry Pi: build ya Pi ina GPIO chache zinazoweza kutumika (hivyo scans huwa polepole); angalia repo kwa pin map na constraints za sasa.

Baada ya ku-flash, fungua serial monitor kwa 115200 baud na utume `h` kwa msaada. Mtiririko wa kawaida:

- `l` tafuta loopbacks ili kuepuka false positives
- `r` badilisha internal pull-ups ikiwa inahitajika
- `s` scan kwa TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` fanya brute-force ya IR ili kugundua opcodes zisizo na documentation
- `x` chukua boundary-scan snapshot ya hali za pini

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Ikiwa TAP halali itapatikana, utaona mistari inayoanza na `FOUND!` ikionyesha pini zilizogunduliwa.

Vidokezo
- Daima unganisha ground, na usiwahi kuendesha pini zisizojulikana juu ya target Vtref. Ikiwa huna uhakika, ongeza 100–470 Ω series resistors kwenye pini zinazowezekana.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya 4-wire JTAG, JTAGenum huenda isiigundue; jaribu SWD tools au adapter inayotumia SWJ-DP.

## Utafutaji salama zaidi wa pini na usanidi wa hardware

- Tambua Vtref na GND kwanza kwa kutumia multimeter. Adapters nyingi zinahitaji Vtref ili kuweka voltage ya I/O.
- Level shifting: pendelea level shifters za pande mbili zilizoundwa kwa push-pull signals (JTAG lines si open-drain). Epuka auto-direction I2C shifters kwa JTAG.
- Adapters muhimu: FT2232H/FT232H boards (kwa mfano, Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (kwenye ESP32-Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; kwa hiari TRST na SRST.

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ni OSS ya de-facto kwa JTAG/SWD. Ukiwa na adapter inayotumika, unaweza ku-scan chain na kusoma IDCODEs:

- Mfano wa jumla ukitumia J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB-JTAG iliyojengewa ndani ya ESP32-S3 (hakuna external probe inayohitajika):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Maelezo
- Ukipata IDCODE ya "all ones/zeros", kagua wiring, power, Vtref, na uhakikishe kuwa port haijafungwa na fuses/option bytes.
- Tazama OpenOCD low-level `irscan`/`drscan` kwa mwingiliano wa mikono na TAP wakati wa kuanzisha chains zisizojulikana.<sup>[[1]](#references)</sup>

## Kusimamisha CPU na kudump memory/flash

Baada ya TAP kutambuliwa na target script kuchaguliwa, unaweza kusimamisha core na kudump memory regions au internal flash. Mifano (rekebisha target, base addresses na sizes):

- Generic target baada ya init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (pendelea SBA inapopatikana):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programisha au soma kupitia OpenOCD helper:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Vidokezo
- Tumia `mdw/mdh/mdb` kufanya sanity-check ya memory kabla ya dumps ndefu.
- Kwa chains zenye devices nyingi, weka BYPASS kwenye targets zisizohusika au tumia board file inayofafanua TAP zote.

## Mbinu za boundary-scan (EXTEST/SAMPLE)

Hata wakati CPU debug access imefungwa, boundary-scan bado inaweza kuwa exposed. Ukiwa na UrJTAG/OpenOCD unaweza:
- SAMPLE kufanya snapshot ya hali za pins wakati system inaendelea kufanya kazi (kutafuta bus activity, kuthibitisha pin mapping).
- EXTEST kuendesha pins (kwa mfano, kufanya bit-bang ya mistari ya external SPI flash kupitia MCU ili kuisoma offline ikiwa board wiring inaruhusu).

Minimal UrJTAG flow yenye FT2232x adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji BSDL ya kifaa ili kujua mpangilio wa bits za boundary register. Tahadhari: baadhi ya vendors hufunga boundary-scan cells wakati wa uzalishaji.

## Targets za kisasa na maelezo

- ESP32-S3/C3 zina native USB-JTAG bridge; OpenOCD inaweza kuwasiliana moja kwa moja kupitia USB bila probe ya nje. Ni rahisi sana kwa triage na dumps.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) inaungwa mkono kwa upana na OpenOCD; pendelea SBA kwa ufikiaji wa memory wakati core haiwezi kusimamishwa kwa usalama.
- MCUs nyingi hutekeleza debug authentication na hali za lifecycle. Ikiwa JTAG inaonekana kutofanya kazi lakini power iko sahihi, kifaa kinaweza kuwa kimefungwa kwenye closed state au kinahitaji probe iliyothibitishwa.

## Defenses na hardening (cha kutarajia kwenye vifaa halisi)

- Zima au funga JTAG/SWD kabisa wakati wa production (kwa mfano, STM32 RDP level 2, ESP eFuses zinazozima PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji authenticated debug (ARMv8.2-A ADIv6 Debug Authentication, challenge-response inayodhibitiwa na OEM) huku ukiendelea kuhifadhi manufacturing access.
- Usipitishie test pads zilizo rahisi kufikiwa; ficha test vias, ondoa/ongeza resistors ili kutenga TAP, na tumia connectors zenye keying au pogo-pin fixtures.
- Power-on debug lock: weka TAP nyuma ya early ROM inayotekeleza secure boot.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
