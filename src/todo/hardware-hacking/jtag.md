# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) ni tool unayoweza kupakia kwenye MCU inayooana na Arduino au (kwa majaribio) Raspberry Pi ili kufanya brute-force ya pinout za JTAG zisizojulikana na hata ku-enumerate instruction registers.

- Arduino: unganisha digital pins D2–D11 kwenye hadi pads/testpoints 10 za JTAG zinazoshukiwa, na Arduino GND kwenye GND ya target. Weka target umeme kando isipokuwa unajua rail ni salama. Pendelea logic ya 3.3 V (kwa mfano, Arduino Due) au tumia level shifter/series resistors unapopima targets za 1.8–3.3 V.
- Raspberry Pi: build ya Pi inaonyesha GPIO chache zinazoweza kutumika (hivyo scans huwa polepole); angalia repo kwa pin map na constraints za sasa.

Baada ya ku-flash, fungua serial monitor kwa baud 115200 na tuma `h` kwa msaada. Mtiririko wa kawaida:

- `l` tafuta loopbacks ili kuepuka false positives
- `r` badilisha internal pull-ups ikiwa inahitajika
- `s` scan kwa TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` fanya brute-force ya IR ili kugundua opcodes ambazo hazijaandikwa
- `x` boundary-scan snapshot ya hali za pins

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Ikiwa TAP halali itapatikana, utaona mistari inayoanza na `FOUND!` ikionyesha pins zilizogunduliwa.

Vidokezo
- Daima unganisha ground pamoja, na usiwahi kuendesha pins zisizojulikana juu ya target Vtref. Ikiwa huna uhakika, ongeza 100–470 Ω series resistors kwenye pins zinazoshukiwa.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya 4-wire JTAG, JTAGenum inaweza kutoigundua; jaribu SWD tools au adapter inayotumia SWJ‑DP.

## Utafutaji salama zaidi wa pins na usanidi wa hardware

- Tambua Vtref na GND kwanza kwa multimeter. Adapters nyingi zinahitaji Vtref ili kuweka I/O voltage.
- Level shifting: pendelea level shifters za mwelekeo-mbili zilizoundwa kwa push-pull signals (mistari ya JTAG si open-drain). Epuka auto-direction I2C shifters kwa JTAG.
- Adapters muhimu: boards za FT2232H/FT232H (kwa mfano, Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (kwenye ESP32-Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; kwa hiari TRST na SRST.

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ni OSS de-facto kwa JTAG/SWD. Ukiwa na adapter inayotumika, unaweza ku-scan chain na kusoma IDCODEs:<sup>[[1]](#references)</sup>

- Mfano wa jumla kwa J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG iliyojengewa ndani (hakuna probe ya nje inayohitajika):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- Ukipata IDCODE ya "all ones/zeros", kagua wiring, power, Vtref, na uhakikishe kuwa port haijafungwa na fuses/option bytes.
- Tazama `irscan`/`drscan` ya kiwango cha chini ya OpenOCD kwa mwingiliano wa manual wa TAP unapowasha chain zisizojulikana.<sup>[[1]](#references)</sup>

## Kusimamisha CPU na kudump memory/flash

Baada ya TAP kutambuliwa na target script kuchaguliwa, unaweza kusimamisha core na kudump maeneo ya memory au internal flash. Mifano (rekebisha target, base addresses na sizes):<sup>[[1]](#references)</sup>

- Target ya jumla baada ya init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (pendelea SBA inapopatikana):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programisha au soma kupitia OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Vidokezo
- Tumia `mdw/mdh/mdb` kufanya ukaguzi wa awali wa memory kabla ya dump ndefu.
- Kwa chains za multi-device, weka BYPASS kwenye targets zisizolengwa au tumia board file inayofafanua TAP zote.

## Mbinu za boundary-scan (EXTEST/SAMPLE)

Hata wakati debug access ya CPU imefungwa, boundary-scan huenda bado imeachwa wazi. Ukiwa na UrJTAG/OpenOCD unaweza:<sup>[[1]](#references)</sup>
- SAMPLE kunakili hali za pin wakati mfumo unaendelea kufanya kazi (kutafuta shughuli za bus, kuthibitisha mapping ya pin).
- EXTEST kuendesha pin (kwa mfano, kutumia MCU kufanya bit-bang kwenye mistari ya external SPI flash ili kuisoma offline ikiwa wiring ya board inaruhusu).

Minimal UrJTAG flow with an FT2232x adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji BSDL ya kifaa ili kujua mpangilio wa bits wa boundary register. Tahadhari kwamba baadhi ya vendors hufunga boundary-scan cells wakati wa production.

## Targets za kisasa na maelezo

- ESP32‑S3/C3 zina native USB‑JTAG bridge; OpenOCD inaweza kuwasiliana moja kwa moja kupitia USB bila external probe. Ni rahisi sana kwa triage na dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) inasaidiwa kwa upana na OpenOCD; pendelea SBA kwa memory access wakati core haiwezi kusimamishwa kwa usalama.
- MCU nyingi hutumia debug authentication na lifecycle states. Ikiwa JTAG inaonekana haifanyi kazi lakini power iko sahihi, kifaa kinaweza kuwa kimefused katika closed state au kinahitaji authenticated probe.

## Defenses na hardening (cha kutarajia kwenye vifaa halisi)

- Disable au lock JTAG/SWD kabisa katika production (kwa mfano, STM32 RDP level 2, ESP eFuses zinazo-disable PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-managed challenge-response) huku ukihifadhi manufacturing access.
- Usipitishie test pads zilizo rahisi kufikiwa; ficha test vias, ondoa/ongeza resistors ili kutenga TAP, tumia connectors zenye keying au pogo-pin fixtures.
- Power-on debug lock: weka TAP nyuma ya early ROM inayotekeleza secure boot.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
