# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** ni tool unayoweza kupakia kwenye MCU inayooana na Arduino au, kwa majaribio, Raspberry Pi, ili kufanya brute-force ya pinout za JTAG zisizojulikana na kuorodhesha instruction registers.<sup>[[3]](#references)</sup>

- Arduino: unganisha pin za kidijitali D2–D11 kwenye hadi pads/testpoints 10 zinazoshukiwa kuwa za JTAG, na Arduino GND kwenye GND ya target. Weka umeme wa target kando isipokuwa una uhakika kuwa rail ni salama. Pendelea logic ya 3.3 V (kwa mfano, Arduino Due) au tumia level shifter/series resistors unapopima targets za 1.8–3.3 V.
- Raspberry Pi: build ya Pi ina GPIO chache zinazoweza kutumika (hivyo scans huwa polepole); angalia repo kwa pin map na constraints za sasa.

Baada ya ku-flash, fungua serial monitor kwa baud 115200 na tuma `h` kwa ajili ya help. Mtiririko wa kawaida:

- `l` tafuta loopbacks ili kuepuka false positives
- `r` badilisha internal pull‑ups ikiwa inahitajika
- `s` scan kwa TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` fanya brute-force ya IR ili kugundua opcodes ambazo hazijaandikwa
- `x` boundary-scan snapshot ya hali za pin

![JTAG - JTAGenum: x boundary‑scan snapshot ya hali za pin](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot ya hali za pin](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot ya hali za pin](<../../images/image (774).png>)



Ikiwa TAP halali itapatikana, utaona mistari inayoanza na `FOUND!` inayoonyesha pin zilizogunduliwa.

### Vidokezo vya Usalama vya JTAGenum

- Daima unganisha ground kwa pamoja, na usiwahi kuendesha pin zisizojulikana juu ya Vtref ya target. Ikiwa huna uhakika, ongeza 100–470 Ω series resistors kwenye pin zinazochaguliwa.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya 4‑wire JTAG, JTAGenum huenda isiigundue; jaribu SWD tools au adapter inayotumia SWJ‑DP.

## Utafutaji salama zaidi wa pin na usanidi wa hardware

- Tambua Vtref na GND kwanza kwa multimeter. Adapters nyingi zinahitaji Vtref ili kuweka voltage ya I/O.
- Level shifting: pendelea level shifters za bidirectional zilizoundwa kwa push‑pull signals (mistari ya JTAG si open‑drain). Epuka auto‑direction I2C shifters kwa JTAG.
- Adapters muhimu: boards za FT2232H/FT232H (kwa mfano, Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (vendor‑specific), ESP‑USB‑JTAG (kwenye ESP32‑Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; kwa hiari TRST na SRST.

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ni OSS inayotumika kwa kawaida kwa JTAG/SWD. Ukiwa na adapter inayotumika, unaweza kuscan chain na kusoma IDCODEs:<sup>[[1]](#references)</sup>

- Mfano wa jumla wa kutumia J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- USB‑JTAG iliyojengewa ndani ya ESP32‑S3 (hakuna probe ya nje inayohitajika):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Maelezo

- Ukipata IDCODE ya "all ones/zeros", kagua wiring, power, Vtref, na uhakikishe kuwa port haijafungwa na fuses/option bytes.
- Tazama `irscan`/`drscan` ya kiwango cha chini ya OpenOCD kwa mwingiliano wa manual wa TAP wakati wa kuanzisha chains zisizojulikana.<sup>[[1]](#references)</sup>

## Kusimamisha CPU na kudump memory/flash

Mara TAP inapotambuliwa na target script kuchaguliwa, unaweza kusimamisha core na kudump memory regions au internal flash. Mifano (rekebisha target, base addresses na sizes):<sup>[[1]](#references)</sup>

- Generic target baada ya init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefer SBA when available):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, program au soma kupitia OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Vidokezo vya Memory-Dumping

- Tumia `mdw/mdh/mdb` kufanya ukaguzi wa msingi wa memory kabla ya dumps ndefu.
- Kwa chains za vifaa vingi, weka BYPASS kwenye vifaa visivyolengwa au tumia board file inayofafanua TAP zote.

## Mbinu za Boundary-scan (EXTEST/SAMPLE)

Hata wakati debug access ya CPU imefungwa, boundary-scan bado inaweza kuwa wazi. Ukiwa na UrJTAG/OpenOCD unaweza:<sup>[[1]](#references)</sup>
- SAMPLE ili kunakili hali za pini wakati system inaendelea kufanya kazi (kutafuta shughuli za bus, kuthibitisha mapping ya pini).
- EXTEST ili kuendesha pini (kwa mfano, ku-bit-bang mistari ya external SPI flash kupitia MCU ili kuisoma offline ikiwa wiring ya board inaruhusu).

Minimal UrJTAG flow yenye adapter ya FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji BSDL ya kifaa ili kujua mpangilio wa biti wa boundary register. Jihadhari kwamba baadhi ya vendors hufunga boundary-scan cells wakati wa uzalishaji.

## Targets za kisasa na maelezo

- ESP32‑S3/C3 zina native USB‑JTAG bridge; OpenOCD inaweza kuwasiliana moja kwa moja kupitia USB bila probe ya nje. Hii ni rahisi sana kwa triage na dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) inaungwa mkono kwa upana na OpenOCD; pendelea SBA kwa ufikiaji wa memory wakati core haiwezi kusimamishwa kwa usalama.
- MCUs nyingi hutumia debug authentication na lifecycle states. Ikiwa JTAG inaonekana kutofanya kazi lakini power iko sahihi, kifaa huenda kimefungwa kwa fuse katika hali iliyofungwa au kinahitaji probe iliyothibitishwa.

## Defenses na hardening (cha kutarajia kwenye vifaa halisi)

- Zima au funga JTAG/SWD kabisa kwenye production (kwa mfano, STM32 RDP level 2, ESP eFuses zinazozima PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-managed challenge-response) huku ukihifadhi manufacturing access.
- Usielekeze test pads zilizo rahisi kufikiwa; ficha test vias, ondoa/ongeza resistors ili kutenga TAP, tumia connectors zenye keying au pogo-pin fixtures.
- Power-on debug lock: weka TAP nyuma ya early ROM inayotekeleza secure boot.

## References

- [1] [Mwongozo wa Mtumiaji wa OpenOCD – Amri na usanidi wa JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Uchunguzi wa JTAG wa Espressif ESP32‑S3 (USB‑JTAG, matumizi ya OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – kichanganuzi cha pinout ya JTAG kinachotumia Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
