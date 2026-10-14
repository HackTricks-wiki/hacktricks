# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** ni zana unayoweza kupakia kwenye MCU inayooana na Arduino au, kwa majaribio, Raspberry Pi ili kufanya brute-force ya pinout zisizojulikana za JTAG na kutambua rejista za maagizo.<sup>[[3]](#references)</sup>

- Arduino: unganisha pini za kidijitali D2–D11 kwenye hadi pedi/testpoint 10 zinazoshukiwa kuwa za JTAG, na Arduino GND kwenye GND ya kifaa lengwa. Weka kifaa lengwa kwenye umeme tofauti isipokuwa unajua kuwa reli yake ni salama. Pendelea mantiki ya 3.3 V (k.m., Arduino Due) au tumia level shifter/vikinzani vya mfululizo unapochunguza vifaa lengwa vya 1.8–3.3 V.
- Raspberry Pi: toleo la Pi lina GPIO chache zinazoweza kutumika (kwa hiyo scans huchukua muda zaidi); angalia repo kwa ramani ya sasa ya pini na vikwazo.

Baada ya kuflash, fungua serial monitor kwa baud 115200 na utume `h` ili kupata msaada. Mtiririko wa kawaida:

- `l` tafuta loopback ili kuepuka matokeo chanya yasiyo sahihi
- `r` washa/zima pull-up za ndani ikihitajika
- `s` scan kutafuta TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` fanya brute-force ya IR ili kugundua opcode zisizoandikwa kwenye nyaraka
- `x` picha ya boundary-scan ya hali za pini

![JTAG - JTAGenum: x picha ya boundary-scan ya hali za pini](<../../images/image (939).png>)

![JTAG - JTAGenum: x picha ya boundary-scan ya hali za pini](<../../images/image (578).png>)

![JTAG - JTAGenum: x picha ya boundary-scan ya hali za pini](<../../images/image (774).png>)



Ikiwa TAP halali itapatikana, utaona mistari inayoanza na `FOUND!` inayoonyesha pini zilizogunduliwa.

### Vidokezo vya Usalama vya JTAGenum

- Unganisha ground kila wakati, na usiwahi kuendesha pini zisizojulikana kwa voltage iliyo juu ya Vtref ya kifaa lengwa. Ikiwa huna uhakika, ongeza vikinzani vya mfululizo vya 100–470 Ω kwenye pini zinazochunguzwa.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya JTAG ya waya 4, huenda JTAGenum isiitambue; jaribu zana za SWD au adapta inayotumia SWJ‑DP.

## Kutafuta pini kwa usalama zaidi na usanidi wa maunzi

- Tambua Vtref na GND kwanza kwa multimeter. Adapta nyingi zinahitaji Vtref ili kuweka voltage ya I/O.
- Level shifting: pendelea level shifter za pande mbili zilizoundwa kwa ishara za push-pull (laini za JTAG si open-drain). Epuka I2C shifters zinazobadilisha mwelekeo kiotomatiki kwa JTAG.
- Adapta zinazofaa: bodi za FT2232H/FT232H (k.m., Tigard), CMSIS-DAP, J-Link, ST-LINK (maalum kwa mtengenezaji), ESP-USB-JTAG (kwenye ESP32-Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; kwa hiari, unganisha TRST na SRST.

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ndiyo OSS inayotumika sana kwa JTAG/SWD. Ukiwa na adapta inayotumika, unaweza kuscan chain na kusoma IDCODE:<sup>[[1]](#references)</sup>

- Mfano wa jumla kwa J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 USB‑JTAG iliyojengewa ndani (hakuna probe ya nje inayohitajika):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Vidokezo

- Ukipata IDCODE yenye “all ones/zeros”, kagua wiring, power, Vtref, na kama port imefungwa kwa fuses/option bytes.
- Tazama `irscan`/`drscan` za kiwango cha chini za OpenOCD kwa mwingiliano wa TAP wa mikono unapowasha chain zisizojulikana.<sup>[[1]](#references)</sup>

## Kusimamisha CPU na kutupa maudhui ya memory/flash

Baada ya TAP kutambuliwa na script ya target kuchaguliwa, unaweza kusimamisha core na kutupa maeneo ya memory au internal flash. Mifano (rekebisha target, base addresses na sizes):<sup>[[1]](#references)</sup>

- Target ya kawaida baada ya init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (pendelea SBA inapopatikana):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programisha au soma kupitia msaidizi wa OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Vidokezo vya Kutupa Maudhui ya Kumbukumbu

- Tumia `mdw/mdh/mdb` kuhakiki kumbukumbu kabla ya kutupa maudhui mengi.
- Kwa minyororo ya vifaa vingi, weka BYPASS kwenye vifaa visivyolengwa au tumia faili ya board inayofafanua TAP zote.

## Mbinu za boundary-scan (EXTEST/SAMPLE)

Hata ufikiaji wa debug wa CPU ukiwa umefungwa, boundary-scan bado inaweza kuwa wazi. Kwa UrJTAG/OpenOCD unaweza:<sup>[[1]](#references)</sup>
- Kutumia SAMPLE kunasa hali za pini wakati mfumo unaendelea kufanya kazi (kutafuta shughuli za basi, kuthibitisha mpangilio wa pini).
- Kutumia EXTEST kuendesha pini (kwa mfano, kutumia bit-bang kusoma mistari ya external SPI flash kupitia MCU ikiwa muunganisho wa board unaruhusu).

Mtiririko wa chini kabisa wa UrJTAG ukitumia adapta ya FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji BSDL ya kifaa ili kujua mpangilio wa biti za boundary register. Tahadhari: baadhi ya wauzaji hufunga boundary-scan cells wakati wa uzalishaji.

## Targets za kisasa na maelezo

- ESP32‑S3/C3 zina bridge ya asili ya USB‑JTAG; OpenOCD inaweza kuwasiliana moja kwa moja kupitia USB bila probe ya nje. Ni rahisi sana kwa uchunguzi wa awali na dumps.<sup>[[2]](#references)</sup>
- Debug ya RISC‑V (v0.13+) inaungwa mkono kwa upana na OpenOCD; pendelea SBA kwa ufikiaji wa memory wakati core haiwezi kusimamishwa kwa usalama.
- MCU nyingi hutumia uthibitishaji wa debug na hali za lifecycle. Ikiwa JTAG haifanyi kazi ingawa umeme uko sawa, huenda kifaa kimewekewa fuse katika hali iliyofungwa au kinahitaji probe iliyothibitishwa.

## Ulinzi na uimarishaji (nini cha kutarajia kwenye vifaa halisi)

- Zima au funga JTAG/SWD kabisa wakati wa uzalishaji (kwa mfano, STM32 RDP level 2, ESP eFuses zinazozima PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji debug iliyothibitishwa (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response inayosimamiwa na OEM) huku ufikiaji wa utengenezaji ukiendelea kuwepo.
- Epuka kupeleka test pads mahali rahisi kufikiwa; ficha test vias, ondoa/wekea resistors ili kutenganisha TAP, na tumia connectors zenye keying au fixtures za pogo-pin.
- Kufunga debug wakati wa kuwasha: weka TAP nyuma ya ROM ya awali inayotekeleza secure boot.

## References

- [1] [Mwongozo wa Mtumiaji wa OpenOCD – Amri na usanidi wa JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, matumizi ya OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Kichanganuzi cha pinout ya JTAG kinachotumia Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
