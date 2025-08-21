# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) ni chombo ambacho unaweza kupakia kwenye MCU inayofanana na Arduino au (kitaalamu) Raspberry Pi ili kujaribu pinouts za JTAG zisizojulikana na hata kuhesabu register za maagizo.

- Arduino: ung'anishe pini za kidijitali D2–D11 kwa hadi 10 za JTAG zinazoshukiwa/punkti za mtihani, na GND ya Arduino kwa GND ya lengo. Pata nguvu kwa lengo tofauti isipokuwa unajua reli ni salama. Prefer 3.3 V logic (mfano, Arduino Due) au tumia level shifter/resistors za mfululizo unapochunguza malengo ya 1.8–3.3 V.
- Raspberry Pi: ujenzi wa Pi unatoa GPIO chache zinazoweza kutumika (hivyo skana ni polepole); angalia repo kwa ramani ya pini ya sasa na vikwazo.

Mara tu unapoflash, fungua monitor ya serial kwa 115200 baud na tuma `h` kwa msaada. Mchakato wa kawaida:

- `l` pata loopbacks ili kuepuka positives za uwongo
- `r` geuza pull‑ups za ndani ikiwa inahitajika
- `s` scan kwa TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` brute‑force IR kugundua opcodes zisizorekodiwa
- `x` snapshot ya boundary‑scan ya hali za pini

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Ikiwa TAP halali imepatikana utaona mistari inayaanza na `FOUND!` ikionyesha pini zilizogunduliwa.

Vidokezo
- Daima shiriki ardhi, na usiendeshe pini zisizojulikana juu ya Vtref ya lengo. Ikiwa una shaka, ongeza resistors za mfululizo 100–470 Ω kwenye pini za wagombea.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya JTAG ya nyaya 4, JTAGenum huenda kisikugundue; jaribu zana za SWD au adapter inayounga mkono SWJ‑DP.

## Uwindaji wa pini salama na usanidi wa vifaa

- Tambua Vtref na GND kwanza kwa kutumia multimeter. Adapta nyingi zinahitaji Vtref kuweka voltage ya I/O.
- Level shifting: pendelea level shifters za pande mbili zilizoundwa kwa ishara za push‑pull (michakato ya JTAG si wazi). Epuka level shifters za I2C za auto‑direction kwa JTAG.
- Adapta zinazofaa: bodi za FT2232H/FT232H (mfano, Tigard), CMSIS‑DAP, J‑Link, ST‑LINK (maalum kwa muuzaji), ESP‑USB‑JTAG (juu ya ESP32‑Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; hiari TRST na SRST.

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ni OSS ya de‑facto kwa JTAG/SWD. Kwa adapter inayounga mkono unaweza skana mnyororo na kusoma IDCODEs:

- Mfano wa jumla na J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 iliyojumuishwa USB‑JTAG (hakuna kipimo cha nje kinachohitajika):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- Ikiwa unapata "sifuri/mmoja zote" IDCODE, angalia wiring, nguvu, Vtref, na kwamba bandari haijafungwa na fuses/option bytes.
- Tazama OpenOCD low‑level `irscan`/`drscan` kwa mwingiliano wa manual wa TAP unapofungua minyororo isiyojulikana.

## Kusimamisha CPU na kutupa kumbukumbu/flash

Mara tu TAP inapokubaliwa na script ya lengo imechaguliwa, unaweza kusimamisha core na kutupa maeneo ya kumbukumbu au flash ya ndani. Mifano (badilisha lengo, anwani za msingi na saizi): 

- Lengo la jumla baada ya kuanzisha:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (pendelea SBA inapopatikana):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programu au soma kupitia msaada wa OpenOCD:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Tumia `mdw/mdh/mdb` kuthibitisha kumbukumbu kabla ya dumps ndefu.
- Kwa minyororo ya vifaa vingi, weka BYPASS kwenye visivyo lengo au tumia faili ya bodi inayofafanua TAP zote.

## Hila za boundary-scan (EXTEST/SAMPLE)

Hata wakati ufikiaji wa debug wa CPU umefungwa, boundary-scan bado inaweza kuwa wazi. Kwa UrJTAG/OpenOCD unaweza:
- SAMPLE kuchukua picha za hali za pini wakati mfumo unafanya kazi (pata shughuli za basi, thibitisha ramani za pini).
- EXTEST kuendesha pini (kwa mfano, bit-bang mistari ya SPI flash ya nje kupitia MCU ili kuisoma bila mtandao ikiwa wiring ya bodi inaruhusu).

Mchakato wa chini wa UrJTAG na adapter ya FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji kifaa BSDL ili kujua mpangilio wa bit za register za mipaka. Kuwa makini kwamba wauzaji wengine wanaweza kufunga seli za skana za mipaka katika uzalishaji.

## Malengo ya kisasa na maelezo

- ESP32‑S3/C3 inajumuisha daraja la USB‑JTAG asilia; OpenOCD inaweza kuzungumza moja kwa moja kupitia USB bila kipimo cha nje. Ni rahisi sana kwa uchambuzi na dump.
- RISC‑V debug (v0.13+) inasaidiwa sana na OpenOCD; pendelea SBA kwa ufikiaji wa kumbukumbu wakati kiini hakiwezi kusimamishwa kwa usalama.
- MCU nyingi zinafanya uthibitisho wa debug na hali za mzunguko wa maisha. Ikiwa JTAG inaonekana kufa lakini nguvu ni sahihi, kifaa kinaweza kuwa kimeunganishwa katika hali iliyofungwa au kinahitaji kipimo kilichothibitishwa.

## Ulinzi na kuimarisha (kila unachoweza kutarajia kwenye vifaa halisi)

- Zima kabisa au fungia JTAG/SWD katika uzalishaji (mfano, STM32 RDP kiwango 2, ESP eFuses zinazozuia PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji uthibitisho wa debug (ARMv8.2‑A ADIv6 Debug Authentication, changamoto-ujibu inayosimamiwa na OEM) huku ukihifadhi ufikiaji wa uzalishaji.
- Usipange pad za majaribio rahisi; ficha vias za majaribio, ondoa/jaza upinzani ili kutenga TAP, tumia viunganishi vyenye ufunguo au vifaa vya pogo‑pin.
- Kufunga lock ya debug wakati wa kuwasha: funga TAP nyuma ya ROM ya mapema inayolazimisha boot salama.

## Marejeleo

- OpenOCD User’s Guide – JTAG Commands and configuration. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
