# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Kutafuta pini kwa usalama zaidi na usanidi wa hardware

- Tambua Vtref na GND kwanza kwa kutumia multimeter. Adapta nyingi zinahitaji Vtref ili kuweka voltage ya I/O.
- Level shifting: pendelea level shifters za pande mbili zilizoundwa kwa ishara za push-pull (mistari ya JTAG si open-drain). Epuka I2C shifters za auto-direction kwa JTAG.
- Adapta zinazofaa: bodi za FT2232H/FT232H (k.m., Tigard), CMSIS-DAP, J-Link, ST-LINK (maalum kwa vendor), ESP-USB-JTAG (kwenye ESP32-Sx). Unganisha angalau TCK, TMS, TDI, TDO, GND na Vtref; kwa hiari, TRST na SRST.

Kwa header isiyo na nyaraka, tambua GND kwa kupima continuity hadi kwenye ground plane inayojulikana **wakati target haina umeme**. Baada ya kubadili hadi hali ya kupima voltage na kuiwasha, usiainishe kila pini yenye voltage ya juu kuwa Vtref: ingizo za kidijitali zenye voltage ya juu zinaweza kuonekana sawa kwenye multimeter. Fuata njia za rails zinazoshukiwa hadi kwenye decoupling capacitors zilizo karibu na ulinganishe mawimbi yake wakati wa kuwasha na kuzima kwa kutumia oscilloscope. Kupanda au kushuka kwa taratibu kama kwa capacitor ni dalili ya net ya supply/reference, lakini hakikisha voltage na wiring kabla ya kuunganisha probe yenye level shifting. Kwenye PiFex, reference ya nje ya voltage ya chini ya target inaweza kuchaguliwa kupitia `VCCA_IN` badala ya mpangilio wake wa kawaida wa 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** ni zana unayoweza kupakia kwenye MCU inayooana na Arduino au, kwa majaribio, Raspberry Pi ili kujaribu mchanganyiko wote wa pinout za JTAG zisizojulikana na kuorodhesha instruction registers.<sup>[[3]](#references)</sup>

- Arduino: unganisha pini za kidijitali D2–D11 hadi kwenye pedi/testpoint zisizozidi 10 zinazoshukiwa kuwa za JTAG, na Arduino GND kwenye target GND. Weka target kwenye umeme tofauti isipokuwa kama unajua rail hiyo ni salama. Pendelea logic ya 3.3 V (k.m., Arduino Due) au tumia level shifter/series resistors unapochunguza targets za 1.8–3.3 V.
- Raspberry Pi: build ya Pi ina GPIO chache zaidi zinazoweza kutumika (hivyo scans huchukua muda zaidi); angalia repo ili kupata pin map na vikwazo vya sasa.

Baada ya ku-flash, fungua serial monitor kwa baud 115200 na utume `h` ili kupata usaidizi. Mtiririko wa kawaida:

- `l` tafuta loopbacks ili kuepuka matokeo chanya ya uongo
- `r` badili internal pull-ups ikihitajika
- `s` changanua ili kupata TCK/TMS/TDI/TDO (na wakati mwingine TRST/SRST)
- `y` jaribu mchanganyiko wote wa IR ili kugundua opcodes zisizo na nyaraka
- `x` picha ya boundary-scan ya hali za pini

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Ikiwa TAP halali itapatikana, utaona mistari inayoanza na `FOUND!` inayoonyesha pini zilizogunduliwa.

### Vidokezo vya Usalama vya JTAGenum

- Unganisha ground kila mara, na usiwahi kuendesha pini zisizojulikana kwa voltage iliyo juu ya Vtref ya target. Ikiwa huna uhakika, ongeza series resistors za 100–470 Ω kwenye pini zinazoshukiwa.
- Ikiwa kifaa kinatumia SWD/SWJ badala ya JTAG ya waya 4, huenda JTAGenum isiigundue; jaribu zana za SWD au adapta inayotumia SWJ-DP.

## Kugundua pini za GPIO kwa kutumia go-jtagenum

Kwenye target iliyo na umeme, ikiwa ground ya pamoja imethibitishwa na voltage ya I/O inaoana, `go-jtagenum` inaweza kuorodhesha ishara zinazoweza kuwa za JTAG kupitia GPIO za Raspberry Pi. JSON ya `-pins` huunganisha lebo na **nambari za GPIO**, si nafasi za pini kwenye header halisi.<sup>[[5]](#references)</sup> Katika mfano wa SSD, uchanganuzi wa kwanza wa IDCODE pia uliripoti mfuatano mrefu usiowezekana wa thamani zinazobadilika: mstari wa TDO unaobadilika peke yake si uthibitisho wa TAP halali. Hakiki tena matokeo yanayoonekana kuwa yanawezekana kwa uchanganuzi wa BYPASS, ambao huhamisha mpangilio wa biti unaojulikana kutoka TDI kupitia bypass register ya biti moja hadi TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Kwa ubao huo, BYPASS ilithibitisha `TCK=10`, `TMS=14`, `TDI=9`, na `TDO=15`; pini za ziada zilikuwa tu wagombea **wanaowezekana** wa nTRST. Ikiwa mgombea anarudisha sifuri zote au muundo usiolingana, kagua mgusano, umeme wa target, pull-ups, na ucheleweshaji wa clock/reset kabla ya kumpa ishara.<sup>[[4]](#references)[[5]](#references)</sup> Zana hiyo pia inakubali `-known-pins` pamoja na `test_bypass` ili kujaribu tena ramani iliyopatikana.<sup>[[5]](#references)</sup>

## Bainisha TAP isiyo na nyaraka kwa UrJTAG

Pinout iliyogunduliwa haibainishi opcodes za instruction-register (IR) au upana wa data-register (DR) unaohitajika kwa debugging. Kwa build ya UrJTAG inayotumia Raspberry Pi GPIO cable, weka ramani iliyopatikana kisha endesha `idcode`, `detect`, halafu `discover`. Mfano wa SSD ulirudisha TAP moja, IR ya biti nne, na upana tofauti wa DR kwa thamani tofauti za IR. Urefu wa DR wa `-1` au ujumbe “TDO imekwama kwenye 0” si ufafanuzi wa register unaoweza kutumika; kagua timing, wiring, na instruction iliyochaguliwa badala ya kumpangia upana.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

This ni TAP reconnaissance, si utambuzi wa CPU kiotomatiki: linganisha IDCODE inayopatikana na nyaraka za kifaa pamoja na targets zinazoungwa mkono na OpenOCD. Database ya ndani ya watengenezaji ya UrJTAG inaweza kuonyesha ID halali kama isiyojulikana.<sup>[[4]](#references)</sup>

## Mawasiliano ya kwanza na OpenOCD (scan na IDCODE)

OpenOCD ndiyo OSS inayotumika kwa kiwango cha de-facto kwa JTAG/SWD. Ukiwa na adapter inayoungwa mkono, unaweza kuchanganua chain na kusoma IDCODE:<sup>[[1]](#references)</sup>

- Mfano wa jumla kwa J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- USB-JTAG iliyojengewa ndani ya ESP32-S3 (hakuna probe ya nje inayohitajika):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Maelezo

- Ukipata IDCODE yenye "all ones/zeros", kagua wiring, power, Vtref, na uhakikishe kuwa port haijafungwa na fuses/option bytes.
- Tazama `irscan`/`drscan` za kiwango cha chini za OpenOCD kwa mwingiliano wa moja kwa moja na TAP unapowasha chain zisizojulikana.<sup>[[1]](#references)</sup>

## Ongeza target isiyo na nyaraka kwenye OpenOCD

Baada ya kujua TAP ID na urefu wa IR, kagua script za OpenOCD za `cpu/`, `target/`, na `board/` ili kupata **usanifu wa CPU unaolingana**, kisha unda usanidi tofauti wa adapter na target.<sup>[[4]](#references)[[6]](#references)</sup> Ramani ifuatayo ya Pi GPIO na target ya ARCv2 ni mfano wa SSD uliofanyiwa majaribio, si usanidi wa jumla wa JTAG. Chaguo la target ya ARC na mipangilio ya debug vilikuwa dhana zilizofaulu kwa kifaa hiki; tumia ID, urefu wa IR, usanifu, na nambari za GPIO zilizopimwa za target husika unapotumia board nyingine.<sup>[[4]](#references)</sup>

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

Endesha `openocd -f raspberrypi-io.cfg -f target.cfg` na uthibitishe kuwa uchunguzi wa TAP umefaulu kabla ya kusoma memory. Mfano ulifungua Telnet kwenye porti `4444` na seva ya GDB kwenye `3333`; IDCODE inayotambuliwa pekee haithibitishi kuwa CPU target iliyochaguliwa inaweza kuchunguzwa au kudebugiwa.<sup>[[4]](#references)</sup> GPIO za Raspberry Pi si lazima ziwe pini zilizoandikwa JTAG kwenye breakout board ikiwa adapter inaruhusu uelekezaji upya wa `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Kusimamisha CPU na kutupa memory/flash

TAP ikishatambuliwa na script ya target kuchaguliwa, unaweza kusimamisha core na kutupa maeneo ya memory au flash ya ndani. Mifano (rekebisha target, anwani za msingi na ukubwa):<sup>[[1]](#references)</sup>

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

### Vidokezo vya Memory-Dumping

- Tumia `mdw/mdh/mdb` kuhakiki kwa haraka memory kabla ya kufanya dumps ndefu.
- Kwa minyororo ya vifaa vingi, weka BYPASS kwenye vifaa visivyolengwa au tumia faili ya board inayofafanua TAP zote.

Kwa memory map isiyoandikwa kwenye nyaraka, utafiti wa SSD ulikagua dump ya 1 MiB kutafuta maandishi ya controller yanayotambulika, kisha ukatumia GDB yenye uwezo wa architecture kupitia OpenOCD kukagua `$pc`, disassembly na registers. Anwani hizo za wakati huo zilielekeza dump ya eneo la pili, ambayo ilikaguliwa dhidi ya instructions zinazolingana katika build ya Ghidra yenye uwezo wa ARC. Maandishi pekee ni ukaguzi wa uwezekano tu, si uthibitisho kwamba image imekamilika au imechorwa kwenye memory kwa usahihi.<sup>[[4]](#references)</sup> Tazama [firmware analysis](../firmware-analysis/) kwa hatua pana zaidi za static analysis.

## Mbinu za Boundary-scan (EXTEST/SAMPLE)

Hata CPU debug access ikiwa imefungwa, boundary-scan huenda bado ikawa wazi. Kwa UrJTAG/OpenOCD unaweza:<sup>[[1]](#references)</sup>
- SAMPLE ili kunasa hali za pini mfumo ukiendelea kufanya kazi (tafuta shughuli za bus, thibitisha mpangilio wa pini).
- EXTEST ili kuendesha pini (kwa mfano, kutumia bit-bang kuendesha mistari ya SPI flash ya nje kupitia MCU na kuisoma offline ikiwa wiring ya board inaruhusu).

Mtiririko mdogo wa UrJTAG wenye adapter ya FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Unahitaji BSDL ya kifaa ili kujua mpangilio wa biti za rejista ya boundary. Tahadhari: baadhi ya wauzaji hufunga seli za boundary-scan wakati wa uzalishaji.

## Malengo ya kisasa na maelezo

- ESP32‑S3/C3 zina bridge asilia ya USB‑JTAG; OpenOCD inaweza kuwasiliana moja kwa moja kupitia USB bila probe ya nje. Ni rahisi sana kwa triage na dumps.<sup>[[2]](#references)</sup>
- Utatuzi wa hitilafu wa RISC‑V (v0.13+) unaungwa mkono sana na OpenOCD; pendelea SBA kwa ufikiaji wa kumbukumbu wakati core haiwezi kusimamishwa kwa usalama.
- MCU nyingi hutekeleza uthibitishaji wa debug na hali za lifecycle. Ikiwa JTAG haifanyi kazi lakini umeme uko sawa, huenda kifaa kimewekewa fuse ili kiwe katika hali iliyofungwa au kinahitaji probe iliyothibitishwa.

## Ulinzi na uimarishaji (mambo ya kutarajia kwenye vifaa halisi)

- Zima au funga JTAG/SWD kabisa wakati wa uzalishaji (kwa mfano, STM32 RDP level 2, eFuses za ESP zinazozima PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Hitaji debug iliyothibitishwa (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response inayodhibitiwa na OEM) huku ukihifadhi ufikiaji wa utengenezaji.
- Epuka kuweka test pads mahali panapofikika kwa urahisi; ficha test vias, ondoa/wekea resistors ili kutenganisha TAP, na tumia connectors zenye keying au fixtures za pogo-pin.
- Kufunga debug wakati wa kuwasha: zuia TAP isipatikane hadi ROM ya awali itekeleze secure boot.

## References

- [1] [Mwongozo wa Mtumiaji wa OpenOCD – Amri za JTAG na usanidi](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3: Utatuzi wa hitilafu wa JTAG (USB‑JTAG, matumizi ya OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Kichanganuzi cha pinout ya JTAG kinachotumia Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — JTAG Hacking kwa kutumia Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — Uhesabuji wa GPIO JTAG](https://github.com/gremwell/go-jtagenum)
- [6] [Mwongozo wa Mtumiaji wa OpenOCD — Usanidi wa Debug Adapter](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
