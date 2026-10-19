# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Bezbednije traženje pinova i hardversko podešavanje

- Multimetrom prvo identifikujte Vtref i GND. Mnogi adapteri zahtevaju Vtref za podešavanje I/O napona.
- Promena nivoa: prednost dajte bidirekcionim level shifterima namenjenim za push-pull signale (JTAG linije nisu open-drain). Za JTAG izbegavajte I2C shiftere sa automatskim određivanjem smera.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifičan za proizvođača), ESP-USB-JTAG (na ESP32-Sx). Povežite najmanje TCK, TMS, TDI, TDO, GND i Vtref; po želji i TRST i SRST.

Kod nedokumentovanog konektora, identifikujte GND proverom kontinuiteta do poznate mase **dok cilj nije pod napajanjem**. Nakon što prebacite multimetar u režim merenja napona i uključite napajanje, nemojte svaki pin sa visokim naponom smatrati Vtref: visoki digitalni ulazi na multimetru mogu izgledati slično. Pratite kandidate za naponske vodove do obližnjih kondenzatora za razvezivanje i uporedite njihove talasne oblike pri uključivanju i isključivanju pomoću osciloskopa. Sporiji rast ili pad napona u obliku karakterističnom za kondenzator ukazuje na naponsku/referentnu mrežu, ali proverite napon i ožičenje pre povezivanja sonde sa level shifterom. Na PiFex-u se spoljašnja referenca nižeg napona za cilj može izabrati preko `VCCA_IN` umesto podrazumevane postavke od 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** je alat koji možete učitati na MCU kompatibilan sa Arduinom ili, eksperimentalno, na Raspberry Pi, da biste metodom brute-force otkrili nepoznate JTAG pinout-e i enumerisali registre instrukcija.<sup>[[3]](#references)</sup>

- Arduino: povežite digitalne pinove D2–D11 sa najviše 10 sumnjivih JTAG padova/test tačaka, a GND Arduina sa GND-om cilja. Cilj napajajте odvojeno, osim ako znate da je naponska šina bezbedna. Dajte prednost logici od 3.3 V (npr. Arduino Due) ili koristite level shifter/serijske otpornike pri testiranju ciljeva od 1.8–3.3 V.
- Raspberry Pi: verzija za Pi ima manje upotrebljivih GPIO pinova (zbog čega su skeniranja sporija); proverite repozitorijum za aktuelnu mapu pinova i ograničenja.

Nakon flešovanja otvorite serijski monitor na 115200 baud i pošaljite `h` za pomoć. Uobičajen tok rada:

- `l` pronađite loopback-e da biste izbegli lažno pozitivne rezultate
- `r` po potrebi uključite interne pull-up otpornike
- `s` skenirajte TCK/TMS/TDI/TDO (a ponekad i TRST/SRST)
- `y` metodom brute-force pretražite IR da biste otkrili nedokumentovane opcode-ove
- `x` napravite boundary-scan snimak stanja pinova

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (774).png>)



Ako se pronađe ispravan TAP, videćete redove koji počinju sa `FOUND!` i označavaju otkrivene pinove.

### Bezbednosni saveti za JTAGenum

- Uvek povežite zajedničku masu i nikada ne dovodite na nepoznate pinove napon viši od ciljnog Vtref. Ako niste sigurni, dodajte serijske otpornike od 100–470 Ω na pinove koje testirate.
- Ako uređaj koristi SWD/SWJ umesto 4-žičnog JTAG-a, JTAGenum ga možda neće detektovati; probajte SWD alate ili adapter koji podržava SWJ-DP.

## Otkrivanje GPIO pinova pomoću go-jtagenum

Na uključenom cilju sa proverenom zajedničkom masom i kompatibilnim I/O naponom, `go-jtagenum` može da enumeriše moguće JTAG signale sa GPIO pinova Raspberry Pi-ja. JSON parametra `-pins` mapira oznake na **GPIO brojeve**, a ne na fizičke pozicije na konektoru.<sup>[[5]](#references)</sup> U primeru sa SSD-om, prvo IDCODE skeniranje prijavilo je i neverovatno dugačak niz vrednosti koje su se menjale: promenljiva vrednost na mogućoj TDO liniji sama po sebi nije dokaz ispravnog TAP-a. Ponovo proverite verovatan rezultat BYPASS skeniranjem, koje pomera poznati bitni obrazac sa TDI-ja kroz jednobitni bypass registar do TDO-a.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Za tu ploču, BYPASS je potvrdio `TCK=10`, `TMS=14`, `TDI=9` i `TDO=15`; dodatni pinovi bili su samo **mogući** kandidati za nTRST. Ako kandidat vraća samo nule ili nedosledan obrazac, proverite kontakt, napajanje ciljnog uređaja, pull-up otpornike i kašnjenja takta/resetovanja pre nego što mu dodelite signal.<sup>[[4]](#references)[[5]](#references)</sup> Alat prihvata i `-known-pins` uz `test_bypass` za ponovno testiranje otkrivene mape.<sup>[[5]](#references)</sup>

## Karakterizacija nedokumentovanog TAP-a pomoću UrJTAG-a

Otkriveni raspored pinova ne određuje opcode-ove registra instrukcija (IR) ni širine registra podataka (DR), potrebne za debugging. U verziji UrJTAG-a koja podržava Raspberry Pi GPIO kabl, postavite otkrivenu mapu i pokrenite `idcode`, zatim `detect`, pa `discover`. Primer sa SSD-om vratio je jedan TAP, četvorobitni IR i različite širine DR-a za različite vrednosti IR-a. Dužina DR-a `-1` ili poruka „TDO stuck at 0” ne predstavljaju upotrebljivu definiciju registra; proverite tajming, ožičenje i izabranu instrukciju umesto da dodelite širinu.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Ovo je izviđanje TAP-a, a ne automatska identifikacija CPU-a: uporedite dobijeni IDCODE sa dokumentacijom uređaja i podržanim OpenOCD targetima. Lokalna baza proizvođača u UrJTAG-u može nepoznatim označiti ID koji je inače validan.<sup>[[4]](#references)</sup>

## Prvi kontakt sa OpenOCD-om (skeniranje i IDCODE)

OpenOCD je de facto OSS za JTAG/SWD. Pomoću podržanog adaptera možete skenirati lanac i pročitati IDCODE-ove:<sup>[[1]](#references)</sup>

- Generički primer sa J-Link-om:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Ugrađeni USB-JTAG na ESP32-S3 (nije potrebna spoljna sonda):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Napomene

- Ako dobijete IDCODE sastavljen isključivo od jedinica ili nula, proverite ožičenje, napajanje, Vtref i da li je port zaključan fuse/option byte vrednostima.
- Pogledajte OpenOCD komande niskog nivoa `irscan`/`drscan` za ručnu TAP interakciju pri pokretanju rada sa nepoznatim lancima.<sup>[[1]](#references)</sup>

## Dodavanje nedokumentovanog cilja u OpenOCD

Kada su poznati TAP ID i dužina IR-a, pregledajte OpenOCD skripte u direktorijumima `cpu/`, `target/` i `board/` da biste pronašli **odgovarajuću CPU arhitekturu**, a zatim napravite zasebne konfiguracije adaptera i cilja.<sup>[[4]](#references)[[6]](#references)</sup> Sledeće mapiranje Pi GPIO pinova i ARCv2 cilj predstavljaju testirani primer za SSD, a ne univerzalnu JTAG konfiguraciju. Izbor ARC cilja i postavke za debagovanje bile su pretpostavke koje su se pokazale uspešnim za ovaj uređaj; na drugoj ploči zamenite ih izmerenim ID-om cilja, dužinom IR-a, arhitekturom i GPIO brojevima.<sup>[[4]](#references)</sup>

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

Pokrenite `openocd -f raspberrypi-io.cfg -f target.cfg` i potvrdite da je ispitivanje TAP-a uspešno pre čitanja memorije. Primer je otvorio Telnet na portu `4444` i GDB server na `3333`; samo prepoznati IDCODE ne dokazuje da se izabrani CPU target može ispitati ili otklanjati mu se greške.<sup>[[4]](#references)</sup> GPIO pinovi na Raspberry Pi-ju ne moraju biti pinovi označeni kao JTAG na breakout ploči ako adapter omogućava ponovno mapiranje pomoću `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Zaustavljanje CPU-a i ispis memorije/flash memorije

Kada je TAP prepoznat i izabrana skripta za target, možete zaustaviti jezgro i ispisati oblasti memorije ili internu flash memoriju. Primeri (prilagodite target, bazne adrese i veličine):<sup>[[1]](#references)</sup>

- Generički target nakon inicijalizacije:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (dajte prednost SBA-u kada je dostupan):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programirati ili čitati pomoću OpenOCD pomoćnog alata:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Saveti za dumpovanje memorije

- Koristite `mdw/mdh/mdb` da proverite memoriju pre dugih dumpova.
- Kod lanaca sa više uređaja, postavite BYPASS na uređajima koji nisu cilj ili koristite board file koji definiše sve TAP-ove.

Za nedokumentovanu mapu memorije, tokom istraživanja SSD-a provereno je da li dump veličine 1 MiB sadrži prepoznatljive stringove kontrolera, a zatim je preko OpenOCD-a korišćen GDB sa podrškom za tu arhitekturu za pregled `$pc`, disasembliranog koda i registara. Te aktivne adrese poslužile su za usmeravanje drugog dumpa regiona, koji je zatim upoređen sa odgovarajućim instrukcijama u verziji Ghidre sa podrškom za ARC. Sami stringovi služe samo kao provera verovatnosti, a ne kao dokaz da je slika potpuna ili ispravno mapirana.<sup>[[4]](#references)</sup> Pogledajte [analizu firmware-a](../firmware-analysis/) za šire korake statičke analize.

## Trikovi sa boundary-scan-om (EXTEST/SAMPLE)

Čak i kada je pristup CPU debug-u zaključan, boundary-scan može i dalje biti dostupan. Uz UrJTAG/OpenOCD možete:<sup>[[1]](#references)</sup>
- Koristiti SAMPLE za snimanje stanja pinova dok sistem radi (pronaći aktivnost magistrale, potvrditi mapiranje pinova).
- Koristiti EXTEST za upravljanje pinovima (npr. bit-bang-ovati linije spoljne SPI flash memorije preko MCU-a da biste je čitali van mreže, ako to ožičenje ploče dozvoljava).

Minimalni UrJTAG tok rada sa FT2232x adapterom:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Potreban vam je BSDL uređaja da biste znali redosled bitova u boundary registru. Imajte na umu da neki proizvođači zaključavaju boundary-scan ćelije u proizvodnji.

## Savremeni ciljevi i napomene

- ESP32‑S3/C3 imaju ugrađeni USB‑JTAG bridge; OpenOCD može direktno da komunicira preko USB-a bez spoljne probe. Veoma praktično za trijažu i dumpove.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) široko je podržan u OpenOCD-u; koristite SBA za pristup memoriji kada jezgro ne može bezbedno da se zaustavi.
- Mnogi MCU-ovi koriste autentifikaciju za debug i stanja životnog ciklusa. Ako JTAG ne reaguje, a napajanje je ispravno, uređaj je možda fuse-ovan u zatvoreno stanje ili je potrebna autentifikovana proba.

## Odbrane i ojačavanje zaštite (šta očekivati na stvarnim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr. STM32 RDP nivo 2, ESP eFuses koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte autentifikovani debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response kojim upravlja OEM), uz zadržavanje pristupa za proizvodnju.
- Nemojte postavljati lako dostupne test padove; sakrijte testne vias, uklonite/postavite otpornike da biste izolovali TAP, koristite konektore sa ključem ili pogo-pin fixture-e.
- Zaključavanje debug-a pri uključivanju: blokirajte TAP dok se ne pokrene ROM koji sprovodi secure boot.

## References

- [1] [OpenOCD korisnički vodič – JTAG komande i konfiguracija](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debagovanje (USB‑JTAG, upotreba OpenOCD-a)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – JTAG skener rasporeda pinova zasnovan na Arduinu](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — JTAG hakovanje pomoću Raspberry Pi-ja](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — enumeracija GPIO JTAG-a](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD korisnički vodič — konfiguracija debug adaptera](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
