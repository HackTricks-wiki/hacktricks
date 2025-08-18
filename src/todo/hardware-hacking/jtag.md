# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) је alat koji možete učitati na Arduino-kompatibilni MCU ili (eksperimentalno) Raspberry Pi da bi brute-forcovao nepoznate JTAG pinove i čak enumerisao registre instrukcija.

- Arduino: povežite digitalne pinove D2–D11 sa do 10 sumnjivih JTAG padova/testnih tačaka, i Arduino GND sa ciljnim GND. Napajajte cilj odvojeno osim ako ne znate da je napajanje sigurno. Preferirajte 3.3 V logiku (npr. Arduino Due) ili koristite level shifter/serijske otpornike kada ispitujete 1.8–3.3 V ciljeve.
- Raspberry Pi: Pi verzija izlaže manje upotrebljivih GPIO-a (tako da su skeniranja sporija); proverite repozitorijum za trenutnu mapu pinova i ograničenja.

Kada se učita, otvorite serijski monitor na 115200 baud i pošaljite `h` za pomoć. Tipičan tok:

- `l` pronađite loopback-ove da izbegnete lažne pozitivne rezultate
- `r` prebacite interne pull-up otpornike ako je potrebno
- `s` skenirajte za TCK/TMS/TDI/TDO (i ponekad TRST/SRST)
- `y` brute-forcujte IR da otkrijete nedokumentovane opkode
- `x` boundary-scan snimak stanja pinova

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



Ako se pronađe validan TAP, videćete linije koje počinju sa `FOUND!` koje označavaju otkrivene pinove.

Saveti
- Uvek delite uzemljenje, i nikada ne napajajte nepoznate pinove iznad ciljnog Vtref. Ako ste u nedoumici, dodajte serijske otpornike od 100–470 Ω na kandidate.
- Ako uređaj koristi SWD/SWJ umesto 4-žičnog JTAG-a, JTAGenum možda neće moći da ga detektuje; pokušajte sa SWD alatima ili adapterom koji podržava SWJ-DP.

## Bezbednije lov na pinove i postavljanje hardvera

- Prvo identifikujte Vtref i GND sa multimetrom. Mnogi adapteri trebaju Vtref da postave I/O napon.
- Level shifting: preferirajte dvosmerne level shiftere dizajnirane za push-pull signale (JTAG linije nisu open-drain). Izbegavajte auto-direkcione I2C shiftere za JTAG.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifični za dobavljača), ESP-USB-JTAG (na ESP32-Sx). Povežite minimalno TCK, TMS, TDI, TDO, GND i Vtref; opcionalno TRST i SRST.

## Prvi kontakt sa OpenOCD (skeniranje i IDCODE)

OpenOCD je de-facto OSS za JTAG/SWD. Sa podržanim adapterom možete skenirati lanac i čitati IDCODE-e:

- Generički primer sa J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 ugrađeni USB‑JTAG (nije potreban spoljašnji prob):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- Ako dobijete "sve jedinice/nule" IDCODE, proverite povezivanje, napajanje, Vtref i da port nije zaključan osiguračima/opcionim bajtovima.
- Pogledajte OpenOCD niskonivo `irscan`/`drscan` za ručnu TAP interakciju prilikom pokretanja nepoznatih lanaca.

## Zaustavljanje CPU-a i dumpovanje memorije/flash-a

Kada je TAP prepoznat i izabran je ciljni skript, možete zaustaviti jezgro i dumpovati memorijske regione ili internu flash. Primeri (prilagodite cilj, osnovne adrese i veličine):

- Generički cilj nakon inicijalizacije:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prefer SBA kada je dostupno):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programirajte ili čitajte putem OpenOCD pomoćnika:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Koristite `mdw/mdh/mdb` za proveru memorije pre dugih dump-ova.
- Za višed uređaje, postavite BYPASS na neciljeve ili koristite datoteku ploče koja definiše sve TAP-ove.

## Trikovi sa granicnim skeniranjem (EXTEST/SAMPLE)

Čak i kada je CPU debug pristup zaključan, granicno skeniranje može biti i dalje dostupno. Sa UrJTAG/OpenOCD možete:
- SAMPLE za snimanje stanja pinova dok sistem radi (pronađite aktivnost na magistrali, potvrdite mapiranje pinova).
- EXTEST za upravljanje pinovima (npr., bit-bang eksternih SPI flash linija putem MCU-a da biste ih pročitali offline ako ožičenje ploče to omogućava).

Minimalni UrJTAG tok sa FT2232x adapterom:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Trebate BSDL uređaja da biste znali redosled bitova granice registra. Budite oprezni, neki proizvođači zaključavaju ćelije granice skeniranja u proizvodnji.

## Moderni ciljevi i napomene

- ESP32‑S3/C3 uključuju nativni USB‑JTAG most; OpenOCD može direktno komunicirati preko USB-a bez spoljnog probira. Veoma zgodno za triage i dump-ove.
- RISC‑V debag (v0.13+) je široko podržan od strane OpenOCD; preferirajte SBA za pristup memoriji kada jezgro ne može biti bezbedno zaustavljeno.
- Mnogi MCU implementiraju autentifikaciju debagovanja i stanja životnog ciklusa. Ako JTAG izgleda mrtvo, ali je napajanje ispravno, uređaj može biti fuzovan u zatvoreno stanje ili zahteva autentifikovani probir.

## Odbrane i učvršćivanje (šta očekivati na pravim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr., STM32 RDP nivo 2, ESP eFuses koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte autentifikovano debagovanje (ARMv8.2‑A ADIv6 Autentifikacija debagovanja, OEM-upravljani izazov-odgovor) dok zadržavate pristup proizvodnji.
- Ne postavljajte lake testne padove; zakopajte testne via, uklonite/popunite otpornike da izolujete TAP, koristite konektore sa ključevima ili pogo-pin fiksacijama.
- Zaključavanje debagovanja pri uključivanju: postavite TAP iza ranog ROM-a koji sprovodi sigurno pokretanje.

## Reference

- OpenOCD Vodič za korisnike – JTAG komande i konfiguracija. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG debagovanje (USB‑JTAG, korišćenje OpenOCD). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
