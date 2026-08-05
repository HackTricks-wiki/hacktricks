# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) je alat koji možete učitati na MCU kompatibilan sa Arduinom ili (eksperimentalno) na Raspberry Pi, kako biste brute-force metodom pronašli nepoznate JTAG pinout-e i čak enumerisali registre instrukcija.

- Arduino: povežite digitalne pinove D2–D11 sa najviše 10 sumnjivih JTAG padova/testpoint-a, a Arduino GND sa GND-om ciljnog uređaja. Napajajte ciljni uređaj zasebno, osim ako znate da je naponska šina bezbedna. Prednost dajte logici od 3,3 V (npr. Arduino Due) ili koristite level shifter/serijske otpornike kada ispitujete ciljne uređaje od 1,8–3,3 V.
- Raspberry Pi: verzija za Pi omogućava korišćenje manjeg broja GPIO pinova (zbog čega su skeniranja sporija); proverite repo za aktuelnu mapu pinova i ograničenja.

Nakon učitavanja firmware-a, otvorite serijski monitor na 115200 baud-a i pošaljite `h` za pomoć. Tipičan tok:

- `l` pronalaženje loopback veza radi izbegavanja lažno pozitivnih rezultata
- `r` uključivanje/isključivanje internih pull-up otpornika po potrebi
- `s` skeniranje za TCK/TMS/TDI/TDO (a ponekad i TRST/SRST)
- `y` brute-force IR-a radi otkrivanja nedokumentovanih opcode-ova
- `x` boundary-scan snimak stanja pinova

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (774).png>)



Ako je pronađen validan TAP, videćete redove koji počinju sa `FOUND!` i označavaju otkrivene pinove.

Saveti
- Uvek povežite masu i nikada nemojte dovoditi napon nepoznatim pinovima iznad ciljnog Vtref-a. Ako niste sigurni, dodajte serijske otpornike od 100–470 Ω na kandidat-pinove.
- Ako uređaj koristi SWD/SWJ umesto 4-žičnog JTAG-a, JTAGenum ga možda neće detektovati; pokušajte sa SWD alatima ili adapterom koji podržava SWJ-DP.

## Bezbednije pronalaženje pinova i hardversko podešavanje

- Prvo identifikujte Vtref i GND multimetrom. Mnogim adapterima je potreban Vtref za podešavanje I/O napona.
- Level shifting: prednost dajte bidirekcionim level shifter-ima projektovanim za push-pull signale (JTAG linije nisu open-drain). Izbegavajte I2C shifter-e sa automatskim smerom za JTAG.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifičan za proizvođača), ESP-USB-JTAG (na ESP32-Sx). Povežite najmanje TCK, TMS, TDI, TDO, GND i Vtref; opciono TRST i SRST.

## Prvi kontakt sa OpenOCD-om (skeniranje i IDCODE)

OpenOCD je de facto OSS za JTAG/SWD. Sa podržanim adapterom možete skenirati lanac i pročitati IDCODE vrednosti:

- Generički primer sa J-Link-om:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32-S3 ugrađeni USB-JTAG (nije potrebna eksterna sonda):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Napomene
- Ako dobijete IDCODE sa „sve jedinice/nule“, proverite ožičenje, napajanje, Vtref i da port nije zaključan fuse-ovima/option bytes.
- Pogledajte OpenOCD low-level `irscan`/`drscan` za ručnu TAP interakciju prilikom pokretanja nepoznatih lanaca.<sup>[[1]](#references)</sup>

## Zaustavljanje CPU-a i dumpovanje memorije/flash-a

Kada je TAP prepoznat i izabrana target skripta, možete zaustaviti jezgro i dumpovati memorijske regione ili interni flash. Primeri (prilagodite target, bazne adrese i veličine):

- Generički target nakon init-a:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (preferirajte SBA kada je dostupan):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programirajte ili čitajte pomoću OpenOCD helper-a:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Saveti
- Koristite `mdw/mdh/mdb` da proverite memoriju pre dugih dumpova.
- Za lance sa više uređaja, postavite BYPASS na uređajima koji nisu ciljni ili koristite board file koji definiše sve TAP-ove.

## Boundary-scan trikovi (EXTEST/SAMPLE)

Čak i kada je CPU debug pristup zaključan, boundary-scan i dalje može biti izložen. Uz UrJTAG/OpenOCD možete:
- SAMPLE da napravite snimak stanja pinova dok sistem radi (pronađite aktivnost magistrale, potvrdite mapiranje pinova).
- EXTEST da upravljate pinovima (npr. bit-bang spoljnim SPI flash linijama preko MCU-a kako biste ga pročitali offline, ako ožičenje ploče to dozvoljava).

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
Potreban vam je BSDL uređaja da biste znali redosled bitova boundary registra. Imajte u vidu da neki proizvođači zaključavaju boundary-scan ćelije u proizvodnji.

## Moderni ciljevi i napomene

- ESP32-S3/C3 imaju nativni USB-JTAG bridge; OpenOCD može direktno da komunicira preko USB-a bez eksternog probe-a. Veoma praktično za triage i dumpove.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) je široko podržan u OpenOCD-u; preferirajte SBA za pristup memoriji kada jezgro ne može bezbedno da se zaustavi.
- Mnogi MCU-ovi implementiraju debug authentication i lifecycle states. Ako JTAG deluje neaktivno, ali je napajanje ispravno, uređaj je možda fuse-ovan u zatvoreno stanje ili zahteva authenticated probe.

## Odbrane i hardening (šta očekivati na stvarnim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr. STM32 RDP level 2, ESP eFuse-ovi koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte authenticated debug (ARMv8.2-A ADIv6 Debug Authentication, challenge-response kojim upravlja OEM), uz zadržavanje pristupa za proizvodnju.
- Nemojte rutirati lako dostupne test padove; sakrijte test vias, uklonite ili postavite otpornike da biste izolovali TAP, koristite konektore sa mehaničkim ključem ili pogo-pin fixtures.
- Power-on debug lock: postavite TAP iza ranog ROM-a koji primenjuje secure boot.

## Reference

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
