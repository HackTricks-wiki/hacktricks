# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** je alat koji možete učitati na MCU kompatibilan sa Arduinom ili, eksperimentalno, na Raspberry Pi, za brute-force nepoznatih JTAG pinout-a i enumeraciju registara instrukcija.<sup>[[3]](#references)</sup>

- Arduino: povežite digitalne pinove D2–D11 sa najviše 10 sumnjivih JTAG padova/testpoint-a, a Arduino GND sa GND ciljnog uređaja. Ciljni uređaj napajajte zasebno, osim ako znate da je naponska grana bezbedna. Prednost dajte logici od 3.3 V (npr. Arduino Due) ili koristite level shifter/serijske otpornike pri sondiranju ciljnih uređaja od 1.8–3.3 V.
- Raspberry Pi: Pi build izlaže manje upotrebljivih GPIO pinova (zato su scan-ovi sporiji); proverite repo za aktuelnu mapu pinova i ograničenja.

Nakon flashovanja, otvorite serijski monitor na 115200 baud-a i pošaljite `h` za pomoć. Tipičan tok:

- `l` pronalazi loopback veze kako bi se izbegli false positive rezultati
- `r` uključuje/isključuje interne pull-up otpornike po potrebi
- `s` skenira TCK/TMS/TDI/TDO (a ponekad TRST/SRST)
- `y` radi brute-force IR-a radi otkrivanja nedokumentovanih opcode-ova
- `x` pravi boundary-scan snimak stanja pinova

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (774).png>)



Ako je pronađen validan TAP, videćete linije koje počinju sa `FOUND!` i koje označavaju otkrivene pinove.

### Bezbednosni saveti za JTAGenum

- Uvek povežite masu i nikada nemojte dovoditi napon na nepoznate pinove iznad Vtref ciljnog uređaja. Ako niste sigurni, dodajte serijske otpornike od 100–470 Ω na kandidate za pinove.
- Ako uređaj koristi SWD/SWJ umesto 4-žilnog JTAG-a, JTAGenum ga možda neće detektovati; pokušajte sa SWD alatima ili adapterom koji podržava SWJ-DP.

## Bezbednije pronalaženje pinova i hardversko podešavanje

- Prvo identifikujte Vtref i GND multimetrom. Mnogim adapterima je potreban Vtref za podešavanje I/O napona.
- Level shifting: prednost dajte bidirekcionim level shifter-ima projektovanim za push-pull signale (JTAG linije nisu open-drain). Izbegavajte I2C shifter-e sa automatskim smerom za JTAG.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifičan za proizvođača), ESP-USB-JTAG (na ESP32-Sx). Povežite najmanje TCK, TMS, TDI, TDO, GND i Vtref; opciono TRST i SRST.

## Prvi kontakt sa OpenOCD-om (scan i IDCODE)

OpenOCD je de facto OSS za JTAG/SWD. Sa podržanim adapterom možete skenirati lanac i očitati IDCODE vrednosti:<sup>[[1]](#references)</sup>

- Generički primer sa J-Link-om:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Ugrađeni USB-JTAG na ESP32-S3 (nije potrebna eksterna sonda):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Napomene

- Ako dobijete IDCODE sa „sve jedinice/nule“, proverite ožičenje, napajanje, Vtref i da port nije zaključan osiguračima/opcionim bajtovima.
- Pogledajte OpenOCD niskonivojski `irscan`/`drscan` za ručnu TAP interakciju pri pokretanju nepoznatih lanaca.<sup>[[1]](#references)</sup>

## Zaustavljanje CPU-a i dump memorije/flash-a

Kada TAP bude prepoznat i izabrana target skripta, možete zaustaviti jezgro i napraviti dump memorijskih regiona ili internog flash-a. Primeri (prilagodite target, početne adrese i veličine):<sup>[[1]](#references)</sup>

- Generički target nakon init-a:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prednost dajte SBA kada je dostupan):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programirajte ili čitajte pomoću OpenOCD helper-a:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Saveti za dump memorije

- Koristi `mdw/mdh/mdb` da proveriš ispravnost memorije pre dugih dumpova.
- Za lance sa više uređaja, postavi BYPASS na uređajima koji nisu ciljni ili koristi board file koji definiše sve TAP-ove.

## Boundary-scan trikovi (EXTEST/SAMPLE)

Čak i kada je CPU debug pristup zaključan, Boundary-scan i dalje može biti izložen. Uz UrJTAG/OpenOCD možeš:<sup>[[1]](#references)</sup>
- SAMPLE za snimanje stanja pinova dok sistem radi (pronalaženje aktivnosti na magistrali, potvrda mapiranja pinova).
- EXTEST za upravljanje pinovima (npr. bit-bang linija spoljnog SPI flash-a preko MCU-a radi offline čitanja, ako ožičenje ploče to omogućava).

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
Potreban vam je BSDL uređaja da biste znali redosled bitova u boundary registru. Imajte na umu da neki proizvođači zaključavaju boundary-scan ćelije u proizvodnji.

## Savremeni ciljevi i napomene

- ESP32-S3/C3 imaju nativni USB-JTAG bridge; OpenOCD može direktno da komunicira preko USB-a bez spoljnog probe-a. Veoma praktično za triage i dump-ove.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) široko je podržan u OpenOCD-u; preferirajte SBA za pristup memoriji kada jezgro ne može bezbedno da se zaustavi.
- Mnogi MCU-ovi implementiraju debug authentication i lifecycle states. Ako JTAG deluje neaktivno, ali je napajanje ispravno, uređaj je možda fuse-ovan u zatvoreno stanje ili zahteva authenticated probe.

## Odbrane i hardening (šta očekivati na stvarnim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr. STM32 RDP level 2, ESP eFuse-ovi koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte authenticated debug (ARMv8.2-A ADIv6 Debug Authentication, OEM-managed challenge-response), uz zadržavanje pristupa za proizvodnju.
- Ne postavljajte lako dostupne test padove; sakrijte test vias, uklonite ili postavite otpornike da biste izolovali TAP, koristite konektore sa mehaničkim ključem ili pogo-pin fixtures.
- Power-on debug lock: postavite TAP iza ranog ROM-a koji sprovodi secure boot.

## References

- [1] [OpenOCD korisničko uputstvo – JTAG komande i konfiguracija](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, upotreba OpenOCD-a)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – JTAG pinout skener zasnovan na Arduinu](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
