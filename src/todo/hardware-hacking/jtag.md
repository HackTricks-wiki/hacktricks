# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) je alat koji možete učitati na MCU kompatibilan sa Arduinom ili (eksperimentalno) na Raspberry Pi, kako biste brute-force metodom pronašli nepoznate JTAG rasporede pinova i čak enumerisali registre instrukcija.

- Arduino: povežite digitalne pinove D2–D11 sa najviše 10 sumnjivih JTAG padova/test point-a, a Arduino GND sa GND-om ciljnog uređaja. Napajajte ciljni uređaj zasebno, osim ako znate da je naponska šina bezbedna. Preferirajte logiku od 3,3 V (npr. Arduino Due) ili koristite level shifter/serijske otpornike pri ispitivanju ciljeva od 1,8–3,3 V.
- Raspberry Pi: Pi build izlaže manji broj upotrebljivih GPIO pinova (zbog čega su skeniranja sporija); proverite repo za trenutnu mapu pinova i ograničenja.

Nakon flashovanja, otvorite serijski monitor na 115200 baud i pošaljite `h` za pomoć. Tipičan tok:

- `l` pronalazi loopback veze kako bi se izbegli false positives
- `r` uključuje/isključuje interne pull-up otpornike po potrebi
- `s` skenira TCK/TMS/TDI/TDO (a ponekad i TRST/SRST)
- `y` brute-force metodom ispituje IR kako bi otkrio nedokumentovane opcode-ove
- `x` pravi boundary-scan snimak stanja pinova

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snimak stanja pinova](<../../images/image (774).png>)



Ako je pronađen validan TAP, videćete linije koje počinju sa `FOUND!` i označavaju pronađene pinove.

Saveti
- Uvek povežite GND i nikada ne dovodite na nepoznate pinove napon veći od ciljnog Vtref. Ako niste sigurni, dodajte serijske otpornike od 100–470 Ω na kandidate za pinove.
- Ako uređaj koristi SWD/SWJ umesto 4-žičnog JTAG-a, JTAGenum ga možda neće detektovati; pokušajte sa SWD alatima ili adapterom koji podržava SWJ-DP.

## Bezbednije pronalaženje pinova i hardversko podešavanje

- Prvo identifikujte Vtref i GND pomoću multimetra. Mnogim adapterima je potreban Vtref za podešavanje I/O napona.
- Level shifting: preferirajte bidirekcione level shifter-e projektovane za push-pull signale (JTAG linije nisu open-drain). Izbegavajte I2C shifter-e sa automatskim smerom za JTAG.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifičan za proizvođača), ESP-USB-JTAG (na ESP32-Sx). Povežite najmanje TCK, TMS, TDI, TDO, GND i Vtref; opciono TRST i SRST.

## Prvi kontakt sa OpenOCD-om (skeniranje i IDCODE)

OpenOCD je de facto OSS za JTAG/SWD. Uz podržani adapter možete skenirati lanac i pročitati IDCODE vrednosti:<sup>[[1]](#references)</sup>

- Generički primer sa J-Link-om:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Ugrađeni USB‑JTAG na ESP32‑S3 (nije potrebna eksterna sonda):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Napomene
- Ako dobijete IDCODE sa „sve jedinice/nule“, proverite ožičenje, napajanje, Vtref i da port nije zaključan fuse-ovima/option bytes.
- Pogledajte OpenOCD low-level `irscan`/`drscan` za ručnu TAP interakciju prilikom uspostavljanja rada sa nepoznatim lancima.<sup>[[1]](#references)</sup>

## Zaustavljanje CPU-a i dump memorije/flash-a

Kada TAP bude prepoznat i izaberete target script, možete zaustaviti jezgro i napraviti dump memorijskih oblasti ili internog flash-a. Primeri (prilagodite target, početne adrese i veličine):<sup>[[1]](#references)</sup>

- Generički target nakon init-a:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (prednost dati SBA kada je dostupan):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programirajte ili čitajte putem OpenOCD helper-a:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Saveti
- Koristite `mdw/mdh/mdb` da proverite ispravnost memorije pre dugih dumpova.
- Za lance sa više uređaja, postavite BYPASS na uređajima koji nisu ciljevi ili koristite board file koji definiše sve TAP-ove.

## Trikovi za boundary-scan (EXTEST/SAMPLE)

Čak i kada je CPU debug pristup zaključan, boundary-scan i dalje može biti izložen. Uz UrJTAG/OpenOCD možete:<sup>[[1]](#references)</sup>
- Koristiti SAMPLE za snimanje stanja pinova dok sistem radi (pronalaženje aktivnosti na magistrali, potvrđivanje mapiranja pinova).
- Koristiti EXTEST za upravljanje pinovima (npr. bit-bang linija spoljnog SPI flash-a preko MCU-a kako biste ga čitali offline, ako ožičenje ploče to omogućava).

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
Potrebno je da imate BSDL uređaja da biste znali redosled bitova boundary registra. Imajte na umu da neki proizvođači zaključavaju boundary-scan ćelije u proizvodnji.

## Moderni ciljevi i napomene

- ESP32‑S3/C3 imaju ugrađeni USB‑JTAG bridge; OpenOCD može direktno da komunicira preko USB-a bez spoljne sonde. Veoma praktično za triage i dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) je široko podržan u OpenOCD-u; prednost dajte SBA-u za pristup memoriji kada jezgro ne može bezbedno da se zaustavi.
- Mnogi MCU-ovi implementiraju debug authentication i lifecycle states. Ako JTAG deluje neaktivno, a napajanje je ispravno, uređaj je možda fuse-ovan u zatvoreno stanje ili zahteva authenticated probe.

## Odbrane i hardening (šta očekivati na stvarnim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr. STM32 RDP level 2, ESP eFuses koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-managed challenge-response), uz zadržavanje proizvodnog pristupa.
- Nemojte izvoditi lako dostupne test padove; sakrijte test vias, uklonite/popunite otpornike da biste izolovali TAP i koristite konektore sa mehaničkim kodiranjem ili pogo-pin fixtures.
- Power-on debug lock: postavite TAP iza ranog ROM-a koji sprovodi secure boot.

## Reference

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
