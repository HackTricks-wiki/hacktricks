# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** je alat koji možete učitati na MCU kompatibilan sa Arduinom ili, eksperimentalno, na Raspberry Pi kako biste brute-force metodom pronašli nepoznat raspored JTAG pinova i enumerisali registre instrukcija.<sup>[[3]](#references)</sup>

- Arduino: povežite digitalne pinove D2–D11 sa najviše 10 pretpostavljenih JTAG padova/testpointova, a Arduino GND sa GND-om ciljnog uređaja. Napajajte ciljni uređaj zasebno, osim ako znate da je naponska linija bezbedna. Prednost dajte logici od 3,3 V (npr. Arduino Due) ili koristite level shifter/serijske otpornike pri ispitivanju uređaja koji rade na 1,8–3,3 V.
- Raspberry Pi: verzija za Pi ima manje dostupnih GPIO pinova (zbog čega skeniranje traje duže); proverite repo za aktuelnu mapu pinova i ograničenja.

Kada ga učitate, otvorite serijski monitor na 115200 baud i pošaljite `h` za pomoć. Uobičajeni postupak:

- `l` pronalazi loopback veze kako bi se izbegli lažno pozitivni rezultati
- `r` uključuje ili isključuje interne pull-up otpornike po potrebi
- `s` skenira TCK/TMS/TDI/TDO (a ponekad i TRST/SRST)
- `y` brute-force metodom pretražuje IR kako bi otkrio nedokumentovane opkode
- `x` pravi boundary-scan snimak stanja pinova

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Ako se pronađe ispravan TAP, videćete redove koji počinju sa `FOUND!` i označavaju pronađene pinove.

### Saveti za bezbednu upotrebu JTAGenum-a

- Uvek povežite uzemljenja i nikada nemojte dovoditi napon na nepoznate pinove koji premašuje Vtref ciljnog uređaja. Ako niste sigurni, dodajte serijske otpornike od 100–470 Ω na pinove koje ispitujete.
- Ako uređaj koristi SWD/SWJ umesto četvorožičnog JTAG-a, JTAGenum ga možda neće detektovati; isprobajte SWD alate ili adapter koji podržava SWJ‑DP.

## Bezbednije pronalaženje pinova i podešavanje hardvera

- Najpre multimetrom utvrdite Vtref i GND. Mnogim adapterima je potreban Vtref za podešavanje I/O napona.
- Level shifting: prednost dajte dvosmernim level shifterima namenjenim push-pull signalima (JTAG linije nisu open-drain). Izbegavajte I2C level shiftere sa automatskim određivanjem smera za JTAG.
- Korisni adapteri: FT2232H/FT232H ploče (npr. Tigard), CMSIS-DAP, J-Link, ST-LINK (specifičan za proizvođača), ESP-USB-JTAG (na ESP32-Sx). Povežite najmanje TCK, TMS, TDI, TDO, GND i Vtref; opciono i TRST i SRST.

## Prvi kontakt sa OpenOCD-om (skeniranje i IDCODE)

OpenOCD je de-facto OSS za JTAG/SWD. Uz podržani adapter možete skenirati lanac i pročitati IDCODE vrednosti:<sup>[[1]](#references)</sup>

- Opšti primer sa J-Link-om:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Ugrađeni USB-JTAG na ESP32-S3 (nije potrebna spoljašnja sonda):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Napomene

- Ako dobijete IDCODE sa „svim jedinicama/nulama“, proverite ožičenje, napajanje, Vtref i da li su port zaključali fuse-ovi/option bytes.
- Pogledajte OpenOCD low-level `irscan`/`drscan` za ručnu interakciju sa TAP-om prilikom pokretanja nepoznatih lanaca.<sup>[[1]](#references)</sup>

## Zaustavljanje CPU-a i dump memorije/flash-a

Kada TAP bude prepoznat i izaberete target script, možete zaustaviti jezgro i napraviti dump memorijskih regiona ili interne flash memorije. Primeri (prilagodite target, bazne adrese i veličine):<sup>[[1]](#references)</sup>

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

- Koristite `mdw/mdh/mdb` za brzu proveru memorije pre dugih dumpova.
- Kod lanaca sa više uređaja, postavite BYPASS na uređajima koji nisu cilj ili koristite board file koji definiše sve TAP-ove.

## Trikovi za boundary-scan (EXTEST/SAMPLE)

Čak i kada je pristup za CPU debugging zaključan, boundary-scan i dalje može biti dostupan. Pomoću UrJTAG/OpenOCD možete:<sup>[[1]](#references)</sup>
- Koristiti SAMPLE za snimanje stanja pinova dok sistem radi (otkrivanje aktivnosti magistrale, potvrda mapiranja pinova).
- Koristiti EXTEST za upravljanje pinovima (npr. bit-bang-om upravljati linijama spoljne SPI flash memorije preko MCU-a kako biste je čitali van mreže, ako to omogućava povezivanje na ploči).

Minimalni UrJTAG postupak sa FT2232x adapterom:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Potreban vam je BSDL uređaja da biste znali redosled bitova u boundary registru. Imajte na umu da neki proizvođači zaključavaju boundary-scan ćelije tokom proizvodnje.

## Savremeni ciljevi i napomene

- ESP32‑S3/C3 imaju ugrađen USB‑JTAG bridge; OpenOCD može direktno da komunicira preko USB-a, bez spoljne probe. Veoma praktično za trijažu i preuzimanje dump-ova.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) široko je podržan u OpenOCD-u; za pristup memoriji prednost dajte SBA-u kada jezgro ne može bezbedno da se zaustavi.
- Mnogi MCU-ovi koriste autentifikaciju za debug i stanja životnog ciklusa. Ako JTAG ne reaguje, a napajanje je ispravno, uređaj je možda konfigurisan u zatvoreno stanje pomoću fuse-ova ili zahteva autentifikovanu probu.

## Odbrane i ojačavanje zaštite (šta očekivati na stvarnim uređajima)

- Trajno onemogućite ili zaključajte JTAG/SWD u proizvodnji (npr. STM32 RDP nivo 2, ESP eFuses koji onemogućavaju PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Zahtevajte autentifikovani debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response kojim upravlja OEM), uz očuvanje pristupa za proizvodnju.
- Nemojte izvoditi lako dostupne testne padove; sakrijte testne vias, uklonite/dodajte otpornike da biste izolovali TAP, koristite konektore sa ključem ili pogo-pin fixture-e.
- Zaključavanje debug-a pri uključivanju: postavite TAP iza ranog ROM-a koji sprovodi secure boot.

## References

- [1] [OpenOCD vodič za korisnike – JTAG komande i konfiguracija](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debug (USB‑JTAG, upotreba OpenOCD-a)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino skener rasporeda JTAG pinova](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
