# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** is ’n hulpmiddel wat jy op ’n Arduino-versoenbare MCU of, eksperimenteel, ’n Raspberry Pi kan laai om onbekende JTAG-penuitlegte met brute force te ontdek en instruksieregisters te enumereer.<sup>[[3]](#references)</sup>

- Arduino: koppel digitale penne D2–D11 aan tot 10 vermoedelike JTAG-pads/toetspunte, en Arduino GND aan teiken-GND. Voorsien die teiken afsonderlik van krag, tensy jy weet dat die toevoerspanning veilig is. Verkies 3.3 V-logika (bv. Arduino Due) of gebruik ’n vlakverskuiwer/serieweerstande wanneer jy teikens van 1.8–3.3 V toets.
- Raspberry Pi: Die Pi-bouweergawe bied minder bruikbare GPIO’s (dus is skanderings stadiger); kyk in die repo vir die huidige penkaart en beperkings.

Sodra dit geflits is, maak die seriële monitor teen 115200 baud oop en stuur `h` vir hulp. Tipiese werkvloei:

- `l` vind loopbacks om vals positiewe te vermy
- `r` skakel interne optrekweerstande aan of af indien nodig
- `s` soek na TCK/TMS/TDI/TDO (en soms TRST/SRST)
- `y` gebruik brute force op IR om ongedokumenteerde opkodes te ontdek
- `x` neem ’n boundary-scan-kiekie van penstatusse

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



As ’n geldige TAP gevind word, sal jy reëls sien wat met `FOUND!` begin en die penne aandui wat ontdek is.

### JTAGenum-veiligheidswenke

- Gebruik altyd ’n gemeenskaplike grond, en dryf nooit onbekende penne hoër as die teiken se Vtref nie. Voeg by twyfel 100–470 Ω-serieweerstande by die kandidaatpenne.
- As die toestel SWD/SWJ in plaas van 4-draad-JTAG gebruik, sal JTAGenum dit moontlik nie opspoor nie; probeer SWD-gereedskap of ’n adapter wat SWJ‑DP ondersteun.

## Veiliger penopsporing en hardeware-opstelling

- Identifiseer eers Vtref en GND met ’n multimeter. Baie adapters benodig Vtref om die I/O-spanning in te stel.
- Vlakverskuiwing: verkies tweerigting-vlakverskuiwers wat vir push-pull-seine ontwerp is (JTAG-lyne is nie open-drain nie). Vermy I2C-vlakverskuiwers met outomatiese rigtingbepaling vir JTAG.
- Nuttige adapters: FT2232H/FT232H-borde (bv. Tigard), CMSIS-DAP, J-Link, ST-LINK (verskafferspesifiek), ESP-USB-JTAG (op ESP32-Sx). Koppel ten minste TCK, TMS, TDI, TDO, GND en Vtref; TRST en SRST is opsioneel.

## Eerste kontak met OpenOCD (skandering en IDCODE)

OpenOCD is die de-facto OSS vir JTAG/SWD. Met ’n ondersteunde adapter kan jy die ketting skandeer en IDCODE’s lees:<sup>[[1]](#references)</sup>

- Generiese voorbeeld met ’n J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 ingeboude USB-JTAG (geen eksterne probe nodig nie):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notas

- As jy ’n IDCODE met “all ones/zeros” kry, gaan die bedrading, krag, Vtref en na of die poort nie deur fuses/option bytes gesluit is nie.
- Sien OpenOCD se laevlak-`irscan`/`drscan` vir handmatige TAP-interaksie wanneer jy onbekende kettings opstel.<sup>[[1]](#references)</sup>

## Stop die CPU en dump geheue/flash

Sodra die TAP herken is en ’n teikenskrip gekies is, kan jy die kern stop en geheuestreke of interne flash dump. Voorbeelde (pas die teiken, basisadresse en groottes aan):<sup>[[1]](#references)</sup>

- Generiese teiken ná init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (verkies SBA wanneer beskikbaar):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmeer of lees via OpenOCD-helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Memory-Dumping-wenke

- Gebruik `mdw/mdh/mdb` om geheue te kontroleer voordat jy lang dumps maak.
- Vir kettings met verskeie toestelle, stel BYPASS op nie-teikens in of gebruik ’n board file wat alle TAPs definieer.

## Boundary-scan-truuks (EXTEST/SAMPLE)

Selfs wanneer die CPU-debugtoegang gesluit is, kan boundary-scan steeds blootgestel wees. Met UrJTAG/OpenOCD kan jy:<sup>[[1]](#references)</sup>
- SAMPLE gebruik om penstatusse vas te lê terwyl die stelsel loop (vind busaktiwiteit, bevestig penkartering).
- EXTEST gebruik om penne aan te dryf (bv. bit-bang eksterne SPI-flitslyne via die MCU om dit vanlyn te lees, as die bordbedrading dit toelaat).

Minimale UrJTAG-vloei met ’n FT2232x-adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Jy benodig die toestel se BSDL om die bitvolgorde van die grensregister te ken. Pasop: sommige verskaffers sluit grensskanselselle tydens produksie.

## Moderne teikens en notas

- ESP32‑S3/C3 sluit ’n inheemse USB‑JTAG-brug in; OpenOCD kan direk oor USB kommunikeer sonder ’n eksterne probe. Baie gerieflik vir triage en dumps.<sup>[[2]](#references)</sup>
- RISC‑V-debug (v0.13+) word wyd deur OpenOCD ondersteun; verkies SBA vir geheuetoegang wanneer die kern nie veilig gestop kan word nie.
- Baie MCU’s implementeer debug-verifikasie en lewensiklustoestande. As JTAG dood lyk, maar die kragtoevoer korrek is, is die toestel dalk met ’n sekering na ’n geslote toestand gestel, of vereis dit ’n geverifieerde probe.

## Verdediging en verharding (wat om op regte toestelle te verwag)

- Deaktiveer of sluit JTAG/SWD permanent in produksie (bv. STM32 RDP-vlak 2, ESP eFuses wat PAD JTAG deaktiveer, NXP/Nordic APPROTECT/DPAP).
- Vereis geverifieerde debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-bestuurde uitdaging-en-reaksie), terwyl toegang vir vervaardiging behoue bly.
- Moenie maklike toetspunte aanlê nie; begrawe toetsvias, verwyder/populeer resistors om die TAP te isoleer, en gebruik verbindings met ’n sleutel of pogo-pin-toebehore.
- Debug-sluiting tydens aanskakeling: plaas die TAP agter ’n vroeë ROM wat veilige selflaai afdwing.

## References

- [1] [OpenOCD-gebruikersgids – JTAG-opdragte en konfigurasie](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG-debugging (USB‑JTAG, OpenOCD-gebruik)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-gebaseerde JTAG-penkaartskandeerder](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
