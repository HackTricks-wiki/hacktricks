# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) is 'n hulpmiddel wat jy op 'n Arduino-ondersteunde MCU of (eksperimenteel) 'n Raspberry Pi kan laai om onbekende JTAG pinouts te brute-force en selfs instruksie registre te tel.

- Arduino: koppel digitale pinne D2–D11 aan tot 10 vermoedelik JTAG pads/toetspunte, en Arduino GND aan teiken GND. Voed die teiken apart, tensy jy weet die rail is veilig. Verkies 3.3 V logika (bv. Arduino Due) of gebruik 'n vlakverskuiwer/reeks weerstande wanneer jy 1.8–3.3 V teikens toets.
- Raspberry Pi: die Pi-bou stel minder bruikbare GPIO's bloot (so skande is stadiger); kyk na die repo vir die huidige pinkaart en beperkings.

Sodra dit geflits is, open die seriële monitor by 115200 baud en stuur `h` vir hulp. Tipiese vloei:

- `l` vind loopbacks om vals positiewe te vermy
- `r` skakel interne pull-ups aan indien nodig
- `s` skandeer vir TCK/TMS/TDI/TDO (en soms TRST/SRST)
- `y` brute-force IR om ongedokumenteerde opcodes te ontdek
- `x` grens-scan snapshot van pin state

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)



As 'n geldige TAP gevind word, sal jy lyne sien wat begin met `FOUND!` wat ontdekte pinne aandui.

Tips
- Deel altyd grond, en moenie onbekende pinne bo teiken Vtref dryf nie. As jy twyfel, voeg 100–470 Ω reeks weerstande by kandidaat pinne.
- As die toestel SWD/SWJ in plaas van 4-draad JTAG gebruik, mag JTAGenum dit nie opspoor nie; probeer SWD-hulpmiddels of 'n adapter wat SWJ-DP ondersteun.

## Veiliger pin jag en hardeware opstelling

- Identifiseer Vtref en GND eers met 'n multimeter. Baie adapters benodig Vtref om I/O spanning in te stel.
- Vlakverskuiwing: verkies bidireksionele vlakverskuiwers wat ontwerp is vir push-pull seine (JTAG lyne is nie oop-drain nie). Vermy outo-rigting I2C verskuiwers vir JTAG.
- Nuttige adapters: FT2232H/FT232H borde (bv. Tigard), CMSIS-DAP, J-Link, ST-LINK (verkoper-spesifiek), ESP-USB-JTAG (op ESP32-Sx). Koppel ten minste TCK, TMS, TDI, TDO, GND en Vtref; opsioneel TRST en SRST.

## Eerste kontak met OpenOCD (skande en IDCODE)

OpenOCD is die de-facto OSS vir JTAG/SWD. Met 'n ondersteunde adapter kan jy die ketting skandeer en IDCODE's lees:

- Generiese voorbeeld met 'n J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 ingeboude USB‑JTAG (geen eksterne sonde benodig):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- As jy "alle eenhede/nulle" IDCODE kry, kyk na bedrading, krag, Vtref, en dat die poort nie deur sekeringe/opsie bytes vergrendel is nie.
- Sien OpenOCD lae‑vlak `irscan`/`drscan` vir handmatige TAP-interaksie wanneer onbekende kettings opgestel word.

## Stop die CPU en dump geheue/flash

Sodra die TAP erken is en 'n teiken-skrip gekies is, kan jy die kern stop en geheuegebiede of interne flash dump. Voorbeelde (pas teiken, basisadresse en groottes aan):

- Generiese teiken na inisiëring:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (verkies SBA wanneer beskikbaar):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, programmeer of lees via OpenOCD helper:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- Gebruik `mdw/mdh/mdb` om geheue te kontroleer voor lang dumps.
- Vir multi‑toestel kettings, stel BYPASS op nie-teikens of gebruik 'n bordlêer wat al die TAPs definieer.

## Grens-scan truuks (EXTEST/SAMPLE)

Selfs wanneer die CPU fouttoegang vergrendel is, kan grens-scan steeds blootgestel wees. Met UrJTAG/OpenOCD kan jy:
- SAMPLE om pin state te neem terwyl die stelsel loop (vind busaktiwiteit, bevestig pin kaart).
- EXTEST om pins aan te dryf (bv., bit‑bang eksterne SPI flitslyne via die MCU om dit aflyn te lees as die bordbedrading dit toelaat).

Minimale UrJTAG vloei met 'n FT2232x-adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
U het die toestel BSDL nodig om die grensregister-bietordering te ken. Wees versigtig dat sommige verskaffers grens-scan selle in produksie vergrendel.

## Moderne teikens en notas

- ESP32‑S3/C3 sluit 'n inheemse USB‑JTAG-brug in; OpenOCD kan direk oor USB kommunikeer sonder 'n eksterne sonde. Baie gerieflik vir triage en dumps.
- RISC‑V debug (v0.13+) word wyd deur OpenOCD ondersteun; verkies SBA vir geheue-toegang wanneer die kern nie veilig gestop kan word nie.
- Baie MCU's implementeer debug-outehentisering en lewensiklusstate. As JTAG dood lyk maar die krag korrek is, mag die toestel na 'n geslote toestand gesmelt wees of 'n geoutentiseerde sonde benodig.

## Verdedigings en versterking (wat om te verwag op werklike toestelle)

- Deaktiveer of vergrendel JTAG/SWD permanent in produksie (bv. STM32 RDP vlak 2, ESP eFuses wat PAD JTAG deaktiveer, NXP/Nordic APPROTECT/DPAP).
- Vereis geoutentiseerde debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-beheerde uitdaging-reaksie) terwyl vervaardigings toegang behou word.
- Moet nie maklike toetspads lei nie; begrawe toetsvias, verwyder/populeer weerstande om TAP te isoleer, gebruik connectors met sleuteling of pogo-pin toebehore.
- Krag-aan debug vergrendeling: sluit die TAP agter vroeë ROM wat veilige opstart afdwing.

## Verwysings

- OpenOCD Gebruikersgids – JTAG Opdragte en konfigurasie. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG-debugging (USB‑JTAG, OpenOCD gebruik). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
