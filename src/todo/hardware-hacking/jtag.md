# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) is 'n tool wat jy op 'n Arduino-versoenbare MCU of (eksperimenteel) 'n Raspberry Pi kan laai om onbekende JTAG-pinlayouts met brute force te toets en selfs instruction registers te enumereer.

- Arduino: koppel digitale penne D2–D11 aan tot 10 vermeende JTAG-pads/testpunte, en Arduino GND aan target GND. Voorsien die target afsonderlik van krag, tensy jy weet die rail is veilig. Verkies 3.3 V-logika (bv. Arduino Due), of gebruik 'n level shifter/series resistors wanneer jy 1.8–3.3 V-targets toets.
- Raspberry Pi: die Pi-build bied minder bruikbare GPIOs (dus is scans stadiger); kyk in die repo vir die huidige pin map en beperkings.

Nadat dit geflashing is, maak die serial monitor teen 115200 baud oop en stuur `h` vir hulp. Tipiese vloei:

- `l` vind loopbacks om false positives te vermy
- `r` skakel interne pull-ups indien nodig
- `s` scan vir TCK/TMS/TDI/TDO (en soms TRST/SRST)
- `y` toets IR met brute force om ongedokumenteerde opcodes te ontdek
- `x` boundary-scan snapshot van pin states

![JTAG - JTAGenum: x boundary-scan snapshot van pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snapshot van pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snapshot van pin states](<../../images/image (774).png>)



As 'n geldige TAP gevind word, sal jy lyne sien wat met `FOUND!` begin en die ontdekte penne aandui.

Wenke
- Deel altyd ground, en dryf nooit onbekende penne bo die target se Vtref nie. As jy onseker is, voeg 100–470 Ω series resistors op kandidaatpenne by.
- As die device SWD/SWJ in plaas van 4-wire JTAG gebruik, sal JTAGenum dit dalk nie detect nie; probeer SWD-tools of 'n adapter wat SWJ-DP ondersteun.

## Veiliger pin hunting en hardware-opstelling

- Identifiseer eers Vtref en GND met 'n multimeter. Baie adapters benodig Vtref om die I/O-spanning te stel.
- Level shifting: verkies bidirectional level shifters wat vir push-pull-seine ontwerp is (JTAG-lyne is nie open-drain nie). Vermy auto-direction I2C-shifters vir JTAG.
- Nuttige adapters: FT2232H/FT232H-borde (bv. Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (op ESP32-Sx). Koppel minstens TCK, TMS, TDI, TDO, GND en Vtref; opsioneel TRST en SRST.

## Eerste kontak met OpenOCD (scan en IDCODE)

OpenOCD is die de facto OSS vir JTAG/SWD. Met 'n ondersteunde adapter kan jy die chain scan en IDCODEs lees:

- Generiese voorbeeld met 'n J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 ingeboude USB‑JTAG (geen eksterne probe benodig nie):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notas
- As jy ’n "all ones/zeros" IDCODE kry, kontroleer die wiring, kragtoevoer, Vtref, en maak seker dat die poort nie deur fuses/option bytes gesluit is nie.
- Sien OpenOCD se laevlak-`irscan`/`drscan` vir handmatige TAP-interaksie wanneer onbekende chains opgestel word.<sup>[[1]](#references)</sup>

## Stop die CPU en dump memory/flash

Sodra die TAP herken is en ’n target script gekies is, kan jy die core stop en memory regions of interne flash dump. Voorbeelde (pas target, basisadresse en groottes aan):

- Generic target na init:
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
Wenke
- Gebruik `mdw/mdh/mdb` om geheue te sanity-check voordat jy lang dumps uitvoer.
- Vir multi-device chains, stel BYPASS op nie-teikens of gebruik ’n board file wat alle TAPs definieer.

## Boundary-scan tricks (EXTEST/SAMPLE)

Selfs wanneer die CPU debug access gesluit is, kan boundary-scan steeds blootgestel wees. Met UrJTAG/OpenOCD kan jy:
- SAMPLE gebruik om pin states te snapshot terwyl die stelsel loop (vind bus activity, bevestig pin mapping).
- EXTEST gebruik om pins aan te dryf (byvoorbeeld bit-bang external SPI flash lines via die MCU om dit offline te lees indien board wiring dit toelaat).

Minimale UrJTAG flow met ’n FT2232x-adapter:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Jy het die device se BSDL nodig om die bitvolgorde van die boundary register te ken. Let daarop dat sommige vendors boundary-scan cells in production sluit.

## Moderne targets en notas

- ESP32-S3/C3 sluit ’n native USB-JTAG bridge in; OpenOCD kan direk oor USB kommunikeer sonder ’n external probe. Baie gerieflik vir triage en dumps.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+) word wyd deur OpenOCD ondersteun; verkies SBA vir memory access wanneer die core nie veilig halted kan word nie.
- Baie MCUs implementeer debug authentication en lifecycle states. As JTAG dood voorkom maar power korrek is, is die device moontlik na ’n closed state gefuse of vereis dit ’n authenticated probe.

## Defenses en hardening (wat om op regte devices te verwag)

- Disable of lock JTAG/SWD permanent in production (bv. STM32 RDP level 2, ESP eFuses wat PAD JTAG disable, NXP/Nordic APPROTECT/DPAP).
- Vereis authenticated debug (ARMv8.2-A ADIv6 Debug Authentication, OEM-managed challenge-response) terwyl manufacturing access behou word.
- Moenie maklike test pads route nie; bury test vias, remove/populate resistors om TAP te isolateer, en gebruik connectors met keying of pogo-pin fixtures.
- Power-on debug lock: gate die TAP agter vroeë ROM wat secure boot afdwing.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
