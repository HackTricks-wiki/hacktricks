# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Veiliger penopsporing en hardeware-opstelling

- Identifiseer eers Vtref en GND met ’n multimeter. Baie adapters benodig Vtref om die I/O-spanning in te stel.
- Level shifting: verkies bidirectionele level shifters wat vir push-pull-seine ontwerp is (JTAG-lyne is nie open-drain nie). Vermy outomatiese rigting-I2C-shifters vir JTAG.
- Nuttige adapters: FT2232H/FT232H-borde (bv. Tigard), CMSIS-DAP, J-Link, ST-LINK (verskafferspesifiek), ESP-USB-JTAG (op ESP32-Sx). Koppel minstens TCK, TMS, TDI, TDO, GND en Vtref; TRST en SRST is opsioneel.

Identifiseer GND op ’n ongedokumenteerde aansluiting deur kontinuïteit na ’n bekende grondvlak te toets **terwyl die teiken nie aangeskakel is nie**. Nadat jy na spanningsmodus oorgeskakel en die teiken aangeskakel het, moet jy nie elke hoë pen as Vtref klassifiseer nie: hoë digitale insette kan op ’n meter soortgelyk lyk. Volg kandidaat-kragrelings na nabygeleë ontkoppelkapasitors en vergelyk hul aanskakel- en afskakelgolfvorms op ’n ossilloskoop. ’n Stadiger, kapasitorvormige styging of daling dui op ’n krag-/verwysingsnet, maar verifieer die spanning en bedrading voordat jy ’n level-shifted probe koppel. Op PiFex kan ’n eksterne teikenverwysing met laer spanning via `VCCA_IN` gekies word in plaas van die verstekinstelling van 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** is ’n hulpmiddel wat jy op ’n Arduino-versoenbare MCU of, eksperimenteel, ’n Raspberry Pi kan laai om onbekende JTAG-penuitlegte met brute force te toets en instruksieregisters te tel.<sup>[[3]](#references)</sup>

- Arduino: koppel digitale penne D2–D11 aan tot 10 vermoedelike JTAG-pads/toetspunte, en Arduino GND aan teiken-GND. Skakel die teiken afsonderlik aan, tensy jy weet dat die kragrail veilig is. Verkies 3.3 V-logika (bv. Arduino Due) of gebruik ’n level shifter/serieweerstande wanneer jy 1.8–3.3 V-teikens toets.
- Raspberry Pi: die Pi-bouweergawe stel minder bruikbare GPIO’s beskikbaar (dus is skanderings stadiger); raadpleeg die repo vir die huidige penkaart en beperkings.

Sodra dit geflits is, maak die serial monitor teen 115200 baud oop en stuur `h` vir hulp. Tipiese verloop:

- `l` vind loopbacks om vals positiewe resultate te vermy
- `r` skakel interne pull-ups aan of af indien nodig
- `s` skandeer vir TCK/TMS/TDI/TDO (en soms TRST/SRST)
- `y` gebruik brute force op IR om ongedokumenteerde opcodes te ontdek
- `x` neem ’n boundary-scan-kiekie van penstatusse

![JTAG - JTAGenum: x boundary-scan-kiekie van penstatusse](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan-kiekie van penstatusse](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan-kiekie van penstatusse](<../../images/image (774).png>)



As ’n geldige TAP gevind word, sal jy reëls sien wat met `FOUND!` begin en die ontdekte penne aandui.

### JTAGenum-veiligheidswenke

- Gebruik altyd ’n gemeenskaplike grond en dryf nooit onbekende penne bo die teiken se Vtref nie. Voeg by twyfel 100–470 Ω-serieweerstande op kandidaatpenne by.
- As die toestel SWD/SWJ in plaas van 4-draad-JTAG gebruik, kan JTAGenum dit dalk nie opspoor nie; probeer SWD-gereedskap of ’n adapter wat SWJ-DP ondersteun.

## GPIO-penontdekking met go-jtagenum

Op ’n aangeskakelde teiken met ’n geverifieerde gemeenskaplike grond en versoenbare I/O-spanning kan `go-jtagenum` kandidaat-JTAG-seine vanaf Raspberry Pi-GPIO’s identifiseer. Die `-pins` JSON koppel etikette aan **GPIO-nommers**, nie fisiese penposisies op die aansluiting nie.<sup>[[5]](#references)</sup> In die SSD-voorbeeld het die eerste IDCODE-skandering ook ’n onwaarskynlik lang ketting van veranderende waardes gerapporteer: ’n kandidaat-TDO-lyn wat verander, is op sigself nie bewys van ’n geldige TAP nie. Bevestig ’n aanneemlike resultaat weer met ’n BYPASS-skandering, wat ’n bekende bispatroon vanaf TDI deur die eenbis-bypassregister na TDO skuif.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Vir daardie bord het BYPASS `TCK=10`, `TMS=14`, `TDI=9` en `TDO=15` bevestig; die ekstra penne was slegs **moontlike** nTRST-kandidate. As ’n kandidaat net nulle of ’n inkonsekwente patroon oplewer, kontroleer die kontak, die teikentoestel se kragtoevoer, die optrekweerstande en die klok-/terugstelvertragings voordat jy ’n sein daaraan toeken.<sup>[[4]](#references)[[5]](#references)</sup> Die nutsmiddel aanvaar ook `-known-pins` saam met `test_bypass` om ’n herwonne kartering weer te toets.<sup>[[5]](#references)</sup>

## Karakteriseer ’n ongedokumenteerde TAP met UrJTAG

’n Ontdekte penuitleg identifiseer nie die instruction-register (IR)-opkodes of data-register (DR)-wydtes wat nodig is vir ontfouting nie. Met ’n UrJTAG-bouweergawe wat die Raspberry Pi GPIO-kabel ondersteun, stel die herwonne kartering in en voer `idcode`, `detect` en dan `discover` uit. Die SSD-voorbeeld het een TAP, ’n vierbis-IR en verskillende DR-wydtes vir verskillende IR-waardes opgelewer. ’n DR-lengte van -1 of “TDO stuck at 0” is nie ’n bruikbare registerdefinisie nie; ondersoek die tydsberekening, bedrading en gekose instruksie eerder as om ’n wydte daaraan toe te ken.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Dit is TAP-verkenning, nie outomatiese SVE-identifikasie nie: vergelyk die resulterende IDCODE met toesteldokumentasie en ondersteunde OpenOCD-teikens. UrJTAG se plaaslike vervaardigerdatabasis kan ’n andersins geldige ID as onbekend etiketteer.<sup>[[4]](#references)</sup>

## Eerste kontak met OpenOCD (skandeer en IDCODE)

OpenOCD is die de facto OSS vir JTAG/SWD. Met ’n ondersteunde adapter kan jy die ketting skandeer en IDCODE’s lees:<sup>[[1]](#references)</sup>

- Generiese voorbeeld met ’n J‑Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 ingeboude USB‑JTAG (geen eksterne probe benodig nie):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Aantekeninge

- As jy ’n "all ones/zeros"-IDCODE kry, gaan die bedrading, krag, Vtref na, en kyk of die poort nie deur fuses/option bytes gesluit is nie.
- Sien OpenOCD se laevlak-`irscan`/`drscan` vir handmatige TAP-interaksie wanneer jy onbekende kettings opstel.<sup>[[1]](#references)</sup>

## Bring ’n ongedokumenteerde teiken in OpenOCD

Sodra die TAP-ID en IR-lengte bekend is, ondersoek OpenOCD se `cpu/`-, `target/`- en `board/`-skripte vir ’n **ooreenstemmende CPU-argitektuur**, en skep dan afsonderlike adapter- en teikenkonfigurasies.<sup>[[4]](#references)[[6]](#references)</sup> Die volgende Pi GPIO-kartering en ARCv2-teiken is die getoetste SSD-voorbeeld, nie ’n universele JTAG-konfigurasie nie. Die keuse van ARC-teiken en ontfoutingsinstellings was aannames wat vir hierdie toestel gewerk het; vervang dit op ’n ander bord met die teiken se gemete ID, IR-lengte, argitektuur en GPIO-nommers.<sup>[[4]](#references)</sup>

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

Voer `openocd -f raspberrypi-io.cfg -f target.cfg` uit en bevestig dat TAP-ondersoek slaag voordat jy geheue lees. Die voorbeeld het Telnet op poort `4444` en ’n GDB-bediener op `3333` oopgemaak; ’n herkende IDCODE bewys op sigself nie dat die gekose CPU-teiken ondersoek of gedebug kan word nie.<sup>[[4]](#references)</sup> Raspberry Pi-GPIO’s hoef nie die penne te wees wat op ’n uitbreekbord as JTAG gemerk is nie, mits die adapter `adapter gpio`-herkartering toelaat.<sup>[[4]](#references)[[6]](#references)</sup>

## Die CPU stop en geheue/flash dump

Sodra die TAP herken is en ’n teikenskrip gekies is, kan jy die kern stop en geheuegebiede of interne flash dump. Voorbeelde (pas teiken, basisadresse en groottes aan):<sup>[[1]](#references)</sup>

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

### Wenke vir geheue-dumps

- Gebruik `mdw/mdh/mdb` om geheue voor lang dumps te kontroleer.
- Stel BYPASS op nie-teikens vir multi-toestelkettings, of gebruik ’n board file wat alle TAPs definieer.

Vir ’n ongedokumenteerde geheuekaart het die SSD-navorsing ’n dump van 1 MiB nagegaan vir herkenbare beheerderstringe, en toe ’n GDB met argitektuurondersteuning deur OpenOCD gebruik om `$pc`, disassembly en registers te inspekteer. Dié lewendige adresse het ’n tweede streek-dump gelei, wat nagegaan is teen ooreenstemmende instruksies in ’n ARC-geskikte Ghidra-bou. Strings alleen is net ’n geloofwaardigheidstoets, nie bewys dat die beeld volledig is of korrek gekarteer is nie.<sup>[[4]](#references)</sup> Sien [firmware-analise](../firmware-analysis/) vir breër statiese-analise-stappe.

## Boundary-scan-truuks (EXTEST/SAMPLE)

Selfs wanneer CPU-ontfoutingstoegang gesluit is, kan boundary-scan steeds beskikbaar wees. Met UrJTAG/OpenOCD kan jy:<sup>[[1]](#references)</sup>
- SAMPLE om penstatusse vas te lê terwyl die stelsel loop (vind busaktiwiteit, bevestig penkartering).
- EXTEST om penne aan te dryf (bv. bit-bang eksterne SPI-flitslyne via die MCU om dit vanlyn te lees, indien die bordbedrading dit toelaat).

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
Jy benodig die toestel se BSDL om die bitvolgorde van die boundary register te ken. Wees bewus daarvan dat sommige verskaffers boundary-scan-selle tydens produksie sluit.

## Moderne teikens en notas

- ESP32‑S3/C3 sluit ’n ingeboude USB‑JTAG-bridge in; OpenOCD kan direk oor USB kommunikeer sonder ’n eksterne probe. Baie gerieflik vir triage en dumps.<sup>[[2]](#references)</sup>
- RISC‑V-debug (v0.13+) word wyd deur OpenOCD ondersteun; verkies SBA vir geheuetoegang wanneer die core nie veilig gestop kan word nie.
- Baie MCU’s implementeer debug-verifikasie en lewensiklustoestande. As JTAG dood lyk maar die kragtoevoer reg is, kan die toestel met ’n fuse na ’n geslote toestand gestel wees of ’n geverifieerde probe vereis.

## Verdediging en verharding (wat om op regte toestelle te verwag)

- Deaktiveer JTAG/SWD permanent of sluit dit in produksie (bv. STM32 RDP-vlak 2, ESP-eFuses wat PAD JTAG deaktiveer, NXP/Nordic APPROTECT/DPAP).
- Vereis geverifieerde debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-bestuurde challenge-response) terwyl toegang vir vervaardiging behoue bly.
- Moenie maklik toeganklike test pads aanlê nie; versteek test-vias, verwyder of plaas resistors om TAP te isoleer, en gebruik verbindings met ’n sleutel of pogo-pin-toebehore.
- Debug-sluiting tydens aanskakeling: plaas die TAP agter vroeë ROM wat secure boot afdwing.

## References

- [1] [OpenOCD-gebruikersgids – JTAG-opdragte en konfigurasie](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG-ontfouting (USB‑JTAG, OpenOCD-gebruik)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino-gebaseerde JTAG-penuitlegskandeerder](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — JTAG Hacking met ’n Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG-enumerasie](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD-gebruikersgids — Debug-adapterkonfigurasie](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
