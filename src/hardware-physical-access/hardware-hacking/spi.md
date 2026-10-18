# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

SPI (Serial Peripheral Interface) is ’n sinchroniese seriële bus wat algemeen vir kortafstandkommunikasie tussen geïntegreerde stroombane gebruik word. ’n Beheerder verskaf die kloksein en kies ’n randapparaat, soos ’n EEPROM, sensor of beheertoestel, met ’n chip-selektsein.<sup>[[1]](#references)</sup>

Verskeie randapparate kan die klok- en datalyne deel, gewoonlik met ’n aparte chip-selektsein vir elke randapparaat. Die beheerder koördineer data-oordragte; randapparate kommunikeer gewoonlik nie direk met mekaar oor die SPI-bus nie. Die polariteit en tydsberekening van chip-selektseine is toestelspesifiek; aktief-lae seleksie is algemeen, maar nie universeel nie. SPI definieer nie ontdekking, adressering, opdragte of ’n enkele maksimum oordraglengte nie, raadpleeg dus altyd die teikentoestel se datablad.<sup>[[1]](#references)</sup>

MOSI/COPI dra data van die beheerder na die randapparaat, en MISO/CIPO dra data van die randapparaat na die beheerder. Data kan gelyktydig in albei rigtings verskuif word. Die verhouding tussen ’n opdrag, adres, dummy-siklusse en teruggestuurde data word deur die randapparaat bepaal—nie deur SPI nie—en hang af van die klok se polariteit en fase (modusse 0–3). Moenie aanvaar dat uitvoer presies een kloksiklus ná die einde van invoer begin nie.<sup>[[1]](#references)</sup>

## Firmware van EEPROMs aflaai

Dit kan nuttig wees om firmware af te laai om dit te ontleed en kwesbaarhede te vind. Die korrekte beeld is dalk nie aanlyn beskikbaar nie, of dit kan verskil volgens model, hardewarehersiening of weergawe. As jy dit dus direk van die fisiese toestel afhaal, kry jy ’n presiese teiken vir assessering.

’n Seriële konsole kan nuttig wees, maar die lêerstelsel daarvan kan leesalleen wees en die teiken het dalk nie ontledingsnutsmiddels nie, insluitend nutsmiddels wat nodig is om toetsverkeer te stuur/ontvang of binêre lêers gerieflik te onttrek. ’n Aflyn beeld behou die volledige flitsuitleg en maak dit moontlik om die lêerstelsel te onttrek en reverse engineering te doen sonder om die teiken wat tans loop, te wysig.

Tydens ’n gemagtigde fisiese assessering kan ’n geverifieerde dump ook beheerde wysigings- en herflitstoetse ondersteun. Dit sluit in om lêers te verander of ’n toetspayload/backdoor in te voeg om volharding op firmwarevlak te demonstreer. Bewaar verskeie ooreenstemmende lesings en die oorspronklike beeld voordat jy iets skryf: ’n verkeerde spanning, skyfiekeuse, uitleg of beeld kan die toestel onbruikbaar maak.

### CH341A EEPROM-programmeerder en -leser

Hierdie goedkoop USB-nutsding kan versoenbare seriële EEPROM- en SPI-flitstoestelle aflaai en herflits. Dit word algemeen gebruik met SPI NOR-flitsskyfies waarin PC BIOS/UEFI-firmware gestoor word, en is handig wanneer fisiese toegang beperk is.

![drawing](../../images/board_image_ch341a.jpg)

Koppel die flitsgeheue aan die CH341A en koppel dan die programmeerder aan die rekenaar. As die programmeerder self nie opgespoor word nie, kontroleer die USB-kabel, OS-toestemmings en die toepaslike CH341A-drywer voordat jy die teikenskyfie foutsoek. Bevestig die skyfie se spanning, pen 1, adapterbedrading en programmeerderuitset aan die hand van die datablaaie of met ’n meter—moenie **staatmaak** op ’n reël soos om VCC oorkant die USB-aansluiting te plaas nie. Verkeerde oriëntasie of 5 V wat op ’n 3.3/1.8 V-komponent toegepas word, kan dit vernietig. Lesings in die stroombaan kan ook misluk omdat die res van die bord die bus belas of van krag voorsien.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Gebruik sagteware soos `flashrom` of G-Flash om die skyfie te lees. G-Flash is ’n minimale GUI en kan versoenbare toestelle outomaties opspoor, wat gerieflik kan wees vir ’n vinnige verkryging, maar bevestig self die opgespoorde model en spanning. Spesifiseer die presiese programmeerder en, waar nodig, die presiese skyfiemodel; doen minstens twee lesings en vergelyk hul hashes voordat jy ’n dump as betroubaar beskou.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nadat die firmware afgelaai is, kan die ontleding op die binêre lêers gedoen word. Nutsmiddels soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die volledige lêerstelsel te onttrek.

Vir aanvanklike triage kan Binwalk bekende handtekeninge soek en ondersteunde ingebedde inhoud onttrek:

```
binwalk -e <filename>
```

Die uitvoerlêer kan `.bin`, `.rom` of ’n ander uitbreiding gebruik; die uitbreiding bepaal nie die formaat nie.

> [!CAUTION]
> Let daarop dat firmware-onttrekking ’n delikate proses is wat baie geduld verg. Enige verkeerde hantering kan die firmware beskadig of selfs heeltemal uitvee, wat die toestel onbruikbaar kan maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te onttrek.

### Bus Pirate + flashrom

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Sommige datablaaie benoem die teikenpenne as `DI` en `DO`: vir ’n konvensionele flash-verbinding met ’n enkele datalyn, koppel die beheerder se **MOSI/COPI aan DI** en die beheerder se **MISO/CIPO aan DO**. Gaan die teikentoestel se datablad na, want onderdele met dual/quad I/O gebruik penne weer in ander modusse.

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Let daarop dat hoewel die PINOUT van die Pirate Bus penne vir MOSI en MISO aandui om aan SPI te koppel, sommige SPIs moontlik...](<../../images/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flash-geheue uit te lees deur iets soos die volgende uit te voer:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Onlangse Bus Pirate-dokumentasie wys ook die opsionele parameters `serialspeed` en `spispeed`. Begin versigtig as lang drade of las in die stroombaan lesings onstabiel maak.<sup>[[3]](#references)</sup>

### Lesings in die stroombaan wanneer die beheerder die flash-bus deel

’n SOIC-klem kan die flash se kragtoevoer na die res van die PCB voer. As die MCU dan aangeskakel is en toegang tot dieselfde skyfie verkry, kan sy SPI-oordragte bots met dié van die eksterne programmeerder. ’n `No EEPROM/flash device found`-resultaat bewys dus nie dat die flash afwesig of nie ondersteun word nie. Gaan eers die penuitleg, spanning en kontak na, en bepaal dan of die beheerder op die bord ook aktief is.<sup>[[4]](#references)</sup>

As ’n reset-toetspad beskikbaar is, bevestig die polariteit en spanning daarvan met ’n multimeter voordat jy dit aktiveer. As jy die MCU in reset hou, kan die flash toeganklik bly terwyl die mededingende SPI-gasheer gestop word. Alternatiewe is om die skyfie te desoldeer of die MCU se lesings passief op te neem; laasgenoemde bied nie toegang tot ongeleesde gedeeltes nie en kan nie na die skyfie skryf nie, en ekstra probedrade kan ’n vinnige bus versteur. ’n Ossillator- of selflaaimodus-ingryping is teikenspesifiek en vervang nie die nagaan van die skematiese diagram en seine nie.<sup>[[4]](#references)</sup>

Met die MCU onaktief gehou, kan ’n Raspberry Pi met ’n geaktiveerde `spidev`-koppelvlak via flashrom se `linux_spi`-programmeerder lees. Verander `-p` vir ’n ander adapter. Herhaal die lesing en vergelyk hashes voordat jy dit vertrou; SFDP-outodeteksie en ’n suksesvolle lesing bewys **nie** dat uitvee-, skryf- of skryfbeskermingsbewerkings op ’n andersins nie-ondersteunde onderdeel werk nie.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Herbou SPI-flitslesings met ’n logikaanaliseerder

Wanneer aktiewe lees nie moontlik is nie, neem die chip select, klok, beheerder-na-flits-data en flits-na-beheerder-data tydens selflaai of ’n gekose UI-aksie op. Identifiseer in PulseView eers die aktiewe chip-select-interval en klok, en stel dan die SPI-dekodeerder se datakanale volgens die flits-penuitleg op. Bevestig dat ’n geloofwaardige opdrag/adres gevolg word deur teruggestuurde grepe. Voer die **MISO/flits-uitset**-grepe met Binary Decoder Output View uit en behou die gedekodeerde leesadresse sodat elke antwoord by die ooreenstemmende flits-offset geplaas kan word. Opnames van slegs kieslys-geïnisieerde lesings bevat net die aangevraagde streke, nie ’n volledige flitsbeeld nie; moenie antwoorde aaneenlas asof hulle aaneenlopend is sonder om die adresse na te gaan nie.<sup>[[4]](#references)</sup>

As ’n dump lyk asof dit grafika eerder as uitvoerbare kode bevat, gaan voort met [rou vertoonbate-triage](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Inleiding tot SPI-koppelvlak](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-handleiding — CH341A SPI-programmeerder en lees-/skryfopsies](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate-dokumentasie — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Herhaling van hardeware-inbraak, deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
