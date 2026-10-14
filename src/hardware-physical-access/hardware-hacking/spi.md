# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

SPI (Serial Peripheral Interface) is ’n sinchrone seriële bus wat algemeen vir kortafstandkommunikasie tussen geïntegreerde stroombane gebruik word. ’n Beheerder voorsien die klok en kies ’n randtoestel, soos ’n EEPROM, sensor of beheertoestel, met behulp van ’n chip-select-sein.<sup>[[1]](#references)</sup>

Verskeie randtoestelle kan die klok- en datalyne deel, gewoonlik met ’n aparte chip-select vir elke randtoestel. Die beheerder koördineer die oordragte; randtoestelle kommunikeer gewoonlik nie direk met mekaar oor die SPI-bus nie. Chip-select-polariteit en -tydsberekening is toestelspesifiek; aktief-laag-seleksie is algemeen, maar nie universeel nie. SPI definieer nie ontdekking, adressering, opdragte of ’n enkele maksimum oordraglengte nie, dus raadpleeg altyd die teikentoestel se datasheet.<sup>[[1]](#references)</sup>

MOSI/COPI dra data van beheerder na randtoestel, en MISO/CIPO dra data van randtoestel na beheerder. Albei rigtings kan gelyktydig verskuif. Die verhouding tussen ’n opdrag, adres, dummy-siklusse en teruggestuurde data word deur die randtoestel bepaal—nie deur SPI nie—en hang af van klokpolariteit en -fase (modusse 0–3). Moenie aanvaar dat uitvoer presies een klok ná die einde van invoer begin nie.<sup>[[1]](#references)</sup>

## Firmware dump vanaf EEPROMs

Firmware dump kan nuttig wees om dit te ontleed en kwesbaarhede te vind. Die korrekte image is dalk nie aanlyn beskikbaar nie, of kan verskil volgens model, hardewarehersiening of weergawe. Deur dit dus direk van die fisiese toestel af te haal, kry jy ’n presiese teiken vir assessering.

’n Seriële konsole kan help, maar sy lêerstelsel kan leesalleen wees en die teiken het dalk nie ontledingsnutsgoed nie, insluitend nutsprogramme wat nodig is om toetsverkeer te stuur/ontvang of binaries gerieflik te onttrek. ’n Vanlyn image behou die volledige flash-uitleg en maak lêerstelselonttrekking en reverse engineering moontlik sonder om die teiken wat tans loop, te wysig.

Tydens ’n gemagtigde fisiese assessering kan ’n geverifieerde dump ook beheerde wysigings- en herflashtoetse ondersteun. Dit sluit in om lêers te wysig of ’n toetspayload/backdoor in te voeg om firmwarevlak-volharding te demonstreer. Bewaar verskeie ooreenstemmende lesings en die oorspronklike image voordat jy skryf: ’n verkeerde spanning, chip-seleksie, uitleg of image kan die toestel onbruikbaar maak.

### CH341A EEPROM-programmeerder en -leser

Hierdie goedkoop USB-instrument kan versoenbare seriële EEPROM- en SPI-flashtoestelle dump en herflits. Dit word algemeen gebruik met die SPI NOR-flashskyfies waarin PC BIOS/UEFI-firmware gestoor word, en is handig wanneer fisiese toegang beperk is tot ’n kort tyd.

![drawing](../../images/board_image_ch341a.jpg)

Koppel die flashgeheue aan die CH341A en koppel dan die programmeerder aan die rekenaar. As die programmeerder self nie opgespoor word nie, gaan die USB-kabel, OS-toestemmings en toepaslike CH341A-drywer na voordat jy die teikenskyfie foutsoek. Bevestig die skyfie se spanning, pen 1, adapterbedrading en programmeerder se uitset aan die hand van die datasheets of met ’n meter—moenie staatmaak op ’n reël soos om VCC oorkant die USB-aansluiting te plaas nie. Verkeerde oriëntasie of 5 V op ’n 3.3/1.8 V-onderdeel kan dit vernietig. Lesings in die stroombaan kan ook misluk omdat die res van die bord die bus belas of van krag voorsien.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Gebruik sagteware soos `flashrom` of G-Flash om die skyfie te lees. G-Flash is ’n eenvoudige GUI en kan versoenbare toestelle outomaties opspoor, wat gerieflik kan wees vir vinnige verkryging, maar bevestig self die opgespoorde model en spanning. Spesifiseer die presiese programmeerder en, indien nodig, die presiese skyfiemodel; doen minstens twee lesings en vergelyk hul hashes voordat jy ’n dump as betroubaar beskou.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nadat die firmware gedump is, kan die binaries ontleed word. Nutsgoed soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die hele lêerstelsel te onttrek.

Vir aanvanklike triage kan Binwalk vir bekende handtekeninge soek en ondersteunde ingebedde inhoud onttrek:

```
binwalk -e <filename>
```

Die uitvoerlêer kan `.bin`, `.rom` of ’n ander uitbreiding gebruik; die uitbreiding bepaal nie die formaat nie.

> [!CAUTION]
> Let daarop dat firmware-ekstraksie ’n delikate proses is en baie geduld vereis. Enige verkeerde hantering kan die firmware moontlik beskadig of dit selfs heeltemal uitvee, wat die toestel onbruikbaar maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te onttrek.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Sommige databladspesifikasies benoem die teikenpenne `DI` en `DO`: vir ’n konvensionele flash-verbinding met ’n enkele datalyn, verbind die beheerder se **MOSI/COPI met DI** en die beheerder se **MISO/CIPO met DO**. Gaan die teiken se datablad na, aangesien onderdele met dual/quad I/O die penne in ander modusse hergebruik.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Let daarop dat selfs al dui die PINOUT van die Pirate Bus penne aan om MOSI en MISO aan SPI te koppel, sommige SPIs dalk...](<../../images/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flashgeheue te dump deur iets soos die volgende uit te voer:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Onlangse Bus Pirate-dokumentasie wys ook opsionele `serialspeed`- en `spispeed`-parameters. Begin versigtig as lang drade of lading in die stroombaan lesings onstabiel maak.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Inleiding tot SPI-koppelvlak](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-handleiding — CH341A SPI-programmeerder en lees-/skryfopsies](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate-dokumentasie — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
