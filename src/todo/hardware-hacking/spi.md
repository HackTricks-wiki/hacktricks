# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

SPI (Serial Peripheral Interface) is 'n sinchrone seriële bus wat algemeen vir kortafstandkommunikasie tussen geïntegreerde stroombane gebruik word. 'n Beheerder verskaf die klok en kies 'n randtoestel, soos 'n EEPROM, sensor of beheertoestel, deur 'n chip-select-sein te gebruik.<sup>[[1]](#references)</sup>

Veelvuldige randtoestelle kan die klok- en datalyne deel, gewoonlik met 'n aparte chip-select per randtoestel. Die beheerder koördineer oordragte; randtoestelle kommunikeer normaalweg nie direk met mekaar oor die SPI-bus nie. Chip-select-polariteit en -tydsberekening is toestelspesifiek; aktief-laag-seleksie is algemeen, maar nie universeel nie. SPI definieer nie discovery, adressering, commands of 'n enkele maksimum oordraglengte nie, dus moet jy altyd die teiken se datasheet raadpleeg.<sup>[[1]](#references)</sup>

MOSI/COPI dra data van die beheerder na die randtoestel, en MISO/CIPO dra data van die randtoestel na die beheerder. Albei rigtings kan gelyktydig geskuif word. Die verhouding tussen 'n command, adres, dummy cycles en teruggestuurde data word deur die randtoestel gedefinieer—nie deur SPI nie—en hang af van klokpolariteit en -fase (modusse 0–3). Moenie aanvaar dat output presies een klok ná die einde van input begin nie.<sup>[[1]](#references)</sup>

## Firmware vanaf EEPROMs Dump

Firmware dump kan nuttig wees om dit te analiseer en kwesbaarhede te vind. Die korrekte image is moontlik nie aanlyn beskikbaar nie, of kan volgens model, hardwarerevisie of weergawe verskil. Deur dit direk vanaf die fisiese toestel te onttrek, kry jy dus 'n presiese assesseringsteiken.

'n Seriële konsole kan help, maar sy filesystem kan read-only wees, en die teiken het moontlik nie analysis tools nie, insluitend utilities wat nodig is om toetsverkeer te stuur/ontvang of binaries gerieflik te onttrek. 'n Offline image bewaar die volledige flash-uitleg en maak filesystem-onttrekking en reverse engineering moontlik sonder om die lopende teiken te wysig.

Tydens 'n gemagtigde fisiese assessering kan 'n geverifieerde dump ook beheerde wysigings- en reflashing-toetse ondersteun. Dit sluit in die wysiging van files of die inspuiting van 'n test payload/backdoor om firmware-vlak-persistentie te demonstreer. Bewaar verskeie ooreenstemmende reads en die oorspronklike image voordat enige write gedoen word: 'n verkeerde voltage, chip selection, uitleg of image kan die toestel brick.

### CH341A EEPROM Programmer and Reader

Hierdie goedkoop USB-tool kan versoenbare seriële EEPROM- en SPI-flashtoestelle dump en reflash. Dit word algemeen gebruik met die SPI NOR-flashchips wat PC BIOS/UEFI-firmware stoor en is gerieflik tydens fisiese toegang wat deur tyd beperk word.

![drawing](../../images/board_image_ch341a.jpg)

Koppel die flash memory aan die CH341A en koppel dan die programmer aan die rekenaar. As die programmer self nie bespeur word nie, kontroleer die USB-kabel, OS-permissies en die toepaslike CH341A-driver voordat jy die teiken-chip begin foutsoek. Bevestig die chip se voltage, pin 1, adapterbedrading en programmer-output met die datasheets of 'n meter—moet **nie** op 'n reël soos die plasing van VCC teenoor die USB-connector staatmaak nie. Verkeerde oriëntasie of 5 V wat op 'n 3.3/1.8 V-komponent toegepas word, kan dit vernietig. In-circuit reads kan ook misluk omdat die res van die board die bus laai of van krag voorsien.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Gebruik software soos `flashrom` of G-Flash om die chip te lees. G-Flash is 'n minimale GUI en kan versoenbare toestelle outomaties bespeur, wat gerieflik kan wees tydens vinnige acquisition, maar bevestig self die bespeurde model en voltage. Spesifiseer die presiese programmer en, wanneer nodig, die presiese chip-model; doen minstens twee reads en vergelyk hul hashes voordat jy 'n dump as betroubaar beskou.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nadat die firmware gedump is, kan die analysis op die binary files gedoen word. Tools soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die hele filesystem te onttrek.

Vir aanvanklike triage kan Binwalk vir bekende signatures skandeer en ondersteunde ingebedde inhoud onttrek:
```
binwalk -e <filename>
```
Die uitvoerlêer kan `.bin`, `.rom` of ’n ander uitbreiding gebruik; die uitbreiding bepaal nie die formaat nie.

> [!CAUTION]
> Let daarop dat firmware-ekstraksie ’n delikate proses is en baie geduld vereis. Enige verkeerde hantering kan die firmware moontlik korrupteer of dit selfs heeltemal uitvee, wat die toestel onbruikbaar kan maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te onttrek.

### Bus Pirate + flashrom

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Sommige datasheets benoem die teikenpenne as `DI` en `DO`: vir ’n konvensionele flash-verbinding met ’n enkele datalyn, verbind die beheerder se **MOSI/COPI met DI** en die beheerder se **MISO/CIPO met DO**. Verifieer die teikendatasheet, omdat dual/quad I/O-onderdele penne in ander modusse hergebruik.

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Let daarop dat, selfs al dui die PINOUT van die Pirate Bus penne aan vir MOSI en MISO om aan SPI te verbind, sommige SPIs moontlik...](<../../images/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flash-geheue te dump deur iets soos die volgende uit te voer:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Onlangse Bus Pirate-dokumentasie toon ook opsionele `serialspeed`- en `spispeed`-parameters. Begin versigtig as lang drade of belasting in die stroombaan lesings onstabiel maak.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Inleiding tot SPI-koppelvlak](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-handleiding — CH341A SPI-programmeerder en lees-/skryfopsies](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate-dokumentasie — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
