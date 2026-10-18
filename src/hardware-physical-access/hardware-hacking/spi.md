# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

SPI (Serial Peripheral Interface) is ’n sinchrone seriële bus wat algemeen vir kortafstandkommunikasie tussen geïntegreerde stroombane gebruik word. ’n Beheerder voorsien die klok en kies ’n randtoestel, soos ’n EEPROM, sensor of beheertoestel, met behulp van ’n chip-select-sein.<sup>[[1]](#references)</sup>

Verskeie randtoestelle kan die klok- en datalyne deel, gewoonlik met ’n aparte chip-select vir elke randtoestel. Die beheerder koördineer die data-oordragte; randtoestelle kommunikeer normaalweg nie direk met mekaar oor die SPI-bus nie. Die chip-select-polariteit en -tydsberekening is toestelspesifiek; aktief-laag-seleksie is algemeen, maar nie universeel nie. SPI definieer nie ontdekking, adressering, opdragte of ’n enkele maksimum-oordraglengte nie, dus raadpleeg altyd die teikentoestel se datablad.<sup>[[1]](#references)</sup>

MOSI/COPI dra data van die beheerder na die randtoestel, en MISO/CIPO dra data van die randtoestel na die beheerder. Albei rigtings kan gelyktydig verskuif word. Die verhouding tussen ’n opdrag, adres, dummy-siklusse en teruggestuurde data word deur die randtoestel—nie deur SPI nie—gedefinieer en hang af van die klokpolariteit en -fase (modusse 0–3). Moenie aanvaar dat uitvoer presies een kloksiklus ná die einde van die invoer begin nie.<sup>[[1]](#references)</sup>

## Uittrek van firmware vanaf EEPROMs

Dit kan nuttig wees om firmware uit te trek om dit te ontleed en kwesbaarhede te vind. Die korrekte image is moontlik nie aanlyn beskikbaar nie, of kan verskil volgens model, hardewarehersiening of weergawe. Deur dit direk van die fisiese toestel af te haal, kry jy dus ’n presiese teiken vir assessering.

’n Seriële konsole kan help, maar sy lêerstelsel kan leesalleen wees en die teiken het dalk nie ontledingsnutsgoed nie, insluitend nutsprogramme wat nodig is om toetsverkeer te stuur/ontvang of binaries gerieflik uit te trek. ’n Vanlyn image behou die volledige flitsuitleg en laat lêerstelselonttrekking en reverse engineering toe sonder om die lopende teiken te verander.

Tydens ’n gemagtigde fisiese assessering kan ’n geverifieerde dump ook beheerde wysigings- en herflitstoetse ondersteun. Dit sluit in om lêers te verander of ’n toets-payload/backdoor in te voeg om volharding op firmwarevlak te demonstreer. Bewaar verskeie ooreenstemmende uitleesresultate en die oorspronklike image voordat jy iets skryf: ’n verkeerde spanning, chip-keuse, uitleg of image kan die toestel onbruikbaar maak.

### CH341A EEPROM-programmeerder en -leser

Hierdie goedkoop USB-nutsding kan versoenbare seriële EEPROM- en SPI-flitstoestelle dump en herflits. Dit word algemeen gebruik met SPI NOR-flitschips wat PC BIOS/UEFI-firmware stoor, en is handig wanneer fisiese toegang beperk is.

![drawing](../../images/board_image_ch341a.jpg)

Koppel die flitsgeheue aan die CH341A en koppel dan die programmeerder aan die rekenaar. As die programmeerder self nie opgespoor word nie, gaan die USB-kabel, OS-toestemmings en toepaslike CH341A-bestuurder na voordat jy die teikenchip foutsoek. Bevestig die chip se spanning, pen 1, adapterbedrading en programmeerderuitset met die datablaaie of ’n meter—moenie **op** ’n reël soos om VCC oorkant die USB-aansluiting te plaas, staatmaak nie. Verkeerde oriëntasie of 5 V op ’n 3.3/1.8 V-komponent kan dit vernietig. Uitlees binne die stroombaan kan ook misluk omdat die res van die bord die bus belas of van krag voorsien.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Gebruik sagteware soos `flashrom` of G-Flash om die chip te lees. G-Flash is ’n minimale GUI en kan versoenbare toestelle outomaties opspoor, wat handig kan wees vir vinnige verkryging, maar bevestig self die opgespoorde model en spanning. Spesifiseer die presiese programmeerder en, indien nodig, die presiese chipmodel; lees die chip minstens twee keer uit en vergelyk die hashes voordat jy ’n dump as betroubaar beskou.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nadat jy die firmware gedump het, kan jy die binaries ontleed. Nutsgoed soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om heelwat inligting oor die firmware én die hele lêerstelsel te onttrek.

Vir aanvanklike triage kan Binwalk vir bekende handtekeninge soek en ondersteunde ingebedde inhoud uittrek:

```
binwalk -e <filename>
```

Die uitvoerlêer kan `.bin`, `.rom` of ’n ander uitbreiding gebruik; die uitbreiding bepaal nie die formaat nie.

> [!CAUTION]
> Let daarop dat firmware-onttrekking ’n delikate proses is wat baie geduld verg. Enige verkeerde hantering kan die firmware moontlik beskadig of selfs heeltemal uitvee, waardeur die toestel onbruikbaar kan word. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te onttrek.

### Bus Pirate + flashrom

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Sommige datablaaie benoem die teikenpenne as `DI` en `DO`: vir ’n konvensionele flashverbinding met ’n enkele datalyn, koppel die beheerder se **MOSI/COPI aan DI** en die beheerder se **MISO/CIPO aan DO**. Gaan die teikendatablad na, aangesien dele met dubbele/vierledige I/O die penne in ander modusse hergebruik.

![CH341A EEPROM-programmeerder en -leser - Bus Pirate + flashrom: Let daarop dat, hoewel die PINOUT van die Pirate Bus penne aandui om MOSI en MISO aan SPI te koppel, sommige SPI's dalk...](<../../images/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flashgeheue uit te lees deur iets soos die volgende uit te voer:

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

’n SOIC-clip kan die flash se kragtoevoer na die res van die PCB voer. As die MCU dan aangeskakel is en toegang tot dieselfde chip verkry, kan sy SPI-transfers bots met die eksterne programmeerder se transfers. ’n `No EEPROM/flash device found`-resultaat bewys dus nie dat die flash ontbreek of nie ondersteun word nie. Gaan eers die pinout, spanning en kontak na, en bepaal dan of die beheerder op die bord ook aktief is.<sup>[[4]](#references)</sup>

As ’n reset-toetspad beskikbaar is, bevestig die polariteit en spanning daarvan met ’n meter voordat jy dit aktiveer. As die MCU in reset gehou word, kan die flash toeganklik bly terwyl die mededingende SPI-host gestop word. Alternatiewe is om die chip te desoldeer of die MCU se lesings passief op te neem; laasgenoemde bied nie toegang tot ongeleesde areas of die vermoë om na die chip te skryf nie, en ekstra probedrade kan ’n vinnige bus versteur. ’n Ossillator- of selflaaimodus-ingreep is teikenspesifiek en vervang nie die nagaan van die skematiese diagram en seine nie.<sup>[[4]](#references)</sup>

Met die MCU onaktief gehou, kan ’n Raspberry Pi met ’n geaktiveerde `spidev`-koppelvlak deur flashrom se `linux_spi`-programmeerder lees. Verander `-p` vir ’n ander adapter. Herhaal die lesing en vergelyk hashes voordat jy dit vertrou; SFDP-outodeteksie en ’n suksesvolle lesing bevestig **nie** dat uitvee-, skryf- of skryfbeskermingsbewerkings op ’n andersins nie-ondersteunde onderdeel werk nie.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Herbou SPI-flashlesings met ’n logika-ontleder

Wanneer aktiewe lees nie moontlik is nie, neem chip-select, klok, data van beheerder na flash en data van flash na beheerder op tydens selflaai of ’n gekose UI-aksie. Identifiseer in PulseView eers die aktiewe chip-select-interval en klok, stel dan die SPI-dekodeerder se datakanale volgens die flash-penuitleg op en verifieer ’n geloofwaardige opdrag/adres, gevolg deur teruggestuurde grepe. Voer die **MISO/flash-uitvoer**-grepe met Binary Decoder Output View uit en bewaar die gedekodeerde leesadresse sodat elke antwoord by die ooreenstemmende flash-offset geplaas kan word. As jy slegs lesings opneem wat deur spyskaarte aangevra word, kry jy net die aangevraagde streke, nie ’n volledige flash-beeld nie; moet dus nie antwoorde aaneenvoeg asof hulle aaneenlopend is sonder om die adresse na te gaan nie.<sup>[[4]](#references)</sup>

As ’n dump blykbaar grafika eerder as uitvoerbare kode bevat, gaan voort met [triage van rou vertoonbates](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy en gemengde SPI/QSPI-opnames

Vir probes sonder etikette, onderskei MOSI van MISO deur vas te stel watter lyn die opcode dra voordat die antwoorddata begin, en verifieer dan die opdrag aan die hand van die flash-datablad. Pulse korter as ’n klokperiode kan probe-geraas wees eerder as bemonsterde bisse, en ekstra krokodilklem-bedrading kan hoëspoed-opnames onbetroubaar maak.<sup>[[5]](#references)</sup>

Saleae se SPI-CSV-uitvoer gebruik `enable` en `disable` om ’n chip-select-interval af te baken, met MOSI/MISO-grepe in `result`-rye. Groepeer grepe volgens interval voordat jy dit dekodeer; as jy alle MISO-data aaneenvoeg, gaan transaksieadresse verlore.<sup>[[5]](#references)</sup> ’n Scapy `Packet` kan die MOSI-opskrif modelleer met ’n `ByteEnumField`-opcode en voorwaardelike adres- en dummy-velde. Vir 24-bis NOR-lesings het `0x03` ’n opcode en drie adresgrepe, terwyl `0x0B` ’n dummy-greep byvoeg. `len(req.self_build())` gee die lengte van die gemodelleerde opskrif: by ’n enkelbaan-lesing is `miso[header_length:]` die flash-antwoord, terwyl MOSI ná die opskrif data bevat waaroor die beheerder nie omgee nie. <sup>[[5]](#references)</sup> Plaas antwoorde by hul gedekodeerde adresse in ’n beeld wat met `0xFF` gevul is, en hou gedekte offsets apart by. ’n Byte wat nie waargeneem is nie, bewys nie dat die flash daar `0xFF` bevat het nie.<sup>[[5]](#references)[[6]](#references)</sup>

’n W25Q-styl `0x6B` (1-1-4)-lesing gebruik een baan vir die opcode en adres, maar IO0–IO3 vir antwoorddata. Aktiwiteit op die voormalige `/WP`- en `/HOLD`-penne is sterker bewys van ’n oorskakeling na quad-modus as ’n vinniger klok alleen; ’n enkelbaan-ontleder kan die quad-antwoord verkeerd dekodeer.<sup>[[5]](#references)</sup> Voer daardie fase uit met ’n QSPI-ontleder wat vir die opdrag se baanwydtes en dummy-siklusse opgestel is, en voeg dan die enkelbaan- en quadbaan-lesings saam volgens flash-adres.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` bespeur albei uitvoerformate outomaties, verwerp lesings wat met die verkeerde baanwydte gedekodeer is, en rapporteer leesdekking.<sup>[[6]](#references)</sup> Voer die volgende uit die repository uit om die opnames saam te voeg nadat jy die afhanklikhede geïnstalleer het:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Die resultaat bly ’n beperkte waarneming, nie ’n volledige chip-dump nie.<sup>[[5]](#references)[[6]](#references)</sup> Om skryfbewerkings afsonderlik te inspekteer, korreleer `0x06`-skryfaktivering, `0x05`-statuspeilings, uitvee-opkodes en `0x02`-bladsyprogrammeeropdragte. Bladsyprogrammeerdata volg die adres op MOSI en word nie by leesalleen-rekonstruksie ingesluit nie.<sup>[[5]](#references)</sup> Ontleed die resulterende beeld met [firmware analysis](../firmware-analysis/) en behou terselfdertyd die leesdekkingsinligting.

## References

- [1] [Analog Devices — Inleiding tot die SPI-koppelvlak](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom-handleiding — CH341A SPI-programmeerder en lees-/skryfopsies](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate-dokumentasie — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Opknapping van Hardware Hacking, Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Scapy uitbrei vir Hardware Reverse Engineering](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI-spoorvaslegging en -rekonstruksie](https://github.com/wrongbaud/spidump)
- [7] [QSPI-ontleder vir Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
