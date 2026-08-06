# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

SPI (Serial Peripheral Interface) is 'n Sinchrone Serial Communication Protocol wat in embedded systems gebruik word vir kortafstandkommunikasie tussen ICs (Integrated Circuits). SPI Communication Protocol maak gebruik van die master-slave-argitektuur, wat deur die Clock- en Chip Select Signal georkestreer word. 'n Master-slave-argitektuur bestaan uit 'n master (gewoonlik 'n mikroverwerker) wat eksterne peripherals soos EEPROM, sensors, beheertoestelle, ens. bestuur, wat as die slaves beskou word.

Veelvuldige slaves kan aan 'n master gekoppel word, maar slaves kan nie met mekaar kommunikeer nie. Slaves word deur twee pins, clock en chip select, geadministreer. Omdat SPI 'n sinchrone kommunikasieprotokol is, volg die input- en output-pins die clock-seine. Die chip select word deur die master gebruik om 'n slave te kies en daarmee te kommunikeer. Wanneer die chip select hoog is, word die slave device nie gekies nie, terwyl die chip gekies is wanneer dit laag is en die master met die slave kommunikeer.

Die MOSI (Master Out, Slave In) en MISO (Master In, Slave Out) is verantwoordelik vir die stuur en ontvangs van data. Data word deur die MOSI-pin na die slave device gestuur terwyl die chip select laag gehou word. Die input-data bevat instruksies, memory addresses of data volgens die datasheet van die slave device se vendor. Na geldige input is die MISO-pin verantwoordelik vir die oordrag van data na die master. Die output-data word presies in die volgende clock cycle gestuur nadat die input geëindig het. Die MISO-pins stuur data totdat die data volledig oorgedra is of totdat die master die chip select-pin hoog stel (in daardie geval sal die slave ophou stuur en die master sal ná daardie clock cycle nie meer luister nie).

## Firmware vanaf EEPROMs Dump

Die dumping van firmware kan nuttig wees om die firmware te ontleed en vulnerabilities daarin te vind. Dikwels is die firmware nie op die internet beskikbaar nie of is dit irrelevant weens variasies in faktore soos modelnommer, weergawe, ens. Daarom kan die direkte ekstraksie van die firmware vanaf die fisiese device nuttig wees om spesifiek na threats te soek.

Om 'n Serial Console te kry kan nuttig wees, maar dikwels gebeur dit dat die files read-only is. Dit beperk die analise om verskeie redes. Byvoorbeeld, tools wat nodig is om packages te stuur en te ontvang, sal nie in die firmware beskikbaar wees nie. Die ekstraksie van die binaries om hulle te reverse engineer is dus nie haalbaar nie. Daarom kan dit baie nuttig wees om die volledige firmware op die system te dump en die binaries vir analise te onttrek.

Ook tydens red teaming en wanneer fisiese toegang tot devices verkry word, kan die dumping van firmware help om die files te wysig of malicious files in te spuit en hulle dan terug in die memory te flash, wat nuttig kan wees om 'n backdoor in die device te plant. Daar is dus talle moontlikhede wat met firmware dumping ontsluit kan word.

### CH341A EEPROM Programmer and Reader

Hierdie device is 'n goedkoop tool vir die dumping van firmware vanaf EEPROMs en om dit ook weer met firmware files te flash. Dit was 'n gewilde keuse vir werk met computer BIOS chips (wat bloot EEPROMs is). Hierdie device verbind oor USB en benodig minimale tools om te begin. Dit voltooi gewoonlik ook die taak vinnig, en kan dus nuttig wees vir fisiese toegang tot devices.

![tekening](../../images/board_image_ch341a.jpg)

Koppel die EEPROM memory aan die CH341a Programmer en prop die device by die computer in. Indien die device nie opgespoor word nie, probeer om drivers op die computer te installeer. Maak ook seker dat die EEPROM in die korrekte oriëntasie gekoppel is (plaas gewoonlik die VCC Pin in die teenoorgestelde oriëntasie as die USB connector); anders sal die software nie die chip kan opspoor nie. Verwys na die diagram indien nodig:

![tekening](../../images/connect_wires_ch341a.jpg) ![tekening](../../images/eeprom_plugged_ch341a.jpg)

Gebruik laastens softwares soos flashrom, G-Flash (GUI), ens. om die firmware te dump. G-Flash is 'n minimale GUI tool wat vinnig is en die EEPROM outomaties opspoor. Dit kan nuttig wees wanneer die firmware vinnig onttrek moet word sonder om veel met die documentation te eksperimenteer.

![tekening](../../images/connected_status_ch341a.jpg)

Nadat die firmware gedump is, kan die analise op die binary files gedoen word. Tools soos strings, hexdump, xxd, binwalk, ens. kan gebruik word om baie inligting oor die firmware sowel as die hele file system te onttrek.

Om die contents vanaf die firmware te onttrek, kan binwalk gebruik word. Binwalk analiseer hex signatures, identifiseer die files in die binary file en is in staat om hulle te onttrek.
```
binwalk -e <filename>
```
Dit kan .bin of .rom wees, volgens die tools en konfigurasies wat gebruik word.

> [!CAUTION]
> Let daarop dat firmware-ekstraksie 'n delikate proses is en baie geduld vereis. Enige verkeerde hantering kan die firmware moontlik korrupteer of dit selfs heeltemal uitvee, wat die toestel onbruikbaar kan maak. Dit word aanbeveel om die spesifieke toestel te bestudeer voordat jy probeer om die firmware te onttrek.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Let daarop dat selfs al dui die PINOUT van die Pirate Bus penne vir **MOSI** en **MISO** aan om aan SPI te koppel, sommige SPIs penne as DI en DO kan aandui. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

In Windows of Linux kan jy die program [**`flashrom`**](https://www.flashrom.org/Flashrom) gebruik om die inhoud van die flash memory te dump deur iets soos die volgende uit te voer:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
