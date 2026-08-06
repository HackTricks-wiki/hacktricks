# SPI

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

SPI (Serial Peripheral Interface) ni Synchronous Serial Communication Protocol inayotumika katika embedded systems kwa mawasiliano ya umbali mfupi kati ya ICs (Integrated Circuits). SPI Communication Protocol hutumia master-slave architecture inayoendeshwa na Clock na Chip Select Signal. Master-slave architecture huwa na master (kwa kawaida microprocessor) inayodhibiti external peripherals kama EEPROM, sensors, control devices, n.k., ambazo huchukuliwa kuwa slaves.

Slaves wengi wanaweza kuunganishwa kwenye master, lakini slaves hawawezi kuwasiliana wao kwa wao. Slaves hudhibitiwa na pins mbili, clock na chip select. Kwa kuwa SPI ni synchronous communication protocol, input na output pins hufuata clock signals. Chip select hutumiwa na master kuchagua slave na kuwasiliana nayo. Chip select ikiwa high, slave device haijachaguliwa; ikiwa low, chip imechaguliwa na master itakuwa ikiwasiliana na slave.

MOSI (Master Out, Slave In) na MISO (Master In, Slave Out) zinahusika na kutuma na kupokea data. Data hutumwa kwenye slave device kupitia MOSI pin wakati chip select ikiwa low. Input data huwa na instructions, memory addresses au data kulingana na datasheet ya mtengenezaji wa slave device. Input halali inapopokelewa, MISO pin huwa na jukumu la kutuma data kwa master. Output data hutumwa katika clock cycle inayofuata mara tu input inapomalizika. MISO pins hutuma data hadi data yote itakapokuwa imetumwa au master iweke chip select pin kuwa high (katika hali hiyo, slave itaacha kutuma na master haitasikiliza baada ya clock cycle hiyo).

## Kudump Firmware kutoka kwenye EEPROMs

Kudump firmware kunaweza kusaidia katika kuichanganua firmware na kutafuta vulnerabilities ndani yake. Mara nyingi firmware haipatikani kwenye internet au huwa haina umuhimu kutokana na tofauti za mambo kama model number, version, n.k. Kwa hiyo, kutoa firmware moja kwa moja kutoka kwenye physical device kunaweza kusaidia kuwa sahihi wakati wa kutafuta threats.

Kupata Serial Console kunaweza kusaidia, lakini mara nyingi files huwa read-only. Hili huzuia uchanganuzi kwa sababu mbalimbali. Kwa mfano, tools zinazohitajika kutuma na kupokea packages hazitakuwepo kwenye firmware. Kwa hiyo, kutoa binaries kwa ajili ya kuzireverse engineer si jambo linalowezekana. Hivyo, kuwa na firmware yote ikiwa imedump kwenye system na kutoa binaries kwa ajili ya analysis kunaweza kusaidia sana.

Pia, wakati wa red teaming na kupata physical access kwenye devices, kudump firmware kunaweza kusaidia kurekebisha files au kuingiza malicious files na kisha kuzi-reflash kwenye memory, jambo ambalo linaweza kusaidia kuimplant backdoor kwenye device. Kwa hiyo, kuna uwezekano mwingi unaoweza kufunguliwa kwa kudump firmware.

### CH341A EEPROM Programmer and Reader

Device hii ni tool ya gharama nafuu ya kudump firmwares kutoka kwenye EEPROMs na pia kuzi-reflash kwa kutumia firmware files. Imekuwa chaguo maarufu kwa kufanya kazi na computer BIOS chips (ambazo ni EEPROMs tu). Device hii huunganishwa kupitia USB na inahitaji tools chache kuanza kuitumia. Pia, kwa kawaida hukamilisha kazi haraka, hivyo inaweza kusaidia wakati wa physical access kwenye devices.

![drawing](../../images/board_image_ch341a.jpg)

Unganisha EEPROM memory kwenye CH341a Programmer na uunganishe device kwenye computer. Ikiwa device haitambuliki, jaribu kusakinisha drivers kwenye computer. Pia, hakikisha kwamba EEPROM imeunganishwa katika mwelekeo sahihi (kwa kawaida, weka VCC Pin katika mwelekeo wa kinyume na USB connector); vinginevyo, software haitaweza kutambua chip. Rejelea mchoro ikihitajika:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Mwishowe, tumia softwares kama flashrom, G-Flash (GUI), n.k. kudump firmware. G-Flash ni minimal GUI tool yenye kasi na hutambua EEPROM automatically. Hii inaweza kusaidia firmware inapohitaji kutolewa haraka, bila kutumia muda mwingi kuchunguza documentation.

![drawing](../../images/connected_status_ch341a.jpg)

Baada ya kudump firmware, analysis inaweza kufanywa kwenye binary files. Tools kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumiwa kutoa taarifa nyingi kuhusu firmware pamoja na file system yote.

Ili kutoa contents kutoka kwenye firmware, binwalk inaweza kutumiwa. Binwalk huchanganua hex signatures na kutambua files ndani ya binary file, na inaweza kuzitoa.
```
binwalk -e <filename>
```
Inaweza kuwa .bin au .rom kulingana na tools na configurations zilizotumika.

> [!CAUTION]
> Kumbuka kwamba firmware extraction ni mchakato nyeti na unahitaji uvumilivu mwingi. Ushughulikiaji usiofaa unaweza kuharibu firmware au hata kuifuta kabisa na kufanya device ishindwe kutumika. Inapendekezwa kuchunguza device mahususi kabla ya kujaribu kufanya firmware extraction.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Kumbuka kwamba hata kama PINOUT ya Pirate Bus inaonyesha pins za **MOSI** na **MISO** za kuunganisha kwenye SPI, baadhi ya SPI zinaweza kuonyesha pins hizo kama DI na DO. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Kumbuka kwamba hata kama PINOUT ya Pirate Bus inaonyesha pins za MOSI na MISO za kuunganisha kwenye SPI, baadhi ya SPI zinaweza...](<../../images/image (360).png>)

Kwenye Windows au Linux unaweza kutumia program [**`flashrom`**](https://www.flashrom.org/Flashrom) kudump content ya flash memory kwa kuendesha kitu kama:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
