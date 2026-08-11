# SPI

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

SPI (Serial Peripheral Interface) ni basi la synchronous serial linalotumiwa kwa kawaida kwa mawasiliano ya umbali mfupi kati ya integrated circuits. Controller hutoa clock na kuchagua peripheral, kama EEPROM, sensor, au kifaa cha udhibiti, kwa kutumia signal ya chip-select.<sup>[[1]](#references)</sup>

Peripherals nyingi zinaweza kushiriki mistari ya clock na data, kwa kawaida kila peripheral ikiwa na chip-select yake. Controller huratibu transfers; kwa kawaida peripherals haziwasiliani moja kwa moja zenyewe kupitia basi la SPI. Polarity na timing ya chip-select hutegemea kifaa; active-low selection ni ya kawaida lakini si ya kila mahali. SPI haifafanui discovery, addressing, commands, au urefu mmoja wa juu wa transfer, kwa hiyo soma datasheet ya target kila wakati.<sup>[[1]](#references)</sup>

MOSI/COPI hubeba data kutoka kwa controller kwenda kwa peripheral, na MISO/CIPO hubeba data kutoka kwa peripheral kwenda kwa controller. Mielekeo yote miwili inaweza ku-shift kwa wakati mmoja. Uhusiano kati ya command, address, dummy cycles, na data inayorejeshwa hufafanuliwa na peripheral—si na SPI—na hutegemea clock polarity na phase (modes 0–3). Usidhani kwamba output huanza clock moja tu baada ya input kuisha.<sup>[[1]](#references)</sup>

## Ku-Dump Firmware kutoka kwenye EEPROMs

Ku-dump firmware kunaweza kusaidia katika kuichanganua na kutafuta vulnerabilities. Image sahihi huenda isipatikane online au ikatofautiana kulingana na model, hardware revision, au version, kwa hiyo kuiextract moja kwa moja kutoka kwenye kifaa halisi hutoa target sahihi ya assessment.

Serial console inaweza kusaidia, lakini filesystem yake inaweza kuwa read-only na target inaweza kukosa analysis tools, zikiwemo utilities zinazohitajika kutuma/kupokea test traffic au ku-extract binaries kwa urahisi. Image ya offline huhifadhi flash layout kamili na kuruhusu filesystem extraction pamoja na reverse engineering bila kurekebisha target inayoendesha.

Wakati wa authorized physical assessment, dump iliyothibitishwa inaweza pia kusaidia controlled modification na reflashing tests. Hii inajumuisha kubadilisha files au kuingiza test payload/backdoor ili kuonyesha firmware-level persistence. Hifadhi reads nyingi zinazolingana na image ya awali kabla ya write yoyote: voltage, chip selection, layout, au image isiyo sahihi inaweza ku-brick kifaa.

### CH341A EEPROM Programmer and Reader

Kifaa hiki cha USB cha bei nafuu kinaweza ku-dump na ku-reflash serial EEPROM na SPI flash devices zinazoendana. Hutumiwa kwa kawaida pamoja na SPI NOR flash chips zinazohifadhi PC BIOS/UEFI firmware na ni rahisi kutumia wakati wa physical access yenye muda mfupi.

![mchoro](../../images/board_image_ch341a.jpg)

Unganisha flash memory kwenye CH341A, kisha unganisha programmer kwenye computer. Ikiwa programmer yenyewe haijatambuliwa, kagua USB cable, OS permissions, na CH341A driver inayofaa kabla ya kutatua matatizo ya target chip. Thibitisha voltage ya chip, pin 1, adapter wiring, na programmer output kwa kutumia datasheets au meter—**usitegemee** kanuni kama kuweka VCC upande wa kinyume na USB connector. Mwelekeo usio sahihi au 5 V iliyowekwa kwenye part ya 3.3/1.8 V inaweza kuiharibu. In-circuit reads pia zinaweza kushindwa kwa sababu sehemu nyingine ya board hu-load au ku-power bus.<sup>[[2]](#references)</sup>

![mchoro](../../images/connect_wires_ch341a.jpg) ![mchoro](../../images/eeprom_plugged_ch341a.jpg)

Tumia software kama `flashrom` au G-Flash kusoma chip. G-Flash ni GUI ndogo na inaweza auto-detect devices zinazoendana, jambo linaloweza kuwa rahisi wakati wa quick acquisition, lakini thibitisha mwenyewe model na voltage iliyotambuliwa. Bainisha programmer halisi na, inapohitajika, model halisi ya chip; fanya reads angalau mbili na ulinganishe hashes zake kabla ya kuchukulia dump kuwa reliable.<sup>[[2]](#references)</sup>

![mchoro](../../images/connected_status_ch341a.jpg)

Baada ya ku-dump firmware, analysis inaweza kufanywa kwenye binary files. Tools kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika ku-extract taarifa nyingi kuhusu firmware pamoja na filesystem nzima.

Kwa initial triage, Binwalk inaweza kuscan known signatures na ku-extract embedded content inayoungwa mkono:
```
binwalk -e <filename>
```
Faili ya output inaweza kutumia `.bin`, `.rom`, au kiendelezi kingine; kiendelezi hakibainishi format.

> [!CAUTION]
> Kumbuka kwamba uchimbaji wa firmware ni mchakato nyeti na unahitaji uvumilivu mwingi. Ushughulikiaji usio sahihi unaweza kuharibu firmware au hata kuifuta kabisa na kufanya kifaa kisiweze kutumika. Inapendekezwa kuchunguza kifaa husika kabla ya kujaribu kuchimba firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Baadhi ya datasheet hutaja pini lengwa kama `DI` na `DO`: kwa muunganisho wa kawaida wa flash wenye laini moja ya data, **MOSI/COPI ya controller huunganishwa na DI**, na **MISO/CIPO ya controller huunganishwa na DO**. Hakikisha unaangalia datasheet ya kifaa lengwa kwa sababu sehemu zenye I/O ya dual/quad hutumia tena pini hizo katika modes nyingine.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Kumbuka kwamba hata kama PINOUT ya Pirate Bus inaonyesha pini za MOSI na MISO kuunganishwa na SPI, baadhi ya SPI zinaweza...](<../../images/image (360).png>)

Katika Windows au Linux unaweza kutumia programu [**`flashrom`**](https://www.flashrom.org/Flashrom) kutupa yaliyomo ya flash memory kwa kuendesha kitu kama:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Nyaraka za hivi karibuni za Bus Pirate pia zinaonyesha vigezo vya hiari vya `serialspeed` na `spispeed`. Anza kwa mipangilio ya tahadhari ikiwa nyaya ndefu au mzigo wa in-circuit unafanya usomaji usiwe thabiti.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Utangulizi wa Kiolesura cha SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Mwongozo wa flashrom — CH341A SPI programmer na chaguo za kusoma/kuandika](https://flashrom.org/classic_cli_manpage.html)
- [3] [Nyaraka za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
