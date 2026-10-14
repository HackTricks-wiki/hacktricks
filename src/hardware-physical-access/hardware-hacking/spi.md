# SPI

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

SPI (Serial Peripheral Interface) ni basi la serial linalotumia saa ya kusawazisha, na hutumiwa kwa kawaida kwa mawasiliano ya umbali mfupi kati ya saketi jumuishi. Kidhibiti hutoa saa na kuchagua kifaa cha pembeni, kama vile EEPROM, kihisi, au kifaa cha kudhibiti, kwa kutumia ishara ya chip-select.<sup>[[1]](#references)</sup>

Vifaa vingi vya pembeni vinaweza kushiriki mistari ya saa na data, kwa kawaida kila kifaa kikiwa na chip-select yake. Kidhibiti huratibu uhamishaji; kwa kawaida vifaa vya pembeni haviwasiliani moja kwa moja kupitia basi la SPI. Polarity na timing ya chip-select hutegemea kifaa; kuchagua kwa active-low ni jambo la kawaida, lakini si la kila wakati. SPI haifafanui ugunduzi, uadressishaji, amri, au urefu mmoja wa juu wa uhamishaji, kwa hivyo rejelea datasheet ya kifaa lengwa kila wakati.<sup>[[1]](#references)</sup>

MOSI/COPI hubeba data kutoka kwa kidhibiti kwenda kwa kifaa cha pembeni, na MISO/CIPO hubeba data kutoka kwa kifaa cha pembeni kwenda kwa kidhibiti. Pande zote mbili zinaweza kuhamisha data kwa wakati mmoja. Uhusiano kati ya amri, anwani, mizunguko ya dummy, na data inayorejeshwa hufafanuliwa na kifaa cha pembeni—si na SPI—na hutegemea polarity na phase ya saa (modes 0–3). Usidhani kwamba utoaji wa data huanza hasa saa moja baada ya ingizo kuisha.<sup>[[1]](#references)</sup>

## Kudump Firmware kutoka kwa EEPROM

Kudump firmware kunaweza kusaidia kuichanganua na kutafuta udhaifu. Huenda picha sahihi isipatikane mtandaoni, au ikatofautiana kulingana na modeli, toleo la hardware, au toleo la firmware. Kwa hiyo, kuichopoa moja kwa moja kutoka kwenye kifaa halisi hutoa lengo sahihi la tathmini.

Serial console inaweza kusaidia, lakini mfumo wake wa faili unaweza kuwa wa kusoma pekee, na kifaa lengwa huenda kikakosa zana za uchanganuzi, zikiwemo huduma zinazohitajika kutuma/kupokea traffic ya majaribio au kuchopoa binaries kwa urahisi. Picha ya offline huhifadhi mpangilio mzima wa flash na huruhusu kuchopoa mfumo wa faili na kufanya reverse engineering bila kurekebisha kifaa lengwa kinachoendeshwa.

Wakati wa tathmini ya kimwili iliyoidhinishwa, dump iliyothibitishwa inaweza pia kusaidia majaribio yanayodhibitiwa ya kurekebisha na kuandika upya firmware. Hii inajumuisha kubadilisha faili au kuingiza payload/backdoor ya majaribio ili kuonyesha persistence ya kiwango cha firmware. Hifadhi nakala kadhaa za usomaji zinazolingana na picha asili kabla ya kuandika chochote: voltage, chip selection, mpangilio, au picha isiyo sahihi inaweza kuharibu kifaa.

### CH341A EEPROM Programmer na Reader

Kifaa hiki cha USB cha gharama nafuu kinaweza kudump na kuandika upya serial EEPROM na SPI flash zinazooana. Hutumiwa sana na chips za SPI NOR flash zinazohifadhi firmware ya PC BIOS/UEFI, na kinafaa wakati wa ufikiaji wa kimwili wenye muda mfupi.

![drawing](../../images/board_image_ch341a.jpg)

Unganisha flash memory kwenye CH341A kisha uunganishe programmer kwenye kompyuta. Ikiwa programmer yenyewe haitambuliki, kagua kebo ya USB, ruhusa za OS, na driver inayofaa ya CH341A kabla ya kutatua matatizo ya chip lengwa. Thibitisha voltage ya chip, pin 1, nyaya za adapter, na output ya programmer kwa kutumia datasheet au mita—**usitegemee** kanuni kama kuweka VCC upande wa pili wa kiunganishi cha USB. Mwelekeo usio sahihi au kuweka 5 V kwenye kifaa cha 3.3/1.8 V kunaweza kukiharibu. Usomaji wa chip ikiwa bado imeunganishwa kwenye circuit pia unaweza kushindwa kwa sababu sehemu nyingine za board huweka mzigo kwenye basi au kulipa umeme.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Tumia programu kama `flashrom` au G-Flash kusoma chip. G-Flash ni GUI rahisi na inaweza kutambua vifaa vinavyooana kiotomatiki; hili linaweza kufaa wakati wa upataji wa haraka, lakini hakikisha mwenyewe modeli na voltage zilizotambuliwa. Bainisha programmer sahihi na, inapohitajika, modeli halisi ya chip; fanya angalau usomaji mara mbili na ulinganishe hash zake kabla ya kuichukulia dump kuwa ya kuaminika.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Baada ya kudump firmware, uchanganuzi unaweza kufanywa kwenye binary files. Zana kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika kuchopoa taarifa nyingi kuhusu firmware na mfumo mzima wa faili pia.

Kwa uchunguzi wa awali, Binwalk inaweza kuchanganua signatures zinazojulikana na kuchopoa maudhui yaliyopachikwa yanayotumika:

```
binwalk -e <filename>
```

Faili la matokeo linaweza kutumia `.bin`, `.rom` au kiendelezi kingine; kiendelezi hakibainishi umbizo.

> [!CAUTION]
> Kumbuka kuwa kutoa firmware ni mchakato nyeti unaohitaji uvumilivu mkubwa. Kushughulikia vibaya kunaweza kuharibu firmware au hata kuifuta kabisa na kufanya kifaa kisiweze kutumika. Inapendekezwa kujifunza kuhusu kifaa husika kabla ya kujaribu kutoa firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Baadhi ya datasheet hutaja pini za kifaa lengwa kama `DI` na `DO`: kwa muunganisho wa kawaida wa flash wenye laini moja ya data, **MOSI/COPI ya kidhibiti huunganishwa na DI**, na **MISO/CIPO ya kidhibiti huunganishwa na DO**. Thibitisha kwenye datasheet ya kifaa lengwa, kwa kuwa sehemu zinazotumia I/O mbili/nne hutumia tena pini hizo katika modi nyingine.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Kumbuka kuwa ingawa PINOUT ya Pirate Bus inaonyesha pini za MOSI na MISO za kuunganisha kwenye SPI, baadhi ya SPI zinaweza...](<../../images/image (360).png>)

Katika Windows au Linux unaweza kutumia programu ya [**`flashrom`**](https://www.flashrom.org/Flashrom) kufanya dump ya maudhui ya kumbukumbu ya flash kwa kutekeleza amri kama hii:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nyaraka za hivi karibuni za Bus Pirate pia zinaonyesha vigezo vya hiari vya `serialspeed` na `spispeed`. Anza kwa kasi ya chini ikiwa nyaya ndefu au mzigo wa mzunguko uliopo unasababisha usomaji kutokuwa thabiti.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Utangulizi wa Kiolesura cha SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Mwongozo wa flashrom — CH341A SPI programmer na chaguo za kusoma/kuandika](https://flashrom.org/classic_cli_manpage.html)
- [3] [Nyaraka za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
