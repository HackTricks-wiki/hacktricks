# SPI

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

SPI (Serial Peripheral Interface) ni basi ya seriali inayotumia synchronous communication na hutumiwa kwa kawaida kwa mawasiliano ya umbali mfupi kati ya integrated circuits. Kidhibiti hutoa clock na kuchagua peripheral, kama vile EEPROM, sensor, au kifaa cha kudhibiti, kwa kutumia ishara ya chip-select.<sup>[[1]](#references)</sup>

Peripherals nyingi zinaweza kutumia pamoja mistari ya clock na data, kwa kawaida kila peripheral ikiwa na chip-select yake. Kidhibiti huratibu uhamishaji; kwa kawaida peripherals haziwasiliani moja kwa moja kupitia basi ya SPI. Polarity na timing ya chip-select hutegemea kifaa; active-low selection ni ya kawaida lakini si ya jumla. SPI haifafanui discovery, addressing, commands, au urefu mmoja wa juu kabisa wa uhamishaji, kwa hiyo kila mara rejelea datasheet ya kifaa lengwa.<sup>[[1]](#references)</sup>

MOSI/COPI hubeba data kutoka kwa kidhibiti kwenda kwa peripheral, na MISO/CIPO hubeba data kutoka kwa peripheral kwenda kwa kidhibiti. Mielekeo yote miwili inaweza kusogeza data kwa wakati mmoja. Uhusiano kati ya command, address, dummy cycles, na data inayorejeshwa hufafanuliwa na peripheral—si SPI—na hutegemea clock polarity na phase (modes 0–3). Usidhani kwamba output huanza hasa clock moja baada ya input kuisha.<sup>[[1]](#references)</sup>

## Kudump Firmware kutoka kwa EEPROM

Kudump firmware kunaweza kusaidia kuichanganua na kupata vulnerabilities. Huenda image sahihi isipatikane mtandaoni au ikatofautiana kulingana na model, hardware revision, au version, kwa hiyo kuichopoa moja kwa moja kutoka kwenye kifaa halisi hutoa target halisi ya assessment.

Serial console inaweza kusaidia, lakini filesystem yake inaweza kuwa read-only na huenda target isiwe na tools za analysis, zikiwemo utilities zinazohitajika kutuma/kupokea test traffic au kutoa binaries kwa urahisi. Image ya offline huhifadhi mpangilio kamili wa flash na huruhusu kutoa filesystem na kufanya reverse engineering bila kurekebisha target inayoendeshwa.

Wakati wa physical assessment iliyoidhinishwa, dump iliyothibitishwa inaweza pia kusaidia majaribio ya controlled modification na reflashing. Hii inajumuisha kubadilisha files au kuingiza test payload/backdoor ili kuonyesha persistence katika kiwango cha firmware. Hifadhi nakala nyingi za usomaji zinazolingana pamoja na image ya awali kabla ya kuandika chochote: voltage, chip selection, layout, au image isiyo sahihi inaweza kuharibu kifaa.

### CH341A EEPROM Programmer and Reader

Kifaa hiki cha USB cha bei nafuu kinaweza kudump na kureflash vifaa vinavyooana vya serial EEPROM na SPI flash. Hutumiwa kwa kawaida na chips za SPI NOR flash zinazohifadhi firmware ya PC BIOS/UEFI, na ni rahisi kutumia wakati wa physical access ya muda mfupi.

![drawing](../../images/board_image_ch341a.jpg)

Unganisha flash memory kwenye CH341A, kisha uunganishe programmer kwenye kompyuta. Ikiwa programmer yenyewe haitambuliki, kagua USB cable, ruhusa za OS, na CH341A driver inayofaa kabla ya kutatua matatizo ya chip lengwa. Thibitisha voltage ya chip, pin 1, wiring ya adapter, na output ya programmer kwa kutumia datasheets au meter—**usitegemee** kanuni kama kuweka VCC upande ulio kinyume na USB connector. Mwelekeo usio sahihi au kutumia 5 V kwenye kifaa cha 3.3/1.8 V kunaweza kukiharibu. Usomaji wa in-circuit pia unaweza kushindwa kwa sababu sehemu nyingine za board zinapakia au kuwasha basi.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Tumia software kama `flashrom` au G-Flash kusoma chip. G-Flash ni GUI ndogo na inaweza kutambua kiotomatiki vifaa vinavyooana, jambo linaloweza kusaidia wakati wa kupata data haraka, lakini thibitisha mwenyewe model na voltage iliyotambuliwa. Bainisha programmer halisi na, inapohitajika, model halisi ya chip; fanya usomaji angalau mara mbili na ulinganishe hashes zake kabla ya kuchukulia dump kuwa ya kuaminika.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Baada ya kudump firmware, analysis inaweza kufanywa kwenye binary files. Tools kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika kutoa taarifa nyingi kuhusu firmware na pia filesystem nzima.

Kwa uchunguzi wa awali, Binwalk inaweza kuchanganua signatures zinazojulikana na kutoa maudhui yaliyopachikwa inayoyasaidia:

```
binwalk -e <filename>
```

Faili ya matokeo inaweza kutumia kiendelezi `.bin`, `.rom` au kingine; kiendelezi hakibainishi umbizo.

> [!CAUTION]
> Kumbuka kwamba kutoa firmware ni mchakato nyeti unaohitaji uvumilivu mwingi. Utunzaji usiofaa unaweza kuharibu firmware au hata kuifuta kabisa na kufanya kifaa kisitumike. Inapendekezwa uchunguze kifaa husika kabla ya kujaribu kutoa firmware.

### Bus Pirate + flashrom

![Programmer na Kisomaji cha CH341A EEPROM - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Baadhi ya datasheet huandika pini lengwa kama `DI` na `DO`: kwa muunganisho wa kawaida wa flash wenye laini moja ya data, **MOSI/COPI ya controller huunganishwa na DI**, na **MISO/CIPO ya controller huunganishwa na DO**. Hakiki datasheet ya kifaa lengwa, kwa sababu sehemu za dual/quad I/O hutumia tena pini katika modi nyingine.

![Programmer na Kisomaji cha CH341A EEPROM - Bus Pirate + flashrom: Kumbuka kuwa hata kama PINOUT ya Pirate Bus inaonyesha pini za kuunganisha MOSI na MISO kwenye SPI, baadhi ya SPI zinaweza...](<../../images/image (360).png>)

Katika Windows au Linux unaweza kutumia programu [**`flashrom`**](https://www.flashrom.org/Flashrom) kunakili yaliyomo kwenye flash memory kwa kutekeleza kitu kama hiki:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nyaraka za hivi karibuni za Bus Pirate pia zinaonyesha vigezo vya hiari vya `serialspeed` na `spispeed`. Anza kwa kasi ya chini ikiwa nyaya ndefu au mzigo wa mzunguko uliopo unasababisha usomaji kutokuwa thabiti.<sup>[[3]](#references)</sup>

### Usomaji wa mzunguko uliopo wakati kidhibiti kinatumia basi moja la flash

Klipu ya SOIC inaweza kupeleka umeme wa flash kwenye sehemu nyingine za PCB. MCU ikiwashwa na kufikia chipu hiyo hiyo, uhamishaji wake wa SPI unaweza kugongana na uhamishaji wa programu ya nje. Kwa hiyo, matokeo ya `No EEPROM/flash device found` hayathibitishi kwamba flash haipo au haitumiki. Kwanza kagua mpangilio wa pini, volteji na mgusano, kisha tambua ikiwa kidhibiti kilicho kwenye bodi pia kinafanya kazi.<sup>[[4]](#references)</sup>

Ikiwa kuna pedi ya majaribio ya reset, thibitisha polarity na volteji yake kwa mita kabla ya kuiweka katika hali ya kuwashwa. Kuweka MCU kwenye reset kunaweza kuacha flash ikifikiwa huku kukisimamisha SPI host inayoshindana nayo. Njia nyingine ni kuondoa chipu kwa desoldering au kurekodi kwa njia tulivu usomaji wa MCU; njia ya pili haiwezi kufikia maeneo ambayo hayajasomwa au kuandika kwenye chipu, na nyaya za ziada za probe zinaweza kuvuruga basi la kasi. Kuingilia oscillator au hali ya boot hutegemea kifaa lengwa, na si mbadala wa kukagua schematic na mawimbi.<sup>[[4]](#references)</sup>

MCU ikiwa imesimamishwa, Raspberry Pi yenye kiolesura cha `spidev` kilichowashwa inaweza kusoma kupitia programu ya `linux_spi` ya flashrom. Badilisha `-p` ukitumia adapta tofauti. Rudia usomaji na ulinganishe hash kabla ya kuuamini; utambuzi wa kiotomatiki wa SFDP na usomaji uliofanikiwa **havithibitishi** kwamba erase, write au write-protect zitafanya kazi kwenye sehemu ambayo haitumiki vinginevyo.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Kuunda upya usomaji wa SPI flash kwa kutumia logic analyzer

Wakati usomaji wa moja kwa moja hauwezekani, nasa chip select, clock, data ya controller-to-flash na data ya flash-to-controller wakati wa boot au kitendo kilichochaguliwa kwenye UI. Katika PulseView, tambua kwanza kipindi cha chip-select inayotumika na clock, kisha sanidi chaneli za data za SPI decoder kulingana na pinout ya flash na uhakikishe kuwa kuna command/address inayowezekana ikifuatiwa na bytes zilizorejeshwa. Hamisha bytes za **MISO/flash-output** kwa kutumia Binary Decoder Output View na hifadhi anwani za usomaji zilizodecode ili kila jibu liwekwe kwenye offset yake inayolingana ya flash. Kunasa usomaji unaoanzishwa kupitia menyu pekee hupata maeneo yaliyoombwa tu, si picha kamili ya flash; usiunganishe majibu kana kwamba yanafuatana bila kukagua anwani.<sup>[[4]](#references)</sup>

Kwa dump inayoonekana kuwa na michoro badala ya code inayoweza kutekelezwa, endelea na [uchanganuzi wa awali wa raw display-asset](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Utangulizi wa Kiolesura cha SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Mwongozo wa flashrom — CH341A SPI programmer na chaguo za kusoma/kuandika](https://flashrom.org/classic_cli_manpage.html)
- [3] [Nyaraka za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Kuboresha Ujuzi wa Hardware Hacking, Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
