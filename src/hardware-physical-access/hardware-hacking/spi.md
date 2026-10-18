# SPI

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

SPI (Serial Peripheral Interface) ni basi ya seriali inayotumia clock na hutumiwa kwa kawaida kwa mawasiliano ya umbali mfupi kati ya integrated circuits. Controller hutoa clock na kuchagua peripheral, kama vile EEPROM, sensor, au kifaa cha udhibiti, kwa kutumia signal ya chip-select.<sup>[[1]](#references)</sup>

Peripherals nyingi zinaweza kutumia kwa pamoja mistari ya clock na data; kwa kawaida kila peripheral huwa na chip-select yake. Controller huratibu uhamishaji wa data; kwa kawaida peripherals haziwasiliani moja kwa moja kupitia basi ya SPI. Polarity na timing za chip-select hutegemea kifaa; uteuzi wa active-low ni wa kawaida lakini si wa lazima. SPI haifafanui ugunduzi, addressing, commands, au urefu mmoja wa juu zaidi wa uhamishaji, kwa hivyo soma datasheet ya kifaa lengwa kila wakati.<sup>[[1]](#references)</sup>

MOSI/COPI hubeba data kutoka controller kwenda peripheral, na MISO/CIPO hubeba data kutoka peripheral kwenda controller. Pande zote mbili zinaweza kusogeza data kwa wakati mmoja. Uhusiano kati ya command, address, dummy cycles na data inayorudishwa hufafanuliwa na peripheral—si na SPI—na hutegemea clock polarity na phase (modes 0–3). Usidhani kwamba matokeo huanza clock moja tu baada ya ingizo kuisha.<sup>[[1]](#references)</sup>

## Kudump Firmware kutoka EEPROMs

Kudump firmware kunaweza kusaidia kuichanganua na kutafuta vulnerabilities. Huenda image sahihi isipatikane mtandaoni au ikatofautiana kulingana na model, hardware revision au version; kwa hiyo, kuichukua moja kwa moja kutoka kwenye kifaa halisi hutoa target sahihi ya assessment.

Serial console inaweza kusaidia, lakini filesystem yake inaweza kuwa read-only na huenda target isiwe na zana za analysis, zikiwemo utilities zinazohitajika kutuma/kupokea test traffic au kutoa binaries kwa urahisi. Image ya offline huhifadhi mpangilio kamili wa flash na huruhusu kutoa filesystem na kufanya reverse engineering bila kurekebisha target inayoendeshwa.

Wakati wa authorized physical assessment, dump iliyothibitishwa inaweza pia kusaidia majaribio yaliyodhibitiwa ya kurekebisha na kuandika upya firmware. Hii inajumuisha kubadilisha files au kuingiza test payload/backdoor ili kuonyesha persistence ya firmware. Hifadhi reads nyingi zinazolingana na image asilia kabla ya kuandika chochote: voltage, chip iliyochaguliwa, mpangilio au image isiyo sahihi inaweza kuifanya kifaa kisifanye kazi.

### CH341A EEPROM Programmer and Reader

Zana hii ya USB ya bei nafuu inaweza kudump na kuandika upya vifaa vinavyooana vya serial EEPROM na SPI flash. Hutumiwa sana na chips za SPI NOR flash zinazohifadhi firmware ya PC BIOS/UEFI, na ni rahisi kutumia wakati wa physical access wa muda mfupi.

![drawing](../../images/board_image_ch341a.jpg)

Unganisha flash memory kwenye CH341A, kisha unganisha programmer kwenye kompyuta. Ikiwa programmer yenyewe haitambuliki, kagua kebo ya USB, ruhusa za OS na driver inayofaa ya CH341A kabla ya kutatua matatizo ya chip lengwa. Thibitisha voltage ya chip, pin 1, wiring ya adapter na output ya programmer ukitumia datasheets au mita—**usitegemee** kanuni kama vile kuweka VCC upande ulio kinyume na kiunganishi cha USB. Kuelekeza vibaya au kutumia 5 V kwenye kifaa cha 3.3/1.8 V kunaweza kukiharibu. Kusoma chip ikiwa bado imeunganishwa kwenye board kunaweza pia kushindwa kwa sababu sehemu nyingine za board huathiri au kuwasha basi.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Tumia software kama `flashrom` au G-Flash kusoma chip. G-Flash ni GUI rahisi na inaweza kutambua kiotomatiki vifaa vinavyooana, jambo linaloweza kusaidia wakati wa kupata data haraka, lakini thibitisha mwenyewe model na voltage iliyotambuliwa. Bainisha programmer husika na, inapohitajika, model halisi ya chip; fanya reads angalau mbili na ulinganishe hashes zake kabla ya kuchukulia dump kuwa ya kuaminika.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Baada ya kudump firmware, unaweza kuchanganua binary files. Zana kama strings, hexdump, xxd, binwalk, n.k. zinaweza kutumika kutoa taarifa nyingi kuhusu firmware na filesystem nzima pia.

Kwa uchunguzi wa awali, Binwalk inaweza kuchanganua signatures zinazojulikana na kutoa maudhui yaliyopachikwa yanayoungwa mkono:

```
binwalk -e <filename>
```

Faili ya matokeo inaweza kutumia `.bin`, `.rom` au kiendelezi kingine; kiendelezi hakibainishi muundo.

> [!CAUTION]
> Kumbuka kuwa kutoa firmware ni mchakato unaohitaji umakini na uvumilivu mwingi. Ushughulikiaji wowote usiofaa unaweza kuharibu firmware au hata kuifuta kabisa na kufanya kifaa kisitumike. Inapendekezwa kuchunguza kifaa mahususi kabla ya kujaribu kutoa firmware.

### Bus Pirate + flashrom

![Programu na Kisomaji cha CH341A EEPROM - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Baadhi ya datasheet hutaja pini lengwa kama `DI` na `DO`: kwa muunganisho wa kawaida wa flash wenye laini moja ya data, **MOSI/COPI ya kidhibiti huunganishwa na DI** na **MISO/CIPO ya kidhibiti huunganishwa na DO**. Hakiki datasheet ya kifaa lengwa kwa sababu sehemu za I/O za dual/quad hutumia tena pini katika modi nyingine.

![Programu na Kisomaji cha CH341A EEPROM - Bus Pirate + flashrom: Kumbuka kuwa hata kama PINOUT ya Pirate Bus inaonyesha pini za MOSI na MISO za kuunganisha kwenye SPI, baadhi ya SPI zinaweza...](<../../images/image (360).png>)

Katika Windows au Linux unaweza kutumia programu ya [**`flashrom`**](https://www.flashrom.org/Flashrom) kutupa maudhui ya kumbukumbu ya flash kwa kuendesha kitu kama:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Nyaraka za hivi karibuni za Bus Pirate pia zinaonyesha vigezo vya hiari vya `serialspeed` na `spispeed`. Anza kwa kasi ya chini ikiwa nyaya ndefu au mzigo wa saketi wakati chipu ikiwa imeunganishwa unasababisha usomaji kutokuwa thabiti.<sup>[[3]](#references)</sup>

### Usomaji chipu ikiwa imeunganishwa kwenye saketi huku kidhibiti kikitumia bus ya flash

Klipu ya SOIC inaweza kusambaza umeme wa flash kwenye sehemu nyingine za PCB. MCU ikiwashwa na kufikia chipu hiyo hiyo, uhamishaji wake wa SPI unaweza kugongana na uhamishaji wa programmer ya nje. Kwa hivyo, matokeo ya `No EEPROM/flash device found` hayathibitishi kwamba flash haipo au haitumiki. Kagua kwanza mpangilio wa pini, voltage na mgusano, kisha tambua ikiwa kidhibiti kilichopo kwenye ubao pia kinafanya kazi.<sup>[[4]](#references)</sup>

Ikiwa kuna test pad ya reset, thibitisha polarity na voltage yake kwa mita kabla ya kuiwasha. Kuweka MCU katika hali ya reset kunaweza kufanya flash ipatikane huku kukisimamisha SPI host inayoshindana nayo. Njia nyingine ni kuondoa chipu kwa kuondoa solder au kurekodi tu usomaji wa MCU; njia ya pili haiwezi kufikia maeneo ambayo hayajasomwa wala kuandika kwenye chipu, na nyaya za ziada za probe zinaweza kuvuruga bus yenye kasi. Kuingilia oscillator au boot mode hutegemea kifaa lengwa; si mbadala wa kukagua schematic na mawimbi.<sup>[[4]](#references)</sup>

MCU ikiwa imezuiwa kufanya kazi, Raspberry Pi yenye kiolesura cha `spidev` kilichowashwa inaweza kusoma kupitia programmer ya `linux_spi` ya flashrom. Badilisha `-p` ikiwa unatumia adapter tofauti. Rudia usomaji na ulinganishe hashes kabla ya kuamini matokeo; utambuzi otomatiki wa SFDP na usomaji uliofaulu **havithibitishi** kwamba shughuli za kufuta, kuandika au write-protect zitafanya kazi kwenye chipu ambayo vinginevyo haitumiki.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Kujenga upya usomaji wa SPI flash kwa kutumia logic analyzer

Wakati usomaji hai hauwezekani, nasa chip select, clock, data kutoka kwa controller kwenda flash na data kutoka flash kwenda kwa controller wakati wa kuwasha kifaa au hatua iliyochaguliwa kwenye UI. Katika PulseView, tambua kwanza muda ambao chip-select iko hai na clock, kisha sanidi channels za data za SPI decoder kulingana na pinout ya flash na uthibitishe kuwa kuna command/address inayowezekana ikifuatiwa na bytes zilizorejeshwa. Hamisha bytes za **MISO/flash-output** kwa kutumia Binary Decoder Output View na hifadhi anwani za usomaji zilizodecode ili kila jibu liwekwe kwenye offset yake inayolingana kwenye flash. Kunasa usomaji unaoanzishwa na menyu pekee kunatoa maeneo yaliyoombwa tu, si picha kamili ya flash; usiunganishe majibu kana kwamba yanafuatana bila kukagua anwani.<sup>[[4]](#references)</sup>

Ikiwa dump inaonekana kuwa na michoro badala ya code inayoweza kutekelezwa, endelea na [uchunguzi wa awali wa raw display assets](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy na kunasa kwa SPI/QSPI mchanganyiko

Kwa probes zisizo na lebo, tofautisha MOSI na MISO kwa kutambua laini inayobeba opcode kabla ya data ya majibu, kisha thibitisha command dhidi ya datasheet ya flash. Mapigo mafupi kuliko upana wa clock yanaweza kuwa kelele za probe badala ya bits zilizopimwa, na waya za ziada za clips zinaweza kufanya kunasa kwa kasi ya juu kusiwe kwa kutegemewa.<sup>[[5]](#references)</sup>

Uhamishaji wa CSV wa Saleae wa SPI hutumia `enable` na `disable` kuweka mipaka ya kipindi cha chip-select, huku bytes za MOSI/MISO zikiwa katika rows za `result`. Panga bytes kwa vipindi kabla ya kuzidecode; kuunganisha data yote ya MISO hupoteza anwani za transactions.<sup>[[5]](#references)</sup> Scapy `Packet` inaweza kuwakilisha kichwa cha MOSI kwa kutumia opcode ya `ByteEnumField` na fields za anwani na dummy zenye masharti. Kwa usomaji wa NOR wa biti 24, `0x03` ina opcode na bytes tatu za anwani, huku `0x0B` ikiongeza byte moja ya dummy. `len(req.self_build())` hutoa urefu wa kichwa kilichowakilishwa: kwenye usomaji wa lane moja, `miso[header_length:]` ni jibu la flash, huku MOSI baada ya kichwa ikiwa data ya don't-care upande wa controller.<sup>[[5]](#references)</sup> Weka majibu kwenye anwani zake zilizodecode ndani ya picha iliyojazwa `0xFF` na ufuatilie kando offsets zilizofunikwa. Byte ambayo haikuonekana si ushahidi kwamba flash ilikuwa na `0xFF` hapo.<sup>[[5]](#references)[[6]](#references)</sup>

Usomaji wa `0x6B` (1-1-4) wa aina ya W25Q hutumia lane moja kwa opcode na anwani, lakini IO0–IO3 kwa data ya majibu. Shughuli kwenye pini zilizokuwa `/WP` na `/HOLD` ni ushahidi imara zaidi wa kubadili kwenda quad-mode kuliko kasi ya clock pekee; analyzer ya lane moja inaweza kudecode vibaya jibu la quad.<sup>[[5]](#references)</sup> Hamisha awamu hiyo kwa QSPI analyzer iliyosanidiwa kwa upana wa lanes na dummy cycles za command, kisha unganisha usomaji wa lane moja na quad-lane kwa kutumia anwani za flash.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` hutambua kiotomatiki fomati zote mbili za uhamishaji, hutupa usomaji uliodecode kwa upana usio sahihi wa lane, na huripoti kiwango cha coverage ya usomaji.<sup>[[6]](#references)</sup> Kutoka kwenye repository yake, baada ya kusakinisha dependencies zake, unganisha captures kwa kutumia:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Matokeo bado ni uchunguzi wenye taarifa chache, si chip dump kamili.<sup>[[5]](#references)[[6]](#references)</sup> Ili kuchunguza writes kando, linganisha `0x06` write-enable, ukaguzi wa hali `0x05`, erase opcodes, na amri za page-program `0x02`. Data ya page-program hufuata anwani kwenye MOSI na haijajumuishwa katika ujenzi upya wa kusoma pekee.<sup>[[5]](#references)</sup> Changanua image iliyopatikana kwa kutumia [uchanganuzi wa firmware](../firmware-analysis/) huku ukihifadhi taarifa za read-coverage.

## References

- [1] [Analog Devices — Utangulizi wa Kiolesura cha SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Mwongozo wa flashrom — Kipanga programu cha SPI cha CH341A na chaguo za kusoma/kuandika](https://flashrom.org/classic_cli_manpage.html)
- [3] [Nyaraka za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Kuboresha Ujuzi wa Hardware Hacking, Sehemu ya 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Kupanua Scapy kwa Reverse Engineering ya Hardware](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — Kunasa na kujenga upya ufuatiliaji wa SPI/QSPI](https://github.com/wrongbaud/spidump)
- [7] [Kichanganuzi cha QSPI cha Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
