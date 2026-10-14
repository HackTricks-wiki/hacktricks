# UART

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za Msingi

UART ni kiolesura cha serial kisichosawazishwa kinachohamisha mtiririko wa bits zilizopangwa kwenye fremu bila clock ya pamoja. Usichanganye UART ya kiwango cha logic na RS-232: RS-232 hutumia viwango tofauti vya voltage, ambavyo mara nyingi huwa hasi, na huhitaji transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa kawaida, laini hushikiliwa juu (katika thamani ya logic 1) UART ikiwa katika hali ya kutofanya kazi. Kisha, ili kuashiria mwanzo wa uhamishaji wa data, mtumaji hutuma start bit kwa mpokeaji, wakati ambapo signal hushikiliwa chini (katika thamani ya logic 0). Baada ya hapo, mtumaji hutuma data bits tano hadi nane zenye ujumbe halisi, zikifuatiwa na parity bit ya hiari na stop bits moja au mbili (zenye thamani ya logic 1), kutegemea usanidi. Parity bit, inayotumika kukagua makosa, haionekani mara nyingi katika matumizi halisi. Stop bit (au bits) huashiria mwisho wa utumaji.

Usanidi unaotumika zaidi ni 8N1: data bits nane, bila parity, na stop bit moja. UART hutuma data bit yenye thamani ndogo zaidi kwanza, kwa hivyo ASCII `C` (`0x43`) hutumwa kama: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Usanidi unaotumika zaidi huitwa 8N1: data bits nane, bila parity, na stop bit moja. Kwa mfano, tukitaka kutuma herufi C, au 0x43 katika ASCII, kupitia UART ya 8N1](<../../images/image (764).png>)

Zana za hardware za kuwasiliana kupitia UART:

- Adapta ya USB-to-serial
- Adapta zenye chip za CP2102 au PL2303
- Zana yenye matumizi mengi kama vile: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Kutambua Milango ya UART

Kichwa cha kawaida cha debug huonyesha **TX**, **RX**, na **GND**; huenda pia kikaonyesha pini ya **Vcc/Vref**, reset, au pini za flow-control. Vcc si signal ya UART na kwa kawaida inapaswa kutumika kama rejeleo la voltage pekee—si kuunganishwa kama chanzo cha umeme—isipokuwa schematic ya board na mahitaji ya current yajulikane.<sup>[[2]](#references)[[3]](#references)</sup>

Anza kifaa kikiwa **kimezimwa** na kimetenganishwa:

- Tambua **GND** kwa kutumia hali ya continuity, ukilinganisha na ground plane, shield ya kiunganishi, au ground ya supply inayojulikana. Usitumie hali ya continuity/resistance kwenye board iliyowashwa.
- Badili kwenda hali ya DC-voltage kabla ya kuwasha kifaa lengwa. Pima pini zinazoweza kuwa sahihi ukilinganisha na ground ili kutambua voltage ya logic. Rail iliyo thabiti huenda ikawa Vcc/Vref; usidhani ni salama kuiunganisha.
- Fuatilia pini zinazoweza kuwa sahihi kwa kutumia logic analyzer au oscilloscope wakati wa kuwasha kifaa. **TX** kwa kawaida huwa juu ikiwa haifanyi kazi na huonyesha milipuko ya data iliyopangwa kwenye fremu. Multimeter inaweza kuonyesha mabadiliko ya wastani, lakini haiwezi kuthibitisha mpangilio wa fremu au baud rate.
- **RX** huenda ikabaki katika hali ya kutofanya kazi, na si salama kuitambua kwa kuwa tu iko karibu na TX. Fuatilia PCB, angalia datasheet ya SoC, au tumia analyzer yenye impedance ya juu kabla ya kuitumia kuendesha signal.

Kubadilishana TX na RX kwa kawaida hakusababishi mawasiliano; kuchanganya umeme, ground, au viwango vya signal kunaweza kuharibu kabisa kifaa lengwa au adapta. Unganisha ground kwanza, kisha anza kwa **kupokea pekee** (TX ya kifaa lengwa kwenye RX ya adapta).

Watengenezaji wanaweza kuacha kichwa hicho, kuacha series resistors bila kusakinishwa, kuzima console kwenye firmware, au kutoa TX pekee. Fuatilia test pads na resistor footprints zilizo karibu hadi SoC, na uongeze muunganisho wa muda wenye impedance ya juu baada tu ya kuthibitisha kiwango cha umeme. Kuwepo kwa warranty hakumaanishi kuwa lazima kuwe na UART inayoweza kufikiwa.

### Kutambua Baud Rate ya UART

Njia rahisi zaidi ya kutambua baud rate sahihi ni kuangalia output ya pini ya **TX na kujaribu kusoma data**. Ikiwa data unayopokea haisomeki, badili hadi baud rate inayofuata inayowezekana mpaka data isomeke. Unaweza kutumia adapta ya USB-to-serial au kifaa chenye matumizi mengi kama Bus Pirate, pamoja na helper script kama [baudrate.py](https://github.com/devttys0/baudrate/). Baud rate zinazotumika zaidi ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kutambua kwamba katika protocol hii unahitaji kuunganisha TX ya kifaa kimoja kwenye RX ya kifaa kingine!

## Adapta ya CP210X UART hadi TTY

CP210x USB-to-UART bridges hupatikana kwenye board nyingi za prototyping na adapta za bei nafuu. Moduli za kawaida huonyesha pini za supply pamoja na GND, RXD, na TXD, lakini vichwa vyake na viwango vya I/O hutofautiana. Thibitisha voltage halisi kutoka kwenye muundo wa board au datasheet. Kwa kawaida, unganisha GND pekee, RX ya adapta kwenye TX ya kifaa lengwa, na—baada ya kuthibitisha upokeaji pekee—TX ya adapta kwenye RX ya kifaa lengwa. Usiunganishe pini ya supply ya 5 V/3.3 V ya adapta isipokuwa unakusudia kuwasha kifaa lengwa ambacho unajua kinaweza kuitumia.<sup>[[3]](#references)</sup>

Ikiwa adapta haitambuliwi, hakikisha kuwa drivers za CP210X zimesakinishwa kwenye mfumo wa host. Baada ya adapta kutambuliwa na kuunganishwa, zana kama picocom, minicom, au screen zinaweza kutumika.

Kuorodhesha vifaa vilivyounganishwa kwenye mifumo ya Linux/MacOS:

```
ls /dev/
```

Kwa mwingiliano wa msingi na kiolesura cha UART, tumia amri ifuatayo:

```
picocom /dev/<adapter> --baud <baudrate>
```

Kwa minicom, tumia amri ifuatayo ili kuisanidi:

```
minicom -s
```

Sanidi mipangilio kama vile baudrate na jina la kifaa katika chaguo la `Serial port setup`.

Baada ya kusanidi, endesha `minicom` ili kufungua console ya UART.

## UART Kupitia Arduino UNO R3 (Bodi zenye Chip ya Atmel 328p Inayoweza Kuondolewa)

Ikiwa adapta za UART Serial to USB hazipatikani, Arduino UNO R3 inaweza kutumika kwa hack ya haraka. Kwa kuwa Arduino UNO R3 hupatikana karibu kila mahali, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina adapta ya USB to Serial iliyojengwa kwenye ubao wenyewe. Ili kupata muunganisho wa UART, ondoa tu chipu ya microcontroller ya Atmel 328p kwenye ubao. Hack hii hufanya kazi kwenye matoleo ya Arduino UNO R3 ambayo Atmel 328p haijauzwa kwenye ubao (toleo la SMD ndilo linalotumika ndani yake). Unganisha pini ya RX ya Arduino (Digital Pin 0) kwenye pini ya TX ya UART Interface, na pini ya TX ya Arduino (Digital Pin 1) kwenye pini ya RX ya UART interface.

Tumia **Serial Monitor** ya Arduino IDE au terminal maalum iliyowekwa kwenye baud rate lengwa. Mawimbi ya serial ya kawaida ya Uno R3 hutumia mantiki ya 5 V, kwa hivyo tumia level shifter au divider kabla ya kuyaunganisha kwenye kifaa lengwa cha 3.3 V au volteji ya chini zaidi.

## Bus Pirate

Nakala ifuatayo ya mawasiliano hutumia interface ya firmware ya zamani ya Bus Pirate kufuatilia matokeo ya UART. Firmware mpya zaidi ya Bus Pirate hutumia amri kama `m uart`, `{`/`}`, `monitor`, au `bridge`; angalia nyaraka za toleo lililosakinishwa.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## Kudump Firmware kupitia UART Console

UART console hutoa ufikiaji wa wakati wa utekelezaji kwa logi za boot na, wakati mwingine, bootloader au shell ya mfumo wa uendeshaji. Hata console ya kusoma pekee hufichua ramani za memory, viendeshi vya flash, hoja za boot, mipangilio ya partitions na matoleo ya firmware. Firmware inaweza kuwa kwenye SPI NOR/NAND, eMMC au kifaa kingine; kwa kawaida haiendeshwi kutoka EEPROM, na faili zilizoandikwa kwenye filesystem endelevu iliyowekwa mount hazipotei lazima kifaa kinapowashwa upya.

Kuna njia kadhaa za kupata nakala, na sehemu ya SPI inaeleza usomaji wa moja kwa moja kutoka kwenye flash ya nje. Upatikanaji unaosaidiwa na console unaweza kuwa na athari ndogo zaidi ikiwa bootloader tayari ina amri salama ya kusoma, lakini kusimamisha boot au kutumia amri za flash kunaweza kuathiri upatikanaji; kwa hiyo, rekodi hali ya awali na epuka amri za kuandika/kufuta.

Kudump firmware kwa msaada wa console mara nyingi huanza kwa kusimamisha bootloader. Vifaa vingi vya Linux vilivyopachikwa hutumia **Das U-Boot**, lakini vingine hutumia bootloader za wamiliki au huzima console shirikishi.

Ili kupima kama bootloader shirikishi inapatikana, unganisha njia ya kupokea UART na terminal kifaa lengwa kikiwa hakina umeme, anza kurekodi, kisha ukiwashe. Fuata ujumbe wa autoboot unaoonyeshwa; kutegemea build, huenda ukahitaji kubonyeza kitufe, mfuatano mfupi wa vitufe, au huenda kipengele hicho kimezimwa kabisa.

Ukifanikiwa kuisimamisha, tumia `help`, `printenv` na amri za uchunguzi zisizoandika ili kuelewa mpangilio wa memory na hifadhi wa kifaa hicho kabla ya kufikia anwani.

Katika U-Boot, `md` huonyesha **memory inayoweza kufikiwa kwa anwani**, si “EEPROM” moja kwa moja. Kwanza tumia amri mahususi za board kama `mtd list`, `sf probe`, `mmc info`, `part list`, vigezo vya mazingira na logi za boot ili kubaini anwani sahihi iliyomappiwa au kupakia eneo la flash kwenye RAM. Kisha onyesha eneo la anwani linalojulikana byte kwa byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Rekodi matokeo ya serial kabla ya kuanza. Matokeo ya `md.b` yana anwani na safu wima ya ASCII, kwa hiyo ni uwakilishaji wa maandishi badala ya picha ghafi ya ROM.

Ondoa safu wima za anwani na ASCII, unganisha sehemu za baiti za heksadesimali pekee, kisha uzisimbue kuwa mfumo wa binary (kwa mfano, kwa kutumia `xxd -r -p`). Thibitisha idadi ya baiti inayotarajiwa na urekodi hash kabla ya uchanganuzi:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk kisha hutambua saini zinazojulikana katika binary iliyoundwa upya. Kusoma flash moja kwa moja kupitia kiolesura kinachofaa cha SPI/eMMC/NAND kwa kawaida huwa haraka zaidi na hupunguza makosa wakati console haiwezi kuhamisha data kwa kutegemewa.

U-Boot inaweza kuzima uwezekano wa kukatiza uanzishaji, kuhitaji mfuatano wa vitufe maalum wa mtengenezaji, au kufunga amri za memory/flash. Fuata kidokezo cha autoboot na boot log badala ya kutuma herufi bila kufikiri. Ikiwa console haiwezi kukatizwa, hifadhi boot log na utumie njia isiyoingilia ya kupata firmware.

## References

- [1] [Mwongozo wa Marejeleo wa Familia ya Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Nyaraka za Bus Pirate - modi ya UART na mipaka ya umeme](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Hati ya data ya CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Nyaraka za U-Boot - amri ya kuonyesha memory ya `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
