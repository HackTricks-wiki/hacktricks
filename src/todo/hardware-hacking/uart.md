# UART

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

UART ni interface ya serial isiyosawazishwa inayohamisha mkondo wa bits uliowekwa katika fremu bila clock ya pamoja. Usichanganye UART ya kiwango cha logic na RS-232: RS-232 hutumia viwango tofauti vya voltage, ambavyo mara nyingi huwa hasi, na huhitaji transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Kwa ujumla, laini hushikiliwa juu (kwenye thamani ya kimantiki 1) wakati UART iko katika hali ya kutofanya kazi. Kisha, kuashiria mwanzo wa uhamishaji wa data, transmitter hutuma start bit kwa receiver, ambapo signal hushikiliwa chini (kwenye thamani ya kimantiki 0). Baada ya hapo, transmitter hutuma bits tano hadi nane za data zilizo na ujumbe halisi, zikifuatiwa na parity bit ya hiari na stop bits moja au mbili (zenye thamani ya kimantiki 1), kulingana na configuration. Parity bit, inayotumika kukagua errors, huonekana mara chache katika matumizi halisi. Stop bit (au bits) huashiria mwisho wa transmission.

Configuration inayotumika zaidi ni 8N1: bits nane za data, hakuna parity, na stop bit moja. UART hutuma data bit yenye uzito mdogo zaidi kwanza, kwa hiyo ASCII `C` (`0x43`) hutumwa kama: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Tunaita configuration inayotumika zaidi 8N1: bits nane za data, hakuna parity, na stop bit moja. Kwa mfano, ikiwa tungetaka kutuma herufi C, au 0x43 katika ASCII, kwenye UART ya 8N1](<../../images/image (764).png>)

Vifaa vya hardware vya kuwasiliana na UART:

- USB-to-serial adapter
- Adapters zilizo na chips za CP2102 au PL2303
- Kifaa cha matumizi mengi kama vile: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Kutambua Ports za UART

Debug header ya kawaida huonyesha **TX**, **RX**, na **GND**; pia inaweza kuonyesha pin ya **Vcc/Vref**, reset, au pins za flow-control. Vcc si signal ya UART na kwa kawaida inapaswa kutumika tu kama reference ya voltage—si kuunganishwa kama chanzo cha power—isipokuwa schematic ya board na mahitaji ya current yajulikane.<sup>[[2]](#references)[[3]](#references)</sup>

Anza kifaa kikiwa **kimezimwa** na kimetenganishwa:

- Tambua **GND** katika continuity mode dhidi ya ground plane inayojulikana, connector shield, au supply ground. Usitumie kamwe continuity/resistance mode kwenye board iliyo na power.
- Badilisha kwenda DC-voltage mode kabla ya kuwasha target. Pima pins zinazoweza kuwa candidates zikilinganishwa na ground ili kutambua logic voltage. Rail thabiti inaweza kuwa Vcc/Vref; usidhani ni salama kuunganisha.
- Chunguza candidates kwa kutumia logic analyzer au oscilloscope wakati wa boot. **TX** kwa kawaida hukaa high ikiwa idle na huonyesha bursts za data iliyowekwa katika frames. Multimeter inaweza kuonyesha fluctuation ya wastani lakini haiwezi kuthibitisha framing au baud rate.
- **RX** inaweza kubaki idle na haiwezi kutambuliwa kwa usalama kwa sababu tu iko karibu na TX. Fuatilia PCB, soma datasheet ya SoC, au tumia analyzer yenye impedance kubwa kabla ya kuiendesha.

Kubadilisha TX na RX kwa kawaida hakutoi mawasiliano; kuchanganya power, ground, au viwango vya signal kunaweza kuharibu target au adapter kabisa. Unganisha ground kwanza na anza katika hali ya **receive-only** (target TX kwenda adapter RX).

Manufacturers wanaweza kuacha header, kuacha series resistors bila kuwekwa, kuzima console kwenye firmware, au kuonyesha TX pekee. Fuatilia test pads na resistor footprints zilizo karibu hadi kwenye SoC na ongeza connection ya muda yenye impedance kubwa baada ya kuthibitisha electrical level. Uwepo wa warranty haumaanishi kwamba UART inayoweza kufikiwa lazima iwepo.

### Kutambua UART Baud Rate

Njia rahisi zaidi ya kutambua baud rate sahihi ni kuangalia **output ya pin ya TX na kujaribu kusoma data**. Ikiwa data unayopokea haisomeki, badilisha kwenda baud rate inayofuata inayowezekana hadi data isomeke. Unaweza kutumia USB-to-serial adapter au kifaa cha matumizi mengi kama Bus Pirate kufanya hivyo, ukikiunganisha na helper script kama [baudrate.py](https://github.com/devttys0/baudrate/). Baud rates zinazotumika zaidi ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kutambua kwamba katika protocol hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kifaa kingine!

## CP210X UART kwenda TTY Adapter

CP210x USB-to-UART bridges hupatikana kwenye prototyping boards nyingi na adapters za bei nafuu. Modules za kawaida huonyesha supply pins pamoja na GND, RXD, na TXD, lakini headers na I/O levels zao hutofautiana. Thibitisha voltage halisi kutoka kwenye muundo wa board au data sheet. Kwa kawaida unganisha GND pekee, adapter RX kwenda target TX, na—baada ya kuthibitisha receive-only—adapter TX kwenda target RX. Usiunganishe supply pin ya 5 V/3.3 V ya adapter isipokuwa unaiwasha target inayojulikana kustahimili voltage hiyo kwa makusudi.<sup>[[3]](#references)</sup>

Ikiwa adapter haitambuliwi, hakikisha kwamba CP210X drivers zimesakinishwa kwenye host system. Baada ya adapter kutambuliwa na kuunganishwa, tools kama picocom, minicom au screen zinaweza kutumika.

Kuorodhesha vifaa vilivyounganishwa kwenye Linux/MacOS systems:
```
ls /dev/
```
Kwa mwingiliano wa msingi na interface ya UART, tumia command ifuatayo:
```
picocom /dev/<adapter> --baud <baudrate>
```
Kwa minicom, tumia amri ifuatayo ili kuisanidi:
```
minicom -s
```
Sanidi mipangilio kama vile baudrate na jina la kifaa katika chaguo la `Serial port setup`.

Baada ya usanidi, endesha `minicom` ili kufungua UART console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Ikiwa UART Serial to USB adapters hazipatikani, Arduino UNO R3 inaweza kutumika kwa hack ya haraka. Kwa kuwa Arduino UNO R3 hupatikana kwa kawaida karibu kila mahali, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina USB to Serial adapter iliyojengwa kwenye board yenyewe. Ili kupata UART connection, ing’oa tu chip ya Atmel 328p microcontroller kutoka kwenye board. Hack hii hufanya kazi kwenye variants za Arduino UNO R3 zilizo na Atmel 328p ambayo haijasolderiwa kwenye board (toleo la SMD hutumika ndani yake). Unganisha RX pin ya Arduino (Digital Pin 0) na TX pin ya UART Interface, na TX pin ya Arduino (Digital Pin 1) na RX pin ya UART interface.

Tumia Arduino IDE **Serial Monitor** au terminal maalum kwa target baud rate. Classic Uno R3 serial signals ni 5 V logic, kwa hivyo tumia level shifter au divider kabla ya kuziunganisha kwenye target ya 3.3 V au voltage ya chini zaidi.

## Bus Pirate

Transcript ifuatayo hutumia legacy Bus Pirate firmware interface kufuatilia UART output. Bus Pirate firmware mpya zaidi hutumia commands kama vile `m uart`, `{`/`}`, `monitor`, au `bridge`; soma documentation ya version iliyosakinishwa.<sup>[[2]](#references)</sup>
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
## Kudump Firmware kwa kutumia UART Console

UART console hutoa ufikiaji wa wakati wa uendeshaji kwa boot logs na, wakati mwingine, bootloader au operating-system shell. Console ya read-only bado hufichua memory maps, flash drivers, boot arguments, partition layouts, na firmware versions. Firmware inaweza kuwa kwenye SPI NOR/NAND, eMMC, au kifaa kingine; kwa kawaida haiendeshwi kutoka EEPROM, na mafaili yaliyoandikwa kwenye mounted persistent filesystem si lazima yapotee baada ya reboot.

Kuna njia kadhaa za kupata firmware, na sehemu ya SPI inaeleza usomaji wa moja kwa moja kutoka external flash. Console-assisted acquisition inaweza kuwa na uingiliaji mdogo wakati bootloader tayari inatoa safe read command, lakini boot interruption au flash command yoyote inaweza kuathiri upatikanaji, kwa hiyo hifadhi hali ya awali na epuka write/erase operations.

Console-assisted firmware dumping mara nyingi huanza kwa kukatiza bootloader. Vifaa vingi vya embedded Linux hutumia **Das U-Boot**, lakini vingine hutumia proprietary bootloaders au huzima interactive console.

Ili kujaribu interactive bootloader, unganisha UART receive path na terminal wakati target haijawashwa, anza logging, kisha iwashie. Fuata autoboot prompt inayoonyeshwa; kulingana na build, interruption inaweza kuhitaji key, sequence fupi, au inaweza kuwa imezimwa kabisa.

Ikiwa interruption itafanikiwa, tumia `help`, `printenv`, na read-only discovery commands ili kuelewa memory na storage layout ya vendor huyo kabla ya kufikia addresses.

Katika U-Boot, `md` huonyesha **addressable memory**, si “EEPROM” moja kwa moja. Kwanza tumia commands zinazolenga board kama `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables, na boot logs ili kutambua mapped address sahihi au kupakia flash region kwenye RAM. Kisha onyesha range inayojulikana byte-by-byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Hifadhi serial output kabla ya kuanza. Output ya `md.b` ina anwani na safu ya ASCII, hivyo ni uwasilishaji wa maandishi badala ya ROM image ghafi.

Ondoa safu za anwani na ASCII, unganisha tu sehemu za hexadecimal byte, kisha zidecode kuwa binary (kwa mfano kwa `xxd -r -p`). Thibitisha idadi ya byte inayotarajiwa na hifadhi hash kabla ya analysis:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk kisha hutambua signatures zinazojulikana katika binary iliyoundwa upya. Kusoma flash moja kwa moja kupitia interface inayofaa ya SPI/eMMC/NAND kwa kawaida huwa haraka zaidi na huwa na uwezekano mdogo wa makosa wakati console haiwezi kuhamisha data kwa uaminifu.

U-Boot inaweza kuzima uingiliaji, kuhitaji mfuatano wa vitufe maalum wa vendor, au kufunga amri za memory/flash. Fuata prompt ya autoboot na boot log badala ya kutuma herufi bila kufikiri. Ikiwa console haiwezi kuingiliwa, hifadhi boot log na utumie njia isiyovamizi ya kupata firmware.

## References

- [1] [Mwongozo wa Marejeleo wa Familia ya Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Nyaraka za Bus Pirate - hali ya UART na mipaka ya umeme](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - data sheet ya CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Nyaraka za U-Boot - amri ya `md` ya kuonyesha memory](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
