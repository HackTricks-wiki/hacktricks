# UART

{{#include ../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

UART ni serial protocol, ambayo huhamisha data kati ya components bit moja kwa wakati. Kinyume chake, parallel communication protocols hutuma data kwa wakati mmoja kupitia channels nyingi. Serial protocols za kawaida zinajumuisha RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, na USB.

Kwa ujumla, line hudumishwa ikiwa juu (kwenye logical 1) wakati UART iko katika hali ya kusubiri. Kisha, ili kuashiria kuanza kwa uhamishaji wa data, transmitter hutuma start bit kwa receiver, ambapo signal hudumishwa ikiwa chini (kwenye logical 0). Baada ya hapo, transmitter hutuma data bits tano hadi nane zenye ujumbe halisi, ikifuatiwa na parity bit ya hiari na stop bits moja au mbili (zenye logical 1), kulingana na configuration. Parity bit, inayotumika kukagua makosa, huonekana mara chache katika matumizi ya kawaida. Stop bit (au bits) huashiria mwisho wa transmission.

Configuration inayotumika zaidi huitwa 8N1: data bits nane, hakuna parity, na stop bit moja. Kwa mfano, ikiwa tungetaka kutuma character C, au 0x43 katika ASCII, kwenye 8N1 UART configuration, tungetuma bits zifuatazo: 0 (start bit); 0, 1, 0, 0, 0, 0, 1, 1 (thamani ya 0x43 katika binary), na 0 (stop bit).

![UART: Configuration inayotumika zaidi huitwa 8N1: data bits nane, hakuna parity, na stop bit moja. Kwa mfano, ikiwa tungetaka kutuma character C, au 0x43 katika ASCII, kwenye 8N1 UART](<../../images/image (764).png>)

Hardware tools za kuwasiliana na UART:

- USB-to-serial adapter
- Adapters zenye chips za CP2102 au PL2303
- Tool ya matumizi mengi kama vile: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Kutambua UART Ports

UART ina ports 4: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), na **GND**(Ground). Huenda ukaweza kupata ports 4 zenye herufi **`TX`** na **`RX`** **zilizoandikwa** kwenye PCB. Lakini ikiwa hakuna alama, huenda ukahitaji kujaribu kuzipata mwenyewe kwa kutumia **multimeter** au **logic analyzer**.

Kwa kutumia **multimeter** na device ikiwa imezimwa:

- Ili kutambua pin ya **GND**, tumia hali ya **Continuity Test**, weka probe ya nyuma kwenye ground na pima kwa ile nyekundu hadi usikie sauti kutoka kwenye multimeter. Pins kadhaa za GND zinaweza kupatikana kwenye PCB, kwa hiyo huenda ukawa umepata au hukupata ile inayohusiana na UART.
- Ili kutambua **VCC port**, chagua **DC voltage mode** na uiweke kwenye voltage ya 20 V. Weka probe nyeusi kwenye ground na probe nyekundu kwenye pin. Washa device. Ikiwa multimeter inapima voltage thabiti ya 3.3 V au 5 V, umepata pin ya Vcc. Ukipata voltages nyingine, jaribu ports nyingine.
- Ili kutambua **TX** **port**, tumia **DC voltage mode** hadi voltage ya 20 V, weka probe nyeusi kwenye ground na probe nyekundu kwenye pin, kisha washa device. Ukiona voltage inabadilika kwa sekunde chache na kisha kutulia kwenye thamani ya Vcc, kuna uwezekano mkubwa umepata TX port. Hii ni kwa sababu wakati wa kuwasha, hutuma debug data.
- **RX port** itakuwa iliyo karibu zaidi na zile 3 nyingine, ikiwa na mabadiliko madogo zaidi ya voltage na thamani ya chini zaidi kwa ujumla kati ya UART pins zote.

Ukichanganya TX na RX ports hakuna kitakachotokea, lakini ukichanganya GND na VCC port unaweza kuunguza circuit.

Katika baadhi ya target devices, UART port huwa imezimwa na manufacturer kwa kuzima RX au TX, au zote mbili. Katika hali hiyo, inaweza kusaidia kufuatilia connections kwenye circuit board na kutafuta breakout point. Dokezo muhimu la kuthibitisha kutogunduliwa kwa UART na kukatika kwa circuit ni kuangalia warranty ya device. Ikiwa device ilisafirishwa ikiwa na warranty, manufacturer huacha baadhi ya debug interfaces (katika hali hii, UART), na hivyo lazima awe ameitenganisha UART na kuiunganisha tena wakati wa debugging. Breakout pins hizi zinaweza kuunganishwa kwa soldering au jumper wires.

### Kutambua UART Baud Rate

Njia rahisi zaidi ya kutambua baud rate sahihi ni kuangalia **TX pin’s output na kujaribu kusoma data**. Ikiwa data unayopokea haisomeki, badilisha hadi baud rate inayofuata inayowezekana mpaka data isomeke. Unaweza kutumia USB-to-serial adapter au device ya matumizi mengi kama Bus Pirate kufanya hivi, pamoja na helper script kama [baudrate.py](https://github.com/devttys0/baudrate/). Baud rates zinazotumika zaidi ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kutambua kwamba katika protocol hii unahitaji kuunganisha TX ya device moja na RX ya nyingine!

## CP210X UART to TTY Adapter

CP210X Chip hutumika kwenye prototyping boards nyingi kama NodeMCU (yenye esp8266) kwa Serial Communication. Adapters hizi zina bei nafuu kiasi na zinaweza kutumika kuunganisha kwenye UART interface ya target. Device hii ina pins 5: 5V, GND, RXD, TXD, 3.3V. Hakikisha unaunganisha voltage inayoungwa mkono na target ili kuepuka uharibifu wowote. Mwisho, unganisha RXD pin ya Adapter na TXD ya target na TXD pin ya Adapter na RXD ya target.

Ikiwa adapter haitambuliwi, hakikisha drivers za CP210X zimesakinishwa kwenye host system. Baada ya adapter kutambuliwa na kuunganishwa, tools kama picocom, minicom au screen zinaweza kutumika.

Kuorodhesha devices zilizounganishwa kwenye Linux/MacOS systems:
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

Baada ya usanidi, tumia command `minicom` kuanzisha UART Console.

## UART Kupitia Arduino UNO R3 (Vibao Vyenye Atmel 328p Inayoweza Kutolewa)

Iwapo UART Serial to USB adapters hazipatikani, Arduino UNO R3 inaweza kutumika kwa hack ya haraka. Kwa kuwa Arduino UNO R3 hupatikana karibu kila mahali, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina USB to Serial adapter iliyojengwa kwenye board yenyewe. Ili kupata UART connection, toa tu microcontroller chip ya Atmel 328p kutoka kwenye board. Hack hii hufanya kazi kwenye variants za Arduino UNO R3 zilizo na Atmel 328p ambayo haijauzwa moja kwa moja kwenye board (toleo la SMD hutumika ndani yake). Unganisha pin ya RX ya Arduino (Digital Pin 0) na pin ya TX ya UART Interface, kisha unganisha pin ya TX ya Arduino (Digital Pin 1) na pin ya RX ya UART interface.

Hatimaye, inapendekezwa kutumia Arduino IDE kupata Serial Console. Katika sehemu ya `tools` kwenye menu, chagua chaguo la `Serial Console` na uweke baud rate kulingana na UART interface.

## Bus Pirate

Katika hali hii tutasniff mawasiliano ya UART ya Arduino ambayo inatuma prints zote za program kwenye Serial Monitor.
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

UART Console hutoa njia nzuri ya kufanya kazi na firmware ya msingi katika mazingira ya runtime. Lakini wakati access ya UART Console ni ya kusoma pekee, inaweza kuleta constraints nyingi. Katika vifaa vingi vya embedded, firmware huhifadhiwa kwenye EEPROM na kutekelezwa na processors zenye memory ya muda (volatile). Kwa hivyo, firmware huwekwa read-only kwa sababu firmware ya awali kutoka wakati wa manufacturing huwa ndani ya EEPROM yenyewe, na files zozote mpya hupotea kutokana na memory ya muda. Kwa hivyo, kudump firmware ni juhudi muhimu wakati wa kufanya kazi na embedded firmware.

Kuna njia nyingi za kufanya hivi, na sehemu ya SPI inaelezea mbinu za ku-extract firmware moja kwa moja kutoka kwenye EEPROM kwa kutumia vifaa mbalimbali. Hata hivyo, inashauriwa kujaribu kwanza kudump firmware kwa kutumia UART, kwa kuwa kudump firmware kwa kutumia vifaa vya kimwili na interactions za nje kunaweza kuwa risky.

Kudump firmware kutoka kwa UART Console kunahitaji kwanza kupata access kwa bootloaders. Vendors wengi maarufu hutumia uboot (Universal Bootloader) kama bootloader yao ya kupakia Linux. Kwa hivyo, kupata access kwa uboot ni muhimu.

Ili kupata access kwa bootloader, connect UART port kwenye computer na utumie mojawapo ya tools za Serial Console, huku power supply ya kifaa ikiwa imekatwa. Setup ikiwa tayari, bonyeza Enter Key na uishikilie. Hatimaye, connect power supply kwenye kifaa na kiruhusu kianze boot.

Kufanya hivi kutakatiza uboot isi-load na kutatoa menu. Inashauriwa kuelewa commands za uboot na kutumia help menu kuziorodhesha. Hii inaweza kuwa command ya `help`. Kwa kuwa vendors tofauti hutumia configurations tofauti, ni muhimu kuzielewa kila moja kivyake.

Kwa kawaida, command ya kudump firmware ni:
```
md
```
ambayo inawakilisha "memory dump". Hii itadump memory (EEPROM Content) kwenye skrini. Inapendekezwa kurekodi matokeo ya Serial Console kabla ya kuanza utaratibu ili kunasa memory dump.

Hatimaye, ondoa data yote isiyohitajika kwenye log file na hifadhi file kama `filename.rom`, kisha tumia binwalk kutoa yaliyomo:
```
binwalk -e <filename.rom>
```
Hii itaorodhesha maudhui yanayowezekana kutoka kwenye EEPROM kulingana na signatures zilizopatikana kwenye hex file.

Hata hivyo, ni muhimu kutambua kwamba si mara zote uboot huwa unlocked hata ikiwa inatumika. Ikiwa Enter Key haifanyi chochote, jaribu keys tofauti kama Space Key, n.k. Ikiwa bootloader imefungwa na haiingiliwi, method hii haitafanya kazi. Ili kuangalia ikiwa uboot ndiyo bootloader ya kifaa, angalia output kwenye UART Console wakati kifaa kinaboot. Huenda ikataja uboot wakati wa kuboot.

{{#include ../../banners/hacktricks-training.md}}
