# UART

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

UART ni protokali ya serial, ambayo inamaanisha inahamisha data kati ya vipengele bit moja kwa wakati. Kinyume chake, protokali za mawasiliano ya sambamba hupeleka data kwa wakati mmoja kupitia njia nyingi. Protokali za kawaida za serial ni pamoja na RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, na USB.

Kwa ujumla, laini inashikiliwa juu (katika thamani ya mantiki 1) wakati UART iko katika hali ya kupumzika. Kisha, ili kuashiria mwanzo wa uhamisho wa data, mtumaji anatumia bit ya mwanzo kwa mpokeaji, wakati ambapo ishara inashikiliwa chini (katika thamani ya mantiki 0). Kisha, mtumaji anatumia bits tano hadi nane za data zinazojumuisha ujumbe halisi, ikifuatiwa na bit ya parity ya hiari na bit moja au mbili za kusitisha (zikiwa na thamani ya mantiki 1), kulingana na usanidi. Bit ya parity, inayotumika kwa ajili ya kuangalia makosa, haionekani mara nyingi katika mazoezi. Bit ya kusitisha (au bits) inaashiria mwisho wa uhamisho.

Tunaita usanidi wa kawaida zaidi 8N1: bits nane za data, hakuna parity, na bit moja ya kusitisha. Kwa mfano, ikiwa tunataka kutuma herufi C, au 0x43 katika ASCII, katika usanidi wa UART wa 8N1, tungepeleka bits zifuatazo: 0 (bit ya mwanzo); 0, 1, 0, 0, 0, 0, 1, 1 (thamani ya 0x43 katika binary), na 0 (bit ya kusitisha).

![](<../../images/image (764).png>)

Vifaa vya vifaa kuwasiliana na UART:

- Adaptari ya USB-to-serial
- Adaptari zenye chips CP2102 au PL2303
- Zana nyingi kama: Bus Pirate, Adafruit FT232H, Shikra, au Attify Badge

### Identifying UART Ports

UART ina bandari 4: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), na **GND**(Ground). Unaweza kuwa na uwezo wa kupata bandari 4 zikiwa na herufi **`TX`** na **`RX`** **zilizoandikwa** kwenye PCB. Lakini ikiwa hakuna dalili, unaweza kujaribu kuzipata mwenyewe kwa kutumia **multimeter** au **logic analyzer**.

Kwa kutumia **multimeter** na kifaa kikiwa kimezimwa:

- Ili kubaini pini ya **GND** tumia hali ya **Continuity Test**, weka uongozi wa nyuma kwenye ardhi na jaribu na uongozi mwekundu hadi usikie sauti kutoka kwa multimeter. Pini kadhaa za GND zinaweza kupatikana kwenye PCB, hivyo unaweza kuwa umepata au hujapata ile inayohusiana na UART.
- Ili kubaini bandari ya **VCC**, weka hali ya **DC voltage mode** na uweke hadi 20 V ya voltage. Uongozi mweusi kwenye ardhi na uongozi mwekundu kwenye pini. Washa kifaa. Ikiwa multimeter inapima voltage isiyobadilika ya 3.3 V au 5 V, umepata pini ya Vcc. Ikiwa unapata voltage nyingine, jaribu tena na bandari nyingine.
- Ili kubaini bandari ya **TX**, weka **DC voltage mode** hadi 20 V ya voltage, uongozi mweusi kwenye ardhi, na uongozi mwekundu kwenye pini, na washia kifaa. Ikiwa unapata voltage inabadilika kwa sekunde chache kisha inastabilika kwenye thamani ya Vcc, umepata bandari ya TX. Hii ni kwa sababu wakati wa kuwasha, inatuma data fulani za debug.
- Bandari ya **RX** itakuwa karibu zaidi na zingine 3, ina mabadiliko madogo ya voltage na thamani ya chini zaidi ya pini zote za UART.

Unaweza kuchanganya bandari za TX na RX na hakuna kitu kitakachotokea, lakini ikiwa unachanganya bandari za GND na VCC unaweza kuharibu mzunguko.

Katika baadhi ya vifaa vya lengo, bandari ya UART imezimwa na mtengenezaji kwa kuzima RX au TX au hata zote mbili. Katika kesi hiyo, inaweza kuwa na manufaa kufuatilia muunganisho kwenye bodi ya mzunguko na kupata sehemu ya kuvunja. Kidokezo kikubwa kuhusu kuthibitisha kutokuwepo kwa UART na kuvunja mzunguko ni kuangalia dhamana ya kifaa. Ikiwa kifaa kimepelekwa na dhamana fulani, mtengenezaji huacha interfaces za debug (katika kesi hii, UART) na hivyo, lazima awe ameondoa UART na ataiunganisha tena wakati wa debugging. Pini hizi za kuvunja zinaweza kuunganishwa kwa kulehemu au nyaya za jumper.

### Identifying the UART Baud Rate

Njia rahisi ya kubaini kiwango sahihi cha baud ni kuangalia **matokeo ya pini ya TX na kujaribu kusoma data**. Ikiwa data unayopokea haiwezi kusomeka, badilisha hadi kiwango kinachowezekana cha baud hadi data iweze kusomeka. Unaweza kutumia adaptari ya USB-to-serial au kifaa cha matumizi mengi kama Bus Pirate kufanya hivyo, pamoja na script ya msaada, kama [baudrate.py](https://github.com/devttys0/baudrate/). Kiwango cha kawaida cha baud ni 9600, 38400, 19200, 57600, na 115200.

> [!CAUTION]
> Ni muhimu kutambua kwamba katika protokali hii unahitaji kuunganisha TX ya kifaa kimoja na RX ya kingine!

## CP210X UART to TTY Adapter

Chip ya CP210X inatumika katika bodi nyingi za prototyping kama NodeMCU (ikiwa na esp8266) kwa Mawasiliano ya Serial. Adaptari hizi ni za bei nafuu na zinaweza kutumika kuunganisha kwenye interface ya UART ya lengo. Kifaa kina pini 5: 5V, GND, RXD, TXD, 3.3V. Hakikisha kuunganisha voltage kama inavyoungwa mkono na lengo ili kuepuka uharibifu wowote. Mwishowe, ungana pini ya RXD ya Adaptari na TXD ya lengo na pini ya TXD ya Adaptari na RXD ya lengo.

Ikiwa adaptari haijagundulika, hakikisha kuwa madereva ya CP210X yamewekwa kwenye mfumo wa mwenyeji. Mara baada ya adaptari kugundulika na kuunganishwa, zana kama picocom, minicom au screen zinaweza kutumika.

Ili orodhesha vifaa vilivyounganishwa kwenye mifumo ya Linux/MacOS:
```
ls /dev/
```
Kwa mwingiliano wa msingi na kiolesura cha UART, tumia amri ifuatayo:
```
picocom /dev/<adapter> --baud <baudrate>
```
Kwa minicom, tumia amri ifuatayo kuikamilisha:
```
minicom -s
```
Sanitize mipangilio kama baudrate na jina la kifaa katika chaguo la `Serial port setup`.

Baada ya usanidi, tumia amri `minicom` kuanza kupata UART Console.

## UART Kupitia Arduino UNO R3 (Bodi za Chip za Atmel 328p Zinazoweza Kuondolewa)

Iwapo adapta za UART Serial hadi USB hazipatikani, Arduino UNO R3 inaweza kutumika kwa hack ya haraka. Kwa kuwa Arduino UNO R3 kwa kawaida inapatikana popote, hii inaweza kuokoa muda mwingi.

Arduino UNO R3 ina adapta ya USB hadi Serial iliyojengwa kwenye bodi yenyewe. Ili kupata muunganisho wa UART, toa chip ya microcontroller ya Atmel 328p kutoka kwenye bodi. Hack hii inafanya kazi kwenye toleo la Arduino UNO R3 lenye Atmel 328p isiyosafishwa kwenye bodi (toleo la SMD linatumika ndani yake). Unganisha pini ya RX ya Arduino (Pini ya Kidijitali 0) kwa pini ya TX ya Kiunganishi cha UART na pini ya TX ya Arduino (Pini ya Kidijitali 1) kwa pini ya RX ya kiunganishi cha UART.

Hatimaye, inapendekezwa kutumia Arduino IDE kupata Serial Console. Katika sehemu ya `tools` kwenye menyu, chagua chaguo la `Serial Console` na weka baud rate kulingana na kiunganishi cha UART.

## Bus Pirate

Katika hali hii tutakuwa tukichunguza mawasiliano ya UART ya Arduino inayotuma uchapishaji wote wa programu kwa Serial Monitor.
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
## Kutolewa kwa Firmware kwa kutumia UART Console

UART Console inatoa njia nzuri ya kufanya kazi na firmware ya msingi katika mazingira ya wakati halisi. Lakini wakati ufikiaji wa UART Console ni wa kusoma tu, inaweza kuleta vizuizi vingi. Katika vifaa vingi vilivyojumuishwa, firmware huhifadhiwa katika EEPROMs na kutekelezwa katika prosesa ambazo zina kumbukumbu ya muda. Hivyo, firmware inahifadhiwa kuwa ya kusoma tu kwani firmware ya awali wakati wa utengenezaji iko ndani ya EEPROM yenyewe na faili zozote mpya zitapotea kutokana na kumbukumbu ya muda. Hivyo, kutolewa kwa firmware ni juhudi ya thamani wakati wa kufanya kazi na firmware zilizojumuishwa.

Kuna njia nyingi za kufanya hivi na sehemu ya SPI inashughulikia mbinu za kutoa firmware moja kwa moja kutoka kwa EEPROM kwa vifaa mbalimbali. Ingawa, inapendekezwa kwanza kujaribu kutolewa kwa firmware kwa kutumia UART kwani kutolewa kwa firmware kwa kutumia vifaa vya kimwili na mwingiliano wa nje kunaweza kuwa na hatari.

Kutolewa kwa firmware kutoka kwa UART Console kunahitaji kwanza kupata ufikiaji wa bootloaders. Wauzaji wengi maarufu hutumia uboot (Universal Bootloader) kama bootloader yao kupakia Linux. Hivyo, kupata ufikiaji wa uboot ni muhimu.

Ili kupata ufikiaji wa boot bootloader, ung'anisha bandari ya UART kwenye kompyuta na tumia yoyote ya zana za Serial Console na uweke usambazaji wa nguvu kwa kifaa kisichounganishwa. Mara tu mipangilio ikikamilika, bonyeza Kitufe cha Enter na ushikilie. Hatimaye, ung'anisha usambazaji wa nguvu kwa kifaa na uache ipakie.

Kufanya hivi kutakatisha uboot kutoka kupakia na kutatoa menyu. Inapendekezwa kuelewa amri za uboot na kutumia menyu ya msaada kuorodhesha hizo. Hii inaweza kuwa amri ya `help`. Kwa kuwa wauzaji tofauti hutumia mipangilio tofauti, ni muhimu kuelewa kila moja yao kwa tofauti.

Kwa kawaida, amri ya kutolewa kwa firmware ni:
```
md
```
ambayo inasimama kwa "memory dump". Hii itatoa yaliyomo kwenye kumbukumbu (EEPROM Content) kwenye skrini. Inapendekezwa kurekodi matokeo ya Serial Console kabla ya kuanza mchakato wa kukamata memory dump.

Hatimaye, ondoa tu data zisizohitajika kutoka kwa faili la log na uhifadhi faili kama `filename.rom` na tumia binwalk kutoa yaliyomo:
```
binwalk -e <filename.rom>
```
Hii itataja maudhui yanayowezekana kutoka kwa EEPROM kulingana na saini zilizopatikana katika faili la hex.

Ingawa, ni muhimu kutambua kwamba si kila wakati uboot imefunguliwa hata kama inatumika. Ikiwa Funguo ya Kuingia haifanyi chochote, angalia funguo tofauti kama Funguo ya Nafasi, n.k. Ikiwa bootloader imefungwa na haikatizwa, njia hii haitafanya kazi. Ili kuangalia ikiwa uboot ndio bootloader wa kifaa, angalia matokeo kwenye UART Console wakati wa kuanzisha kifaa. Inaweza kutaja uboot wakati wa kuanzisha. 

{{#include ../../banners/hacktricks-training.md}}
