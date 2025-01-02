# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

UART is 'n serial protokol, wat beteken dit oordra data tussen komponente een bit op 'n slag. In teenstelling hiermee, parallel kommunikasie protokolle oordra data gelyktydig deur verskeie kanale. Algemene serial protokolle sluit RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express, en USB in.

Oor die algemeen, die lyn word hoog gehou (by 'n logiese 1 waarde) terwyl UART in die idle toestand is. Dan, om die begin van 'n data-oordrag aan te dui, stuur die transmitter 'n beginbit na die ontvanger, waartydens die sein laag gehou word (by 'n logiese 0 waarde). Volgende, stuur die transmitter vyf tot agt databits wat die werklike boodskap bevat, gevolg deur 'n opsionele pariteitsbit en een of twee stopbits (met 'n logiese 1 waarde), afhangende van die konfigurasie. Die pariteitsbit, wat gebruik word vir foutkontrole, word selde in die praktyk gesien. Die stopbit (of bits) dui die einde van die oordrag aan.

Ons noem die mees algemene konfigurasie 8N1: agt databits, geen pariteit, en een stopbit. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, in 'n 8N1 UART konfigurasie wou stuur, sou ons die volgende bits stuur: 0 (die beginbit); 0, 1, 0, 0, 0, 0, 1, 1 (die waarde van 0x43 in binêr), en 0 (die stopbit).

![](<../../images/image (764).png>)

Hardeware gereedskap om met UART te kommunikeer:

- USB-naar-serial adapter
- Adapters met die CP2102 of PL2303 skyfies
- Veelsydige gereedskap soos: Bus Pirate, die Adafruit FT232H, die Shikra, of die Attify Badge

### Identifisering van UART Poorte

UART het 4 poorte: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage), en **GND**(Ground). Jy mag dalk 4 poorte vind met die **`TX`** en **`RX`** letters **geskryf** in die PCB. Maar as daar geen aanduiding is nie, mag jy dit self moet probeer vind met 'n **multimeter** of 'n **logika analiseerder**.

Met 'n **multimeter** en die toestel afgeskakel:

- Om die **GND** pen te identifiseer, gebruik die **Continuity Test** modus, plaas die agterste draad in die grond en toets met die rooi een totdat jy 'n geluid van die multimeter hoor. Verskeie GND penne kan in die PCB gevind word, so jy mag dalk die een wat aan UART behoort gevind het of nie.
- Om die **VCC poort** te identifiseer, stel die **DC voltage mode** in en stel dit op 20 V spanning. Swart sonde op grond en rooi sonde op die pen. Skakel die toestel aan. As die multimeter 'n konstante spanning van óf 3.3 V of 5 V meet, het jy die Vcc pen gevind. As jy ander spannings kry, probeer weer met ander poorte.
- Om die **TX** **poort** te identifiseer, **DC voltage mode** tot 20 V spanning, swart sonde op grond, en rooi sonde op die pen, en skakel die toestel aan. As jy vind dat die spanning vir 'n paar sekondes fluktueer en dan stabiliseer by die Vcc waarde, het jy waarskynlik die TX poort gevind. Dit is omdat dit, wanneer dit aangeskakel word, 'n paar debug data stuur.
- Die **RX poort** sou die naaste een aan die ander 3 wees, dit het die laagste spanning fluktuasie en die laagste algehele waarde van al die UART penne.

Jy kan die TX en RX poorte verwar en niks sal gebeur nie, maar as jy die GND en die VCC poort verwar, kan jy die stroombaan verbrand.

In sommige teiken toestelle is die UART poort deur die vervaardiger gedeaktiveer deur RX of TX of selfs albei te deaktiveer. In daardie geval kan dit nuttig wees om die verbindings in die stroombaan na te spoor en 'n breekpunt te vind. 'n Sterk aanduiding oor die bevestiging van geen opsporing van UART en die breek van die stroombaan is om die toestel se waarborg te kontroleer. As die toestel met 'n waarborg gestuur is, laat die vervaardiger 'n paar debug interfaces (in hierdie geval, UART) agter, en moet dus die UART ontkoppel het en dit weer aansluit terwyl dit gedebug word. Hierdie breekpunte kan verbind word deur te soldeer of met jumper drade.

### Identifisering van die UART Baud Rate

Die maklikste manier om die korrekte baud rate te identifiseer, is om na die **TX pen se uitgang te kyk en die data te probeer lees**. As die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baud rate totdat die data leesbaar word. Jy kan 'n USB-naar-serial adapter of 'n veelsydige toestel soos Bus Pirate gebruik om dit te doen, saam met 'n helper skrip, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die mees algemene baud rates is 9600, 38400, 19200, 57600, en 115200.

> [!CAUTION]
> Dit is belangrik om te noem dat jy in hierdie protokol die TX van een toestel aan die RX van die ander moet koppel!

## CP210X UART na TTY Adapter

Die CP210X Chip word in baie prototipering borde soos NodeMCU (met esp8266) vir Serial Kommunikasie gebruik. Hierdie adapters is relatief goedkoop en kan gebruik word om aan die UART interface van die teiken te koppel. Die toestel het 5 penne: 5V, GND, RXD, TXD, 3.3V. Maak seker om die spanning te koppel soos deur die teiken ondersteun om enige skade te vermy. Laastens koppel die RXD pen van die Adapter aan TXD van die teiken en TXD pen van die Adapter aan RXD van die teiken.

As die adapter nie opgespoor word nie, maak seker dat die CP210X bestuurders in die gasheer stelsel geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan gereedskap soos picocom, minicom of screen gebruik word.

Om die toestelle wat aan Linux/MacOS stelsels gekoppel is, te lys:
```
ls /dev/
```
Vir basiese interaksie met die UART-koppelvlak, gebruik die volgende opdrag:
```
picocom /dev/<adapter> --baud <baudrate>
```
Vir minicom, gebruik die volgende opdrag om dit te konfigureer:
```
minicom -s
```
Stel die instellings soos baudrate en toestelnaam in die `Serial port setup` opsie.

Na konfigurasie, gebruik die opdrag `minicom` om die UART Console te begin.

## UART Via Arduino UNO R3 (Verwyderbare Atmel 328p Chip Borde)

As UART Serial na USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 gebruik word met 'n vinnige hack. Aangesien Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit 'n groot hoeveelheid tyd bespaar.

Arduino UNO R3 het 'n USB na Serial-adapter wat op die bord self ingebou is. Om UART-verbinding te kry, trek eenvoudig die Atmel 328p mikrocontroller-skyfie van die bord af. Hierdie hack werk op Arduino UNO R3 variasies wat die Atmel 328p nie op die bord gesoldeer het nie (SMD weergawe word daarin gebruik). Verbind die RX-pin van Arduino (Digitale Pin 0) aan die TX-pin van die UART-interface en die TX-pin van die Arduino (Digitale Pin 1) aan die RX-pin van die UART-interface.

Laastens, dit word aanbeveel om Arduino IDE te gebruik om die Serial Console te kry. In die `tools` afdeling in die spyskaart, kies die `Serial Console` opsie en stel die baud rate in volgens die UART-interface.

## Bus Pirate

In hierdie scenario gaan ons die UART kommunikasie van die Arduino snuffel wat al die afdrukke van die program na die Serial Monitor stuur.
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
## Dumping Firmware with UART Console

UART Console bied 'n uitstekende manier om met die onderliggende firmware in 'n runtime-omgewing te werk. Maar wanneer die UART Console-toegang slegs lees is, kan dit baie beperkings inhou. In baie ingebedde toestelle word die firmware in EEPROMs gestoor en uitgevoer in verwerkers wat vlugtige geheue het. Daarom word die firmware as lees-slegs gehou aangesien die oorspronklike firmware tydens vervaardiging binne die EEPROM self is en enige nuwe lêers sou verlore gaan weens vlugtige geheue. Daarom is dit 'n waardevolle poging om firmware te dump terwyl jy met ingebedde firmwares werk.

Daar is baie maniere om dit te doen en die SPI-afdeling dek metodes om firmware direk uit die EEPROM met verskeie toestelle te onttrek. Alhoewel, dit word aanbeveel om eers te probeer om firmware met UART te dump, aangesien die dumping van firmware met fisiese toestelle en eksterne interaksies riskant kan wees.

Die dumping van firmware vanaf die UART Console vereis eers toegang tot bootloaders. Baie gewilde verskaffers gebruik uboot (Universal Bootloader) as hul bootloader om Linux te laai. Daarom is dit nodig om toegang tot uboot te verkry.

Om toegang tot die boot bootloader te verkry, koppel die UART-poort aan die rekenaar en gebruik enige van die Serial Console-gereedskap en hou die kragtoevoer na die toestel ontkoppel. Sodra die opstelling gereed is, druk die Enter-sleutel en hou dit in. Laastens, koppel die kragtoevoer aan die toestel en laat dit opstart.

Deur dit te doen, sal uboot se laai onderbreek word en 'n menu verskaf. Dit word aanbeveel om uboot-opdragte te verstaan en die helpmenu te gebruik om hulle te lys. Dit mag die `help` opdrag wees. Aangesien verskillende verskaffers verskillende konfigurasies gebruik, is dit nodig om elkeen van hulle apart te verstaan.

Gewoonlik is die opdrag om die firmware te dump:
```
md
```
wat staan vir "geheue-aflaai". Dit sal die geheue (EEPROM Inhoud) op die skerm aflaai. Dit word aanbeveel om die Serial Console-uitset te log voordat jy die prosedure begin om die geheue-aflaai te vang.

Laastens, verwyder net al die onnodige data uit die loglêer en stoor die lêer as `filename.rom` en gebruik binwalk om die inhoud te onttrek:
```
binwalk -e <filename.rom>
```
Dit sal die moontlike inhoud van die EEPROM lys volgens die handtekeninge wat in die hex-lêer gevind is.

Alhoewel, dit is nodig om op te let dat dit nie altyd die geval is dat die uboot ontgrendel is nie, selfs al word dit gebruik. As die Enter-sleutel niks doen nie, kyk vir verskillende sleutels soos die Spasie-sleutel, ens. As die bootloader vergrendel is en nie onderbreek word nie, sal hierdie metode nie werk nie. Om te kyk of uboot die bootloader vir die toestel is, kyk na die uitvoer op die UART-konsol terwyl die toestel opstart. Dit mag uboot noem terwyl dit opstart.

{{#include ../../banners/hacktricks-training.md}}
