# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese Inligting

UART is ’n serial protocol, wat beteken dat dit data tussen komponente een bis op ’n slag oordra. In teenstelling hiermee stuur parallelle kommunikasieprotokolle data gelyktydig deur verskeie kanale. Algemene serial protocols sluit RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express en USB in.

Oor die algemeen word die lyn hoog gehou (teen ’n logiese 1-waarde) terwyl UART in die idle-toestand is. Dan, om die begin van ’n data-oordrag aan te dui, stuur die transmitter ’n start bit na die receiver, waartydens die sein laag gehou word (teen ’n logiese 0-waarde). Vervolgens stuur die transmitter vyf tot agt databisse wat die werklike boodskap bevat, gevolg deur ’n opsionele parity bit en een of twee stop bits (met ’n logiese 1-waarde), afhangend van die konfigurasie. Die parity bit, wat vir foutkontrolering gebruik word, word selde in die praktyk gesien. Die stop bit (of bits) dui die einde van die transmissie aan.

Ons noem die algemeenste konfigurasie 8N1: agt databisse, geen parity nie, en een stop bit. Byvoorbeeld, indien ons die karakter C, of 0x43 in ASCII, in ’n 8N1 UART-konfigurasie wou stuur, sou ons die volgende bisse stuur: 0 (die start bit); 0, 1, 0, 0, 0, 0, 1, 1 (die waarde van 0x43 in binêre), en 0 (die stop bit).

![UART: Ons noem die algemeenste konfigurasie 8N1: agt databisse, geen parity nie, en een stop bit. Byvoorbeeld, indien ons die karakter C, of 0x43 in ASCII, in ’n 8N1 UART wou stuur](<../../images/image (764).png>)

Hardware tools om met UART te kommunikeer:

- USB-to-serial adapter
- Adapters met die CP2102- of PL2303-chips
- Multipurpose tool soos: Bus Pirate, die Adafruit FT232H, die Shikra of die Attify Badge

### Identifisering van UART-poorte

UART het 4 poorte: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) en **GND**(Ground). Jy kan moontlik 4 poorte vind met die letters **`TX`** en **`RX`** wat op die PCB **geskryf** is. Maar indien daar geen aanduiding is nie, moet jy dit moontlik self probeer vind deur ’n **multimeter** of ’n **logic analyzer** te gebruik.

Met ’n **multimeter** en die toestel afgeskakel:

- Om die **GND**-pen te identifiseer, gebruik die **Continuity Test**-modus, plaas die swart meetpen op ground en toets met die rooi een totdat jy ’n geluid van die multimeter hoor. Verskeie GND-penne kan op die PCB gevind word, dus het jy moontlik die een gevind wat aan UART behoort, of moontlik nie.
- Om die **VCC-poort** te identifiseer, stel die **DC voltage mode** in en stel dit op 20 V. Plaas die swart meetpen op ground en die rooi meetpen op die pen. Skakel die toestel aan. Indien die multimeter ’n konstante spanning van óf 3.3 V óf 5 V meet, het jy die Vcc-pen gevind. Indien jy ander spannings kry, probeer weer met ander poorte.
- Om die **TX**-**poort** te identifiseer, gebruik **DC voltage mode** tot 20 V, plaas die swart meetpen op ground en die rooi meetpen op die pen, en skakel die toestel aan. Indien jy vind dat die spanning vir ’n paar sekondes fluktueer en dan by die Vcc-waarde stabiliseer, het jy heel waarskynlik die TX-poort gevind. Dit is omdat dit tydens aanskakeling debug-data stuur.
- Die **RX-poort** sal die naaste een aan die ander 3 wees; dit het die laagste spanningsfluktuasie en laagste algehele waarde van al die UART-penne.

Jy kan die TX- en RX-poorte verwar en niks sal gebeur nie, maar indien jy die GND- en VCC-poort verwar, kan jy die circuit beskadig.

In sommige target devices word die UART-poort deur die vervaardiger gedeaktiveer deur RX of TX, of selfs albei, te deaktiveer. In daardie geval kan dit nuttig wees om die verbindings op die circuit board na te spoor en ’n breakout point te vind. ’n Sterk aanduiding om te bevestig dat UART nie opgespoor word nie en dat die circuit onderbreek is, is om die toestel se warranty na te gaan. Indien die toestel met ’n warranty verskeep is, laat die vervaardiger sommige debug interfaces (in hierdie geval UART) agter en moes die UART dus ontkoppel het, om dit weer tydens debugging aan te sluit. Hierdie breakout pins kan deur soldering of jumper wires verbind word.

### Identifisering van die UART Baud Rate

Die maklikste manier om die korrekte baud rate te identifiseer, is om na die **TX-pin se output te kyk en die data te probeer lees**. Indien die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baud rate totdat die data leesbaar word. Jy kan ’n USB-to-serial adapter of ’n multipurpose device soos Bus Pirate gebruik, saam met ’n helper script, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die algemeenste baud rates is 9600, 38400, 19200, 57600 en 115200.

> [!CAUTION]
> Dit is belangrik om daarop te let dat jy in hierdie protocol die TX van een toestel aan die RX van die ander moet koppel!

## CP210X UART to TTY Adapter

Die CP210X Chip word in baie prototyping boards soos NodeMCU (met esp8266) vir Serial Communication gebruik. Hierdie adapters is relatief goedkoop en kan gebruik word om aan die UART-interface van die target te koppel. Die toestel het 5 penne: 5V, GND, RXD, TXD, 3.3V. Maak seker dat jy die spanning koppel wat deur die target ondersteun word om enige skade te voorkom. Koppel laastens die RXD-pen van die Adapter aan die TXD van die target, en die TXD-pen van die Adapter aan die RXD van die target.

Indien die adapter nie opgespoor word nie, maak seker dat die CP210X-drivers in die host system geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan tools soos picocom, minicom of screen gebruik word.

Om die toestelle wat aan Linux/MacOS-stelsels gekoppel is te lys:
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
Stel die instellings soos baudrate en toestelnaam in die `Serial port setup`-opsie op.

Gebruik ná die konfigurasie die opdrag `minicom` om die UART Console te begin.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Indien UART Serial to USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 met ’n vinnige hack gebruik word. Aangesien Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het ’n USB to Serial-adapter wat op die bord self gebou is. Om ’n UART-verbinding te kry, haal eenvoudig die Atmel 328p-mikrobeheerder-skyfie uit die bord. Hierdie hack werk op Arduino UNO R3-variante waar die Atmel 328p nie op die bord gesoldeer is nie (die SMD-weergawe word daarin gebruik). Verbind die RX-pen van Arduino (Digital Pin 0) met die TX-pen van die UART Interface, en TX-pen van Arduino (Digital Pin 1) met die RX-pen van die UART Interface.

Laastens word dit aanbeveel om Arduino IDE te gebruik om die Serial Console te verkry. Kies in die `tools`-afdeling van die kieslys die `Serial Console`-opsie en stel die baud rate volgens die UART Interface in.

## Bus Pirate

In hierdie scenario gaan ons die UART-kommunikasie van die Arduino afluister wat al die uitvoer van die program na die Serial Monitor stuur.
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
## Dumping van Firmware met UART Console

UART Console bied 'n uitstekende manier om met die onderliggende firmware in 'n runtime environment te werk. Maar wanneer toegang tot die UART Console slegs-lees is, kan dit baie beperkings veroorsaak. In baie embedded devices word die firmware in EEPROMs gestoor en uitgevoer in processors wat volatile memory het. Daarom word die firmware slegs-lees gehou, aangesien die oorspronklike firmware tydens vervaardiging binne die EEPROM self is en enige nuwe lêers weens volatile memory verlore sal gaan. Daarom is dumping van firmware 'n waardevolle poging wanneer met embedded firmwares gewerk word.

Daar is baie maniere om dit te doen, en die SPI-afdeling dek metodes om firmware direk uit die EEPROM te onttrek met verskeie devices. Dit word egter aanbeveel om eers firmware met UART te probeer dump, aangesien die dumping van firmware met fisiese devices en eksterne interaksies riskant kan wees.

Om firmware uit UART Console te dump, moet jy eers toegang tot bootloaders verkry. Baie gewilde vendors gebruik uboot (Universal Bootloader) as hul bootloader om Linux te laai. Daarom is dit nodig om toegang tot uboot te verkry.

Om toegang tot die bootloader te verkry, koppel die UART-poort aan die rekenaar en gebruik enige van die Serial Console-tools, terwyl die kragtoevoer na die device ontkoppel bly. Sodra die opstelling gereed is, druk die Enter Key en hou dit ingedruk. Koppel laastens die kragtoevoer aan die device en laat dit boot.

Deur dit te doen, sal uboot se laaiery onderbreek word en sal 'n menu verskyn. Dit word aanbeveel om uboot-opdragte te verstaan en die help-menu te gebruik om hulle te lys. Dit kan die `help`-opdrag wees. Aangesien verskillende vendors verskillende konfigurasies gebruik, is dit nodig om elkeen afsonderlik te verstaan.

Gewoonlik is die opdrag om die firmware te dump:
```
md
```
wat staan vir "memory dump". Dit sal die geheue (EEPROM Content) op die skerm dump. Dit word aanbeveel om die Serial Console-uitset aan te teken voordat die prosedure begin word, om die memory dump vas te lê.

Ten slotte, verwyder eenvoudig al die onnodige data uit die loglêer en stoor die lêer as `filename.rom`, en gebruik binwalk om die inhoud te onttrek:
```
binwalk -e <filename.rom>
```
Dit sal die moontlike inhoud van die EEPROM lys volgens die signatures wat in die hex file gevind is.

Dit is egter belangrik om daarop te let dat die uboot nie altyd unlocked is nie, selfs al word dit gebruik. As die Enter Key niks doen nie, kyk vir ander keys soos Space Key, ens. As die bootloader locked is en nie interrupted word nie, sal hierdie metode nie werk nie. Om te kyk of uboot die bootloader vir die toestel is, kontroleer die output op die UART Console tydens die toestel se boot. Dit mag uboot tydens die boot noem.

{{#include ../../banners/hacktricks-training.md}}
