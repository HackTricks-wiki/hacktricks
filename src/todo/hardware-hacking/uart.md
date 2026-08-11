# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

UART is ’n asinchrone seriële koppelvlak wat ’n geraamde stroom bisse sonder ’n gedeelde klok oordra. Moenie UART op logikavlak met RS-232 verwar nie: RS-232 gebruik ander, dikwels negatiewe, spanningsvlakke en vereis ’n transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Oor die algemeen word die lyn hoog gehou (op ’n logiese 1-waarde) terwyl UART in die ledige toestand is. Om die begin van ’n data-oordrag aan te dui, stuur die sender ’n beginbis na die ontvanger, waartydens die sein laag gehou word (op ’n logiese 0-waarde). Vervolgens stuur die sender vyf tot agt databisse wat die werklike boodskap bevat, gevolg deur ’n opsionele pariteitsbis en een of twee stopbisse (met ’n logiese 1-waarde), afhangend van die konfigurasie. Die pariteitsbis, wat vir foutkontrole gebruik word, word selde in die praktyk gesien. Die stopbis (of -bisse) dui die einde van die oordrag aan.

Die algemeenste konfigurasie is 8N1: agt databisse, geen pariteit nie, en een stopbis. UART stuur die minste-betekenisvolle databis eerste, dus word ASCII `C` (`0x43`) as volg versend: begin `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Ons noem die algemeenste konfigurasie 8N1: agt databisse, geen pariteit nie, en een stopbis. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, in ’n 8N1 UART wou stuur](<../../images/image (764).png>)

Hardeware-nutsmiddels om met UART te kommunikeer:

- USB-na-seriële adapter
- Adapters met die CP2102- of PL2303-skyfies
- Veeldoelige hulpmiddel soos: Bus Pirate, die Adafruit FT232H, die Shikra, of die Attify Badge

### Identifisering van UART-poorte

’n Tipiese debug-header stel **TX**, **RX**, en **GND** bloot; dit kan ook ’n **Vcc/Vref**-pen, reset- of vloeibeheerpenne blootstel. Vcc is nie ’n UART-sein nie en moet normaalweg slegs as ’n spanningsverwysing gebruik word—nie as ’n kragbron gekoppel word nie—tensy die bord se skematiese diagram en stroomvereistes bekend is.<sup>[[2]](#references)[[3]](#references)</sup>

Begin met die toestel **afgeskakel** en ontkoppel:

- Identifiseer **GND** in kontinuïteitsmodus teenoor ’n bekende grondvlak, verbindingskerm of toevoergrond. Moet nooit kontinuïteits-/weerstandsmodus op ’n aangeskakelde bord gebruik nie.
- Skakel na GS-spanningsmodus voordat jy die teiken aanskakel. Meet kandidaatpenne relatief tot grond om die logikaspanning te identifiseer. ’n Bestendige spoor kan Vcc/Vref wees; moenie aanvaar dat dit veilig is om te koppel nie.
- Neem kandidate met ’n logiese ontleder of ossilloskoop waar tydens selflaai. **TX** is gewoonlik ledig hoog en toon sarsies geraamde data. ’n Multimeter kan ’n gemiddelde skommeling toon, maar kan nie die raamwerk of baudtempo bevestig nie.
- **RX** kan ledig bly en kan nie veilig geïdentifiseer word bloot omdat dit langs TX is nie. Volg die PCB-spore, raadpleeg die SoC-datablad, of gebruik ’n ontleder met hoë impedansie voordat jy dit aandryf.

Om TX en RX om te ruil lewer normaalweg geen kommunikasie nie; verwarring tussen krag, grond of seinvlakke kan die teiken of adapter permanent beskadig. Koppel eers grond en begin **slegs met ontvangs** (teiken-TX na adapter-RX).

Vervaardigers kan die header weglaat, serieweerstande ongepopuleer laat, die konsole in firmware deaktiveer, of slegs TX blootstel. Volg nabygeleë toetsblokkies en weerstandvoetspore na die SoC en voeg slegs ’n tydelike verbinding met hoë impedansie by nadat die elektriese vlak bevestig is. Die teenwoordigheid van ’n waarborg impliseer nie dat ’n toeganklike UART moet bestaan nie.

### Identifisering van die UART-baudtempo

Die maklikste manier om die korrekte baudtempo te identifiseer, is om na die **TX-pen se uitvoer te kyk en die data te probeer lees**. As die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baudtempo totdat die data leesbaar word. Jy kan ’n USB-na-seriële adapter of ’n veeldoelige toestel soos Bus Pirate gebruik, saam met ’n helperskrip, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die algemeenste baudtempo’s is 9600, 38400, 19200, 57600 en 115200.

> [!CAUTION]
> Dit is belangrik om daarop te let dat jy in hierdie protokol die TX van een toestel aan die RX van die ander toestel moet koppel!

## CP210X UART-na-TTY-adapter

CP210x USB-na-UART-bridges verskyn op baie prototiperingsborde en goedkoop adapters. Algemene modules stel toevoerpennetjies saam met GND, RXD en TXD bloot, maar hul headers en I/O-vlakke verskil. Bevestig die werklike spanning uit die bordontwerp of datablad. Gewoonlik moet slegs GND, adapter-RX na teiken-TX, en—nadat slegs-ontvangs gevalideer is—adapter-TX na teiken-RX gekoppel word. Moenie die adapter se 5 V/3.3 V-toevoerpen koppel nie, tensy jy doelbewus ’n teiken van krag voorsien wat bekend is dat dit dit kan verdra.<sup>[[3]](#references)</sup>

As die adapter nie bespeur word nie, maak seker dat die CP210X-drywers op die gasheerstelsel geïnstalleer is. Sodra die adapter bespeur en gekoppel is, kan nutsmiddels soos picocom, minicom of screen gebruik word.

Om die toestelle wat aan Linux/MacOS-stelsels gekoppel is, te lys:
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
Konfigureer die instellings, soos baudrate en toestelnaam, in die `Serial port setup`-opsie.

Begin ná konfigurasie `minicom` om die UART-konsole oop te maak.

## UART via Arduino UNO R3 (verwyderbare Atmel 328p-skyfieborde)

Indien UART Serial to USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 met ’n vinnige hack gebruik word. Omdat Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het ’n USB to Serial-adapter wat op die bord self gebou is. Om ’n UART-verbinding te kry, trek eenvoudig die Atmel 328p-mikrobeheerderskyfie uit die bord. Hierdie hack werk op Arduino UNO R3-variante waarvan die Atmel 328p nie op die bord gesoldeer is nie (die SMD-weergawe word daarin gebruik). Verbind die RX-pen van Arduino (Digital Pin 0) met die TX-pen van die UART Interface, en die TX-pen van Arduino (Digital Pin 1) met die RX-pen van die UART-interface.

Gebruik die Arduino IDE **Serial Monitor** of ’n toegewyde terminaal teen die teiken se baudrate. Klassieke Uno R3-serialseine is 5 V-logika, dus moet ’n level shifter of divider gebruik word voordat dit aan ’n 3.3 V- of laerspanningsteiken verbind word.

## Bus Pirate

Die volgende transkripsie gebruik die legacy Bus Pirate-firmware-interface om UART-uitvoer te monitor. Nuwer Bus Pirate-firmware gebruik opdragte soos `m uart`, `{`/`}`, `monitor` of `bridge`; raadpleeg die dokumentasie vir die geïnstalleerde weergawe.<sup>[[2]](#references)</sup>
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
## Firmware met UART Console dump

'n UART-console bied runtime-toegang tot bootlogs en soms 'n bootloader- of operating-system-shell. Selfs 'n leesalleen-console onthul geheuekaarte, flash drivers, boot-argumente, partisieuitlegte en firmware-weergawes. Firmware kan in SPI NOR/NAND, eMMC of 'n ander toestel wees; dit word gewoonlik nie vanaf 'n EEPROM uitgevoer nie, en lêers wat na 'n gemonteerde persistente lêerstelsel geskryf word, verdwyn nie noodwendig ná 'n reboot nie.

Daar is verskeie verkrygingspaaie, en die SPI-afdeling dek direkte leesaksies vanaf eksterne flash. Console-assisted acquisition kan minder indringend wees wanneer die bootloader reeds 'n veilige leesopdrag bied, maar enige bootonderbreking of flash-opdrag kan beskikbaarheid beïnvloed; teken dus die oorspronklike toestand aan en vermy write/erase-bewerkings.

Console-assisted firmware dumping begin dikwels deur 'n bootloader te onderbreek. Baie embedded Linux-toestelle gebruik **Das U-Boot**, maar ander gebruik proprietary bootloaders of deaktiveer die interactive console.

Om vir 'n interactive bootloader te toets, koppel die UART receive path en terminal terwyl die target afgeskakel is, begin logging en skakel dit aan. Volg die vertoonde autoboot-prompt; afhangend van die build kan onderbreking 'n sleutel, 'n kort sequence vereis, of heeltemal gedeaktiveer wees.

As die onderbreking slaag, gebruik `help`, `printenv` en read-only discovery commands om daardie vendor se memory- en storage-uitleg te verstaan voordat jy toegang tot adresse verkry.

In U-Boot vertoon `md` **addressable memory**, nie outomaties “the EEPROM” nie. Gebruik eers board-specific commands soos `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables en bootlogs om die korrekte mapped address te identifiseer, of laai 'n flash-region in RAM. Vertoon daarna 'n bekende reeks byte vir byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Teken die serial-uitvoer aan voordat jy begin. Die `md.b`-uitvoer bevat adresse en ’n ASCII-kolom, dus is dit ’n tekstuele voorstelling eerder as ’n rou ROM-image.

Verwyder die adres- en ASCII-kolomme, voeg slegs die heksadesimale bisvelde saam en dekodeer dit na binêr (byvoorbeeld met `xxd -r -p`). Verifieer die verwagte grepetelling en teken ’n hash aan voordat jy dit ontleed:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk identifiseer dan bekende handtekeninge in die gerekonstrueerde binêre lêer. ’n Direkte flash-leesbewerking deur die toepaslike SPI/eMMC/NAND-koppelvlak is gewoonlik vinniger en minder foutgevoelig wanneer die console nie data betroubaar kan oordra nie.

U-Boot kan onderbreking deaktiveer, ’n verskafferspesifieke sleutelvolgorde vereis, of geheue-/flash-opdragte sluit. Volg die autoboot-prompt en boot-log eerder as om karakters blindelings te stuur. As die console nie onderbreek kan word nie, behou die boot-log en skakel oor na ’n nie-indringende firmware-verkrygingspad.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
