# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

UART is ’n asinchrone seriële koppelvlak wat ’n geraamde stroom bisse sonder ’n gedeelde klok oordra. Moenie logikavlak-UART met RS-232 verwar nie: RS-232 gebruik ander, dikwels negatiewe, spanningsvlakke en vereis ’n transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Oor die algemeen word die lyn hoog gehou (op ’n logiese 1-vlak) terwyl UART in die ledige toestand is. Om die begin van ’n dataoordrag aan te dui, stuur die sender ’n beginbis na die ontvanger; gedurende dié bis word die sein laag gehou (op ’n logiese 0-vlak). Daarna stuur die sender vyf tot agt databisse met die werklike boodskap, gevolg deur ’n opsionele pariteitsbis en een of twee stopbisse (op ’n logiese 1-vlak), na gelang van die opstelling. Die pariteitsbis, wat vir foutkontrole gebruik word, kom selde in die praktyk voor. Die stopbis(se) dui die einde van die oordrag aan.

Die algemeenste opstelling is 8N1: agt databisse, geen pariteit nie en een stopbis. UART stuur die minste-beduidende databits eerste, dus word ASCII `C` (`0x43`) soos volg oorgedra: begin `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Ons noem die algemeenste opstelling 8N1: agt databisse, geen pariteit nie en een stopbis. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, met 8N1 UART wil stuur](<../../images/image (764).png>)

Hardewarehulpmiddels om met UART te kommunikeer:

- USB-na-seriële adapter
- Adapters met die CP2102- of PL2303-skyfies
- Veeldoelige hulpmiddel soos: Bus Pirate, die Adafruit FT232H, die Shikra of die Attify Badge

### Identifisering van UART-poorte

’n Tipiese debug-header stel **TX**, **RX** en **GND** beskikbaar; dit kan ook ’n **Vcc/Vref**-pen, reset- of vloeibeheerpenne hê. Vcc is nie ’n UART-sein nie en moet gewoonlik slegs as ’n spanningsverwysing gebruik word—nie as ’n kragbron gekoppel word nie—tensy die stroombaandiagram en stroomvereistes van die bord bekend is.<sup>[[2]](#references)[[3]](#references)</sup>

Begin met die toestel **afgeskakel** en ontkoppel:

- Identifiseer **GND** in kontinuïteitsmodus teenoor ’n bekende grondvlak, konnektorskerm of kragtoevoergrond. Moet nooit kontinuïteits-/weerstandsmodus op ’n bord gebruik wat aangeskakel is nie.
- Skakel oor na GS-spanningsmodus voordat jy die teikentoestel aanskakel. Meet moontlike penne relatief tot grond om die logikaspanning te bepaal. ’n Stabiele spanningsrail kan Vcc/Vref wees; moenie aanvaar dat dit veilig is om te koppel nie.
- Monitor moontlike penne tydens selflaai met ’n logikaanaliseerder of ossilloskoop. **TX** is gewoonlik ledig hoog en toon sarsies geraamde data. ’n Multimeter kan ’n gemiddelde skommeling wys, maar kan nie die raamformaat of baudtempo bevestig nie.
- **RX** kan ledig bly en kan nie veilig geïdentifiseer word bloot omdat dit langs TX is nie. Volg die PCB-spore, raadpleeg die SoC-datablad of gebruik ’n hoë-impedansie-analiseerder voordat jy ’n sein daarop toepas.

Om TX en RX om te ruil, veroorsaak gewoonlik dat geen kommunikasie plaasvind nie; verwarring oor krag, grond of seinvlakke kan die teikentoestel of adapter permanent beskadig. Koppel eers die grond en begin in **slegs-ontvangsmodus** (teikentoestel se TX na adapter se RX).

Vervaardigers kan die header weglaat, serieweerstande ongeïnstalleer laat, die konsole in firmware deaktiveer of slegs TX beskikbaar stel. Volg nabygeleë toetsblokkies en weerstandvoetspore na die SoC, en voeg eers ’n tydelike hoë-impedansieverbinding by nadat jy die elektriese vlak bevestig het. Die teenwoordigheid van ’n waarborg beteken nie dat daar noodwendig ’n toeganklike UART is nie.

### Identifisering van die UART-baudtempo

Die maklikste manier om die korrekte baudtempo te bepaal, is om na die uitvoer van die **TX-pen te kyk en te probeer om die data te lees**. As die data wat jy ontvang nie leesbaar is nie, probeer die volgende moontlike baudtempo totdat die data leesbaar word. Jy kan ’n USB-na-seriële adapter of ’n veeldoelige toestel soos Bus Pirate gebruik, saam met ’n hulpskrip soos [baudrate.py](https://github.com/devttys0/baudrate/). Die algemeenste baudtempo’s is 9600, 38400, 19200, 57600 en 115200.

> [!CAUTION]
> Dit is belangrik om daarop te let dat jy in hierdie protokol die TX van een toestel aan die RX van die ander moet koppel!

## CP210X UART-na-TTY-adapter

CP210x USB-na-UART-brûe kom op baie prototiperingsborde en goedkoop adapters voor. Algemene modules stel kragpenne saam met GND, RXD en TXD beskikbaar, maar hul headers en I/O-vlakke verskil. Bevestig die werklike spanning aan die hand van die bordontwerp of datablad. Gewoonlik koppel jy slegs GND en adapter-RX aan teikentoestel-TX; koppel adapter-TX aan teikentoestel-RX eers nadat jy slegs-ontvangs gevalideer het. Moenie die adapter se 5 V-/3.3 V-kragpen koppel nie, tensy jy doelbewus ’n teikentoestel van krag voorsien wat daarvoor geskik is.<sup>[[3]](#references)</sup>

As die adapter nie opgespoor word nie, maak seker dat die CP210X-drywers op die gasheerstelsel geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan hulpmiddels soos picocom, minicom of screen gebruik word.

Om die toestelle te lys wat aan Linux-/MacOS-stelsels gekoppel is:

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

Stel die instellings, soos baudrate en toestelnaam, in die `Serial port setup`-opsie op.

Voer ná die konfigurasie `minicom` uit om die UART-konsole oop te maak.

## UART Via Arduino UNO R3 (Verwyderbare Atmel 328p-skyfiéborde)

Indien UART Serial-na-USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 met ’n vinnige hack gebruik word. Omdat Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het ’n USB-na-Serial-adapter wat op die bord self ingebou is. Om ’n UART-verbinding te kry, haal eenvoudig die Atmel 328p-mikrobeheerder uit die bord. Hierdie hack werk met Arduino UNO R3-variante waar die Atmel 328p nie op die bord gesoldeer is nie (die SMD-weergawe word daarin gebruik). Koppel die RX-pen van Arduino (Digital Pin 0) aan die TX-pen van die UART-koppelvlak, en die TX-pen van Arduino (Digital Pin 1) aan die RX-pen van die UART-koppelvlak.

Gebruik die Arduino IDE **Serial Monitor** of ’n toegewyde terminaal teen die teikenbaudtempo. Klassieke Uno R3-serialseine gebruik 5 V-logika, dus gebruik ’n vlakverskuiwer of spanningsverdeler voordat jy dit aan ’n 3.3 V-teiken of ’n teiken met ’n laer spanning koppel.

## Bus Pirate

Die volgende transkripsie gebruik die verouderde Bus Pirate-firmware-koppelvlak om UART-uitvoer te monitor. Nuwer Bus Pirate-firmware gebruik opdragte soos `m uart`, `{`/`}`, `monitor` of `bridge`; raadpleeg die dokumentasie vir die geïnstalleerde weergawe.<sup>[[2]](#references)</sup>

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

## Firmware dump met UART-konsole

’n UART-konsole bied toegang tydens looptyd tot selflaailogboeke en soms ’n bootloader- of bedryfstelseldop. Selfs ’n leesalleen-konsole onthul geheuekaarte, flash-drywers, selflaaiargumente, partisie-uitlegte en firmwareweergawes. Firmware kan op SPI NOR/NAND, eMMC of ’n ander toestel gestoor wees; dit word gewoonlik nie vanaf ’n EEPROM uitgevoer nie, en lêers wat na ’n gemonteerde, persistente lêerstelsel geskryf word, verdwyn nie noodwendig met ’n herlaai nie.

Daar is verskeie maniere om firmware te bekom, en die SPI-afdeling dek direkte lesings vanaf eksterne flash. Bekomming met behulp van die konsole kan minder indringend wees wanneer die bootloader reeds ’n veilige leesopdrag bied, maar enige onderbreking van die selflaai of flash-opdrag kan beskikbaarheid beïnvloed. Teken dus die oorspronklike toestand aan en vermy skryf- of uitvee-opdragte.

Firmware word dikwels met behulp van die konsole gestort deur die selflaaiproses in ’n bootloader te onderbreek. Baie ingebedde Linux-toestelle gebruik **Das U-Boot**, maar ander gebruik eiendomsregtelike bootloaders of deaktiveer die interaktiewe konsole.

Om te toets of daar ’n interaktiewe bootloader is, koppel die UART-ontvangspad en terminaal terwyl die teikentoestel afgeskakel is, begin logging en skakel dit aan. Volg die vertoonde outomatiese-selflaaiprompt; afhangend van die bouweergawe kan onderbreking ’n sleutel, ’n kort volgorde vereis, of heeltemal gedeaktiveer wees.

As die onderbreking slaag, gebruik `help`, `printenv` en leesalleen-verkenningsopdragte om die vervaardiger se geheue- en berginguitleg te verstaan voordat jy adresse gebruik.

In U-Boot vertoon `md` **adresseerbare geheue**, nie outomaties “die EEPROM” nie. Gebruik eers bordspesifieke opdragte soos `mtd list`, `sf probe`, `mmc info`, `part list`, omgewingsveranderlikes en selflaailogboeke om die korrekte gekarteerde adres te identifiseer of ’n flash-streek na RAM te laai. Vertoon dan ’n bekende reeks greep vir greep:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Teken die seriële uitvoer aan voordat jy begin. Die `md.b`-uitvoer bevat adresse en ’n ASCII-kolom, dus is dit ’n tekstuele voorstelling eerder as ’n rou ROM-beeld.

Verwyder die adres- en ASCII-kolomme, voeg net die heksadesimale greepvelde saam en dekodeer dit na binêre data (byvoorbeeld met `xxd -r -p`). Verifieer die verwagte greepgetal en teken ’n hash aan voordat jy met die ontleding begin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifiseer dan bekende handtekeninge in die gerekonstrueerde binêre lêer. ’n Direkte flitsgeheue-lesing deur die toepaslike SPI/eMMC/NAND-koppelvlak is gewoonlik vinniger en minder foutgevoelig wanneer die konsole nie data betroubaar kan oordra nie.

U-Boot kan onderbreking deaktiveer, ’n verskafferspesifieke sleutelkombinasie vereis of geheue-/flitsopdragte sluit. Volg die outobegin-aanporboodskap en selflaailog eerder as om blindelings karakters te stuur. As die konsole nie onderbreek kan word nie, behou die selflaailog en gebruik ’n nie-indringende metode om die firmware te verkry.

## References

- [1] [Microchip PIC32-familieverwysingshandleiding - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-dokumentasie - UART-modus en elektriese limiete](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C-datablad](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-dokumentasie - `md`-geheuevertoonopdrag](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
