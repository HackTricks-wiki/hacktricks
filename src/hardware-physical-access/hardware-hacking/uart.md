# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

UART is ’n asynchrone seriële koppelvlak wat ’n geraamde stroom bisse sonder ’n gedeelde klok oordra. Moenie logikavlak-UART met RS-232 verwar nie: RS-232 gebruik ander, dikwels negatiewe, spanningsvlakke en vereis ’n transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Oor die algemeen word die lyn hoog gehou (op ’n logiese 1-waarde) terwyl UART in die ledige toestand is. Om die begin van ’n data-oordrag aan te dui, stuur die sender dan ’n startbit aan die ontvanger, waartydens die sein laag gehou word (op ’n logiese 0-waarde). Vervolgens stuur die sender vyf tot agt databisse wat die werklike boodskap bevat, gevolg deur ’n opsionele pariteitsbit en een of twee stopbisse (met ’n logiese 1-waarde), afhangend van die konfigurasie. Die pariteitsbit, wat vir foutkontrole gebruik word, word selde in die praktyk gesien. Die stopbit (of -bisse) dui die einde van die oordrag aan.

Die algemeenste konfigurasie is 8N1: agt databisse, geen pariteit nie, en een stopbit. UART stuur die minste-beduidende databit eerste, dus word ASCII `C` (`0x43`) as volg versend: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Ons noem die algemeenste konfigurasie 8N1: agt databisse, geen pariteit nie, en een stopbit. As ons byvoorbeeld die karakter C, of 0x43 in ASCII, in ’n 8N1 UART wou stuur](<../../images/image (764).png>)

Hardeware-nutsmiddels om met UART te kommunikeer:

- USB-na-seriële adapter
- Adapters met die CP2102- of PL2303-skyfies
- Veeldoelige hulpmiddel soos: Bus Pirate, die Adafruit FT232H, die Shikra, of die Attify Badge

### Identifisering van UART-poorte

’n Tipiese debug-header stel **TX**, **RX** en **GND** beskikbaar; dit kan ook ’n **Vcc/Vref**-pen, reset of vloei beheer-penne hê. Vcc is nie ’n UART-sein nie en moet normaalweg net as ’n spanningsverwysing gebruik word—moenie dit as ’n kragbron koppel nie—tensy die bord se skematiese diagram en stroomvereistes bekend is.<sup>[[2]](#references)[[3]](#references)</sup>

Begin met die toestel **afgeskakel** en ontkoppel:

- Identifiseer **GND** in kontinuïteitsmodus teenoor ’n bekende grondvlak, konnektorafskerming of kragtoevoergrond. Moet nooit kontinuïteits-/weerstandsmodus op ’n bord gebruik wat aangeskakel is nie.
- Skakel oor na GS-spanningsmodus voordat jy die teiken aanskakel. Meet kandidaatpenne teenoor grond om die logikaspanning te identifiseer. ’n Stabiele kragrail kan Vcc/Vref wees; moenie aanvaar dat dit veilig is om te koppel nie.
- Neem kandidaatpenne met ’n logikaanaliseerder of ossilloskoop waar terwyl die toestel selflaai. **TX** is gewoonlik ledig hoog en toon uitbarstings van geraamde data. ’n Multimeter kan ’n gemiddelde skommeling wys, maar kan nie die raamformaat of baud rate bevestig nie.
- **RX** kan ledig bly en kan nie veilig geïdentifiseer word bloot omdat dit langs TX is nie. Volg die PCB-spore, raadpleeg die SoC-datablad of gebruik ’n hoë-impedansie-analiseerder voordat jy dit aandryf.

As TX en RX omgeruil word, is daar gewoonlik geen kommunikasie nie; as krag, grond of seinvlakke verwar word, kan dit die teiken of adapter permanent beskadig. Koppel eers die grond en begin **slegs met ontvangs** (teiken-TX na adapter-RX).

Vervaardigers kan die header weglaat, serieweerstande ongeïnstalleer laat, die konsole in firmware deaktiveer, of net TX beskikbaar stel. Volg nabygeleë toetspenne en weerstandvoetspore na die SoC en voeg slegs ’n tydelike hoë-impedansieverbinding by nadat die elektriese vlak bevestig is. Die teenwoordigheid van ’n waarborg beteken nie dat ’n toeganklike UART noodwendig bestaan nie.

### Identifisering van die UART-baud rate

Die maklikste manier om die korrekte baud rate te identifiseer, is om na die **TX-pen se uitset te kyk en die data te probeer lees**. As die data wat jy ontvang nie leesbaar is nie, probeer die volgende moontlike baud rate totdat die data leesbaar is. Jy kan ’n USB-na-seriële adapter of ’n veeldoelige toestel soos Bus Pirate gebruik om dit te doen, saam met ’n hulpskrip, soos [baudrate.py](https://github.com/devttys0/baudrate/). Die algemeenste baud rates is 9600, 38400, 19200, 57600 en 115200.

> [!CAUTION]
> Dit is belangrik om daarop te let dat jy in hierdie protokol die TX van een toestel aan die RX van die ander toestel moet koppel!

### Outomatisering van UART-opname tydens selflaai met SCPI

As die selflaai-uitvoer kort is of die TX-toetspen nog onbekend is, outomatiseer herhaalde aanskakelings eerder as om die kragtoevoer en ossilloskoop met die hand te beheer. Koppel ’n programmeerbare kragtoevoer met stroombeperking aan die teiken se geverifieerde kraginvoer. Toets elke kandidaat-TX-toetspen met ’n hoë-impedansie-ossilloskoopinvoer en gedeelde grond; moenie die toetspen aandryf nie.<sup>[[5]](#references)</sup>

VISA open seriële of Ethernet-instrumentsessies, terwyl SCPI die uitset, sneller en golfvormuitlees beheer.<sup>[[5]](#references)[[6]](#references)</sup> Installeer `pyvisa` en `pyvisa-py` (plus `pyserial` vir seriële VISA-hulpbronne); `ResourceManager('@py')` kies uitdruklik die Python-agtergrondstelsel.<sup>[[5]](#references)[[7]](#references)</sup> Vervang die hulpbronstringe en opdragte met dié wat deur die betrokke instrumente ondersteun word.<sup>[[5]](#references)</sup>

In die Rigol MSO5000-voorbeeld, stel ’n enkelskoot-sneller op ’n dalende flank gereed voordat jy die bord aanskakel: ’n ledig-hoë UART TX daal eers vir sy startbit.<sup>[[5]](#references)</sup> Stel die snellervlak tussen die gemete ledige en lae vlakke, en stel die tydsbasis om die betrokke selflaaitydperk te dek.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` kan herhaalde flanke in deurlopende opnames onderdruk, maar dit vervang nie die kontrole dat ’n enkelskoot-opname werklik voltooi is nie.<sup>[[5]](#references)</sup> Die volgende neem een selflaai vas en stoor beide die ongetekende grepe en hul skaalmetadata; ’n uitteltyd skakel die teiken af eerder as om vir ewig te wag.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA-aanskakeling en enkelskoot-opname van UART-golfvorm</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Vir ’n pad-opname, herhaal die enkelopname nadat jy die probe verskuif het, of hou die toevoersessie oop en skakel die uitset aan en af met ’n opstartvertraging en ’n af-interval. Heraktiveer die ossilloskoop voor elke aanskakeling sodat elke lêer met een opstart en een pad ooreenstem.<sup>[[5]](#references)</sup>

Die Rigol-voorloopdata is `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Die **derde** waarde is die aantal punte, nie die sample rate soos in die artikel aangedui nie.<sup>[[5]](#references)[[6]](#references)</sup> In die voorbeeld beteken `25,000,000` punte en `xincrement = 2e-8` sekondes `1 / xincrement = 50,000,000` samples/second, nie 25 MSa/s nie.<sup>[[5]](#references)[[6]](#references)</sup> Hou die voorloopdata saam met die binêre lêer en maak seker dat die leeslengte met `<points>` ooreenstem; die gids beskryf gesegmenteerde/gebondelde lesings vir groot opnames.<sup>[[6]](#references)</sup>

Om die vasgelegde sein te dekodeer, voer `capture.bin` in PulseView in as **Raw Analog Data Without Header**, kies unsigned 8-bit (`U8`)-waardes en voer die sample rate in wat uit `xincrement` bereken is.<sup>[[5]](#references)[[6]](#references)</sup> Pas **Logic via Threshold** op die analoogkanaal toe en kies ’n drempelwaarde tussen die lae en hoë sample-waardes.<sup>[[5]](#references)</sup> Meet ’n skoon beginbitwydte om die baud rate te skat (ongeveer 17.36 µs vir 57,600 baud), pas dan PulseView se UART-dekodeerder toe en bevestig dat verskeie rame konsekwent dekodeer.<sup>[[5]](#references)</sup> ’n Dalende flank alleen bewys nie dat ’n pad UART is nie.

## CP210X UART-na-TTY-adapter

CP210x USB-na-UART-brûe kom op baie prototiperingsborde en goedkoop adapters voor. Algemene modules het toevoerpennetjies langs GND, RXD en TXD, maar hul aansluitings en I/O-vlakke verskil. Bevestig die werklike spanning aan die hand van die bordontwerp of datablad. Koppel gewoonlik net GND en adapter-RX aan teiken-TX, en—nadat slegs ontvangs gevalideer is—adapter-TX aan teiken-RX. Moenie die adapter se 5 V/3.3 V-toevoerpennetjie koppel nie, tensy jy doelbewus ’n teiken van krag voorsien waarvan jy weet dat dit dié spanning kan hanteer.<sup>[[3]](#references)</sup>

As die adapter nie opgespoor word nie, maak seker dat die CP210X-drywers op die gasheerstelsel geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan nutsmiddels soos picocom, minicom of screen gebruik word.

Om die toestelle te lys wat aan Linux/MacOS-stelsels gekoppel is:

```
ls /dev/
```

Vir basiese interaksie met die UART-koppelvlak, gebruik die volgende opdrag:

```
picocom /dev/<adapter> --baud <baudrate>
```

Vir minicom, gebruik die volgende opdrag om dit op te stel:

```
minicom -s
```

Stel die instellings, soos baudrate en toestelnaam, in die opsie `Serial port setup` op.

Voer `minicom` uit om die UART-konsole oop te maak nadat jy die instellings opgestel het.

## UART via Arduino UNO R3 (verwyderbare Atmel 328p-skyfieborde)

As UART Serial-na-USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 met ’n vinnige hack gebruik word. Omdat Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het ’n USB-na-Serial-adapter wat op die bord self ingebou is. Om ’n UART-verbinding te kry, haal eenvoudig die Atmel 328p-mikrobeheerderskyfie van die bord af. Hierdie hack werk met Arduino UNO R3-variante waar die Atmel 328p nie op die bord gesoldeer is nie (die SMD-weergawe word daarin gebruik). Koppel die Arduino se RX-pen (Digital Pin 0) aan die UART-koppelvlak se TX-pen en die Arduino se TX-pen (Digital Pin 1) aan die UART-koppelvlak se RX-pen.

Gebruik die Arduino IDE **Serial Monitor** of ’n toegewyde terminaal teen die teiken se baudrate. Klassieke Uno R3-seriële seine gebruik 5 V-logika, dus gebruik ’n vlakverskuiwer of spanningsverdeler voordat jy dit aan ’n teiken met 3.3 V of laer spanning koppel.

## Bus Pirate

Die volgende transkripsie gebruik die legacy Bus Pirate-firmware-koppelvlak om UART-uitset te monitor. Nuwer Bus Pirate-firmware gebruik opdragte soos `m uart`, `{`/`}`, `monitor` of `bridge`; raadpleeg die dokumentasie vir die geïnstalleerde weergawe.<sup>[[2]](#references)</sup>

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

’n UART Console bied toegang tydens looptyd tot boot logs en soms tot ’n bootloader- of bedryfstelsel-shell. Selfs ’n leesalleen-console onthul geheuekaarte, flash-drywers, bootargumente, partisieuitlegte en firmwareweergawes. Firmware kan in SPI NOR/NAND, eMMC of ’n ander toestel gestoor wees; dit word gewoonlik nie vanaf ’n EEPROM uitgevoer nie, en lêers wat na ’n gemonteerde aanhoudende lêerstelsel geskryf word, verdwyn nie noodwendig ná ’n herlaai nie.

Daar is verskeie verkrygingsmetodes, en die SPI-afdeling dek direkte lees vanaf eksterne flash. Verkryging met behulp van die console kan minder indringend wees wanneer die bootloader reeds ’n veilige leesopdrag bied, maar enige onderbreking van die bootproses of flash-opdrag kan beskikbaarheid beïnvloed. Teken dus die oorspronklike toestand aan en vermy skryf-/uitvee-bewerkings.

Firmware-dumping met behulp van die console begin dikwels deur ’n bootloader te onderbreek. Baie ingebedde Linux-toestelle gebruik **Das U-Boot**, maar ander gebruik eie bootloaders of deaktiveer die interaktiewe console.

Om te toets of ’n interaktiewe bootloader beskikbaar is, koppel die UART-ontvangspad en terminaal terwyl die teiken afgeskakel is, begin logging en skakel dit dan aan. Volg die vertoonde autoboot-aanwysing; afhangend van die bouweergawe kan onderbreking ’n sleutel, ’n kort volgorde vereis, of heeltemal gedeaktiveer wees.

As die onderbreking slaag, gebruik `help`, `printenv` en leesalleen-verkenningsopdragte om daardie vervaardiger se geheue- en sto उitleg te verstaan voordat jy toegang tot adresse verkry.

In U-Boot vertoon `md` **adresseerbare geheue**, nie outomaties “die EEPROM” nie. Gebruik eers bordspesifieke opdragte soos `mtd list`, `sf probe`, `mmc info`, `part list`, omgewingsveranderlikes en boot logs om die korrekte gekarteerde adres te identifiseer of ’n flash-streek na RAM te laai. Vertoon dan ’n bekende reeks greep vir greep:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Teken die seriële uitset aan voordat jy begin. Die `md.b`-uitset bevat adresse en ’n ASCII-kolom, dus is dit ’n tekstuele voorstelling eerder as ’n rou ROM-beeld.

Verwyder die adres- en ASCII-kolomme, voeg slegs die heksadesimale grepe saam en dekodeer dit na binêre data (byvoorbeeld met `xxd -r -p`). Verifieer die verwagte grepetelling en teken ’n hash aan voordat jy met die ontleding begin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifiseer vervolgens bekende handtekeninge in die gerekonstrueerde binêre lêer. ’n Direkte flitslesing via die toepaslike SPI/eMMC/NAND-koppelvlak is gewoonlik vinniger en minder foutgevoelig wanneer die konsole nie data betroubaar kan oordra nie.

U-Boot kan onderbreking deaktiveer, ’n verskafferspesifieke sleutelkombinasie vereis of geheue-/flitsopdragte sluit. Volg die outoboot-aanporboodskap en selflaailog eerder as om blindelings karakters te stuur. As die konsole nie onderbreek kan word nie, behou die selflaailog en volg ’n nie-indringende pad om die firmware te bekom.

## References

- [1] [Microchip PIC32-familieverwysingshandleiding - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-dokumentasie - UART-modus en elektriese limiete](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C-datablad](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-dokumentasie - `md`-opdrag om geheue te vertoon](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI en hardeware-instrumentasie vir omgekeerde ingenieurs, Deel 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000-programmeringsgids](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Die backend instel](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
