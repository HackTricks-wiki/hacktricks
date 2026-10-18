# UART

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

UART is ’n asinchrone seriële koppelvlak wat ’n geënkodeerde stroom bisse oordra sonder ’n gedeelde klok. Moenie logikavlak-UART met RS-232 verwar nie: RS-232 gebruik ander, dikwels negatiewe, spanningsvlakke en vereis ’n transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Gewoonlik word die lyn hoog gehou (op ’n logiese 1-waarde) wanneer UART in die ledige toestand is. Om die begin van ’n data-oordrag aan te dui, stuur die sender ’n beginbis na die ontvanger; gedurende hierdie bis word die sein laag gehou (op ’n logiese 0-waarde). Daarna stuur die sender vyf tot agt databisse wat die werklike boodskap bevat, gevolg deur ’n opsionele pariteitsbis en een of twee stopbisse (met ’n logiese 1-waarde), afhangend van die konfigurasie. Die pariteitsbis, wat vir foutkontrole gebruik word, word selde in die praktyk gesien. Die stopbis(se) dui die einde van die oordrag aan.

Die algemeenste konfigurasie is 8N1: agt databisse, geen pariteit en een stopbis. UART stuur die minste beduidende databis eerste, dus word ASCII `C` (`0x43`) as volg oorgedra: begin `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Ons noem die algemeenste konfigurasie 8N1: agt databisse, geen pariteit en een stopbis. Byvoorbeeld, as ons die karakter C, of 0x43 in ASCII, in ’n 8N1 UART wou stuur](<../../images/image (764).png>)

Hardewaregereedskap om met UART te kommunikeer:

- USB-na-serieel-adapter
- Adapters met die CP2102- of PL2303-skyfies
- Veeldoelige gereedskap soos: Bus Pirate, die Adafruit FT232H, die Shikra of die Attify Badge

### Identifisering van UART-poorte

’n Tipiese debug-header stel **TX**, **RX** en **GND** beskikbaar; dit kan ook ’n **Vcc/Vref**-pen, reset of vloeibeheerpenne hê. Vcc is nie ’n UART-sein nie en moet gewoonlik slegs as ’n spanningsverwysing gebruik word—nie as ’n kragbron gekoppel word nie—tensy die bord se skematiese diagram en stroomvereistes bekend is.<sup>[[2]](#references)[[3]](#references)</sup>

Begin met die toestel **afgeskakel** en ontkoppel:

- Identifiseer **GND** in kontinuïteitsmodus deur dit teen ’n bekende grondvlak, aansluitingskerm of kragtoevoergrond te toets. Moet nooit kontinuïteits-/weerstandsmodus op ’n bord gebruik wat aangeskakel is nie.
- Skakel oor na GS-spanningsmodus voordat jy die teikentoestel aanskakel. Meet kandidaatpenne relatief tot grond om die logikaspanning te bepaal. ’n Bestendige spanningsrail kan Vcc/Vref wees; moenie aanvaar dat dit veilig is om te koppel nie.
- Monitor kandidaatpenne met ’n logikaanaliseerder of ossilloskoop tydens selflaai. **TX** is gewoonlik ledig hoog en toon sarsies geënkodeerde data. ’n Multimeter kan ’n gemiddelde skommeling toon, maar kan nie die raamformaat of baudtempo bevestig nie.
- **RX** kan ledig bly en kan nie veilig geïdentifiseer word bloot omdat dit langs TX is nie. Volg die PCB-spore, raadpleeg die SoC-datablad of gebruik ’n hoë-impedansie-analiseerder voordat jy die pen aandryf.

As TX en RX omgeruil word, is daar gewoonlik geen kommunikasie nie; as krag, grond of seinvlakke verwar word, kan dit die teikentoestel of adapter permanent beskadig. Koppel eers grond en begin **slegs met ontvangs** (teiken se TX na adapter se RX).

Vervaardigers kan die header weglaat, serieweerstande ongeïnstalleer laat, die konsole in firmware deaktiveer of net TX beskikbaar stel. Volg nabygeleë toetsblokkies en weerstandvoetspore na die SoC en voeg eers ’n tydelike hoë-impedansieverbinding by nadat die elektriese vlak bevestig is. Die teenwoordigheid van ’n waarborg beteken nie dat daar noodwendig ’n toeganklike UART is nie.

### Herwinning van ’n TX-blokkie wat laag lyk

’n Gemerkte TX-blokkie wat laag bly in ’n aanvanklike ossilloskoopvaslegging is nie genoeg rede om UART uit te sluit nie. Nadat jy die teiken se logikaspanning bevestig het en ’n gemeenskaplike grond gevestig het, probeer ’n swak optrekweerstand (die gedokumenteerde voorbeeld het **10 kΩ na 3.3 V** gebruik) en herhaal die vaslegging terwyl jy knoppies gebruik of die toestel selflaai. Gebruik slegs die teiken se geverifieerde logikaspanningsrail; moenie ’n optrekweerstand aan ’n onbekende of aktief aangedrewe sein koppel nie. As geënkodeerde oorgange verskyn, meet die kortste skoon bisperiode om die baudtempo te beraam voordat jy die blokkie slegs vir ontvangs aan ’n seriële adapter koppel. In die voorbeeld het dit knoppiegebeurtenislogboeke teen 115200 baud herwin, maar nie ’n firmware-storting blootgelê nie.<sup>[[8]](#references)</sup>

### Identifisering van die UART-baudtempo

Die maklikste manier om die korrekte baudtempo te identifiseer, is om na die uitset van die **TX-pen** te kyk en die data te probeer lees. As die data wat jy ontvang nie leesbaar is nie, skakel oor na die volgende moontlike baudtempo totdat die data leesbaar word. Jy kan ’n USB-na-serieel-adapter of ’n veeldoelige toestel soos Bus Pirate gebruik, saam met ’n hulpskrip soos [baudrate.py](https://github.com/devttys0/baudrate/). Die algemeenste baudtempo’s is 9600, 38400, 19200, 57600 en 115200.

> [!CAUTION]
> Dit is belangrik om daarop te let dat jy in hierdie protokol die TX van een toestel aan die RX van die ander toestel moet koppel!

### Outomatisering van UART-vaslegging tydens selflaai met SCPI

As selflaai-uitset kort is of die TX-blokkie nog onbekend is, outomatiseer herhaalde aanskakelings eerder as om die kragtoevoer en ossilloskoop met die hand te bedien. Koppel ’n programmeerbare kragtoevoer met stroombeperking aan die geverifieerde kragtoevoer-invoer van die teikentoestel. Toets elke kandidaat-TX-blokkie met ’n hoë-impedansie-ossilloskoopinvoer en ’n gedeelde grond; moenie die blokkie aandryf nie.<sup>[[5]](#references)</sup>

VISA open seriële of Ethernet-instrumentsessies, terwyl SCPI die uitset, sneller en golfvormuitlees beheer.<sup>[[5]](#references)[[6]](#references)</sup> Installeer `pyvisa` en `pyvisa-py` (plus `pyserial` vir seriële VISA-hulpbronne); `ResourceManager('@py')` kies uitdruklik die Python-agtergrondstelsel.<sup>[[5]](#references)[[7]](#references)</sup> Vervang die hulpbronstringe en opdragte met dié wat deur die betrokke instrumente ondersteun word.<sup>[[5]](#references)</sup>

In die Rigol MSO5000-voorbeeld, aktiveer ’n enkelvoudige dalende-rand-sneller voordat jy die bord aanskakel: ’n UART TX wat in die ledige toestand hoog is, daal eers vir sy beginbis.<sup>[[5]](#references)</sup> Stel die snellerdrempel tussen die gemete ledige en lae vlakke, en stel die tydskaal so in dat dit die selflaaitydperk van belang dek.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` kan herhaalde rande in deurlopende vasleggings onderdruk, maar dit vervang nie die kontrole dat ’n enkelvoudige vaslegging werklik voltooi is nie.<sup>[[5]](#references)</sup> Die volgende kode vang een selflaai vas en stoor beide die ongetekende grepe en hul skaalmetadata; ’n uitteltyd skakel die teikentoestel af eerder as om onbepaald te wag.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA-kragaanskakeling en enkelvoudige UART-golfvormvaslegging</summary>

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

Vir 'n pad-opname, herhaal die enkelskootvaslegging nadat jy die probe verskuif het, of hou die toevoersessie oop en skakel die uitset met 'n aanskakeltyd en 'n af-interval. Stel die ossilloskoop weer gereed voor elke aanskakeling sodat elke lêer met een aanskakeling en een pad ooreenstem.<sup>[[5]](#references)</sup>

Die Rigol-preambule is `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> Die **derde** waarde is die aantal punte, nie die monstertempo soos in die artikel vermeld nie.<sup>[[5]](#references)[[6]](#references)</sup> In die voorbeeld impliseer `25,000,000` punte en `xincrement = 2e-8` sekondes `1 / xincrement = 50,000,000` monsters/sekonde, nie 25 MSa/s nie.<sup>[[5]](#references)[[6]](#references)</sup> Hou die preambule saam met die binêre lêer en maak seker dat die leeslengte met `<points>` ooreenstem; die gids beskryf gesegmenteerde/gebondelde leesbewerkings vir groot opnames.<sup>[[6]](#references)</sup>

Om die vasgelegde sein te dekodeer, voer `capture.bin` in PulseView in as **Raw Analog Data Without Header**, kies ongetekende 8-bis-waardes (`U8`) en voer die monstertempo in wat uit `xincrement` bereken is.<sup>[[5]](#references)[[6]](#references)</sup> Pas **Logic via Threshold** op die analoogkanaal toe en kies 'n drempel tussen die lae en hoë monst waardes.<sup>[[5]](#references)</sup> Meet die breedte van 'n skoon beginbis om die baudtempo te skat (ongeveer 17.36 µs vir 57,600 baud), pas dan PulseView se UART-dekodeerder toe en verifieer dat verskeie rame konsekwent dekodeer.<sup>[[5]](#references)</sup> 'n Dalende flank alleen bewys nie dat 'n pad UART is nie.

## CP210X UART-na-TTY-adapter

CP210x USB-na-UART-brûe kom op baie prototiperingsborde en goedkoop adapters voor. Algemene modules het toevoerpennetjies langs GND, RXD en TXD, maar hul koppelstukke en I/O-vlakke verskil. Bevestig die werklike spanning aan die hand van die bordontwerp of datablad. Verbind gewoonlik slegs GND, adapter-RX aan teiken-TX en—nadat slegs-ontvangs bekragtig is—adapter-TX aan teiken-RX. Moenie die adapter se 5 V/3.3 V-toevoerpennetjie verbind nie, tensy jy doelbewus 'n teiken van krag voorsien waarvan bekend is dat dit dié spanning kan hanteer.<sup>[[3]](#references)</sup>

Indien die adapter nie opgespoor word nie, maak seker dat die CP210X-drywers op die gasheerstelsel geïnstalleer is. Sodra die adapter opgespoor en gekoppel is, kan nutsprogramme soos picocom, minicom of screen gebruik word.

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

Stel instellings soos die baudrate en toestelnaam in die `Serial port setup`-opsie op.

Voer `minicom` uit om die UART-konsole oop te maak nadat jy die instellings opgestel het.

## UART via Arduino UNO R3 (verwyderbare Atmel 328p-skyfieborde)

As UART Serial-na-USB-adapters nie beskikbaar is nie, kan Arduino UNO R3 met ’n vinnige hack gebruik word. Aangesien Arduino UNO R3 gewoonlik oral beskikbaar is, kan dit baie tyd bespaar.

Arduino UNO R3 het ’n USB-na-Serial-adapter wat op die bord self ingebou is. Om ’n UART-verbinding te kry, haal eenvoudig die Atmel 328p-mikrobeheerder-skyfie van die bord af. Hierdie hack werk met Arduino UNO R3-variante waar die Atmel 328p nie op die bord gesoldeer is nie (die SMD-weergawe word daarin gebruik). Koppel die RX-pen van die Arduino (Digital Pin 0) aan die TX-pen van die UART-koppelvlak, en die TX-pen van die Arduino (Digital Pin 1) aan die RX-pen van die UART-koppelvlak.

Gebruik die Arduino IDE se **Serial Monitor** of ’n toegewyde terminaal teen die teiken se baudrate. Klassieke Uno R3-seinlyne gebruik 5 V-logika, dus gebruik ’n vlakverskuiwer of spanningsverdeler voordat jy dit aan ’n 3.3 V- of laerspanningsteiken koppel.

## Bus Pirate

Die volgende transkripsie gebruik die verouderde Bus Pirate-firmware-koppelvlak om UART-uitset te monitor. Nuwer Bus Pirate-firmware gebruik opdragte soos `m uart`, `{`/`}`, `monitor` of `bridge`; raadpleeg die dokumentasie vir die geïnstalleerde weergawe.<sup>[[2]](#references)</sup>

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

## Firmware-dumping met UART-konsole

’n UART-konsole bied looptydtoegang tot selflaailogboeke en soms ’n bootloader- of bedryfstelsel-shell. Selfs ’n leesalleen-konsole onthul geheuekaarte, flash-drywers, selflaaiparameters, partisieuitlegte en firmware-weergawes. Firmware kan op SPI NOR/NAND, eMMC of ’n ander toestel gestoor wees; dit word gewoonlik nie vanaf ’n EEPROM uitgevoer nie, en lêers wat na ’n gemonteerde persistente lêerstelsel geskryf word, verdwyn nie noodwendig ná ’n herlaai nie.

Daar is verskeie verkrygingsmetodes, en die SPI-afdeling dek direkte lees vanaf eksterne flash. Verkryging met behulp van die konsole kan minder indringend wees wanneer die bootloader reeds ’n veilige leesopdrag bied. Enige onderbreking van die selflaaiproses of flash-opdrag kan egter beskikbaarheid beïnvloed, dus moet jy die oorspronklike toestand aanteken en skryf-/uitvee-opdragte vermy.

Firmware-dumping met behulp van die konsole begin dikwels deur ’n bootloader se selflaaiproses te onderbreek. Baie ingebedde Linux-toestelle gebruik **Das U-Boot**, maar ander gebruik eie bootloaders of deaktiveer die interaktiewe konsole.

Om vir ’n interaktiewe bootloader te toets, koppel die UART-ontvangspad en terminaal terwyl die teiken afgeskakel is, begin logging en skakel dit dan aan. Volg die vertoonde outomatiese selflaaiprompt; afhangend van die bouweergawe kan onderbreking ’n sleutel, ’n kort volgorde vereis, of heeltemal gedeaktiveer wees.

As die onderbreking slaag, gebruik `help`, `printenv` en leesalleen-verkenningsopdragte om die betrokke vervaardiger se geheue- en stooruitleg te verstaan voordat jy adresse benader.

In U-Boot vertoon `md` **adresseerbare geheue**, nie outomaties “die EEPROM” nie. Gebruik eers bordspesifieke opdragte soos `mtd list`, `sf probe`, `mmc info`, `part list`, omgewingsveranderlikes en selflaailogboeke om die korrekte gekarteerde adres te identifiseer of ’n flash-streek na RAM te laai. Vertoon dan ’n bekende reeks greep vir greep:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Teken die seriële uitset aan voordat jy begin. Die `md.b`-uitset bevat adresse en ’n ASCII-kolom, dus is dit ’n tekstuele voorstelling en nie ’n rou ROM-beeld nie.

Verwyder die adres- en ASCII-kolomme, voeg slegs die heksadesimale greepvelde saam en dekodeer dit na binêre data (byvoorbeeld met `xxd -r -p`). Verifieer die verwagte grepetal en teken ’n hash aan voordat jy met die ontleding begin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk identifiseer dan bekende handtekeninge in die gerekonstrueerde binêre lêer. ’n Direkte flash-lesing deur die toepaslike SPI/eMMC/NAND-koppelvlak is gewoonlik vinniger en minder foutgevoelig wanneer die konsole nie data betroubaar kan oordra nie.

U-Boot kan onderbreking deaktiveer, ’n verskafferspesifieke sleutelkombinasie vereis, of geheue-/flash-opdragte sluit. Volg die autoboot-aanporboodskap en selflaailog eerder as om blindelings karakters te stuur. As die konsole nie onderbreek kan word nie, behou die selflaailog en gebruik ’n nie-indringende firmware-verkrygingsmetode.

## References

- [1] [Microchip PIC32-familieverwysingshandleiding - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate-dokumentasie - UART-modus en elektriese limiete](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C-datablad](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot-dokumentasie - `md`-geheuevertoonopdrag](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI en hardeware-instrumentasie vir reverse engineers, Deel 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000-programmeringsgids](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Konfigurasie van die backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Herhaling van hardewarehacking, Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
