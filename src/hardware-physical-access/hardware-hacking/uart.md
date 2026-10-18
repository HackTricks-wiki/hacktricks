# UART

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

UART je asinhroni serijski interfejs koji prenosi uokvireni niz bitova bez zajedničkog takta. Nemojte mešati UART na logičkom nivou sa RS-232: RS-232 koristi drugačije, često negativne naponske nivoe i zahteva primopredajnik.<sup>[[1]](#references)[[3]](#references)</sup>

Uopšteno, linija se drži na visokom nivou (logička vrednost 1) dok je UART u stanju mirovanja. Zatim, da bi signalizovao početak prenosa podataka, predajnik šalje prijemniku start bit, tokom kog se signal drži na niskom nivou (logička vrednost 0). Zatim predajnik šalje pet do osam data bitova koji sadrže stvarnu poruku, iza kojih slede opcioni parity bit i jedan ili dva stop bita (logička vrednost 1), u zavisnosti od konfiguracije. Parity bit, koji se koristi za proveru grešaka, retko se viđa u praksi. Stop bit (ili bitovi) označava kraj prenosa.

Najčešća konfiguracija je 8N1: osam data bitova, bez parity bita i jedan stop bit. UART šalje najmanje značajan data bit prvi, pa se ASCII `C` (`0x43`) prenosi kao: start `0`; podaci `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najčešća konfiguracija je 8N1: osam data bitova, bez parity bita i jedan stop bit. Na primer, ako želimo da pošaljemo znak C, odnosno 0x43 u ASCII-ju, preko UART-a 8N1](<../../images/image (764).png>)

Hardverski alati za komunikaciju preko UART-a:

- USB-to-serial adapter
- Adapteri sa čipovima CP2102 ili PL2303
- Višenamenski alat kao što su: Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

### Identifikacija UART portova

Tipično zaglavlje za otklanjanje grešaka izlaže pinove **TX**, **RX** i **GND**; može izložiti i pin **Vcc/Vref**, reset ili pinove za kontrolu protoka. Vcc nije UART signal i obično treba da se koristi samo kao referentni napon — ne povezivati ga kao izvor napajanja — osim ako su poznati šema ploče i zahtevi za strujom.<sup>[[2]](#references)[[3]](#references)</sup>

Počnite tako što ćete uređaj **isključiti** i odvojiti ga od napajanja:

- U režimu za proveru kontinuiteta identifikujte **GND** pomoću poznate uzemljene površine, oklopa konektora ili mase napajanja. Nikada ne koristite režim za proveru kontinuiteta/otpora na uključenoj ploči.
- Pre uključivanja ciljnog uređaja prebacite instrument u režim merenja jednosmernog napona. Izmerite napon na kandidatima u odnosu na masu da biste utvrdili logički napon. Stabilan napon može biti Vcc/Vref; nemojte pretpostaviti da je bezbedno povezati ga.
- Tokom pokretanja posmatrajte kandidate pomoću logičkog analizatora ili osciloskopa. **TX** je obično u stanju mirovanja na visokom nivou i prikazuje nizove uokvirenih podataka. Multimetar može prikazati prosečne promene, ali ne može potvrditi uokviravanje ni baud rate.
- **RX** može ostati u stanju mirovanja i ne može se bezbedno identifikovati samo zato što se nalazi pored TX-a. Pratite vodove na štampanoj ploči, konsultujte datasheet za SoC ili koristite analizator visoke ulazne impedanse pre nego što dovedete signal na njega.

Zamena TX i RX pinova obično onemogućava komunikaciju; zamena napajanja, mase ili nivoa signala može trajno oštetiti ciljni uređaj ili adapter. Prvo povežite masu i počnite u režimu **samo za prijem** (TX ciljnog uređaja na RX adaptera).

Proizvođači mogu izostaviti zaglavlje, ostaviti serijske otpornike nepostavljene, onemogućiti konzolu u firmware-u ili izložiti samo TX. Pratite obližnje testne tačke i mesta za otpornike do SoC-a i dodajte privremenu vezu visoke impedanse tek nakon što potvrdite električni nivo. Postojanje garancije ne znači da UART mora biti dostupan.

### Identifikacija baud rate-a UART-a

Najlakši način da utvrdite ispravan baud rate jeste da pogledate izlaz na pinu **TX** i pokušate da pročitate podatke. Ako primljeni podaci nisu čitljivi, pređite na sledeći mogući baud rate dok podaci ne postanu čitljivi. Za to možete koristiti USB-to-serial adapter ili višenamenski uređaj kao što je Bus Pirate, zajedno sa pomoćnom skriptom, na primer [baudrate.py](https://github.com/devttys0/baudrate/). Najčešći baud rate-ovi su 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Važno je napomenuti da u ovom protokolu morate povezati TX jednog uređaja sa RX-om drugog!

### Automatizovano snimanje UART-a tokom pokretanja pomoću SCPI-ja

Ako je izlaz tokom pokretanja kratak ili TX pad još nije poznat, automatizujte ponovljena pokretanja umesto da ručno rukujete napajanjem i osciloskopom. Povežite programski izvor napajanja sa ograničenjem struje na provereni ulaz za napajanje ciljnog uređaja. Sondu osciloskopa visoke ulazne impedanse i zajedničku masu povežite sa svakim kandidatom za TX pad; nemojte dovoditi signal na pad.<sup>[[5]](#references)</sup>

VISA otvara serijske ili Ethernet sesije sa instrumentima, dok SCPI upravlja izlazom, okidanjem i očitavanjem talasnog oblika.<sup>[[5]](#references)[[6]](#references)</sup> Instalirajte `pyvisa` i `pyvisa-py` (kao i `pyserial` za serijske VISA resurse); `ResourceManager('@py')` eksplicitno bira Python backend.<sup>[[5]](#references)[[7]](#references)</sup> Zamenite nizove resursa i komande onima koje podržavaju instrumenti koji se koriste.<sup>[[5]](#references)</sup>

U primeru sa Rigol MSO5000, postavite jednokratno okidanje na opadajuću ivicu pre uključivanja ploče: UART TX, koji je u stanju mirovanja na visokom nivou, prvo opada pri slanju start bita.<sup>[[5]](#references)</sup> Podesite prag okidanja između izmerenih nivoa mirovanja i niskog nivoa, a vremensku bazu podesite tako da obuhvati željeni interval pokretanja.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` može da potisne ponovljene ivice u kontinuiranim snimcima, ali ne zamenjuje proveru da li je jednokratno snimanje zaista završeno.<sup>[[5]](#references)</sup> Sledeći primer snima jedno pokretanje i čuva i uzorke kao neoznačene bajtove i njihove metapodatke za skaliranje; ako istekne vreme čekanja, ciljni uređaj se isključuje umesto da čeka beskonačno.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA uključivanje napajanja i jednokratno snimanje talasnog oblika UART-a</summary>

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

Za pregled kontaktnih padova, ponovite jednokratno snimanje nakon pomeranja sonde ili ostavite sesiju napajanja otvorenom i ciklično uključujte i isključujte izlaz, uz zadržavanje napajanja tokom pokretanja i interval isključenog napajanja. Ponovo pripremite osciloskop pre svakog uključivanja napajanja, tako da svaka datoteka odgovara jednom pokretanju i jednom padu.<sup>[[5]](#references)</sup>

Rigol preambula je `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> **Treća** vrednost je broj tačaka, a ne frekvencija uzorkovanja, kako je navedeno u članku.<sup>[[5]](#references)[[6]](#references)</sup> U njihovom primeru, `25,000,000` tačaka i `xincrement = 2e-8` sekundi podrazumevaju `1 / xincrement = 50,000,000` uzoraka u sekundi, a ne 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Sačuvajte preambulu uz binarnu datoteku i proverite da li dužina očitanih podataka odgovara vrednosti `<points>`; vodič opisuje segmentirano/serijsko očitavanje za velike zapise.<sup>[[6]](#references)</sup>

Da biste dekodirali snimljeni signal, uvezite `capture.bin` u PulseView kao **Raw Analog Data Without Header**, izaberite neoznačene 8-bitne (`U8`) vrednosti i unesite frekvenciju uzorkovanja izračunatu na osnovu `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Primeniте **Logic via Threshold** na analogni kanal i izaberite prag između niskih i visokih vrednosti uzoraka.<sup>[[5]](#references)</sup> Izmerite širinu čistog start-bit-a da biste procenili baud rate (oko 17,36 µs za 57.600 baud), zatim primenite PulseView UART dekoder i proverite da li se više frejmova dosledno dekodira.<sup>[[5]](#references)</sup> Sama opadajuća ivica ne dokazuje da je pad UART.

## CP210X UART na TTY adapter

CP210x USB-to-UART mostovi nalaze se na mnogim prototipskim pločama i jeftinim adapterima. Uobičajeni moduli izlažu pinove za napajanje, kao i GND, RXD i TXD, ali se raspored pinova i I/O nivoi razlikuju. Proverite stvarni napon u dizajnu ploče ili tehničkom listu. Obično povežite samo GND i adapter RX sa TX ciljnog uređaja, a — nakon provere samo prijema — adapter TX sa RX ciljnog uređaja. Nemojte povezivati pin za napajanje od 5 V/3,3 V na adapteru osim ako nameravate da napajate ciljni uređaj i znate da može da podnese taj napon.<sup>[[3]](#references)</sup>

Ako adapter nije prepoznat, proverite da li su CP210X upravljački programi instalirani na host sistemu. Kada adapter bude prepoznat i povezan, mogu se koristiti alati kao što su picocom, minicom ili screen.

Da biste prikazali uređaje povezane sa Linux/MacOS sistemima:

```
ls /dev/
```

Za osnovnu interakciju sa UART interfejsom koristite sledeću komandu:

```
picocom /dev/<adapter> --baud <baudrate>
```

Za minicom, koristite sledeću komandu da biste ga konfigurisali:

```
minicom -s
```

Konfigurišite podešavanja kao što su baudrate i naziv uređaja u opciji `Serial port setup`.

Nakon konfigurisanja, pokrenite `minicom` da biste otvorili UART konzolu.

## UART preko Arduino UNO R3 (ploče sa uklonjivim Atmel 328p čipom)

Ako UART Serial-to-USB adapteri nisu dostupni, Arduino UNO R3 može se upotrebiti uz brz hack. Pošto je Arduino UNO R3 obično svuda dostupan, ovo može znatno da uštedi vreme.

Arduino UNO R3 ima USB-to-Serial adapter ugrađen na samoj ploči. Da biste uspostavili UART vezu, samo izvadite Atmel 328p mikrokontrolerski čip iz ploče. Ovaj hack radi na varijantama Arduino UNO R3 kod kojih Atmel 328p nije zalemljen na ploču (u njima se koristi SMD verzija). Povežite RX pin Arduina (Digital Pin 0) sa TX pinom UART interfejsa, a TX pin Arduina (Digital Pin 1) sa RX pinom UART interfejsa.

Koristite **Serial Monitor** u Arduino IDE-u ili namenski terminal podešen na brzinu prenosa (baud rate) ciljnog uređaja. Klasični serijski signali Uno R3 ploče koriste logički nivo od 5 V, zato pre povezivanja na ciljni uređaj od 3,3 V ili nižeg napona koristite level shifter ili delitelj napona.

## Bus Pirate

Sledeći transkript koristi nasleđeni interfejs firmware-a Bus Pirate za praćenje UART izlaza. Noviji firmware Bus Pirate koristi komande kao što su `m uart`, `{`/`}`, `monitor` ili `bridge`; pogledajte dokumentaciju za instaliranu verziju.<sup>[[2]](#references)</sup>

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

## Dumpovanje firmware-a pomoću UART konzole

UART konzola omogućava pristup tokom rada zapisima pokretanja i, ponekad, shell-u bootloader-a ili operativnog sistema. Konzola samo za čitanje i dalje otkriva mape memorije, flash drajvere, argumente pokretanja, raspored particija i verzije firmware-a. Firmware može biti smešten u SPI NOR/NAND, eMMC ili drugom uređaju; uglavnom se ne izvršava iz EEPROM-a, a datoteke zapisane u montirani persistent filesystem ne moraju nužno nestati nakon ponovnog pokretanja.

Postoji nekoliko načina za preuzimanje, a SPI odeljak pokriva direktno čitanje iz spoljne flash memorije. Preuzimanje uz pomoć konzole može biti manje invazivno ako bootloader već nudi bezbednu komandu za čitanje, ali svaki prekid pokretanja ili flash komanda može uticati na dostupnost, zato zabeležite početno stanje i izbegavajte operacije upisivanja/brisanja.

Dumpovanje firmware-a uz pomoć konzole često počinje prekidanjem bootloader-a. Mnogi uređaji sa ugrađenim Linux-om koriste **Das U-Boot**, ali drugi koriste vlasničke bootloader-e ili imaju onemogućenu interaktivnu konzolu.

Da biste proverili da li je bootloader interaktivan, povežite UART putanju za prijem i terminal dok je cilj isključen, započnite beleženje i uključite ga. Pratite prikazani prompt za autoboot; u zavisnosti od build-a, prekid može zahtevati taster, kratku sekvencu ili može biti potpuno onemogućen.

Ako prekid uspe, koristite `help`, `printenv` i komande za otkrivanje koje samo čitaju podatke, da biste razumeli raspored memorije i skladišta tog proizvođača pre pristupa adresama.

U U-Boot-u, `md` prikazuje **adresabilnu memoriju**, a ne automatski „EEPROM“. Najpre koristite komande specifične za ploču, kao što su `mtd list`, `sf probe`, `mmc info`, `part list`, promenljive okruženja i zapisi pokretanja, da biste identifikovali ispravnu mapiranu adresu ili učitali region flash memorije u RAM. Zatim prikažite poznat opseg bajt po bajt:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zabeležite serijski izlaz pre početka. Izlaz komande `md.b` sadrži adrese i ASCII kolonu, pa predstavlja tekstualni prikaz, a ne sirovu ROM sliku.

Uklonite kolone sa adresama i ASCII tekstom, spojite samo polja sa heksadecimalnim bajtovima i dekodirajte ih u binarni zapis (na primer pomoću `xxd -r -p`). Proverite očekivani broj bajtova i zabeležite hash pre analize:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk zatim prepoznaje poznate potpise u rekonstruisanom binarnom fajlu. Direktno čitanje fleša preko odgovarajućeg SPI/eMMC/NAND interfejsa obično je brže i manje podložno greškama kada konzola ne može pouzdano da prenosi podatke.

U-Boot može da onemogući prekidanje pokretanja, zahteva niz tastera specifičan za proizvođača ili zaključa komande za memoriju/fleš. Pratite prompt za automatsko pokretanje i log pokretanja umesto da nasumično šaljete znakove. Ako pokretanje ne može da se prekine preko konzole, sačuvajte log pokretanja i pređite na neinvazivan način pribavljanja firmware-a.

## References

- [1] [Referentni priručnik za porodicu Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacija za Bus Pirate - UART režim i električna ograničenja](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Tehnički list za CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacija za U-Boot - komanda `md` za prikaz memorije](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI i hardverska instrumentacija za reverse engineering, 1. deo](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Vodič za programiranje Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Konfigurisanje backend-a](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
