# UART

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

UART je asinhroni serijski interfejs koji prenosi uokvireni niz bitova bez zajedničkog takta. Ne mešajte UART logičkog nivoa sa RS-232: RS-232 koristi drugačije, često negativne naponske nivoe i zahteva primopredajnik.<sup>[[1]](#references)[[3]](#references)</sup>

Linija se obično održava na visokom nivou (logička vrednost 1) dok je UART u stanju mirovanja. Zatim, da bi označio početak prenosa podataka, predajnik šalje prijemniku početni bit, tokom kojeg se signal održava na niskom nivou (logička vrednost 0). Predajnik potom šalje pet do osam bitova podataka koji sadrže samu poruku, zatim opcioni paritetni bit i jedan ili dva završna bita (sa logičkom vrednošću 1), u zavisnosti od konfiguracije. Paritetni bit, koji se koristi za proveru grešaka, retko se sreće u praksi. Završni bit (ili bitovi) označava kraj prenosa.

Najčešća konfiguracija je 8N1: osam bitova podataka, bez pariteta i jedan završni bit. UART šalje bit najmanje težine prvi, pa se ASCII znak `C` (`0x43`) prenosi kao: početni bit `0`; podaci `1, 1, 0, 0, 0, 0, 1, 0`; završni bit `1`.<sup>[[1]](#references)</sup>

![UART: Najčešću konfiguraciju zovemo 8N1: osam bitova podataka, bez pariteta i jedan završni bit. Na primer, ako želimo da pošaljemo znak C, odnosno 0x43 u ASCII-ju, preko UART-a u konfiguraciji 8N1](<../../images/image (764).png>)

Hardverski alati za komunikaciju preko UART-a:

- USB-to-serial adapter
- Adapteri sa čipovima CP2102 ili PL2303
- Višenamenski alat kao što su Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

### Identifikacija UART portova

Tipično debug zaglavlje izlaže **TX**, **RX** i **GND**; može imati i pin **Vcc/Vref**, reset ili pinove za kontrolu protoka. Vcc nije UART signal i obično ga treba koristiti samo kao referencu napona — ne priključivati kao izvor napajanja — osim ako su poznate šema ploče i zahtevi za strujom.<sup>[[2]](#references)[[3]](#references)</sup>

Počnite tako što ćete uređaj **isključiti** i odvojiti od napajanja:

- Identifikujte **GND** u režimu kontinuiteta, u odnosu na poznatu uzemljenu ravan, oklop konektora ili masu napajanja. Nikada ne koristite režim kontinuiteta/otpora na uključenoj ploči.
- Pre nego što uključite ciljni uređaj, prebacite multimetar u režim merenja jednosmernog napona. Izmerite potencijal kandidata za pinove u odnosu na masu da biste utvrdili logički napon. Stabilan napon može biti Vcc/Vref; ne pretpostavljajte da je bezbedno povezati ga.
- Posmatrajte kandidate pomoću logičkog analizatora ili osciloskopa tokom pokretanja. **TX** je obično u stanju mirovanja na visokom nivou i prikazuje rafale uokvirenih podataka. Multimetar može pokazati prosečnu promenu napona, ali ne može da potvrdi uokviravanje ni baud rate.
- **RX** može ostati u stanju mirovanja i ne može se bezbedno identifikovati samo zato što se nalazi pored TX-a. Pratite vodove na PCB-u, konsultujte datasheet SoC-a ili upotrebite analizator visoke ulazne impedanse pre nego što ga pobudite.

Zamena TX i RX obično dovodi do izostanka komunikacije; zamena napajanja, mase ili nivoa signala može trajno oštetiti ciljni uređaj ili adapter. Prvo povežite masu i počnite samo sa **prijemom** (TX ciljnog uređaja na RX adaptera).

Proizvođači mogu izostaviti zaglavlje, ostaviti nepopunjene serijske otpornike, onemogućiti konzolu u firmware-u ili izložiti samo TX. Pratite obližnje testne tačke i mesta za otpornike do SoC-a i dodajte privremeni priključak visoke impedanse tek nakon što potvrdite električni nivo. Postojanje garancije ne znači da UART mora biti dostupan.

### Oporavak TX pada koji deluje kao da je na niskom nivou

Ako označeni TX pad ostaje na niskom nivou pri početnom snimanju osciloskopom, to nije dovoljno da se isključi mogućnost UART-a. Nakon što potvrdite logički napon ciljnog uređaja i zajedničku masu, pokušajte sa slabim pull-up otpornikom (u dokumentovanom primeru korišćeno je **10 kΩ na 3.3 V**) i ponovite snimanje dok pritiskate dugmad ili pokrećete uređaj. Koristite samo proverenu logičku naponsku granu ciljnog uređaja; ne povezujte pull-up sa nepoznatim signalom ili signalom kojim se aktivno upravlja. Ako se pojave uokvireni prelazi, izmerite najkraći čist period bita da biste procenili baud rate pre nego što povežete pad samo za prijem sa serijskim adapterom. Ovim postupkom su u primeru vraćeni logovi događaja dugmadi na 115200 bauda, ali nije otkriven dump firmware-a.<sup>[[8]](#references)</sup>

### Utvrđivanje UART baud rate-a

Najlakši način da utvrdite ispravan baud rate jeste da pogledate izlaz na **TX pinu i pokušate da pročitate podatke**. Ako primljeni podaci nisu čitljivi, pređite na sledeći mogući baud rate dok podaci ne postanu čitljivi. Možete koristiti USB-to-serial adapter ili višenamenski uređaj poput Bus Pirate-a, uz pomoćnu skriptu kao što je [baudrate.py](https://github.com/devttys0/baudrate/). Najčešći baud rate-ovi su 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Važno je napomenuti da u ovom protokolu TX jednog uređaja treba povezati sa RX-om drugog!

### Automatizacija UART snimanja pri pokretanju pomoću SCPI-ja

Ako je izlaz pri pokretanju kratak ili TX pad još nije poznat, automatizujte ponovljena pokretanja umesto da ručno upravljate napajanjem i osciloskopom. Povežite programabilno napajanje sa ograničenjem struje na provereni ulaz za napajanje ciljnog uređaja. Ispitajte svaki mogući TX pad ulazom osciloskopa visoke impedanse i zajedničkom masom; nemojte pobuđivati pad.<sup>[[5]](#references)</sup>

VISA otvara sesije sa instrumentima preko serijske veze ili Etherneta, dok SCPI upravlja izlazom, okidanjem i očitavanjem talasnog oblika.<sup>[[5]](#references)[[6]](#references)</sup> Instalirajte `pyvisa` i `pyvisa-py` (uz `pyserial` za serijske VISA resurse); `ResourceManager('@py')` eksplicitno bira Python backend.<sup>[[5]](#references)[[7]](#references)</sup> Zamenite nizove resursa i komande onima koje podržavaju instrumenti koje koristite.<sup>[[5]](#references)</sup>

U primeru sa Rigol MSO5000, aktivirajte jednokratno okidanje na opadajuću ivicu pre nego što uključite ploču: UART TX u stanju mirovanja na visokom nivou prvo pada zbog početnog bita.<sup>[[5]](#references)</sup> Podesite prag okidanja između izmerenih nivoa mirovanja i niskog nivoa, a vremensku bazu podesite tako da obuhvati željeni interval pokretanja.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` može da potisne ponovljene ivice u kontinuiranom snimanju, ali ne zamenjuje proveru da li je jednokratno snimanje zaista završeno.<sup>[[5]](#references)</sup> Sledeći primer snima jedno pokretanje i čuva uzorke kao neoznačene bajtove i njihove metapodatke za skaliranje; nakon isteka vremena, isključuje ciljni uređaj umesto da čeka beskonačno.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISA uključivanje napajanja i jednokratno snimanje UART talasnog oblika</summary>

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

Za pregled padova, ponovite jednokratno snimanje nakon pomeranja sonde ili ostavite sesiju napajanja otvorenom i ciklično uključujte i isključujte izlaz, uz interval za pokretanje i interval isključenog napajanja. Ponovo pripremite osciloskop pre svakog uključivanja napajanja kako bi svaka datoteka odgovarala jednom pokretanju i jednom padu.<sup>[[5]](#references)</sup>

Rigol preambula je `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> **Treća** vrednost je broj tačaka, a ne brzina uzorkovanja, kako je navedeno u članku.<sup>[[5]](#references)[[6]](#references)</sup> U primeru, `25,000,000` tačaka i `xincrement = 2e-8` sekundi znače da je `1 / xincrement = 50,000,000` uzoraka u sekundi, a ne 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Sačuvajte preambulu uz binarnu datoteku i proverite da li se dužina očitanih podataka poklapa sa vrednošću `<points>`; vodič opisuje segmentirana/serijska očitavanja za velike zapise.<sup>[[6]](#references)</sup>

Da biste dekodirali snimljeni signal, uvezite `capture.bin` u PulseView kao **Raw Analog Data Without Header**, izaberite neoznačene 8-bitne (`U8`) vrednosti i unesite brzinu uzorkovanja izračunatu na osnovu vrednosti `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Primenite **Logic via Threshold** na analogni kanal i izaberite prag između niske i visoke vrednosti uzorka.<sup>[[5]](#references)</sup> Izmerite širinu čistog start bita da biste procenili baud rate (oko 17.36 µs za 57,600 baud), zatim primenite PulseView-ov UART dekoder i proverite da li se nekoliko frejmova dosledno dekodira.<sup>[[5]](#references)</sup> Sama silazna ivica ne dokazuje da je pad UART.

## CP210X UART–TTY adapter

CP210x USB-to-UART mostovi se nalaze na mnogim prototipskim pločama i jeftinim adapterima. Uobičajeni moduli izlažu pinove za napajanje uz GND, RXD i TXD, ali se raspored pinova i I/O nivoi razlikuju. Proverite stvarni napon na osnovu dizajna ploče ili tehničkog lista. Obično povežite samo GND i adapterov RX sa TX-om ciljnog uređaja; adapterov TX povežite sa RX-om ciljnog uređaja tek nakon provere samo prijema. Nemojte povezivati pin za napajanje od 5 V/3.3 V na adapteru, osim ako namerno ne napajate ciljni uređaj za koji je poznato da podnosi taj napon.<sup>[[3]](#references)</sup>

Ako adapter nije prepoznat, proverite da li su CP210X drajveri instalirani na host sistemu. Kada adapter bude prepoznat i povezan, mogu se koristiti alati kao što su picocom, minicom ili screen.

Da biste izlistali uređaje povezane sa Linux/MacOS sistemima:

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

Podesite opcije kao što su brzina prenosa i naziv uređaja u opciji `Serial port setup`.

Nakon podešavanja, pokrenite `minicom` da biste otvorili UART konzolu.

## UART preko Arduino UNO R3 (ploče sa uklonjivim Atmel 328p čipom)

Ako UART Serial-to-USB adapteri nisu dostupni, Arduino UNO R3 može se upotrebiti uz brzu izmenu. Pošto je Arduino UNO R3 obično lako dostupan, ovo može znatno da uštedi vreme.

Arduino UNO R3 ima USB-to-Serial adapter ugrađen na samoj ploči. Da biste uspostavili UART vezu, jednostavno izvadite Atmel 328p mikrokontrolerski čip sa ploče. Ovaj postupak radi na varijantama Arduino UNO R3 kod kojih Atmel 328p nije zalemljen na ploču (u njima se koristi SMD verzija). Povežite RX pin Arduina (Digital Pin 0) sa TX pinom UART interfejsa, a TX pin Arduina (Digital Pin 1) sa RX pinom UART interfejsa.

Koristite **Serial Monitor** u Arduino IDE-u ili namenski terminal podešen na odgovarajuću brzinu prenosa. Klasični Uno R3 koristi serijske signale logičkog nivoa od 5 V, zato pre povezivanja sa uređajem koji radi na 3,3 V ili nižem naponu upotrebite pretvarač nivoa ili delitelj napona.

## Bus Pirate

Sledeći transkript koristi zastareli interfejs firmvera Bus Pirate za praćenje UART izlaza. Novije verzije firmvera Bus Pirate koriste komande kao što su `m uart`, `{`/`}`, `monitor` ili `bridge`; pogledajte dokumentaciju za instaliranu verziju.<sup>[[2]](#references)</sup>

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

## Dumping firmvera pomoću UART konzole

UART konzola omogućava pristup zapisima pokretanja tokom rada i, ponekad, ljusci bootloader-a ili operativnog sistema. Čak i konzola samo za čitanje otkriva mape memorije, flash drajvere, argumente pokretanja, rasporede particija i verzije firmvera. Firmver može da se nalazi u SPI NOR/NAND memoriji, eMMC-u ili drugom uređaju; uglavnom se ne izvršava iz EEPROM-a, a datoteke upisane na montirani trajni sistem datoteka ne nestaju nužno nakon ponovnog pokretanja.

Postoji nekoliko načina za pribavljanje podataka, a odeljak o SPI-ju obrađuje direktno čitanje spoljne flash memorije. Pribavljanje podataka pomoću konzole može biti manje invazivno ako bootloader već ima bezbednu komandu za čitanje, ali svaki prekid pokretanja ili komanda za flash memoriju može da utiče na dostupnost, zato zabeležite prvobitno stanje i izbegavajte operacije upisa/brisanja.

Dumpovanje firmvera pomoću konzole često počinje prekidanjem bootloader-a. Mnogi uređaji sa ugrađenim Linux-om koriste **Das U-Boot**, ali drugi koriste vlasničke bootloader-e ili imaju onemogućenu interaktivnu konzolu.

Da biste proverili da li postoji interaktivni bootloader, povežite UART putanju za prijem i terminal dok je ciljna naprava isključena, započnite beleženje, pa je uključite. Pratite prikazani upit za automatsko pokretanje; u zavisnosti od verzije, prekid može zahtevati pritisak na taster, kratku sekvencu ili biti potpuno onemogućen.

Ako prekid uspe, upotrebite `help`, `printenv` i komande za otkrivanje koje ne menjaju podatke kako biste razumeli raspored memorije i skladišta tog proizvođača pre pristupa adresama.

U U-Boot-u, `md` prikazuje **memoriju dostupnu adresiranjem**, a ne automatski „EEPROM“. Najpre upotrebite komande specifične za ploču, kao što su `mtd list`, `sf probe`, `mmc info`, `part list`, promenljive okruženja i zapisi pokretanja, da biste identifikovali ispravnu mapiranu adresu ili učitali region flash memorije u RAM. Zatim prikažite poznati opseg bajt po bajt:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zabeležite serijski izlaz pre početka. Izlaz `md.b` sadrži adrese i ASCII kolonu, pa predstavlja tekstualni prikaz, a ne sirovu ROM sliku.

Uklonite kolone sa adresama i ASCII sadržajem, spojite samo heksadecimalna polja bajtova i dekodirajte ih u binarni format (na primer, pomoću `xxd -r -p`). Pre analize proverite očekivani broj bajtova i zabeležite hash:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk zatim prepoznaje poznate potpise u rekonstruisanom binarnom fajlu. Direktno očitavanje flash memorije preko odgovarajućeg SPI/eMMC/NAND interfejsa obično je brže i manje podložno greškama kada konzola ne može pouzdano da prenosi podatke.

U-Boot može da onemogući prekid pokretanja, zahteva sekvencu tastera specifičnu za proizvođača ili zaključa komande za memoriju/flash. Pratite prompt za automatsko pokretanje i zapis pokretanja umesto da nasumično šaljete znakove. Ako se pokretanje ne može prekinuti preko konzole, sačuvajte zapis pokretanja i pređite na nedestruktivan način pribavljanja firmware-a.

## References

- [1] [Referentni priručnik za porodicu Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacija za Bus Pirate - UART režim i električna ograničenja](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - Tehnički list za CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Dokumentacija za U-Boot - komanda `md` za prikaz memorije](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI i hardverska instrumentacija za reverse engineering, 1. deo](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Programski vodič za Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Konfigurisanje backend-a](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Obnavljanje znanja o hardware hackingu, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
