# UART

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

UART je asinhroni serijski interfejs koji prenosi uokvireni tok bitova bez zajedničkog takta. Nemojte mešati UART na logičkom nivou sa RS-232: RS-232 koristi drugačije, često negativne naponske nivoe i zahteva primopredajnik.<sup>[[1]](#references)[[3]](#references)</sup>

Linija se uglavnom održava na visokom nivou (logička vrednost 1) dok je UART u stanju mirovanja. Zatim, da bi označio početak prenosa podataka, predajnik šalje prijemniku početni bit, tokom kojeg se signal održava na niskom nivou (logička vrednost 0). Predajnik potom šalje pet do osam bitova podataka koji sadrže samu poruku, zatim opcioni bit parnosti i jedan ili dva završna bita (logička vrednost 1), u zavisnosti od konfiguracije. Bit parnosti, koji se koristi za proveru grešaka, retko se sreće u praksi. Završni bit (ili bitovi) označava kraj prenosa.

Najčešća konfiguracija je 8N1: osam bitova podataka, bez parnosti i jedan završni bit. UART šalje prvo bit najmanje težine, pa se ASCII znak `C` (`0x43`) prenosi kao: početni bit `0`; podaci `1, 1, 0, 0, 0, 0, 1, 0`; završni bit `1`.<sup>[[1]](#references)</sup>

![UART: Najčešću konfiguraciju nazivamo 8N1: osam bitova podataka, bez parnosti i jedan završni bit. Na primer, ako bismo želeli da pošaljemo znak C, odnosno 0x43 u ASCII-ju, putem UART-a sa konfiguracijom 8N1](<../../images/image (764).png>)

Hardverski alati za komunikaciju putem UART-a:

- USB-to-serial adapter
- Adapteri sa čipovima CP2102 ili PL2303
- Višenamenski alat kao što su: Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

### Identifikovanje UART portova

Tipično zaglavlje za otklanjanje grešaka izlaže **TX**, **RX** i **GND**; može da izlaže i pin **Vcc/Vref**, reset ili pinove za kontrolu toka. Vcc nije UART signal i obično treba da se koristi samo kao referentni napon — ne sme da se povezuje kao izvor napajanja — osim ako su poznati šema ploče i zahtevi za strujom.<sup>[[2]](#references)[[3]](#references)</sup>

Počnite tako što ćete uređaj **isključiti** i odvojiti:

- U režimu provere kontinuiteta, identifikujte **GND** u odnosu na poznatu uzemljenu površinu, oklop konektora ili masu napajanja. Nikada ne koristite režim provere kontinuiteta/otpora na uključenoj ploči.
- Pre uključivanja ciljnog uređaja, prebacite multimetar u režim merenja jednosmernog napona. Izmerite potencijalne pinove u odnosu na masu da biste utvrdili logički napon. Stabilna naponska šina može biti Vcc/Vref; nemojte pretpostaviti da je bezbedno povezati je.
- Posmatrajte potencijalne pinove pomoću logičkog analizatora ili osciloskopa tokom pokretanja. **TX** je obično u stanju mirovanja na visokom nivou i prikazuje nizove uokvirenih podataka. Multimetar može da pokaže prosečne promene, ali ne može da proveri uokviravanje ni baud rate.
- **RX** može ostati u stanju mirovanja i ne može se bezbedno identifikovati samo zato što se nalazi pored TX-a. Pratite vodove na štampanoj ploči, konsultujte list sa podacima za SoC ili koristite analizator visoke ulazne impedanse pre nego što pošaljete signal na taj pin.

Zamena TX i RX obično ne omogućava komunikaciju; zamena napajanja, mase ili nivoa signala može trajno da ošteti ciljni uređaj ili adapter. Prvo povežite masu i započnite u režimu **samo za prijem** (TX ciljnog uređaja na RX adaptera).

Proizvođači mogu da izostave zaglavlje, da ne postave serijske otpornike, da onemoguće konzolu u firmware-u ili da izlože samo TX. Pratite obližnje testne tačke i mesta za otpornike do SoC-a i dodajte privremenu vezu visoke impedanse tek nakon što potvrdite električni nivo. Postojanje garancije ne znači da UART mora biti dostupan.

### Identifikovanje UART baud rate-a

Najlakši način da identifikujete ispravan baud rate jeste da pogledate izlaz pina **TX** i pokušate da pročitate podatke. Ako primljeni podaci nisu čitljivi, pređite na sledeći mogući baud rate dok podaci ne postanu čitljivi. Možete da koristite USB-to-serial adapter ili višenamenski uređaj kao što je Bus Pirate, uz pomoćnu skriptu kao što je [baudrate.py](https://github.com/devttys0/baudrate/). Najčešći baud rate-ovi su 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Važno je napomenuti da u ovom protokolu morate da povežete TX jednog uređaja sa RX-om drugog!

## CP210X UART to TTY adapter

CP210x USB-to-UART mostovi se nalaze na mnogim prototipskim pločama i jeftinim adapterima. Uobičajeni moduli, pored GND, RXD i TXD, izlažu i pinove za napajanje, ali se njihova zaglavlja i I/O nivoi razlikuju. Proverite stvarni napon prema dizajnu ploče ili listu sa podacima. Obično povežite samo GND, RX adaptera na TX ciljnog uređaja i — nakon provere samo za prijem — TX adaptera na RX ciljnog uređaja. Nemojte povezivati pin za napajanje od 5 V/3.3 V na adapteru osim ako namerno napajate ciljni uređaj za koji je poznato da podnosi taj napon.<sup>[[3]](#references)</sup>

Ako adapter nije prepoznat, proverite da li su CP210X drajveri instalirani na host sistemu. Kada adapter bude prepoznat i povezan, mogu da se koriste alati kao što su picocom, minicom ili screen.

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

Podesite parametre kao što su baudrate i naziv uređaja u opciji `Serial port setup`.

Nakon podešavanja, pokrenite `minicom` da biste otvorili UART konzolu.

## UART preko Arduino UNO R3 (ploče sa uklonjivim Atmel 328p čipom)

Ako UART Serial to USB adapteri nisu dostupni, Arduino UNO R3 se može iskoristiti uz brzu prepravku. Pošto je Arduino UNO R3 obično lako dostupan, ovo može znatno da uštedi vreme.

Arduino UNO R3 na samoj ploči ima ugrađen USB to Serial adapter. Da biste uspostavili UART vezu, jednostavno izvadite Atmel 328p mikrokontrolerski čip iz ploče. Ova prepravka radi na varijantama Arduino UNO R3 kod kojih Atmel 328p nije zalemljen na ploču (koristi se SMD verzija). Povežite RX pin Arduina (Digital Pin 0) sa TX pinom UART interfejsa, a TX pin Arduina (Digital Pin 1) sa RX pinom UART interfejsa.

Koristite **Serial Monitor** u Arduino IDE-ju ili namenski terminal podešen na brzinu prenosa (baud rate) ciljnog uređaja. Klasični Uno R3 serijski signali koriste logički nivo od 5 V, zato pre povezivanja sa ciljnim uređajem koji radi na 3,3 V ili nižem naponu upotrebite pretvarač nivoa ili delitelj napona.

## Bus Pirate

Sledeći zapis koristi nasleđeni interfejs firmvera za Bus Pirate za nadgledanje UART izlaza. Novije verzije firmvera za Bus Pirate koriste komande kao što su `m uart`, `{`/`}`, `monitor` ili `bridge`; pogledajte dokumentaciju za instaliranu verziju.<sup>[[2]](#references)</sup>

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

UART konzola omogućava pristup tokom rada boot logovima i, ponekad, bootloader-u ili ljusci operativnog sistema. Čak i konzola samo za čitanje otkriva mapu memorije, flash drajvere, argumente za boot, raspored particija i verzije firmware-a. Firmware može da se nalazi u SPI NOR/NAND memoriji, eMMC-u ili drugom uređaju; uglavnom se ne izvršava iz EEPROM-a, a datoteke upisane na montirani trajni sistem datoteka ne nestaju nužno nakon ponovnog pokretanja.

Postoji nekoliko načina za pribavljanje podataka, a odeljak o SPI-ju pokriva direktno čitanje spoljne flash memorije. Pribavljanje podataka pomoću konzole može biti manje invazivno ako bootloader već nudi bezbednu komandu za čitanje, ali svaki prekid boot procesa ili komanda za flash memoriju može uticati na dostupnost, zato zabeležite prvobitno stanje i izbegavajte operacije upisa/brisanja.

Dumpovanje firmware-a pomoću konzole često počinje prekidanjem bootloader-a. Mnogi uređaji sa ugrađenim Linux-om koriste **Das U-Boot**, ali drugi koriste vlasničke bootloader-e ili imaju onemogućenu interaktivnu konzolu.

Da biste proverili da li postoji interaktivni bootloader, povežite UART prijemnu liniju i terminal dok je cilj isključen, pokrenite beleženje i uključite ga. Pratite prikazani upit za automatski boot; u zavisnosti od verzije, prekid može zahtevati pritisak na taster, kratku sekvencu ili možda biti potpuno onemogućen.

Ako prekid uspe, koristite `help`, `printenv` i komande za otkrivanje koje ne menjaju stanje da biste razumeli raspored memorije i skladišta tog proizvođača pre pristupa adresama.

U U-Boot-u, `md` prikazuje **adresabilnu memoriju**, a ne automatski „EEPROM“. Najpre koristite komande specifične za ploču, kao što su `mtd list`, `sf probe`, `mmc info`, `part list`, promenljive okruženja i boot logovi, da biste utvrdili ispravnu mapiranu adresu ili učitali region flash memorije u RAM. Zatim prikažite poznati opseg bajt po bajt:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Zabeležite serijski izlaz pre početka. Izlaz `md.b` sadrži adrese i ASCII kolonu, pa je tekstualni prikaz, a ne sirova ROM slika.

Uklonite kolone s adresama i ASCII tekstom, spojite samo heksadecimalna polja bajtova i dekodirajte ih u binarni format (na primer pomoću `xxd -r -p`). Proverite očekivani broj bajtova i zabeležite hash pre analize:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk zatim identifikuje poznate potpise u rekonstruisanom binarnom fajlu. Direktno očitavanje flash memorije putem odgovarajućeg SPI/eMMC/NAND interfejsa obično je brže i manje podložno greškama kada konzola ne može pouzdano da prenosi podatke.

U-Boot može da onemogući prekidanje autoboot-a, da zahteva kombinaciju tastera specifičnu za proizvođača ili da zaključa komande za memoriju/flash. Pratite prompt za autoboot i boot log, umesto da nasumično šaljete znakove. Ako se konzola ne može prekinuti, sačuvajte boot log i pređite na neinvazivan način pribavljanja firmware-a.

## References

- [1] [Referentni priručnik za porodicu Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Dokumentacija za Bus Pirate - UART režim i električna ograničenja](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - tehnički list za CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot dokumentacija - komanda `md` za prikaz memorije](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
