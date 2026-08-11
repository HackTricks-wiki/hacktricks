# UART

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

UART je asinhroni serijski interfejs koji prenosi uokvireni tok bitova bez zajedničkog takta. Nemojte mešati UART na logičkom nivou sa RS-232: RS-232 koristi drugačije, često negativne naponske nivoe i zahteva transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Linija se uglavnom održava na visokom nivou (logička vrednost 1) dok je UART u stanju mirovanja. Zatim, da bi signalizirao početak prenosa podataka, predajnik šalje start bit prijemniku, pri čemu se signal održava na niskom nivou (logička vrednost 0). Nakon toga predajnik šalje pet do osam bitova podataka koji sadrže stvarnu poruku, zatim opcioni parity bit i jedan ili dva stop bita (sa logičkom vrednošću 1), u zavisnosti od konfiguracije. Parity bit, koji se koristi za proveru grešaka, retko se viđa u praksi. Stop bit (ili bitovi) označava kraj prenosa.

Najčešća konfiguracija je 8N1: osam bitova podataka, bez parity bita i jedan stop bit. UART najpre šalje bit podataka najmanje težine, tako da se ASCII `C` (`0x43`) prenosi kao: start `0`; podaci `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Najčešću konfiguraciju nazivamo 8N1: osam bitova podataka, bez parity bita i jedan stop bit. Na primer, ako želimo da pošaljemo znak C, odnosno 0x43 u ASCII-ju, kroz 8N1 UART](<../../images/image (764).png>)

Hardverski alati za komunikaciju sa UART-om:

- USB-to-serial adapter
- Adapteri sa CP2102 ili PL2303 čipovima
- Višenamenski alat kao što su: Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

### Identifikacija UART portova

Tipičan debug header izlaže **TX**, **RX** i **GND**; može izlagati i pin **Vcc/Vref**, reset ili pinove za kontrolu toka. Vcc nije UART signal i normalno bi trebalo da se koristi samo kao naponska referenca, a ne da se povezuje kao izvor napajanja, osim ako su šema ploče i zahtevi za strujom poznati.<sup>[[2]](#references)[[3]](#references)</sup>

Počnite sa **isključenim** i odspojenim uređajem:

- Identifikujte **GND** u continuity režimu u odnosu na poznatu ground plane površinu, oklop konektora ili masu napajanja. Nikada ne koristite continuity/resistance režim na ploči koja je pod napajanjem.
- Pre uključivanja cilja prebacite multimetar u režim merenja jednosmernog napona. Izmerite potencijal kandidata za pinove u odnosu na masu da biste identifikovali logički napon. Stabilna naponska grana može biti Vcc/Vref; nemojte pretpostaviti da je bezbedno povezati je.
- Posmatrajte kandidate pomoću logic analyzer-a ili osciloskopa tokom pokretanja. **TX** je obično u stanju mirovanja na visokom nivou i prikazuje burst-ove uokvirenih podataka. Multimetar može prikazati prosečnu promenu, ali ne može potvrditi framing ili baud rate.
- **RX** može ostati u stanju mirovanja i ne može se bezbedno identifikovati samo zato što se nalazi pored TX-a. Pratite vodove na PCB-u, konsultujte datasheet SoC-a ili koristite analyzer visoke impedanse pre nego što ga pobudite.

Zamena TX i RX obično ne proizvodi komunikaciju; mešanje napajanja, mase ili nivoa signala može trajno oštetiti cilj ili adapter. Prvo povežite masu i počnite u režimu **receive-only** (TX cilja na RX adaptera).

Proizvođači mogu izostaviti header, ostaviti serijske otpornike nepopunjene, onemogućiti konzolu u firmware-u ili izložiti samo TX. Pratite obližnje test padove i footprint-e otpornika do SoC-a i dodajte privremenu vezu visoke impedanse tek nakon potvrde električnog nivoa. Postojanje garancije ne znači da UART mora biti dostupan.

### Identifikacija UART baud rate-a

Najlakši način za identifikaciju ispravnog baud rate-a jeste da posmatrate izlaz pina **TX** i pokušate da pročitate podatke. Ako podaci koje primite nisu čitljivi, pređite na sledeći mogući baud rate dok podaci ne postanu čitljivi. Za to možete koristiti USB-to-serial adapter ili višenamenski uređaj kao što je Bus Pirate, u kombinaciji sa pomoćnom skriptom kao što je [baudrate.py](https://github.com/devttys0/baudrate/). Najčešći baud rate-ovi su 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Važno je napomenuti da u ovom protokolu morate povezati TX jednog uređaja sa RX-om drugog uređaja!

## CP210X UART u TTY adapter

CP210x USB-to-UART bridge-ovi se pojavljuju na mnogim prototyping pločama i jeftinim adapterima. Uobičajeni moduli izlažu pinove napajanja zajedno sa GND, RXD i TXD, ali njihovi header-i i I/O nivoi se razlikuju. Potvrdite stvarni napon na osnovu dizajna ploče ili datasheet-a. Obično se povezuju samo GND, RX adaptera na TX cilja i, nakon validacije u režimu receive-only, TX adaptera na RX cilja. Nemojte povezivati 5 V/3.3 V pin za napajanje adaptera, osim ako namerno napajate cilj za koji je poznato da to može da podnese.<sup>[[3]](#references)</sup>

Ako adapter nije detektovan, proverite da li su CP210X drivers instalirani na host sistemu. Kada adapter bude detektovan i povezan, mogu se koristiti alati kao što su picocom, minicom ili screen.

Za izlistavanje uređaja povezanih sa Linux/MacOS sistemima:
```
ls /dev/
```
Za osnovnu interakciju sa UART interfejsom koristite sledeću komandu:
```
picocom /dev/<adapter> --baud <baudrate>
```
Za minicom koristite sledeću komandu da biste ga konfigurisali:
```
minicom -s
```
Konfigurišite podešavanja kao što su baudrate i naziv uređaja u opciji `Serial port setup`.

Nakon konfigurisanja, pokrenite `minicom` da biste otvorili UART konzolu.

## UART putem Arduino UNO R3 (ploče sa uklonjivim Atmel 328p čipom)

U slučaju da UART Serial to USB adapteri nisu dostupni, Arduino UNO R3 može da se koristi uz brzi hack. Pošto je Arduino UNO R3 obično dostupan svuda, ovo može uštedeti mnogo vremena.

Arduino UNO R3 ima USB to Serial adapter ugrađen na samoj ploči. Da biste ostvarili UART vezu, jednostavno izvadite Atmel 328p mikrokontrolerski čip sa ploče. Ovaj hack funkcioniše na Arduino UNO R3 varijantama kod kojih Atmel 328p nije zalemljen na ploču (u njima se koristi SMD verzija). Povežite RX pin Arduina (Digital Pin 0) sa TX pinom UART interfejsa, a TX pin Arduina (Digital Pin 1) sa RX pinom UART interfejsa.

Koristite Arduino IDE **Serial Monitor** ili namenski terminal sa baudrate-om ciljnog uređaja. Klasični Uno R3 serijski signali koriste logiku od 5 V, zato pre povezivanja sa ciljnim uređajem od 3,3 V ili nižeg napona koristite level shifter ili naponski delilac.

## Bus Pirate

Sledeći transcript koristi legacy Bus Pirate firmware interfejs za praćenje UART izlaza. Noviji Bus Pirate firmware koristi komande kao što su `m uart`, `{`/`}`, `monitor` ili `bridge`; pogledajte dokumentaciju za instaliranu verziju.<sup>[[2]](#references)</sup>
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
## Dumpovanje firmvera pomoću UART Console

UART konzola pruža pristup tokom izvršavanja boot logovima i, ponekad, bootloaderu ili shell-u operativnog sistema. Konzola samo za čitanje i dalje otkriva mape memorije, flash drajvere, boot argumente, rasporede particija i verzije firmvera. Firmware može biti smešten u SPI NOR/NAND, eMMC ili drugom uređaju; obično se ne izvršava iz EEPROM-a, a fajlovi upisani u montirani persistentni filesystem ne moraju nestati nakon reboot-a.

Postoji nekoliko načina pribavljanja, a SPI odeljak pokriva direktna čitanja iz eksternog flash-a. Pribavljanje uz pomoć konzole može biti manje invazivno kada bootloader već pruža bezbednu komandu za čitanje, ali svaki prekid boot-a ili flash komanda može uticati na dostupnost, zato zabeležite prvobitno stanje i izbegavajte write/erase operacije.

Dumpovanje firmvera uz pomoć konzole često počinje prekidom bootloadera. Mnogi embedded Linux uređaji koriste **Das U-Boot**, ali drugi koriste vlasničke bootloadere ili onemogućavaju interaktivnu konzolu.

Da biste proverili da li bootloader podržava interakciju, povežite prijemnu putanju UART-a i terminal dok je target isključen, pokrenite logging i uključite ga. Pratite prikazani autoboot prompt; u zavisnosti od build-a, prekid može zahtevati taster, kratku sekvencu ili može biti potpuno onemogućen.

Ako prekid uspe, koristite `help`, `printenv` i read-only discovery komande da biste razumeli raspored memorije i storage-a tog proizvođača pre pristupanja adresama.

U U-Boot-u, `md` prikazuje **adresabilnu memoriju**, a ne automatski „EEPROM“. Najpre koristite board-specific komande kao što su `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables i boot logove da biste identifikovali odgovarajuću mapiranu adresu ili učitali flash region u RAM. Zatim prikažite poznati opseg bajt po bajt:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Zabeležite serijski izlaz pre početka. Izlaz `md.b` sadrži adrese i ASCII kolonu, pa predstavlja tekstualni prikaz, a ne sirovu ROM sliku.

Uklonite kolone sa adresama i ASCII vrednostima, spojite samo heksadecimalna polja bajtova i dekodirajte ih u binarni format (na primer pomoću `xxd -r -p`). Proverite očekivani broj bajtova i zabeležite hash pre analize:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk zatim identifikuje poznate potpise u rekonstruisanom binarnom fajlu. Direktno čitanje flash memorije putem odgovarajućeg SPI/eMMC/NAND interfejsa obično je brže i manje podložno greškama kada konzola ne može pouzdano da prenosi podatke.

U-Boot može onemogućiti prekid, zahtevati sekvencu tastera specifičnu za proizvođača ili zaključati komande za memoriju/flash. Pratite prompt za autoboot i boot log, umesto da naslepo šaljete karaktere. Ako se konzola ne može prekinuti, sačuvajte boot log i pređite na neinvazivni način preuzimanja firmware-a.

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate dokumentacija - UART mode i električna ograničenja](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C tehnički list](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot dokumentacija - `md` komanda za prikaz memorije](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
