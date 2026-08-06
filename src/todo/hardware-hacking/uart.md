# UART

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

UART je serijski protokol, što znači da prenosi podatke između komponenti bit po bit. Nasuprot tome, paralelni komunikacioni protokoli prenose podatke istovremeno kroz više kanala. Uobičajeni serijski protokoli uključuju RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express i USB.

Uopšteno, linija je na visokom nivou (logička vrednost 1) dok je UART u stanju mirovanja. Zatim, da bi signalizirao početak prenosa podataka, predajnik šalje startni bit prijemniku, pri čemu se signal drži na niskom nivou (logička vrednost 0). Nakon toga predajnik šalje pet do osam bitova podataka koji sadrže stvarnu poruku, zatim opcioni bit parnosti i jedan ili dva stop bita (sa logičkom vrednošću 1), u zavisnosti od konfiguracije. Bit parnosti, koji se koristi za proveru grešaka, retko se viđa u praksi. Stop bit (ili bitovi) označava kraj prenosa.

Najčešću konfiguraciju nazivamo 8N1: osam bitova podataka, bez parnosti i jedan stop bit. Na primer, ako želimo da pošaljemo znak C, odnosno 0x43 u ASCII-ju, u 8N1 UART konfiguraciji, poslali bismo sledeće bitove: 0 (startni bit); 0, 1, 0, 0, 0, 0, 1, 1 (vrednost 0x43 u binarnom obliku) i 0 (stop bit).

![UART: Najčešću konfiguraciju nazivamo 8N1: osam bitova podataka, bez parnosti i jedan stop bit. Na primer, ako želimo da pošaljemo znak C, odnosno 0x43 u ASCII-ju, u 8N1 UART konfiguraciji](<../../images/image (764).png>)

Hardverski alati za komunikaciju sa UART-om:

- USB-to-serial adapter
- Adapteri sa CP2102 ili PL2303 čipovima
- Višenamenski alat kao što su: Bus Pirate, Adafruit FT232H, Shikra ili Attify Badge

### Identifikacija UART portova

UART ima 4 porta: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) i **GND** (Ground). Možda ćete moći da pronađete 4 porta sa slovima **`TX`** i **`RX`** **ispisanim** na PCB-u. Ali ako nema oznaka, možda ćete morati sami da ih pronađete pomoću **multimetra** ili **logičkog analizatora**.

Sa **multimetrom** i isključenim uređajem:

- Da biste identifikovali **GND** pin, koristite režim **Continuity Test**, postavite crnu sondu na uzemljenje i testirajte crvenom sondom dok ne čujete zvuk multimetra. Na PCB-u se može pronaći više GND pinova, pa možda jeste, a možda i niste pronašli onaj koji pripada UART-u.
- Da biste identifikovali **VCC port**, podesite režim **DC voltage** i opseg napona na 20 V. Crnu sondu postavite na uzemljenje, a crvenu na pin. Uključite uređaj. Ako multimetar izmeri konstantan napon od 3,3 V ili 5 V, pronašli ste Vcc pin. Ako dobijete druge vrednosti napona, pokušajte sa drugim portovima.
- Da biste identifikovali **TX** **port**, podesite režim **DC voltage** i opseg napona do 20 V, postavite crnu sondu na uzemljenje, a crvenu na pin i uključite uređaj. Ako napon nekoliko sekundi varira, a zatim se stabilizuje na vrednosti Vcc, najverovatnije ste pronašli TX port. To je zato što se pri uključivanju šalju određeni debug podaci.
- **RX port** bi trebalo da bude najbliži ostala 3 porta; on ima najmanje variranje napona i najnižu ukupnu vrednost od svih UART pinova.

Možete zameniti TX i RX portove i ništa se neće dogoditi, ali ako pomešate GND i VCC port, mogli biste da spržite kolo.

Na nekim ciljnim uređajima proizvođač onemogućava UART port tako što onemogući RX ili TX, ili čak oba. U tom slučaju može biti korisno pratiti veze na ploči i pronaći neku breakout tačku. Dobar pokazatelj za potvrdu da UART nije detektovan i da je kolo prekinuto jeste provera garancije uređaja. Ako je uređaj isporučen sa garancijom, proizvođač ostavlja neke debug interfejse (u ovom slučaju UART) i zato mora da odvoji UART, a zatim da ga ponovo poveže tokom debugovanja. Ovi breakout pinovi mogu se povezati lemljenjem ili jumper žicama.

### Identifikacija UART Baud Rate-a

Najlakši način da identifikujete ispravan baud rate jeste da pogledate izlaz sa **TX pina i pokušate da pročitate podatke**. Ako podaci koje primite nisu čitljivi, pređite na sledeći mogući baud rate dok podaci ne postanu čitljivi. Za to možete koristiti USB-to-serial adapter ili višenamenski uređaj kao što je Bus Pirate, u kombinaciji sa pomoćnom skriptom, kao što je [baudrate.py](https://github.com/devttys0/baudrate/). Najčešći baud rate-ovi su 9600, 38400, 19200, 57600 i 115200.

> [!CAUTION]
> Važno je napomenuti da u ovom protokolu morate povezati TX jednog uređaja sa RX-om drugog uređaja!

## CP210X UART to TTY Adapter

CP210X čip se koristi na velikom broju prototyping ploča, kao što je NodeMCU (sa esp8266), za serijsku komunikaciju. Ovi adapteri su relativno jeftini i mogu se koristiti za povezivanje sa UART interfejsom cilja. Uređaj ima 5 pinova: 5V, GND, RXD, TXD, 3.3V. Obavezno povežite napon koji podržava cilj kako biste izbegli oštećenja. Na kraju povežite RXD pin adaptera sa TXD pinom cilja, a TXD pin adaptera sa RXD pinom cilja.

Ako adapter nije detektovan, proverite da li su CP210X drajveri instalirani na host sistemu. Kada se adapter detektuje i poveže, mogu se koristiti alati kao što su picocom, minicom ili screen.

Za izlistavanje uređaja povezanih sa Linux/MacOS sistemima:
```
ls /dev/
```
Za osnovnu interakciju sa UART interfejsom, koristite sledeću komandu:
```
picocom /dev/<adapter> --baud <baudrate>
```
Za minicom koristite sledeću komandu da ga konfigurišete:
```
minicom -s
```
Konfigurišite podešavanja kao što su baudrate i naziv uređaja u opciji `Serial port setup`.

Nakon konfiguracije, koristite komandu `minicom` da pokrenete UART Console.

## UART preko Arduino UNO R3 (ploče sa uklonjivim Atmel 328p čipom)

U slučaju da UART Serial to USB adapteri nisu dostupni, Arduino UNO R3 može da se koristi uz brzu izmenu. Pošto je Arduino UNO R3 obično dostupan svuda, ovo može značajno uštedeti vreme.

Arduino UNO R3 na samoj ploči ima ugrađen USB to Serial adapter. Da biste ostvarili UART vezu, jednostavno izvadite Atmel 328p mikrokontrolerski čip sa ploče. Ovaj hack radi na Arduino UNO R3 varijantama kod kojih Atmel 328p nije zalemljen na ploču (u njima se koristi SMD verzija). Povežite RX pin Arduina (Digital Pin 0) sa TX pinom UART Interface-a, a TX pin Arduina (Digital Pin 1) sa RX pinom UART Interface-a.

Na kraju, preporučuje se korišćenje Arduino IDE-a za pristup Serial Console-u. U odeljku `tools` u meniju izaberite opciju `Serial Console` i podesite baud rate u skladu sa UART Interface-om.

## Bus Pirate

U ovom scenariju ćemo presretati UART komunikaciju Arduina koji šalje sve ispise programa u Serial Monitor.
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

UART Console pruža odličan način za rad sa osnovnim firmware-om u runtime environment-u. Međutim, kada je pristup UART Console-u read-only, to može predstavljati brojna ograničenja. U mnogim embedded uređajima, firmware se čuva u EEPROM-ovima i izvršava u procesorima koji imaju volatile memory. Zbog toga se firmware čuva kao read-only, jer se originalni firmware tokom proizvodnje nalazi unutar samog EEPROM-a, dok bi se sve nove datoteke izgubile zbog volatile memory-ja. Zbog toga je dumping firmware-a vredan postupak pri radu sa embedded firmware-ima.

Postoji mnogo načina za ovo, a SPI sekcija obuhvata metode za direktno izvlačenje firmware-a iz EEPROM-a pomoću različitih uređaja. Ipak, preporučuje se da najpre pokušate dumping firmware-a pomoću UART-a, jer dumping firmware-a fizičkim uređajima i spoljnim interakcijama može biti rizičan.

Dumping firmware-a iz UART Console-a najpre zahteva pristup bootloader-ima. Mnogi popularni vendor-i koriste uboot (Universal Bootloader) kao bootloader za učitavanje Linux-a. Zbog toga je neophodno dobiti pristup uboot-u.

Da biste dobili pristup bootloader-u, povežite UART port sa računarom i upotrebite neki od Serial Console alata, a napajanje uređaja ostavite isključeno. Kada je podešavanje spremno, pritisnite i zadržite Enter Key. Zatim povežite napajanje uređaja i pustite ga da se pokrene.

Ovim ćete prekinuti učitavanje uboot-a i prikazaće se meni. Preporučuje se da razumete uboot komande i da koristite help meni za njihovo izlistavanje. To može biti komanda `help`. Pošto različiti vendor-i koriste različite konfiguracije, neophodno je razumeti svaku od njih zasebno.

Obično je komanda za dumping firmware-a:
```
md
```
što znači „memory dump“. Ovo će prikazati memoriju (EEPROM Content) na ekranu. Preporučuje se da pre pokretanja procedure zabeležite izlaz Serial Console-a kako biste sačuvali memory dump.

Na kraju, jednostavno uklonite sve nepotrebne podatke iz log datoteke, sačuvajte datoteku kao `filename.rom` i koristite binwalk za izdvajanje sadržaja:
```
binwalk -e <filename.rom>
```
Ovo će izlistati moguće sadržaje EEPROM-a na osnovu potpisa pronađenih u hex fajlu.

Ipak, važno je napomenuti da uboot nije uvek otključan čak i kada se koristi. Ako pritiskanje tastera Enter ne radi ništa, proverite druge tastere, kao što je Space, itd. Ako je bootloader zaključan i ne može da se prekine, ova metoda neće raditi. Da biste proverili da li je uboot bootloader uređaja, proverite izlaz na UART Console tokom pokretanja uređaja. Možda će se tokom pokretanja pomenuti uboot.

{{#include ../../banners/hacktricks-training.md}}
