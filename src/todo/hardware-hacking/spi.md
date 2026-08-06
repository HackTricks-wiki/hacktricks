# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je Synchronous Serial Communication Protocol koji se koristi u embedded sistemima za komunikaciju na kratkim udaljenostima između IC-ova (Integrated Circuits). SPI Communication Protocol koristi master-slave arhitekturu kojom upravljaju Clock i Chip Select Signal. Master-slave arhitektura se sastoji od master-a (obično mikroprocesora) koji upravlja eksternim perifernim uređajima kao što su EEPROM, senzori, kontrolni uređaji itd., koji se smatraju slave uređajima.

Više slave uređaja može biti povezano sa jednim master uređajem, ali slave uređaji ne mogu međusobno da komuniciraju. Slave uređajima se upravlja pomoću dva pina, clock i chip select. Pošto je SPI synchronous communication protocol, ulazni i izlazni pinovi prate clock signale. Chip select master koristi za izbor slave uređaja i interakciju sa njim. Kada je chip select high, slave uređaj nije izabran, dok je, kada je low, chip izabran i master komunicira sa slave uređajem.

MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) zaduženi su za slanje i prijem podataka. Podaci se šalju slave uređaju kroz MOSI pin dok je chip select postavljen na low. Ulazni podaci sadrže instrukcije, memorijske adrese ili podatke, u skladu sa datasheet-om proizvođača slave uređaja. Nakon validnog ulaza, MISO pin je zadužen za prenos podataka master-u. Izlazni podaci se šalju tačno u sledećem clock cycle-u nakon završetka ulaza. MISO pin prenosi podatke sve dok se podaci u potpunosti ne prenesu ili dok master ne postavi chip select pin na high (u tom slučaju slave prestaje sa prenosom, a master više ne prima podatke nakon tog clock cycle-a).

## Dumping Firmware-a sa EEPROM-ova

Dumping firmware-a može biti koristan za analizu firmware-a i pronalaženje ranjivosti u njemu. Često firmware nije dostupan na internetu ili je neupotrebljiv zbog različitih faktora kao što su broj modela, verzija itd. Zbog toga ekstrakcija firmware-a direktno sa fizičkog uređaja može biti korisna za preciznije traženje pretnji.

Dobijanje Serial Console-a može biti korisno, ali se često dešava da su fajlovi read-only. Ovo ograničava analizu iz različitih razloga. Na primer, alati potrebni za slanje i prijem paketa neće se nalaziti u firmware-u. Zbog toga ekstrakcija binarnih fajlova radi reverse engineering-a nije izvodljiva. Zato može biti veoma korisno imati kompletan firmware dump na sistemu i ekstrahovati binarne fajlove radi analize.

Takođe, tokom red teaming-a i dobijanja fizičkog pristupa uređajima, dumping firmware-a može pomoći pri izmeni fajlova ili ubacivanju malicious fajlova, a zatim njihovom ponovnom upisivanju u memoriju, što može biti korisno za ubacivanje backdoor-a u uređaj. Zbog toga dumping firmware-a otvara brojne mogućnosti.

### CH341A EEPROM Programmer and Reader

Ovaj uređaj je jeftin alat za dumping firmware-a sa EEPROM-ova, kao i za njihovo ponovno upisivanje pomoću firmware fajlova. Popularan je izbor za rad sa computer BIOS chip-ovima (koji su zapravo EEPROM-ovi). Ovaj uređaj se povezuje preko USB-a i za početak rada zahteva minimalan broj alata. Takođe, obično brzo završava zadatak, pa može biti koristan i pri fizičkom pristupu uređaju.

![drawing](../../images/board_image_ch341a.jpg)

Povežite EEPROM memoriju sa CH341a Programmer-om i priključite uređaj na računar. Ako uređaj nije detektovan, pokušajte da instalirate driver-e na računar. Takođe proverite da li je EEPROM povezan u pravilnoj orijentaciji (obično se VCC Pin postavlja u suprotnom smeru od USB konektora), jer u suprotnom software neće moći da detektuje chip. Ako je potrebno, pogledajte dijagram:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Na kraju, koristite software kao što su flashrom, G-Flash (GUI) itd. za dumping firmware-a. G-Flash je minimalan GUI alat koji je brz i automatski detektuje EEPROM. Ovo može biti korisno kada firmware treba brzo ekstrahovati, bez mnogo proučavanja dokumentacije.

![drawing](../../images/connected_status_ch341a.jpg)

Nakon dumpinga firmware-a, analiza se može izvršiti nad binarnim fajlovima. Alati kao što su strings, hexdump, xxd, binwalk itd. mogu se koristiti za ekstrakciju velikog broja informacija o firmware-u, kao i o celom file system-u.

Za ekstrakciju sadržaja iz firmware-a može se koristiti binwalk. Binwalk analizira hex signatures, identifikuje fajlove u binarnom fajlu i može da ih ekstrahuje.
```
binwalk -e <filename>
```
Može biti .bin ili .rom, u zavisnosti od korišćenih alata i konfiguracija.

> [!CAUTION]
> Imajte na umu da je ekstrakcija firmware-a delikatan proces i zahteva mnogo strpljenja. Nepravilno rukovanje može potencijalno oštetiti firmware ili ga čak potpuno izbrisati i učiniti uređaj neupotrebljivim. Pre pokušaja ekstrakcije firmware-a preporučuje se proučavanje konkretnog uređaja.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Imajte na umu da, čak i ako PINOUT uređaja Pirate Bus označava pinove **MOSI** i **MISO** za povezivanje sa SPI-jem, neki SPI uređaji mogu označavati pinove kao DI i DO. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) za dump sadržaja flash memorije pokretanjem nečega poput:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
