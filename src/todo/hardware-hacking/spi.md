# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhroni serijski komunikacioni protokol koji se koristi u ugrađenim sistemima za kratkodistansku komunikaciju između IC-ova (integrisanih kola). SPI komunikacioni protokol koristi arhitekturu master-slave koju orkestrira signal sata i signal odabira čipa. Arhitektura master-slave se sastoji od mastera (obično mikroprocesora) koji upravlja spoljnim perifernim uređajima kao što su EEPROM, senzori, kontrolni uređaji itd., koji se smatraju slugama.

Više sluga može biti povezano sa masterom, ali sluge ne mogu međusobno komunicirati. Slugama upravljaju dva pina, sat i odabir čipa. Pošto je SPI sinhroni komunikacioni protokol, ulazni i izlazni pinovi prate signale sata. Signal odabira čipa koristi master da odabere slugu i komunicira s njom. Kada je signal odabira čipa visok, uređaj sluge nije odabran, dok kada je nizak, čip je odabran i master bi komunicirao sa slugom.

MOSI (Master Out, Slave In) i MISO (Master In, Slave Out) su odgovorni za slanje i primanje podataka. Podaci se šalju uređaju sluge putem MOSI pina dok je signal odabira čipa nizak. Ulazni podaci sadrže instrukcije, adrese u memoriji ili podatke prema tehničkoj dokumentaciji dobavljača uređaja sluge. Nakon validnog ulaza, MISO pin je odgovoran za prenos podataka ka masteru. Izlazni podaci se šalju tačno u sledećem ciklusu sata nakon što ulaz završi. MISO pin prenosi podatke sve dok podaci nisu potpuno preneseni ili dok master ne postavi pin odabira čipa na visok (u tom slučaju, sluga bi prestao sa prenosom i master ne bi slušao nakon tog ciklusa sata).

## Dumpovanje firmvera sa EEPROM-a

Dumpovanje firmvera može biti korisno za analizu firmvera i pronalaženje ranjivosti u njima. Često, firmver nije dostupan na internetu ili je nerelevantan zbog varijacija faktora kao što su broj modela, verzija itd. Stoga, direktno izvlačenje firmvera sa fizičkog uređaja može biti korisno da se bude specifičan prilikom lova na pretnje.

Dobijanje serijske konzole može biti korisno, ali često se dešava da su datoteke samo za čitanje. To ograničava analizu iz raznih razloga. Na primer, alati koji su potrebni za slanje i primanje paketa ne bi bili prisutni u firmveru. Dakle, izvlačenje binarnih datoteka za obrnuto inženjerstvo nije izvodljivo. Stoga, imati ceo firmver dumpovan na sistemu i izvlačiti binarne datoteke za analizu može biti veoma korisno.

Takođe, tokom red reaming-a i dobijanja fizičkog pristupa uređajima, dumpovanje firmvera može pomoći u modifikaciji datoteka ili injektovanju zlonamernih datoteka, a zatim ponovnom flešovanju u memoriju, što može biti korisno za implantaciju backdoora u uređaj. Stoga, postoji brojne mogućnosti koje se mogu otključati dumpovanjem firmvera.

### CH341A EEPROM programer i čitač

Ovaj uređaj je jeftin alat za dumpovanje firmvera sa EEPROM-a i takođe ponovo flešovanje sa datotekama firmvera. Ovo je popularan izbor za rad sa BIOS čipovima računara (koji su samo EEPROM-ovi). Ovaj uređaj se povezuje preko USB-a i zahteva minimalne alate za početak. Takođe, obično brzo obavlja zadatak, pa može biti koristan i za fizički pristup uređaju.

![drawing](../../images/board_image_ch341a.jpg)

Povežite EEPROM memoriju sa CH341a programerom i priključite uređaj na računar. U slučaju da uređaj nije prepoznat, pokušajte da instalirate drajvere na računar. Takođe, uverite se da je EEPROM povezan u pravom položaju (obično, postavite VCC pin u obrnutom položaju u odnosu na USB konektor) ili softver neće moći da prepozna čip. Pogledajte dijagram ako je potrebno:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Na kraju, koristite softvere kao što su flashrom, G-Flash (GUI), itd. za dumpovanje firmvera. G-Flash je minimalni GUI alat koji je brz i automatski prepoznaje EEPROM. Ovo može biti korisno kada je potrebno brzo izvući firmver, bez mnogo petljanja sa dokumentacijom.

![drawing](../../images/connected_status_ch341a.jpg)

Nakon dumpovanja firmvera, analiza se može obaviti na binarnim datotekama. Alati kao što su strings, hexdump, xxd, binwalk, itd. mogu se koristiti za ekstrakciju mnogo informacija o firmveru kao i o celom fajl sistemu.

Za ekstrakciju sadržaja iz firmvera može se koristiti binwalk. Binwalk analizira heksadecimalne potpise i identifikuje datoteke u binarnoj datoteci i sposoban je da ih ekstrakuje.
```
binwalk -e <filename>
```
Može biti .bin ili .rom u zavisnosti od alata i konfiguracija koje se koriste.

> [!CAUTION]
> Imajte na umu da je ekstrakcija firmvera delikatan proces i zahteva puno strpljenja. Svako nepravilno rukovanje može potencijalno oštetiti firmver ili čak potpuno obrisati i učiniti uređaj neupotrebljivim. Preporučuje se proučavanje specifičnog uređaja pre nego što pokušate da ekstraktujete firmver.

### Bus Pirate + flashrom

![](<../../images/image (910).png>)

Imajte na umu da čak i ako PINOUT Pirate Bus-a ukazuje na pinove za **MOSI** i **MISO** za povezivanje sa SPI, neki SPIs mogu označavati pinove kao DI i DO. **MOSI -> DI, MISO -> DO**

![](<../../images/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da dump-ujete sadržaj flash memorije pokrećući nešto poput:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
