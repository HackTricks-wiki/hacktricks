# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhrona serijska magistrala koja se često koristi za komunikaciju na kratkim rastojanjima između integrisanih kola. Kontroler obezbeđuje takt i bira periferni uređaj, kao što su EEPROM, senzor ili kontrolni uređaj, pomoću signala za izbor čipa.<sup>[[1]](#references)</sup>

Više perifernih uređaja može da deli linije takta i podataka, obično sa zasebnim signalom za izbor čipa za svaki uređaj. Kontroler upravlja prenosima; periferni uređaji obično ne komuniciraju direktno međusobno preko SPI magistrale. Polaritet i vremenski raspored signala za izbor čipa zavise od uređaja; aktivni niski nivo je čest, ali nije univerzalan. SPI ne definiše otkrivanje uređaja, adresiranje, komande niti jedinstvenu maksimalnu dužinu prenosa, zato uvek konsultujte datasheet ciljnog uređaja.<sup>[[1]](#references)</sup>

MOSI/COPI prenosi podatke od kontrolera ka perifernom uređaju, a MISO/CIPO podatke od perifernog uređaja ka kontroleru. Podaci mogu istovremeno da se pomeraju u oba smera. Odnos između komande, adrese, dodatnih ciklusa i vraćenih podataka definiše periferni uređaj, a ne SPI, i zavisi od polariteta i faze takta (režimi 0–3). Nemojte pretpostavljati da izlaz počinje tačno jedan takt nakon završetka ulaza.<sup>[[1]](#references)</sup>

## Dumpovanje firmware-a iz EEPROM-ova

Dumpovanje firmware-a može biti korisno za njegovu analizu i pronalaženje ranjivosti. Odgovarajuća kopija možda nije dostupna na mreži ili se može razlikovati po modelu, hardverskoj reviziji ili verziji, pa njeno direktno izdvajanje sa fizičkog uređaja omogućava procenu tačne verzije.

Serijska konzola može biti korisna, ali njen fajl-sistem može biti samo za čitanje, a ciljnom uređaju možda nedostaju alati za analizu, uključujući uslužne programe potrebne za slanje/primanje testnog saobraćaja ili jednostavno izdvajanje binarnih datoteka. Offline kopija čuva kompletan raspored flash memorije i omogućava izdvajanje fajl-sistema i reverse engineering bez izmena na uređaju koji je u funkciji.

Tokom ovlašćene fizičke procene, verifikovani dump može da posluži i za kontrolisane izmene i testove ponovnog upisivanja. To obuhvata menjanje fajlova ili ubacivanje testnog payload-a/backdoor-a radi demonstracije postojanosti na nivou firmware-a. Sačuvajte više podudarnih očitavanja i originalnu kopiju pre bilo kakvog upisa: pogrešan napon, izbor čipa, raspored ili kopija mogu da onesposobe uređaj.

### CH341A EEPROM programator i čitač

Ovaj jeftin USB alat može da dumpuje i ponovo upisuje kompatibilne serijske EEPROM i SPI flash uređaje. Često se koristi sa SPI NOR flash čipovima u kojima se čuva firmware PC BIOS/UEFI-ja i praktičan je tokom fizičkog pristupa koji je vremenski ograničen.

![drawing](../../images/board_image_ch341a.jpg)

Povežite flash memoriju sa CH341A, a zatim povežite programator sa računarom. Ako programator nije prepoznat, pre rešavanja problema sa ciljnim čipom proverite USB kabl, dozvole OS-a i odgovarajući CH341A drajver. Pomoću datasheet-ova ili mernog instrumenta proverite napon čipa, pin 1, ožičenje adaptera i izlaz programatora — **nemojte** se oslanjati na pravilo kao što je postavljanje VCC-a nasuprot USB konektoru. Pogrešna orijentacija ili dovođenje 5 V na komponentu od 3,3/1,8 V može da je uništi. Očitavanja u kolu takođe mogu da ne uspeju jer ostatak ploče opterećuje ili napaja magistralu.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Za čitanje čipa koristite softver kao što su `flashrom` ili G-Flash. G-Flash je jednostavan GUI koji može automatski da prepozna kompatibilne uređaje, što može biti praktično tokom brzog prikupljanja podataka, ali sami potvrdite prepoznati model i napon. Navedite tačan programator i, kada je potrebno, tačan model čipa; obavite najmanje dva očitavanja i uporedite njihove hash vrednosti pre nego što dump smatrate pouzdanim.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nakon dumpovanja firmware-a, analiza se može obaviti nad binarnim fajlovima. Alati kao što su strings, hexdump, xxd, binwalk itd. mogu da se koriste za izdvajanje velikog broja informacija o firmware-u, kao i o celom fajl-sistemu.

Za početnu trijažu, Binwalk može da skenira poznate potpise i izdvoji podržani ugrađeni sadržaj:

```
binwalk -e <filename>
```

Izlazna datoteka može imati ekstenziju `.bin`, `.rom` ili neku drugu; ekstenzija ne određuje format.

> [!CAUTION]
> Imajte na umu da je izdvajanje firmvera delikatan postupak koji zahteva mnogo strpljenja. Nepravilno rukovanje može da ošteti firmver ili čak da ga potpuno izbriše, čime uređaj postaje neupotrebljiv. Pre pokušaja izdvajanja firmvera preporučuje se da proučite konkretan uređaj.

### Bus Pirate + flashrom

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Neki datasheet-ovi označavaju pinove na ciljnom uređaju kao `DI` i `DO`: kod uobičajene flash veze sa jednom linijom za prenos podataka, kontrolerov **MOSI/COPI povezuje se na DI**, a kontrolerov **MISO/CIPO povezuje se na DO**. Proverite datasheet ciljnog uređaja, jer se kod komponenti sa dual/quad I/O režimima ti pinovi koriste na druge načine.

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Imajte na umu da, iako su na PINOUT-u Bus Pirate-a navedeni pinovi MOSI i MISO za povezivanje na SPI, neki SPI uređaji mogu...](<../../images/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) za pravljenje dump-a sadržaja flash memorije, na primer, pomoću sledeće komande:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Novija dokumentacija za Bus Pirate takođe prikazuje opcione parametre `serialspeed` i `spispeed`. Počnite oprezno ako dugačke žice ili opterećenje kola tokom rada čine očitavanja nestabilnim.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Uvod u SPI interfejs](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Uputstvo za flashrom — CH341A SPI programator i opcije za čitanje/upisivanje](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacija za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
