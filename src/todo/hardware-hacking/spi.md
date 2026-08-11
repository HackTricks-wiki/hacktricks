# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhrona serijska magistrala koja se često koristi za komunikaciju na kratkim rastojanjima između integrisanih kola. Controller obezbeđuje takt i bira peripheral, kao što su EEPROM, senzor ili kontrolni uređaj, koristeći signal za izbor čipa.<sup>[[1]](#references)</sup>

Više peripheral uređaja može deliti linije takta i podataka, obično uz zaseban chip-select za svaki peripheral. Controller upravlja prenosima; peripheral uređaji obično ne komuniciraju direktno međusobno preko SPI magistrale. Polaritet i vremenski raspored chip-select signala zavise od uređaja; aktiviranje niskim nivoom je uobičajeno, ali nije univerzalno. SPI ne definiše otkrivanje uređaja, adresiranje, komande niti jednu maksimalnu dužinu prenosa, zato se uvek konsultujte sa datasheet-om ciljnog uređaja.<sup>[[1]](#references)</sup>

MOSI/COPI prenosi podatke od controller-a ka peripheral-u, a MISO/CIPO podatke od peripheral-a ka controller-u. Oba smera mogu istovremeno da pomeraju podatke. Odnos između komande, adrese, dummy cycles i vraćenih podataka definiše peripheral, a ne SPI, i zavisi od polariteta i faze takta (režimi 0–3). Nemojte pretpostaviti da izlaz počinje tačno jedan takt nakon završetka ulaza.<sup>[[1]](#references)</sup>

## Dumping Firmware-a iz EEPROM-ova

Dumping firmware-a može biti koristan za njegovu analizu i pronalaženje ranjivosti. Odgovarajuća image datoteka možda nije dostupna online ili se može razlikovati u zavisnosti od modela, hardverske revizije ili verzije, pa njeno direktno izdvajanje sa fizičkog uređaja obezbeđuje tačan cilj za procenu.

Serijska konzola može pomoći, ali njen filesystem može biti samo za čitanje, a ciljnom uređaju mogu nedostajati alati za analizu, uključujući utilities potrebne za praktično slanje/primanje testnog saobraćaja ili izdvajanje binarnih datoteka. Offline image čuva kompletan raspored flash memorije i omogućava izdvajanje filesystem-a i reverse engineering bez menjanja uređaja koji je u radu.

Tokom autorizovane fizičke procene, verifikovani dump može podržati i kontrolisano menjanje i reflashing testove. To obuhvata menjanje datoteka ili ubacivanje testnog payload-a/backdoor-a radi demonstracije persistence-a na nivou firmware-a. Sačuvajte više podudarnih očitavanja i originalnu image datoteku pre bilo kakvog upisivanja: neodgovarajući napon, izbor čipa, raspored ili image mogu da brick-uju uređaj.

### CH341A EEPROM Programmer and Reader

Ovaj jeftin USB alat može da dump-uje i reflash-uje kompatibilne serijske EEPROM i SPI flash uređaje. Često se koristi sa SPI NOR flash čipovima koji čuvaju PC BIOS/UEFI firmware i praktičan je tokom fizičkog pristupa ograničenog vremenom.

![drawing](../../images/board_image_ch341a.jpg)

Povežite flash memoriju sa CH341A, a zatim programmer sa računarom. Ako programmer nije detektovan, proverite USB kabl, OS dozvole i odgovarajući CH341A driver pre rešavanja problema sa ciljnim čipom. Proverite napon čipa, pin 1, ožičenje adaptera i izlaz programmer-a pomoću datasheet-ova ili multimetra — **nemojte** se oslanjati na pravilo kao što je postavljanje VCC-a nasuprot USB konektoru. Pogrešna orijentacija ili primena napona od 5 V na komponentu od 3,3/1,8 V može da je uništi. Očitavanja u kolu takođe mogu da ne uspeju jer ostatak ploče opterećuje ili napaja magistralu.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Za čitanje čipa koristite software kao što su `flashrom` ili G-Flash. G-Flash je minimalni GUI i može automatski da detektuje kompatibilne uređaje, što može biti praktično tokom brzog prikupljanja, ali sami potvrdite detektovani model i napon. Navedite tačan programmer i, kada je potrebno, tačan model čipa; obavite najmanje dva čitanja i uporedite njihove hash vrednosti pre nego što dump smatrate pouzdanim.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nakon dump-ovanja firmware-a, analiza se može obaviti nad binarnim datotekama. Alati kao što su strings, hexdump, xxd, binwalk itd. mogu se koristiti za izdvajanje velike količine informacija o firmware-u, kao i o celom filesystem-u.

Za početni triage, Binwalk može da skenira poznate potpise i izdvoji podržani ugrađeni sadržaj:
```
binwalk -e <filename>
```
Izlazna datoteka može koristiti ekstenziju `.bin`, `.rom` ili neku drugu; ekstenzija ne određuje format.

> [!CAUTION]
> Imajte na umu da je ekstrakcija firmware-a delikatan proces i zahteva mnogo strpljenja. Nepravilno rukovanje može potencijalno oštetiti firmware ili ga čak potpuno izbrisati i učiniti uređaj neupotrebljivim. Pre pokušaja ekstrakcije firmware-a preporučuje se proučavanje konkretnog uređaja.

### Bus Pirate + flashrom

![Programator i čitač CH341A EEPROM-a - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Neki datasheet-ovi označavaju ciljne pinove kao `DI` i `DO`: kod konvencionalne flash veze sa jednom linijom za prenos podataka, kontroler **MOSI/COPI povezuje se sa DI**, a kontroler **MISO/CIPO povezuje se sa DO**. Proverite datasheet ciljnog uređaja jer komponente sa dual/quad I/O režimima koriste iste pinove na druge načine.

![Programator i čitač CH341A EEPROM-a - Bus Pirate + flashrom: Imajte na umu da, čak i ako PINOUT uređaja Pirate Bus prikazuje pinove za MOSI i MISO za povezivanje sa SPI interfejsom, neki SPI interfejsi mogu...](<../../images/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da dumpujete sadržaj flash memorije pokretanjem nečega poput:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Novija Bus Pirate dokumentacija takođe prikazuje opcione parametre `serialspeed` i `spispeed`. Počnite konzervativno ako dugi kablovi ili opterećenje u kolu čine očitavanja nestabilnim.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Uvod u SPI interfejs](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom manual — CH341A SPI programmer i opcije za čitanje/upis](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate dokumentacija — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
