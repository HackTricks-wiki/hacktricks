# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhrona serijska magistrala koja se često koristi za komunikaciju na kratkim rastojanjima između integrisanih kola. Kontroler obezbeđuje takt i bira periferni uređaj, kao što su EEPROM, senzor ili kontrolni uređaj, pomoću signala za izbor čipa.<sup>[[1]](#references)</sup>

Više perifernih uređaja može da deli linije takta i podataka, obično uz zaseban signal za izbor čipa za svaki uređaj. Kontroler upravlja prenosima; periferni uređaji uglavnom ne komuniciraju direktno međusobno preko SPI magistrale. Polaritet i vremensko usklađivanje signala za izbor čipa zavise od uređaja; aktiviranje na niskom nivou je uobičajeno, ali nije univerzalno. SPI ne definiše otkrivanje uređaja, adresiranje, komande ni jednu maksimalnu dužinu prenosa, zato uvek konsultujte datasheet ciljnog uređaja.<sup>[[1]](#references)</sup>

MOSI/COPI prenosi podatke od kontrolera ka perifernom uređaju, a MISO/CIPO prenosi podatke od perifernog uređaja ka kontroleru. Podaci se mogu istovremeno pomerati u oba smera. Odnos između komande, adrese, dummy ciklusa i vraćenih podataka definiše periferni uređaj, a ne SPI, i zavisi od polariteta i faze takta (režimi 0–3). Nemojte pretpostavljati da izlaz počinje tačno jedan takt nakon završetka ulaza.<sup>[[1]](#references)</sup>

## Izvlačenje firmware-a iz EEPROM-ova

Izvlačenje firmware-a može biti korisno za njegovu analizu i pronalaženje ranjivosti. Odgovarajuća slika možda nije dostupna na internetu ili se može razlikovati po modelu, hardverskoj reviziji ili verziji, pa njeno direktno izdvajanje sa fizičkog uređaja daje tačan cilj za procenu.

Serijska konzola može biti korisna, ali njen fajl-sistem može biti samo za čitanje, a ciljnom uređaju možda nedostaju alati za analizu, uključujući uslužne programe potrebne za slanje/prijem testnog saobraćaja ili jednostavno izdvajanje binarnih datoteka. Slika van mreže čuva kompletan raspored flash memorije i omogućava izdvajanje fajl-sistema i reverse engineering bez izmena na uređaju koji je u radu.

Tokom ovlašćene fizičke procene, provereni dump može da posluži i za kontrolisano testiranje izmena i ponovnog upisivanja. To obuhvata menjanje fajlova ili ubacivanje testnog payload-a/backdoor-a radi demonstracije postojanosti na nivou firmware-a. Sačuvajte više podudarnih očitavanja i originalnu sliku pre bilo kakvog upisa: neispravan napon, izbor čipa, raspored ili slika mogu da onesposobe uređaj.

### CH341A EEPROM programator i čitač

Ovaj jeftin USB alat može da izvuče i ponovo upiše podatke na kompatibilne serijske EEPROM i SPI flash uređaje. Često se koristi sa SPI NOR flash čipovima u kojima se čuva firmware PC BIOS/UEFI i praktičan je kada je fizički pristup vremenski ograničen.

![drawing](../../images/board_image_ch341a.jpg)

Povežite flash memoriju sa CH341A, a zatim povežite programator sa računarom. Ako programator nije prepoznat, proverite USB kabl, dozvole OS-a i odgovarajući CH341A drajver pre nego što počnete da rešavate probleme sa ciljnim čipom. Proverite napon čipa, pin 1, ožičenje adaptera i izlaz programatora pomoću datasheet-ova ili multimetra — **nemojte** se oslanjati na pravilo poput postavljanja VCC-a nasuprot USB konektoru. Pogrešna orijentacija ili dovođenje napona od 5 V na komponentu od 3,3/1,8 V može da je uništi. Očitavanja u kolu takođe mogu da ne uspeju jer ostatak ploče opterećuje ili napaja magistralu.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Za čitanje čipa koristite softver kao što su `flashrom` ili G-Flash. G-Flash je jednostavan GUI i može automatski da prepozna kompatibilne uređaje, što može biti praktično pri brzom prikupljanju podataka, ali sami potvrdite prepoznati model i napon. Navedite tačan programator i, kada je potrebno, tačan model čipa; obavite najmanje dva čitanja i uporedite njihove hash vrednosti pre nego što dump smatrate pouzdanim.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nakon izvlačenja firmware-a, analiza se može obaviti nad binarnim datotekama. Alati kao što su strings, hexdump, xxd, binwalk itd. mogu se koristiti za izdvajanje mnoštva informacija o firmware-u, kao i o celom fajl-sistemu.

Za početnu trijažu, Binwalk može da skenira poznate potpise i izdvoji podržani ugrađeni sadržaj:

```
binwalk -e <filename>
```

Izlazna datoteka može koristiti ekstenziju `.bin`, `.rom` ili neku drugu; ekstenzija ne određuje format.

> [!CAUTION]
> Imajte na umu da je izdvajanje firmvera delikatan postupak i zahteva mnogo strpljenja. Svako nepravilno rukovanje može potencijalno da ošteti firmver ili čak da ga potpuno izbriše i učini uređaj neupotrebljivim. Pre pokušaja izdvajanja firmvera preporučuje se da proučite konkretan uređaj.

### Bus Pirate + flashrom

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

U nekim datasheet-ovima pinovi na ciljnom uređaju označeni su kao `DI` i `DO`: kod uobičajene flash veze sa jednom linijom za prenos podataka, MOSI/COPI kontrolera povezuje se sa DI, a MISO/CIPO kontrolera sa DO. Proverite datasheet ciljnog uređaja jer se kod komponenti sa dual/quad I/O pinovi koriste u drugim režimima.

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Imajte na umu da, iako PINOUT uređaja Bus Pirate označava pinove za povezivanje MOSI i MISO na SPI, neki SPI uređaji mogu...](<../../images/image (360).png>)

U operativnim sistemima Windows ili Linux možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da biste sačuvali sadržaj flash memorije, na primer, ovako:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Novija Bus Pirate dokumentacija prikazuje i opcione parametre `serialspeed` i `spispeed`. Počnite konzervativno ako dugačke žice ili opterećenje u kolu izazivaju nestabilna očitavanja.<sup>[[3]](#references)</sup>

### Očitavanja u kolu kada kontroler deli flash magistralu

SOIC klipsa može dovesti napajanje flash-a do ostatka PCB-a. Ako se MCU tada napaja i pristupa istom čipu, njegovi SPI prenosi mogu da se sudare sa prenosima spoljnog programatora. Zato rezultat `No EEPROM/flash device found` ne dokazuje da flash ne postoji ili da nije podržan. Najpre proverite raspored pinova, napon i kontakt, a zatim utvrdite da li je kontroler na ploči takođe aktivan.<sup>[[4]](#references)</sup>

Ako postoji testna tačka za reset, pre aktiviranja multimetrom proverite njen polaritet i napon. Držanje MCU-a u resetu može ostaviti flash dostupan, a istovremeno zaustaviti SPI host koji ometa komunikaciju. Druge mogućnosti su odlemljivanje čipa ili pasivno beleženje MCU-ovih očitavanja; ova druga opcija ne omogućava pristup nepročitanim oblastima niti upis u čip, a dodatno ožičenje sonde može da ometa brzu magistralu. Intervencija u oscilator ili režim pokretanja zavisi od konkretnog ciljnog uređaja i nije zamena za proveru šeme i signala.<sup>[[4]](#references)</sup>

Kada je MCU neaktivan, Raspberry Pi sa omogućenim interfejsom `spidev` može da čita pomoću flashrom-ovog programatora `linux_spi`. Promenite `-p` za drugi adapter. Ponovite očitavanje i uporedite hash vrednosti pre nego što mu ukažete poverenje; SFDP automatsko prepoznavanje i uspešno očitavanje **ne** potvrđuju da funkcionišu operacije brisanja, upisa ili zaštite od upisa na inače nepodržanom delu.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Rekonstrukcija SPI flash čitanja pomoću analizatora logike

Kada aktivno čitanje nije moguće, snimite chip select, takt, podatke od kontrolera ka flash memoriji i podatke od flash memorije ka kontroleru tokom pokretanja ili odabrane radnje u UI-ju. U PulseView-u prvo pronađite aktivni interval chip select signala i takt, a zatim podesite kanale podataka za SPI dekoder prema rasporedu pinova flash memorije i proverite da li se pojavljuje verovatna komanda/adresa praćena vraćenim bajtovima. Izvezite bajtove **MISO/flash-output** pomoću prikaza Binary Decoder Output View i sačuvajte dekodirane adrese čitanja kako bi svaki odgovor mogao da se smesti na odgovarajući flash offset. Snimanje samo čitanja pokrenutih kroz menije obuhvata samo zatražene oblasti, a ne celu flash sliku; nemojte spajati odgovore kao da su susedni bez provere adresa.<sup>[[4]](#references)</sup>

Ako dump izgleda kao da sadrži grafiku, a ne izvršni kod, nastavite sa [trijažom sirovih elemenata prikaza](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — Uvod u SPI interfejs](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Uputstvo za flashrom — CH341A SPI programator i opcije za čitanje/upisivanje](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacija za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Obnavljanje znanja o hardware hacking-u, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
