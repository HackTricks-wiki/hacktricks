# SPI

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

SPI (Serial Peripheral Interface) je sinhrona serijska magistrala koja se često koristi za komunikaciju na kratkim rastojanjima između integrisanih kola. Kontroler obezbeđuje takt i bira periferni uređaj, kao što su EEPROM, senzor ili kontrolni uređaj, pomoću signala chip-select.<sup>[[1]](#references)</sup>

Više perifernih uređaja može da deli linije takta i podataka, obično uz poseban chip-select za svaki uređaj. Kontroler upravlja prenosima; periferni uređaji obično ne komuniciraju direktno međusobno preko SPI magistrale. Polaritet i vremenski parametri chip-select signala zavise od uređaja; izbor aktivan na niskom nivou je čest, ali nije univerzalan. SPI ne definiše otkrivanje uređaja, adresiranje, komande niti jedinstvenu maksimalnu dužinu prenosa, zato uvek proverite datasheet ciljnog uređaja.<sup>[[1]](#references)</sup>

MOSI/COPI prenosi podatke od kontrolera ka perifernom uređaju, a MISO/CIPO podatke od perifernog uređaja ka kontroleru. Podaci se mogu istovremeno pomerati u oba smera. Odnos između komande, adrese, dummy ciklusa i vraćenih podataka definiše periferni uređaj, a ne SPI, i zavisi od polariteta i faze takta (modovi 0–3). Nemojte pretpostaviti da izlaz počinje tačno jedan takt nakon završetka ulaza.<sup>[[1]](#references)</sup>

## Dumpovanje firmware-a iz EEPROM-ova

Dumpovanje firmware-a može biti korisno za njegovu analizu i pronalaženje ranjivosti. Odgovarajuća slika možda nije dostupna na internetu ili se može razlikovati u zavisnosti od modela, hardverske revizije ili verzije, pa njeno direktno izdvajanje sa fizičkog uređaja omogućava preciznu procenu konkretne mete.

Serijska konzola može biti korisna, ali njen filesystem može biti samo za čitanje, a na ciljnom uređaju možda nedostaju alati za analizu, uključujući uslužne programe potrebne za slanje/primanje testnog saobraćaja ili jednostavno izdvajanje binarnih datoteka. Offline slika čuva kompletan raspored flash memorije i omogućava izdvajanje filesystem-a i reverse engineering bez menjanja uređaja dok radi.

Tokom ovlašćene fizičke procene, provereni dump može da posluži i za kontrolisane testove izmena i ponovnog flešovanja. To uključuje menjanje datoteka ili ubacivanje testnog payload-a/backdoor-a radi demonstracije perzistencije na nivou firmware-a. Sačuvajte više podudarnih očitavanja i originalnu sliku pre bilo kakvog upisa: pogrešan napon, izbor čipa, raspored ili slika mogu da onesposobe uređaj.

### CH341A EEPROM programator i čitač

Ovaj jeftin USB alat može da dumpuje i ponovo flešuje kompatibilne serijske EEPROM i SPI flash uređaje. Često se koristi sa SPI NOR flash čipovima koji čuvaju firmware PC BIOS/UEFI sistema i praktičan je kada je vreme fizičkog pristupa ograničeno.

![drawing](../../images/board_image_ch341a.jpg)

Povežite flash memoriju sa CH341A, a zatim povežite programator sa računarom. Ako računar ne prepoznaje sam programator, pre nego što počnete da otklanjate probleme sa ciljnim čipom proverite USB kabl, dozvole OS-a i odgovarajući CH341A drajver. Proverite napon čipa, pin 1, ožičenje adaptera i izlaz programatora pomoću datasheet-ova ili multimetra — **nemojte** se oslanjati na pravilo kao što je postavljanje VCC-a nasuprot USB konektoru. Pogrešna orijentacija ili dovođenje 5 V na komponentu od 3,3/1,8 V može da je uništi. Očitavanja u kolu takođe mogu da ne uspeju jer ostatak ploče opterećuje ili napaja magistralu.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Za očitavanje čipa koristite softver kao što su `flashrom` ili G-Flash. G-Flash je minimalni GUI i može automatski da prepozna kompatibilne uređaje, što može biti praktično pri brzom prikupljanju podataka, ali sami proverite prepoznati model i napon. Navedite tačan programator i, po potrebi, tačan model čipa; obavite najmanje dva očitavanja i uporedite njihove hash vrednosti pre nego što dump smatrate pouzdanim.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Nakon dumpovanja firmware-a, analiza se može obaviti nad binarnim datotekama. Alati kao što su strings, hexdump, xxd, binwalk itd. mogu da se koriste za izdvajanje velikog broja informacija o firmware-u, kao i o celom filesystem-u.

Za početnu trijažu, Binwalk može da skenira poznate potpise i izdvoji podržani ugrađeni sadržaj:

```
binwalk -e <filename>
```

Izlazna datoteka može imati ekstenziju `.bin`, `.rom` ili neku drugu; ekstenzija ne određuje format.

> [!CAUTION]
> Imajte na umu da je izdvajanje firmware-a delikatan postupak i zahteva mnogo strpljenja. Nepravilno rukovanje može da ošteti firmware ili ga čak potpuno izbriše i učini uređaj neupotrebljivim. Pre pokušaja izdvajanja firmware-a preporučuje se da proučite konkretan uređaj.

### Bus Pirate + flashrom

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

U nekim datasheet-ovima ciljni pinovi su označeni kao `DI` i `DO`: kod uobičajene flash veze sa jednom linijom za prenos podataka, kontrolerov **MOSI/COPI povezuje se sa DI**, a kontrolerov **MISO/CIPO sa DO**. Proverite datasheet ciljnog uređaja jer se kod komponenti sa dual/quad I/O pinovi ponovo koriste u drugim režimima.

![CH341A EEPROM programator i čitač - Bus Pirate + flashrom: Imajte na umu da, iako PINOUT uređaja Pirate Bus navodi pinove za povezivanje MOSI i MISO sa SPI interfejsom, neki SPI uređaji mogu...](<../../images/image (360).png>)

U Windows-u ili Linux-u možete koristiti program [**`flashrom`**](https://www.flashrom.org/Flashrom) da biste napravili dump sadržaja flash memorije, na primer, ovako:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Novija dokumentacija za Bus Pirate prikazuje i opcione parametre `serialspeed` i `spispeed`. Počnite konzervativno ako duge žice ili opterećenje u kolu čine očitavanja nestabilnim.<sup>[[3]](#references)</sup>

### Očitavanja u kolu kada kontroler deli flash magistralu

SOIC klipsa može da dovede napajanje flash-a do ostatka PCB-a. Ako se MCU tada napaja i pristupa istom čipu, njegovi SPI prenosi mogu da se sudare sa prenosima spoljnog programatora. Zato rezultat `No EEPROM/flash device found` ne dokazuje da flash nedostaje ili nije podržan. Najpre proverite pinout, napon i kontakt, a zatim utvrdite da li je kontroler na ploči takođe aktivan.<sup>[[4]](#references)</sup>

Ako je dostupan testni pad za reset, pre aktiviranja multimetrom proverite njegov polaritet i napon. Zadržavanje MCU-a u resetu može da ostavi flash dostupan i istovremeno zaustavi konkurentski SPI host. Alternative su odlemljivanje čipa ili pasivno snimanje MCU-ovih očitavanja; ova druga opcija ne omogućava pristup nepročitanim oblastima niti upis u čip, a dodatno ožičenje sondi može da ometa brzu magistralu. Intervencija u oscilator ili režim pokretanja zavisi od ciljnog uređaja i nije zamena za proveru šeme i signala.<sup>[[4]](#references)</sup>

Dok je MCU neaktivan, Raspberry Pi sa omogućenim interfejsom `spidev` može da čita pomoću flashrom programatora `linux_spi`. Promenite `-p` za drugi adapter. Ponovite očitavanje i uporedite hash vrednosti pre nego što mu poverujete; SFDP autodetekcija i uspešno očitavanje **ne** dokazuju da operacije brisanja, upisa ili zaštite od upisa rade na delu koje inače nije podržano.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Rekonstrukcija čitanja SPI flash memorije pomoću logičkog analizatora

Kada aktivno čitanje nije moguće, snimite chip select, clock, podatke od kontrolera ka flash memoriji i podatke od flash memorije ka kontroleru tokom pokretanja ili odabrane radnje u UI-ju. U PulseView-u prvo identifikujte aktivni interval chip-select signala i clock, a zatim konfigurišite kanale podataka SPI dekodera prema rasporedu pinova flash memorije i proverite da li su komanda/adresa uverljive, kao i bajtovi koji slede kao odgovor. Izvezite bajtove **MISO/izlaza flash memorije** pomoću prikaza Binary Decoder Output i sačuvajte dekodirane adrese čitanja, kako bi se svaki odgovor smestio na odgovarajući pomeraj u flash memoriji. Snimanje samo čitanja pokrenutih kroz meni daje samo tražene oblasti, a ne kompletnu sliku flash memorije; nemojte spajati odgovore kao da su uzastopni bez provere adresa.<sup>[[4]](#references)</sup>

Ako dump izgleda kao da sadrži grafiku, a ne izvršni kod, nastavite sa [trijažom sirovih resursa za prikaz](../firmware-analysis/#raw-display-assets-in-external-flash).<sup>[[4]](#references)</sup>

#### Scapy i mešoviti SPI/QSPI snimci

Kod neoznačenih sondi, razlikujte MOSI od MISO tako što ćete utvrditi na kojoj liniji se prenosi opcode pre podataka odgovora, a zatim proverite komandu prema datasheet-u flash memorije. Impulsi kraći od perioda clock-a mogu biti šum sonde, a dodatno ožičenje klipsi može učiniti snimke pri velikim brzinama nepouzdanim.<sup>[[5]](#references)</sup>

Saleae-ov SPI CSV izvoz koristi `enable` i `disable` za omeđivanje intervala chip-select signala, dok se MOSI/MISO bajtovi nalaze u redovima `result`. Grupišite bajtove po intervalu pre dekodiranja; spajanje svih MISO podataka gubi adrese transakcija.<sup>[[5]](#references)</sup> Scapy `Packet` može da modeluje MOSI zaglavlje pomoću opcode-a `ByteEnumField` i uslovnih polja za adresu i dummy podatke. Kod 24-bitnih NOR čitanja, `0x03` sadrži opcode i tri bajta adrese, dok `0x0B` dodaje jedan dummy bajt. `len(req.self_build())` daje dužinu modelovanog zaglavlja: kod čitanja sa jednom linijom, `miso[header_length:]` predstavlja odgovor flash memorije, dok su MOSI podaci nakon zaglavlja kontrolerski podaci čija je vrednost nebitna.<sup>[[5]](#references)</sup> Smestite odgovore na njihove dekodirane adrese u sliku popunjenu vrednostima `0xFF` i zasebno pratite pokrivene pomeraje. Bajt koji nije posmatran nije dokaz da je flash memorija na tom mestu sadržala `0xFF`.<sup>[[5]](#references)[[6]](#references)</sup>

Čitanje `0x6B` (1-1-4) u stilu W25Q koristi jednu liniju za opcode i adresu, ali IO0–IO3 za podatke odgovora. Aktivnost na pinovima `/WP` i `/HOLD`, koji su ranije imali te namene, jači je dokaz prelaska u quad režim nego samo viši clock; analizator sa jednom linijom može pogrešno da dekodira quad odgovor.<sup>[[5]](#references)</sup> Izvezite tu fazu pomoću QSPI analizatora podešenog prema širinama linija komande i dummy ciklusima, a zatim spojite čitanja sa jednom i četiri linije prema adresi u flash memoriji.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` automatski prepoznaje oba formata izvoza, odbacuje čitanja dekodirana sa pogrešnom širinom linije i prikazuje pokrivenost čitanja.<sup>[[6]](#references)</sup> Iz njegovog repozitorijuma, nakon instaliranja zavisnosti, spojite snimke pomoću:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Rezultat ostaje oskudno opažanje, a ne kompletan dump čipa.<sup>[[5]](#references)[[6]](#references)</sup> Da biste zasebno pregledali upise, povežite `0x06` omogućavanje upisa, `0x05` provere statusa, opcode-ove za brisanje i komande `0x02` za programiranje stranice. Podaci za programiranje stranice slede adresu na MOSI-ju i nisu obuhvaćeni rekonstrukcijom koja samo čita.<sup>[[5]](#references)</sup> Analizirajte dobijenu sliku pomoću [analize firmvera](../firmware-analysis/) i pritom sačuvajte informacije o pokrivenosti čitanjem.

## References

- [1] [Analog Devices — Uvod u SPI interfejs](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom priručnik — CH341A SPI programator i opcije za čitanje/upisivanje](https://flashrom.org/classic_cli_manpage.html)
- [3] [Dokumentacija za Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Obnavljanje znanja o hardverskom hakovanju, 2. deo](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Proširenje Scapy-ja za obrnuti inženjering hardvera](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — Snimanje i rekonstrukcija SPI/QSPI tragova](https://github.com/wrongbaud/spidump)
- [7] [QSPI analizator za Saleae Logic/KingstVIS](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
