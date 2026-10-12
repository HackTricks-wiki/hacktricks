# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Pre povezivanja Bus Pirate-a proverite napon ciljnog uređaja, raspored pinova, konfiguraciju pull-up otpornika i zajedničku masu. Nemojte uključivati napajanje Bus Pirate-a na magistrali koja je već pod naponom ciljnog uređaja samo da biste je prisluškivali; dva napajanja mogu međusobno da se sukobe i oštete hardver. Transkript u nastavku je primer specifičan za uređaj, za Bus Pirate v3/community firmware, a ne univerzalno uputstvo za povezivanje.<sup>[[1]](#references)[[2]](#references)</sup>

Da biste proverili da li Bus Pirate radi, povežite +5V sa VPU i 3.3V sa ADC, pristupite Bus Pirate-u (na primer, pomoću Tera Term-a) i upotrebite komandu `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Kao što možete da vidite u prethodnoj komandnoj liniji, pronađeno je 0 grešaka. Ovo je veoma korisno da biste znali da uređaj radi nakon kupovine ili flešovanja firmware-a.

Da biste se povezali sa Bus Pirate-om, možete da pratite dokumentaciju:

![Koristite komandu - Pritisnite razmak: Da biste se povezali sa Bus Pirate-om, možete da pratite dokumentaciju](<../../images/image (484).png>)

U ovom slučaju cilj je I²C EEPROM iz porodice 24C256. Proverite tačan sufiks i datasheet, jer podržani napon napajanja zavisi od konkretnog modela.<sup>[[3]](#references)</sup>

![Koristite komandu - Pritisnite razmak: U ovom slučaju ću se povezati sa EPROM-om: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Za komunikaciju sa Bus Pirate-om koristio sam Tera Term, povezan sa COM portom Bus Pirate-a, uz podešavanje Setup --> Serial Port --> Speed na 115200.\
U sledećoj komunikaciji možete videti kako da pripremite Bus Pirate za I2C komunikaciju i kako da upisujete i čitate podatke iz memorije (komentari počinju znakom „#“; nemojte očekivati taj deo u komunikaciji):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

U ovom scenariju ćemo prisluškivati I2C komunikaciju između arduina i prethodnog EPROM-a. Potrebno je samo da komunicirate sa oba uređaja, a zatim povežete bus pirate sa pinovima SCL, SDA i GND:

![Čitanje 20B sa adrese 0x69, prethodno konfigurisano - Sniffer: U ovom scenariju ćemo prisluškivati I2C komunikaciju između arduina i prethodnog EPROM-a. Potrebno je samo da...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Rekonstrukcija I2C protokola crne kutije

### Identifikujte magistralu pomoću aktivnih pinova

Kada periferni uređaj nema raspored pinova ni datasheet, počnite pasivno, koristeći logički analizator velike impedanse dok originalni host radi. Nakon što uspostavite zajedničku masu i bezbedan logički nivo, razvrstajte konstantne pinove kao moguće naponske vodove, mase ili signale sa pull-up otpornicima, a zatim uporedite aktivne linije sa uobičajenim magistralama: UART ima asinhrone, nezavisno usmerene TX/RX linije; konvencionalni SPI obično ima clock, chip select i odvojene smerove prenosa podataka; I2C ima pravilan clock i jednu dvosmernu liniju za prenos podataka. I2C dekodiranje bi zatim trebalo da otkrije 7-bitne adrese ciljnih uređaja, smer čitanja/upisa, ACK/NACK i ponavljajuće payload-ove.<sup>[[2]](#references)[[4]](#references)</sup>

Zabeležite nekoliko legitimnih razmena i sačuvajte i dekodirane bajtove i sirovo vreme. Ponovljeni frejmovi su korisni testovi sa poznatim odgovorima za kasnije serijalizatore, dok razlike između zahteva mogu da otkriju verovatna polja za opcode, indeks, offset, dužinu, sekvencu ili kontrolnu sumu.<sup>[[4]](#references)</sup>

### Rekonstruišite uokviravanje iz firmware-a hosta

Ako firmware perifernog uređaja nije dostupan, izvucite firmware **hosta** i pronađite komponentu koja otvara I2C uređaj. Pretražite stringove i simbole za naziv perifernog uređaja, `/dev/i2c-`, funkcije za sastavljanje komandi, parsere odgovora, rutine za resetovanje/inicijalizaciju i funkcije za kontrolnu sumu. Za svaki sastavljač zabeležite tačne offsete polja, konstante, prihvaćene veličine argumenata, dužinu payload-a, opseg bajtova obuhvaćen kontrolnom sumom, redosled bajtova kontrolne sume i dužinu vraćenog frejma, umesto da format zaključujete na osnovu naziva funkcija.<sup>[[4]](#references)</sup>

Naziv funkcije kontrolne sume `crc16_ccitt` nije dovoljan za izbor preseta. Utvrdite smer pomeranja, bajt za indeksiranje tabele, polinom predstavljen tabelom, početni registar, refleksiju ulaza/izlaza, završni XOR/inverziju i redosled bajtova serijalizatora na žici. Na primer, tabela niskih bajtova koja se pomera udesno, zasnovana na obrnutom polinomu `0x8408`, inicijalizovana sa `0xFFFF` i komplementirana na kraju, identifikuje **CRC-16/X-25 (IBM-SDLC)**. Ispravna kontrolna suma je često neophodna da bi testni slučajevi prošli proveru integriteta i stigli do parsera komandi.<sup>[[4]](#references)</sup>

Nakon rekonstrukcije formata, potražite prepoznatljive nazive simbola i konstante u javno dostupnom kodu. U slučaju MJA1, nezavisno pronađen SDK omotač potvrdio je ID-jeve komandi, proveru argumenata, definicije odgovora i preslikanu implementaciju CRC-a; takav izvor koristite za validaciju, a ne kao zamenu za proveru tačnog ciljnog binarnog fajla i redosleda bajtova na žici.<sup>[[4]](#references)[[5]](#references)</sup>

### Šaljite frejmove sa rooted Linux hosta

Rooted embedded Linux host može da komunicira sa perifernim uređajem bez dodavanja drugog kontrolera magistrale. Otvorite odgovarajući adapter, izaberite 7-bitnu adresu pomoću `I2C_SLAVE` i pošaljite frejm koji je napravio namenski serijalizator; zadržite režim za sirove frejmove radi mutacije i fuzzing-a.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Prevedite unakrsno koristeći toolchain kompatibilan sa ciljanim CPU-om i libc-om i uporedite tragove analizatora iz testnog klijenta sa legitimnim saobraćajem. Granice transakcija, redosled upisa/čitanja, kašnjenja i stanje periferije mogu biti važni čak i kada su vidljivi bajtovi isti.<sup>[[4]](#references)</sup>

### Enumeracija opcode-ova vođena odgovorima

Kada utvrdite najkraći ispravan okvir i checksum, ispitajte ceo opseg opcode-ova i kao negativnu osnovu koristite eksplicitni odgovor protokola **unsupported-command**. Drugačiji rezultat — kao što su neispravni argumenti, neispravno stanje ili nedokumentovan status — ukazuje na to da je dekodiranje stiglo do implementiranog ili delimično implementiranog rukovaoca. To **ne** potvrđuje da je moguće iskoristiti ranjivost; dajte prednost tom kandidatu za strukturisano fuzzing dužine, argumenata, stanja i sekvenci komandi.<sup>[[4]](#references)</sup>

Ako test zaglavi periferni uređaj, automatizujte po jedan izolovan slučaj pri svakom pokretanju, koristeći eksterni kontroler: povežite se preko SSH-a, izvršite slučaj, sačuvajte sirov zahtev/odgovor i vremenske oznake, ponovo pokrenite uređaj ili ga isključite i uključite, sačekajte da provere ispravnosti potvrde oporavak, pa nastavite. Kasniji prelazak na postolje kojim upravlja mikrokontroler može da omogući deterministička resetovanja, direktnu kontrolu napajanja i brže fuzzing testiranje.<sup>[[4]](#references)</sup>

## References

- [1] [Dokumentacija za Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Specifikacija i korisnički priručnik za I²C magistralu](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Tehnički list za AT24C256C I²C serijski EEPROM](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Ispitivanje crne kutije: bezbednosna analiza Xiaomi MJA1 bezbednosnog čipa](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK — omotač za kriptografiju MJA1](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
