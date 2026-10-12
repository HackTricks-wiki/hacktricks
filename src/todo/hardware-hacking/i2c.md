# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Verifieer die teikenspanning, penuitleg, optrekreëling en gemeenskaplike aarde voordat jy ’n Bus Pirate koppel. Moenie die Bus Pirate se kragtoevoer op ’n lewendige bus wat deur die teiken aangedryf word aktiveer net om dit af te luister nie; twee kragtoevoere kan met mekaar bots en hardeware beskadig. Die transkripsie hieronder is ’n voorbeeld spesifiek vir Bus Pirate v3/gemeenskapsfermware, nie ’n universele bedradingsresep nie.<sup>[[1]](#references)[[2]](#references)</sup>

Om te toets of ’n Bus Pirate werk, koppel +5V aan VPU en 3.3V aan ADC, kry toegang tot die Bus Pirate (byvoorbeeld met Tera Term) en gebruik die opdrag `~`:

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

Soos jy in die vorige opdragreël kan sien, het dit aangedui dat 0 foute gevind is. Dit is baie nuttig om te weet dat dit werk nadat jy dit gekoop het of firmware geflash het.

Om met die bus pirate te koppel, kan jy die dokumentasie volg:

![Gebruik opdrag - Druk spasie: Om met die bus pirate te koppel, kan jy die dokumentasie volg](<../../images/image (484).png>)

In hierdie geval is die teiken ’n 24C256-familie-I²C-EEPROM. Bevestig die presiese agtervoegsel en datablad, want die ondersteunde toevoerspanning wissel na gelang van die onderdeel.<sup>[[3]](#references)</sup>

![Gebruik opdrag - Druk spasie: In hierdie geval gaan ek aan ’n EPROM koppel: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Om met bus pirate te kommunikeer, het ek Tera Term gebruik, gekoppel aan die COM-poort van die pirate bus met Setup --> Serial Port --> Speed op 115200.\
In die volgende kommunikasie kan jy sien hoe om die bus pirate voor te berei vir I2C-kommunikasie en hoe om data na die geheue te skryf en daaruit te lees (Opmerkings begin met "#"; moenie daardie deel in die kommunikasie verwag nie):

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

In hierdie scenario gaan ons die I2C-kommunikasie tussen die arduino en die vorige EPROM afluister. Jy hoef net albei toestelle te kommunikeer en dan die bus pirate aan die SCL-, SDA- en GND-penne te koppel:

![Read 20B from address 0x69 configured before - Sniffer: In this scenario we are going to sniff the I2C communication between the arduino and the previous EPROM, you just need to...](<../../images/image (166).png>)

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

## Swartboks-I2C-protokolrekonstruksie

### Identifiseer die bus vanaf aktiewe penne

Wanneer die randtoestel geen penout of datablad het nie, begin passief met ’n hoë-impedansie-logika-ontleder terwyl die oorspronklike gasheer werk. Nadat ’n gemeenskaplike aarde en veilige logikavlak vasgestel is, klassifiseer konstante penne as waarskynlike voedingspennetjies, aardings of penne met optrekweerstande. Vergelyk dan die aktiewe lyne met algemene busse: UART het asinkrone TX/RX-lyne wat onafhanklik in verskillende rigtings werk; konvensionele SPI het gewoonlik ’n klok, chip-select en aparte datarigtings; I2C het ’n gereelde klok plus een tweerigting-datalyn. ’n I2C-dekodering behoort dan 7-bis-teikenadresse, lees-/skryfrigting, ACK/NACK’s en herhalende loonvragte te wys.<sup>[[2]](#references)[[4]](#references)</sup>

Leg verskeie geldige uitruilings vas en bewaar sowel die gedekodeerde grepe as die rou tydsberekening. Herhaalde rame is nuttige bekende-antwoord-toetse vir latere serialiseerders, terwyl verskille tussen versoeke waarskynlike opcode-, indeks-, offset-, lengte-, volgorde- of kontrolesomvelde kan onthul.<sup>[[4]](#references)</sup>

### Herwin die raamformaat uit gasheersagteware

As die randtoestel se firmware ontoeganklik is, haal die **gasheer** se firmware uit en vind die komponent wat die I2C-toestel oopmaak. Soek na stringe en simbole vir die randtoestel se naam, `/dev/i2c-`, opdragbouers, antwoordontleders, terugstel-/initialiseringsroetines en kontrolesomfunksies. Teken vir elke bouer die presiese veldverskuiwings, konstantes, aanvaarde argumentgroottes, loonvraglengte, kontrolesomdekking, kontrolesomgreepvolgorde en teruggekeerde raamlengte aan, eerder as om die formaat uit funksiename af te lei.<sup>[[4]](#references)</sup>

’n Kontrolesomfunksie met die naam `crc16_ccitt` is nie genoeg om ’n preset te kies nie. Bepaal die skuifrigting, tabelindeksgreep, polinoom wat deur die tabel voorgestel word, beginregister, invoer-/uitvoerrefleksie, finale XOR/inversie en die serialiseerder se bytevolgorde op die draad. Byvoorbeeld, ’n laebyte-tabel wat regs skuif en op die omgekeerde polinoom `0x8408` berus, met `0xFFFF` as beginwaarde en komplementering aan die einde, dui op **CRC-16/X-25 (IBM-SDLC)**. ’n Korrekte kontrolesom is dikwels nodig om te verseker dat toetsgevalle verby integriteitsvalidering kom en die opdragontleder bereik.<sup>[[4]](#references)</sup>

Nadat die formaat gerekonstrueer is, soek na kenmerkende simboolname en konstantes in openbare kode. In die MJA1-geval het ’n SDK-omhulsel wat onafhanklik opgespoor is, opdrag-ID’s, argumentvalidering, antwoorddefinisies en die ooreenstemmende CRC-implementering bevestig. Gebruik sulke bronkode as bevestiging, nie as plaasvervanger vir kontrolering van die presiese teikenbinêre lêer en bytevolgorde op die draad nie.<sup>[[4]](#references)[[5]](#references)</sup>

### Stuur rame vanaf ’n Linux-gasheer met root-toegang

’n Gekompromitteerde ingebedde Linux-gasheer kan die randtoestel toets sonder om nog ’n busbeheerder by te voeg. Maak die betrokke adapter oop, kies die 7-bis-adres met `I2C_SLAVE` en stuur ’n raam wat deur ’n toegewyde serialiseerder vervaardig is; behou ’n rou-raammodus vir mutasie en fuzzing.<sup>[[4]](#references)</sup>

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

Kruis-kompileer teen ’n toolchain wat met die teiken-SVE en libc versoenbaar is, en vergelyk ontleder-spore van die toetsh kliënt met legitieme verkeer. Transaksiegrense, skryf-/leesvolgorde, vertragings en randtoestand kan saak maak, selfs wanneer die sigbare grepe ooreenstem.<sup>[[4]](#references)</sup>

### Responsgeleide opcode-enumerasie

Sodra die kortste geldige raam en kontrolesom bekend is, enumereer die volledige opcode-wydte en gebruik die protokol se eksplisiete **unsupported-command**-respons as die negatiewe basislyn. ’n Ander resultaat—soos ongeldige argumente, ongeldige toestand of ’n ongedokumenteerde status—dui daarop dat dekodering ’n geïmplementeerde of gedeeltelik geïmplementeerde hanteerder bereik het. Dit bewys **nie** dat die teiken uitbuitbaar is nie; prioritiseer die kandidaat vir gestruktureerde fuzzing van lengte, argumente, toestand en opdragreekse.<sup>[[4]](#references)</sup>

As ’n toets die randtoestel laat vashaak, outomatiseer een geïsoleerde geval per selflaai vanaf ’n eksterne beheerder: koppel via SSH, voer die geval uit, stoor die rou versoek/antwoord en tydsberekening, herlaai of skakel die krag af en weer aan, wag dat gesondheidskontroles herstel, en gaan dan voort. Deur die komponent later na ’n mikrobeheerderbeheerde toetstuig te verskuif, kan deterministiese terugstellings, direkte kragbeheer en vinniger fuzzing moontlik gemaak word.<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate-dokumentasie — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-busspesifikasie en gebruikershandleiding](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C-seriële EEPROM-datablad](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Swartboks-ondersoek: ’n sekuriteitsontleding van Xiaomi se MJA1 Secure Chip](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1-kriptografie-omhulsel](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
