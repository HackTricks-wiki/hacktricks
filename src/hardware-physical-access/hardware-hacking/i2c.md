# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Verifieer die teikenspanning, pinout, pull-up-opstelling en gemeenskaplike ground voordat jy ’n Bus Pirate koppel. Moenie die Bus Pirate se kragtoevoer aanskakel op ’n bus wat reeds deur die teiken van krag voorsien word bloot om dit te sniff nie; twee kragtoevoere kan teen mekaar werk en hardeware beskadig. Die transkripsie hieronder is ’n voorbeeld vir ’n spesifieke toestel met Bus Pirate v3/community-firmware, nie ’n universele bedradingsresep nie.<sup>[[1]](#references)[[2]](#references)</sup>

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

Soos jy in die vorige opdragreël kan sien, het dit aangedui dat dit 0 foute gevind het. Dit is baie nuttig om te weet dat dit werk nadat jy dit gekoop het of firmware geflits het.

Om aan die Bus Pirate te koppel, kan jy die dokumentasie volg:

![Gebruik opdrag - Druk spasie: Om aan die Bus Pirate te koppel, kan jy die dokumentasie volg](<../../images/image (484).png>)

In hierdie geval is die teiken ’n 24C256-familie-I²C-EEPROM. Bevestig die presiese agtervoegsel en datablad, aangesien die ondersteunde toevoerspanning per onderdeel verskil.<sup>[[3]](#references)</sup>

![Gebruik opdrag - Druk spasie: In hierdie geval gaan ek aan ’n EPROM koppel: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Om met Bus Pirate te kommunikeer, het ek Tera Term gebruik, gekoppel aan die Bus Pirate se COM-poort met Setup --> Serial Port --> Speed of 115200.\
In die volgende kommunikasie kan jy sien hoe om die Bus Pirate voor te berei om met I2C te kommunikeer en hoe om data na die geheue te skryf en daarvan te lees (kommentaar verskyn met "#"; moenie daardie deel in die kommunikasie verwag nie):

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

In hierdie scenario gaan ons die I2C-kommunikasie tussen die arduino en die vorige EPROM afluister. Jy hoef net met albei toestelle te kommunikeer en dan die bus pirate aan die SCL-, SDA- en GND-penne te koppel:

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

## Rekonstruksie van I2C-protokol as swartboks

### Identifiseer die bus vanaf lewendige penne

Wanneer die randapparaat geen penuitleg of datablad het nie, begin passief met ’n hoë-impedansie-logika-ontleder terwyl die oorspronklike gasheer werk. Nadat ’n gemeenskaplike grond en veilige logikavlak vasgestel is, klassifiseer konstante penne as waarskynlike kragrelings, gronde of seine met optrekweerstande. Vergelyk dan die aktiewe lyne met algemene busse: UART het asynchrone TX/RX-lyne met onafhanklike rigtings; konvensionele SPI het gewoonlik ’n klok, chip-select en aparte datarigtings; I2C het ’n gereelde klok plus een tweerigting-datalyn. ’n I2C-dekodering behoort dan 7-bis-teikenadresse, lees/skryf-rigting, ACK/NACK’s en herhalende payloads te wys.<sup>[[2]](#references)[[4]](#references)</sup>

Neem verskeie geldige uitruilings op en bewaar beide die gedekodeerde grepe en die rou tydsberekening. Herhaalde rame is nuttige bekende-antwoorde-toetse vir latere serialiseerders, terwyl verskille tussen versoeke waarskynlike opcode-, indeks-, offset-, lengte-, volgorde- of kontrolesomvelde kan blootlê.<sup>[[4]](#references)</sup>

### Herstel die raamformaat uit die gasheer-firmware

As die randapparaat se firmware ontoeganklik is, onttrek die **gasheer**-firmware en vind die komponent wat die I2C-toestel oopmaak. Soek na stringe en simbole vir die randapparaat se naam, `/dev/i2c-`, opdragbouers, antwoordontleders, terugstel-/inisialiseringsroetines en kontrolesomfunksies. Teken vir elke bouer die presiese veldafsets, konstantes, aanvaarde argumentgroottes, payload-lengte, kontrolesomdekking, kontrolesomgrepe-volgorde en teruggestuurde raamlengte aan, eerder as om die formaat uit funksiename af te lei.<sup>[[4]](#references)</sup>

’n Kontrolesomfunksie met die naam `crc16_ccitt` is nie genoeg om ’n preset te kies nie. Bepaal die skuifrigting, tabelindeks-greep, polinoom wat deur die tabel voorgestel word, aanvanklike register, invoer-/uitvoer-refleksie, finale XOR/inversie en die serialiseerder se byte-volgorde op die draad. Byvoorbeeld, ’n tabel vir die lae greep met regsskuif, gebaseer op die omgekeerde polinoom `0x8408`, geïnitialiseer met `0xFFFF` en aan die einde gekomplementeer, dui op **CRC-16/X-25 (IBM-SDLC)**. ’n Korrekte kontrolesom is dikwels nodig om te verseker dat toetsgevalle verby integriteitsvalidering kom en die opdragontleder bereik.<sup>[[4]](#references)</sup>

Nadat die formaat gerekonstrueer is, soek na kenmerkende simboolname en konstantes in publieke kode. In die MJA1-geval het ’n SDK-omhulsel wat onafhanklik gevind is, opdrag-ID’s, argumentvalidering, antwoorddefinisies en die ooreenstemmende CRC-implementering bevestig; gebruik sulke bronkode as validering, nie as plaasvervanger vir die nagaan van die presiese teikenbinêre lêer en die byte-volgorde op die draad nie.<sup>[[4]](#references)[[5]](#references)</sup>

### Stuur rame vanaf ’n rooted Linux-gasheer

’n Gekompromitteerde ingebedde Linux-gasheer kan die randapparaat toets sonder om nog ’n busbeheerder by te voeg. Maak die toepaslike adapter oop, kies die 7-bis-adres met `I2C_SLAVE` en stuur ’n raam wat deur ’n toegewyde serialiseerder saamgestel is; behou ’n rou-raam-modus vir mutasie en fuzzing.<sup>[[4]](#references)</sup>

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

Kruiskompileer teen 'n toolchain wat met die teiken-SVE en libc versoenbaar is, en vergelyk die ontleder se traces van die toetskliënt met legitieme verkeer. Transaksiegrense, skryf-/leesvolgorde, vertragings en randtoesteltoestand kan saak maak, selfs wanneer die sigbare grepe ooreenstem.<sup>[[4]](#references)</sup>

### Opcode-enumerasie gelei deur response

Sodra die kortste geldige raam en kontrolesom bekend is, enumereer die volledige opcode-breedte en gebruik die protokol se eksplisiete **unsupported-command**-response as die negatiewe basislyn. 'n Ander resultaat—soos ongeldige argumente, ongeldige toestand of 'n ongedokumenteerde status—dui daarop dat dekodering 'n geïmplementeerde of gedeeltelik geïmplementeerde handler bereik het. Dit bewys **nie** dat dit uitbuitbaar is nie; prioritiseer die kandidaat vir gestruktureerde fuzzing van lengte, argumente, toestand en opdragreekse.<sup>[[4]](#references)</sup>

As 'n toets die randtoestel laat hang, outomatiseer een geïsoleerde geval per selflaai vanaf 'n eksterne beheerder: koppel oor SSH, voer die geval uit, stoor die rou versoek/response en tydsberekening, herlaai of skakel die krag af en aan, wag totdat gesondheidstoetse weer slaag, en gaan voort. Om die komponent na 'n mikrobeheerderbeheerde toetsopstelling te skuif, kan later deterministiese terugstellings, direkte kragbeheer en vinniger fuzzing moontlik maak.<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate-dokumentasie — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus-spesifikasie en gebruikershandleiding](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C-seriële EEPROM-datablad](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: 'n sekuriteitsontleding van Xiaomi se MJA1 Secure Chip](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1-kriptografie-omhulsel](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
