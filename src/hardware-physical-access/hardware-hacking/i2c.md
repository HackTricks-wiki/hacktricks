# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Hakikisha voltage ya kifaa lengwa, mpangilio wa pini, mpangilio wa pull-up na ground ya pamoja kabla ya kuunganisha Bus Pirate. Usiwashe power supplies za Bus Pirate kwenye bus inayowashwa na kifaa lengwa ili tu kuisniff; power supplies mbili zinaweza kushindana na kuharibu hardware. Nakala ya mawasiliano iliyo hapa chini ni mfano mahususi wa kifaa wa Bus Pirate v3/community-firmware, si mwongozo wa jumla wa kuunganisha nyaya.<sup>[[1]](#references)[[2]](#references)</sup>

Ili kupima kama Bus Pirate inafanya kazi, unganisha +5V na VPU na 3.3V na ADC, kisha ufikie Bus Pirate (kwa mfano, ukitumia Tera Term) na utumie amri `~`:

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

Kama unavyoona kwenye mstari wa amri uliotangulia, ilisema imepata makosa 0. Hii ni muhimu sana kujua kuwa inafanya kazi baada ya kuinunua au baada ya ku-flash firmware.

Ili kuunganishwa na Bus Pirate, unaweza kufuata nyaraka:

![Tumia amri - Bonyeza space: Ili kuunganishwa na Bus Pirate, unaweza kufuata nyaraka](<../../images/image (484).png>)

Katika hali hii, kifaa lengwa ni EEPROM ya I²C ya familia ya 24C256. Thibitisha kiambishi tamati halisi/modeli na datasheet, kwa sababu volti ya usambazaji inayotumika hutofautiana kulingana na sehemu.<sup>[[3]](#references)</sup>

![Tumia amri - Bonyeza space: Katika hali hii nitaunganisha kwenye EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Ili kuwasiliana na Bus Pirate nilitumia Tera Term iliyounganishwa kwenye porti ya COM ya Bus Pirate, nikiwa nimeweka Setup --> Serial Port --> Speed kuwa 115200.\
Katika mawasiliano yafuatayo unaweza kuona jinsi ya kuandaa Bus Pirate ili iwasiliane kupitia I2C, na jinsi ya kuandika na kusoma kutoka kwenye memory (Maoni hutumia "#"; usitarajie sehemu hiyo kwenye mawasiliano):

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

Katika hali hii, tutasikiliza mawasiliano ya I2C kati ya arduino na EPROM iliyotajwa awali. Unahitaji tu kuwasiliana na vifaa vyote viwili kisha uunganishe bus pirate kwenye pini za SCL, SDA na GND:

![Soma 20B kutoka anwani 0x69 iliyosanidiwa awali - Sniffer: Katika hali hii, tutasikiliza mawasiliano ya I2C kati ya arduino na EPROM iliyotajwa awali. Unahitaji tu...](<../../images/image (166).png>)

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

## Uundaji upya wa itifaki ya I2C kwa uchunguzi wa black-box

### Tambua basi kwa kutumia pini zilizo hai

Wakati peripheral haina mpangilio wa pini wala datasheet, anza kwa ufuatiliaji wa kimya ukitumia logic analyzer yenye impedance ya juu wakati host ya awali inafanya kazi. Baada ya kuweka ground ya pamoja na kiwango salama cha logic, ainisha pini zisizobadilika kama huenda ni reli za umeme, ground, au mawimbi yenye pull-up; kisha linganisha laini zinazoendelea na mabasi ya kawaida: UART ina TX/RX zisizolingana na zinazoelekezwa kivyake; SPI ya kawaida huonyesha clock, chip select, na njia tofauti za data; I2C ina clock ya kawaida pamoja na laini moja ya data inayoweza kuelekezwa pande zote mbili. Kisha decode ya I2C inapaswa kuonyesha anwani lengwa za biti 7, mwelekeo wa kusoma/kuandika, ACK/NACK, na payload zinazojirudia.<sup>[[2]](#references)[[4]](#references)</sup>

Nasa mabadilishano kadhaa halali na uhifadhi baiti zilizodecode pamoja na muda ghafi. Fremu zinazojirudia ni majaribio muhimu ya majibu yanayojulikana kwa serializer utakazotumia baadaye, huku mabadiliko kati ya maombi yakifichua sehemu zinazowezekana kuwa opcode, index, offset, length, sequence, au checksum.<sup>[[4]](#references)</sup>

### Rejesha muundo wa fremu kutoka kwa firmware ya host

Ikiwa firmware ya peripheral haipatikani, toa firmware ya **host** na utafute kipengele kinachofungua kifaa cha I2C. Tafuta strings na symbols za jina la peripheral, `/dev/i2c-`, vitengenezaji vya amri, vichanganuzi vya majibu, taratibu za reset/initialization, na functions za checksum. Kwa kila kitengenezaji, rekodi offset halisi za sehemu, thamani zisizobadilika, ukubwa wa argument unaokubaliwa, urefu wa payload, sehemu inayojumuishwa kwenye checksum, mpangilio wa baiti za checksum, na urefu wa fremu inayorejeshwa, badala ya kukisia muundo kutokana na majina ya function.<sup>[[4]](#references)</sup>

Jina la function la checksum kama `crc16_ccitt` halitoshi kuchagua preset. Bainisha mwelekeo wa shift, baiti ya table index, polynomial inayowakilishwa na jedwali, register ya mwanzo, input/output reflection, XOR/inversion ya mwisho, na endianness ya serializer kwenye waya. Kwa mfano, jedwali la baiti ya chini linalotumia shift kwenda kulia, lililotokana na polynomial iliyogeuzwa `0x8408`, lililoanzishwa kwa `0xFFFF` na kukamilishwa mwishoni, hutambulisha **CRC-16/X-25 (IBM-SDLC)**. Checksum sahihi mara nyingi huhitajika ili majaribio yapite ukaguzi wa uadilifu na kufika kwenye command parser.<sup>[[4]](#references)</sup>

Baada ya kuunda upya muundo, tafuta majina bainifu ya symbol na thamani zisizobadilika kwenye code ya umma. Katika kisa cha MJA1, SDK wrapper iliyopatikana kwa kujitegemea ilithibitisha command IDs, uthibitishaji wa argument, ufafanuzi wa majibu, na utekelezaji wa CRC uliolinganishwa; tumia source hiyo kama uthibitisho, si kama mbadala wa kukagua binary lengwa halisi na mpangilio wa baiti zinazotumwa kwenye waya.<sup>[[4]](#references)[[5]](#references)</sup>

### Tuma fremu kutoka kwa host ya Linux yenye root

Host ya Linux iliyopachikwa iliyoathiriwa inaweza kuendesha majaribio kwenye peripheral bila kuongeza kidhibiti kingine cha basi. Fungua adapter husika, chagua anwani ya biti 7 kwa kutumia `I2C_SLAVE`, kisha tuma fremu iliyotengenezwa na serializer maalum; hifadhi mode ya fremu ghafi kwa ajili ya mabadiliko na fuzzing.<sup>[[4]](#references)</sup>

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

Cross-compile kwa kutumia toolchain inayoendana na CPU na libc lengwa, kisha linganisha analyzer traces kutoka kwa test client na traffic halali. Mipaka ya transaction, mpangilio wa write/read, ucheleweshaji na hali ya peripheral vinaweza kuwa muhimu hata wakati bytes zinazoonekana zinafanana.<sup>[[4]](#references)</sup>

### Uhesabuji wa opcode kwa mwongozo wa majibu

Baada ya kujua frame halali fupi zaidi na checksum, hesabu upana wote wa opcode na utumie jibu bayana la protocol la **unsupported-command** kama msingi hasi wa kulinganisha. Matokeo tofauti—kama vile hoja zisizo halali, hali isiyo halali au status isiyoandikwa kwenye nyaraka—yanapendekeza kuwa decoding imefikia handler iliyotekelezwa kikamilifu au kwa sehemu. Hii **haithibitishi** kuwa kuna uwezekano wa exploit; ipe kipaumbele hiyo candidate kwa fuzzing iliyopangwa ya urefu, hoja, hali na mfuatano wa command.<sup>[[4]](#references)</sup>

Ikiwa jaribio litasababisha peripheral kukwama, otomatisha kesi moja pekee kwa kila boot kutoka kwa external controller: unganisha kupitia SSH, tekeleza kesi, hifadhi request/response ghafi pamoja na muda, washa upya au zima na kuwasha kifaa, subiri ukaguzi wa afya ukamilike, kisha endelea. Baadaye, kuhamishia component kwenye fixture inayodhibitiwa na microcontroller kunaweza kuwezesha reset za uhakika, udhibiti wa moja kwa moja wa nishati na fuzzing ya haraka zaidi.<sup>[[4]](#references)</sup>

## References

- [1] [Nyaraka za Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Specification ya I²C-bus na mwongozo wa mtumiaji](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Datasheet ya AT24C256C I²C serial EEPROM](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: Uchambuzi wa usalama wa chipu salama ya MJA1 ya Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Kifungashio cha cryptography cha Mijia BLE SDK MJA1](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
