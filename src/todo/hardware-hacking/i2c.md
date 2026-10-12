# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Hakikisha voltage ya kifaa lengwa, mpangilio wa pini, mpangilio wa pull-up na ground ya pamoja kabla ya kuunganisha Bus Pirate. Usiwashe vifaa vya umeme vya Bus Pirate kwenye bus inayotumika na kupewa umeme na kifaa lengwa ili kuisniff tu; vifaa viwili vya umeme vinaweza kushindana na kuharibu hardware. Nakala ya mawasiliano iliyo hapa chini ni mfano mahususi wa kifaa wa Bus Pirate v3/community-firmware, si mwongozo wa jumla wa wiring.<sup>[[1]](#references)[[2]](#references)</sup>

Ili kujaribu kama Bus Pirate inafanya kazi, unganisha +5V na VPU, na 3.3V na ADC, kisha ufikie Bus Pirate (kwa mfano, ukitumia Tera Term) na utumie amri `~`:

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

Kama unavyoona kwenye mstari wa amri uliotangulia, ilisema kuwa haikupata makosa. Hii ni muhimu sana kujua kuwa inafanya kazi baada ya kuinunua au baada ya kuflash firmware.

Ili kuunganisha na Bus Pirate, unaweza kufuata nyaraka:

![Tumia amri - Bonyeza space: Ili kuunganisha na Bus Pirate, unaweza kufuata nyaraka](<../../images/image (484).png>)

Katika hali hii, kifaa lengwa ni I²C EEPROM ya familia ya 24C256. Thibitisha kiambishi tamati na datasheet halisi kwa sababu volti ya usambazaji inayotumika hutofautiana kulingana na sehemu husika.<sup>[[3]](#references)</sup>

![Tumia amri - Bonyeza space: Katika hali hii nitaunganisha kwenye EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Ili kuwasiliana na Bus Pirate, nilitumia Tera Term iliyounganishwa kwenye porti ya COM ya Bus Pirate kupitia Setup --> Serial Port --> Speed ya 115200.\
Katika mawasiliano yafuatayo unaweza kuona jinsi ya kuandaa Bus Pirate ili kuwasiliana kupitia I2C na jinsi ya kuandika na kusoma kutoka kwenye memory (Maoni yanaonekana kwa kutumia "#"; usitarajie sehemu hiyo kwenye mawasiliano):

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

Katika hali hii, tutasikiliza mawasiliano ya I2C kati ya arduino na EPROM iliyotangulia. Unahitaji tu kuwasiliana na vifaa vyote viwili, kisha uunganishe bus pirate kwenye pini za SCL, SDA na GND:

![Soma 20B kutoka anwani 0x69 iliyosanidiwa awali - Sniffer: Katika hali hii, tutasikiliza mawasiliano ya I2C kati ya arduino na EPROM iliyotangulia. Unahitaji tu...](<../../images/image (166).png>)

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

## Ujenzi upya wa itifaki ya I2C kwa black-box

### Tambua basi kutoka kwa pini zinazotumika

Wakati peripheral haina mpangilio wa pini wala datasheet, anza kwa uchunguzi usioingilia utendaji ukitumia logic analyzer yenye impedance ya juu huku host asilia ikiitumia. Baada ya kuunganisha ground ya pamoja na kuthibitisha kiwango salama cha logic, ainisha pini zisizobadilika kuwa huenda ni rails, ground, au mawimbi yenye pull-up, kisha linganisha laini zinazotumika na mabasi ya kawaida: UART ina TX/RX zisizolingana, zinazotuma data kwa kujitegemea; SPI ya kawaida huwa na clock, chip select, na njia tofauti za data; I2C ina clock ya kawaida pamoja na laini moja ya data inayotuma na kupokea. Kisha decode ya I2C inapaswa kuonyesha anwani za target za biti 7, mwelekeo wa read/write, ACK/NACK, na payload zinazojirudia.<sup>[[2]](#references)[[4]](#references)</sup>

Nasa mawasiliano halali kadhaa na uhifadhi biti zilizodecode pamoja na timing ghafi. Fremu zinazojirudia ni majaribio muhimu yenye majibu yanayojulikana kwa serializer utakazotengeneza baadaye, huku mabadiliko kati ya maombi yakifichua sehemu zinazowezekana kuwa opcode, index, offset, length, sequence, au checksum.<sup>[[4]](#references)</sup>

### Rejesha muundo wa fremu kutoka kwa firmware ya host

Ikiwa firmware ya peripheral haipatikani, toa firmware ya **host** na utafute sehemu inayofungua kifaa cha I2C. Tafuta strings na alama za symbol zinazohusiana na jina la peripheral, `/dev/i2c-`, wajenzi wa command, vichanganuzi vya response, taratibu za reset/initialization, na functions za checksum. Kwa kila builder, andika offset halisi za field, constants, ukubwa wa argument unaokubaliwa, urefu wa payload, sehemu zinazojumuishwa kwenye checksum, mpangilio wa byte za checksum, na urefu wa fremu inayorejeshwa badala ya kukisia muundo kutokana na majina ya function.<sup>[[4]](#references)</sup>

Jina la checksum function `crc16_ccitt` pekee halitoshi kuchagua preset. Tambua mwelekeo wa shift, byte ya table index, polynomial inayowakilishwa na table, register ya mwanzo, reflection ya ingizo/tokeo, XOR/inversion ya mwisho, na endianness ya waya ya serializer. Kwa mfano, table ya low-byte inayotumia right-shift na polynomial iliyogeuzwa `0x8408`, iliyoanzishwa na `0xFFFF` na kukamilishwa mwishoni, hutambulisha **CRC-16/X-25 (IBM-SDLC)**. Checksum sahihi mara nyingi ni muhimu ili majaribio yapite ukaguzi wa uadilifu na kufika kwenye command parser.<sup>[[4]](#references)</sup>

Baada ya kujenga upya muundo, tafuta majina mahususi ya symbol na constants kwenye code ya umma. Katika kisa cha MJA1, SDK wrapper iliyopatikana kando ilithibitisha command IDs, uthibitishaji wa argument, ufafanuzi wa response, na utekelezaji wa CRC ulioakisiwa; tumia chanzo hicho kuthibitisha matokeo, si badala ya kukagua binary halisi ya target na mpangilio wa byte unaotumika kwenye waya.<sup>[[4]](#references)[[5]](#references)</sup>

### Tuma fremu kutoka kwa host ya Linux yenye root

Host ya Linux iliyopachikwa na kuathiriwa inaweza kujaribu peripheral bila kuongeza controller nyingine ya basi. Fungua adapter husika, chagua anwani ya biti 7 kwa kutumia `I2C_SLAVE`, na utume fremu iliyotengenezwa na serializer maalum; hifadhi hali ya raw-frame kwa ajili ya mutation na fuzzing.<sup>[[4]](#references)</sup>

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

Compile kwa cross-compilation ukitumia toolchain inayooana na CPU na libc ya kifaa lengwa, kisha linganisha trace za analyzer kutoka kwa test client na trafiki halali. Mipaka ya transaction, mpangilio wa write/read, ucheleweshaji na hali ya peripheral vinaweza kuwa muhimu hata wakati bytes zinazoonekana zinafanana.<sup>[[4]](#references)</sup>

### Uorodheshaji wa opcode kwa mwongozo wa majibu

Baada ya kujua fremu halali fupi zaidi na checksum, orodhesha upana mzima wa opcode na utumie jibu la wazi la **unsupported-command** la protocol kama msingi hasi. Matokeo tofauti—kama vile hoja zisizo halali, hali isiyo halali au status isiyoandikwa kwenye nyaraka—yanadokeza kuwa decoding ilifikia handler iliyotekelezwa au kutekelezwa kwa sehemu. Hii **haithibitishi** kuwa kuna uwezekano wa exploit; weka mgombea huyo kipaumbele kwa fuzzing iliyopangwa ya urefu, hoja, hali na mfuatano wa amri.<sup>[[4]](#references)</sup>

Ikiwa jaribio litasababisha peripheral kukwama, otomatisha kesi moja iliyotengwa kwa kila boot kutoka kwa controller ya nje: unganisha kupitia SSH, tekeleza kesi hiyo, hifadhi ombi/jibu ghafi na muda wake, washa upya au zima na kuwasha tena kifaa, subiri ukaguzi wa afya ukamilike, kisha endelea. Baadaye, kuhamisha component kwenye kifaa cha majaribio kinachodhibitiwa na microcontroller kunaweza kutoa reset thabiti, udhibiti wa moja kwa moja wa nishati na fuzzing ya haraka zaidi.<sup>[[4]](#references)</sup>

## References

- [1] [Nyaraka za Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Maelezo ya I²C-bus na mwongozo wa mtumiaji](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Datasheet ya AT24C256C I²C serial EEPROM](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Uchunguzi wa Black Box: Uchambuzi wa Usalama wa Chipu Salama ya MJA1 ya Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Kifungashio cha cryptography cha Mijia BLE SDK MJA1](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
