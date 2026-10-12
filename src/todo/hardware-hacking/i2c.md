# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate'ı bağlamadan önce hedef voltajını, pin dizilimini, pull-up düzenini ve ortak toprak bağlantısını doğrulayın. Bus'ı yalnızca dinlemek için Bus Pirate'ın güç kaynaklarını hedefin zaten çalıştırdığı bir bus üzerinde etkinleştirmeyin; iki güç kaynağı birbiriyle çakışarak donanıma zarar verebilir. Aşağıdaki oturum kaydı, cihaza özgü bir Bus Pirate v3/topluluk firmware'i örneğidir; evrensel bir kablolama tarifi değildir.<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirate'ın çalışıp çalışmadığını test etmek için VPU'yu +5V'a, ADC'yi 3.3V'a bağlayın ve Bus Pirate'a erişin (örneğin Tera Term kullanarak), ardından `~` komutunu kullanın:

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

Önceki komut satırında da görebileceğiniz gibi 0 hata bulunduğunu belirtti. Bu, satın aldıktan veya firmware yükledikten sonra çalıştığını doğrulamak için çok faydalıdır.

Bus Pirate'a bağlanmak için belgeleri takip edebilirsiniz:

![Komutu kullanın - Boşluk tuşuna basın: Bus Pirate'a bağlanmak için belgeleri takip edebilirsiniz](<../../images/image (484).png>)

Bu durumda hedef, 24C256 ailesinden bir I²C EEPROM'dur. Desteklenen besleme gerilimi parçaya göre değiştiğinden tam son eki/datasheet'i doğrulayın.<sup>[[3]](#references)</sup>

![Komutu kullanın - Boşluk tuşuna basın: Bu durumda bir EPROM'a bağlanacağım: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus Pirate ile iletişim kurmak için, Setup --> Serial Port --> Speed ayarı 115200 olacak şekilde COM portuna bağlanmış Tera Term kullandım.\
Aşağıdaki iletişimde Bus Pirate'ı I2C ile iletişim kuracak şekilde nasıl hazırlayacağınızı ve bellekten nasıl yazıp okuyacağınızı görebilirsiniz (yorumlar "#" ile başlar; iletişimde bu kısmın yer almasını beklemeyin):

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

Bu senaryoda Arduino ile önceki EPROM arasındaki I2C iletişimini dinleyeceğiz. İki cihaz arasında iletişim kurmanız ve ardından Bus Pirate'ı SCL, SDA ve GND pinlerine bağlamanız yeterlidir:

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

## Kara kutu I2C protokolünü yeniden oluşturma

### Veriyolunu canlı pinlerden belirleme

Çevre biriminin pinout'u veya datasheet'i yoksa, özgün host çalışırken yüksek empedanslı bir logic analyzer ile pasif olarak başlayın. Ortak bir toprak ve güvenli logic level sağladıktan sonra sabit pinleri olası güç hatları, toprak veya pull-up uygulanmış sinyaller olarak sınıflandırın ve etkin hatları yaygın veriyollarıyla karşılaştırın: UART'ta asenkron ve birbirinden bağımsız yönlere sahip TX/RX bulunur; geleneksel SPI'da genellikle clock, chip select ve ayrı veri yönleri bulunur; I2C'de ise düzenli bir clock ve çift yönlü tek bir veri hattı bulunur. Ardından I2C decode işlemi 7-bit hedef adreslerini, read/write yönünü, ACK/NACK'leri ve tekrarlanan payload'ları ortaya çıkarmalıdır.<sup>[[2]](#references)[[4]](#references)</sup>

Birkaç geçerli alışverişi yakalayın ve hem decode edilmiş byte'ları hem de ham zamanlamayı saklayın. Tekrarlanan frame'ler sonraki serializer'lar için bilinen yanıt testleri olarak kullanışlıdır; istekler arasındaki değişiklikler de olası opcode, index, offset, length, sequence veya checksum alanlarını açığa çıkarabilir.<sup>[[4]](#references)</sup>

### Host firmware'den çerçevelemeyi çıkarma

Çevre biriminin firmware'ine erişilemiyorsa **host** firmware'ini çıkarın ve I2C aygıtını açan bileşeni bulun. Çevre biriminin adı, `/dev/i2c-`, command builder'lar, response parser'lar, reset/initialization rutinleri ve checksum işlevleri için string ve sembollerde arama yapın. Her builder için, biçimi işlev adlarından çıkarsamak yerine alanların tam offset'lerini, sabitleri, kabul edilen argüman boyutlarını, payload uzunluğunu, checksum kapsamını, checksum byte sıralamasını ve döndürülen frame uzunluğunu kaydedin.<sup>[[4]](#references)</sup>

`crc16_ccitt` adlı bir checksum işlevi, bir preset seçmek için yeterli değildir. Kaydırma yönünü, tablo indeks byte'ını, tablonun temsil ettiği polynomial'i, başlangıç register'ını, girdi/çıktı yansıtmasını, son XOR/terslemeyi ve serializer'ın kablo üzerindeki byte sıralamasını belirleyin. Örneğin, ters çevrilmiş `0x8408` polynomial'ini temel alan, düşük byte üzerinden indekslenen bir tablo; `0xFFFF` başlangıç değeri ve sonda tümleyen kullanımı **CRC-16/X-25 (IBM-SDLC)** olduğunu gösterir. Komut parser'ına ulaşabilmek için test örneklerinin bütünlük doğrulamasını geçmesi çoğu zaman doğru checksum gerektirir.<sup>[[4]](#references)</sup>

Biçimi yeniden oluşturduktan sonra, ayırt edici sembol adlarını ve sabitleri herkese açık kodda arayın. MJA1 örneğinde, bağımsız olarak bulunan bir SDK wrapper'ı komut ID'lerini, argüman doğrulamasını, yanıt tanımlarını ve eşlenmiş CRC uygulamasını doğrulamıştır; bu tür kaynakları doğrulama amacıyla kullanın, hedef binary'yi ve kablo üzerindeki byte sıralamasını kontrol etmenin yerine değil.<sup>[[4]](#references)[[5]](#references)</sup>

### Root edilmiş bir Linux host'tan frame gönderme

Ele geçirilmiş bir embedded Linux host'u, başka bir bus controller eklemeden çevre birimini test edebilir. İlgili adapter'ı açın, `I2C_SLAVE` ile 7-bit adresi seçin ve özel bir serializer'ın oluşturduğu frame'i gönderin; mutasyon ve fuzzing için ham frame modunu da koruyun.<sup>[[4]](#references)</sup>

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

Cross-compile işlemini hedef CPU ve libc ile uyumlu bir toolchain kullanarak yapın ve analyzer izlerini test client'tan alınan izlerle meşru trafik izleriyle karşılaştırın. Görünür baytlar eşleşse bile transaction sınırları, yazma/okuma sıralaması, gecikmeler ve çevre biriminin durumu önemli olabilir.<sup>[[4]](#references)</sup>

### Yanıta göre yönlendirilen opcode numaralandırması

En kısa geçerli frame ve checksum belirlendikten sonra opcode genişliğinin tamamını numaralandırın ve protokolün açık **unsupported-command** yanıtını negatif temel değer olarak kullanın. Farklı bir sonuç (örneğin geçersiz argümanlar, geçersiz durum veya belgelenmemiş bir durum kodu), çözümlemenin uygulanmış ya da kısmen uygulanmış bir handler'a ulaştığını gösterir. Bu, exploit edilebilir olduğunu **kanıtlamaz**; adayı yapılandırılmış uzunluk, argüman, durum ve komut dizisi fuzzing'i için önceliklendirin.<sup>[[4]](#references)</sup>

Bir test çevre birimini kilitlerse, harici bir controller'dan her boot için tek bir izole test çalıştırın: SSH ile bağlanın, testi yürütün, ham istek/yanıtı ve zamanlamayı kaydedin, yeniden başlatın veya gücü kesip yeniden verin, health check'lerin düzelmesini bekleyin ve devam edin. Bileşeni mikrodenetleyici kontrollü bir düzeneğe taşımak, ileride deterministik sıfırlamalar, doğrudan güç kontrolü ve daha hızlı fuzzing sağlayabilir.<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate belgeleri — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus spesifikasyonu ve kullanıcı kılavuzu](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C seri EEPROM veri sayfası](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: Xiaomi'nin MJA1 güvenli çipinin güvenlik analizi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 cryptography wrapper](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
