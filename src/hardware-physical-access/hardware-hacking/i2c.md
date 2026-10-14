# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Bus Pirate'ı bağlamadan önce hedef voltajını, pin düzenini, pull-up bağlantısını ve ortak ground'u doğrulayın. Yalnızca veri trafiğini dinlemek için Bus Pirate'ın güç kaynaklarını hedef tarafından zaten beslenen bir bus üzerinde etkinleştirmeyin; iki güç kaynağı birbiriyle çakışarak donanıma zarar verebilir. Aşağıdaki kayıt, belirli bir Bus Pirate v3/community-firmware örneğidir; her durumda geçerli bir bağlantı talimatı değildir.<sup>[[1]](#references)[[2]](#references)</sup>

Bus Pirate'ın çalıştığını test etmek için +5V'ı VPU'ya, 3.3V'ı ADC'ye bağlayın ve Bus Pirate'a erişip (örneğin Tera Term kullanarak) `~` komutunu kullanın:

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

Önceki komut satırında görebileceğiniz gibi 0 hata bulunduğu belirtilmişti. Satın aldıktan veya firmware yükledikten sonra çalıştığını bilmek açısından bu çok faydalıdır.

Bus Pirate'a bağlanmak için belgelerdeki adımları izleyebilirsiniz:

![Komutu kullanın - Boşluk tuşuna basın: Bus Pirate'a bağlanmak için belgelerdeki adımları izleyebilirsiniz](<../../images/image (484).png>)

Bu durumda hedef, 24C256 ailesinden bir I²C EEPROM'dur. Desteklenen besleme gerilimi parçaya göre değiştiğinden tam soneki ve veri sayfasını doğrulayın.<sup>[[3]](#references)</sup>

![Komutu kullanın - Boşluk tuşuna basın: Bu durumda bir EPROM'a bağlanacağım: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Bus Pirate ile iletişim kurmak için Tera Term'i Bus Pirate'ın COM portuna bağlayıp Setup --> Serial Port --> Speed ayarını 115200 olarak belirledim.\
Aşağıdaki iletişimde Bus Pirate'ı I2C ile iletişim kuracak şekilde hazırlama ve bellekten yazma ve okuma adımlarını görebilirsiniz (Yorumlarda "#" kullanılır; bu kısmın iletişimde yer almasını beklemeyin):

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

Bu senaryoda Arduino ile önceki EPROM arasındaki I2C iletişimini dinleyeceğiz. İki cihazı iletişim kuracak şekilde bağlamanız ve ardından Bus Pirate'ı SCL, SDA ve GND pinlerine bağlamanız yeterlidir:

![Önceden yapılandırılmış 0x69 adresinden 20B oku - Sniffer: Bu senaryoda Arduino ile önceki EPROM arasındaki I2C iletişimini dinleyeceğiz. İki cihazı iletişim kuracak şekilde bağlamanız ve ardından...](<../../images/image (166).png>)

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

## Black-box I2C protokolünü yeniden oluşturma

### Canlı pinlerden bus'ı belirleme

Çevre biriminin pinout'u veya datasheet'i yoksa, orijinal host çalışırken yüksek empedanslı bir logic analyzer ile pasif olarak başlayın. Ortak ground ve güvenli logic seviyesini belirledikten sonra sabit pinleri olası güç hatları, ground veya pull-up'lı sinyaller olarak sınıflandırın; ardından etkin hatları yaygın bus'larla karşılaştırın: UART'ta asenkron ve bağımsız yönlü TX/RX bulunur; geleneksel SPI'da genellikle clock, chip select ve ayrı veri yönleri vardır; I2C'de ise düzenli bir clock ile çift yönlü tek bir veri hattı bulunur. Ardından I2C decode işlemi 7 bitlik hedef adreslerini, okuma/yazma yönünü, ACK/NACK'leri ve yinelenen payload'ları göstermelidir.<sup>[[2]](#references)[[4]](#references)</sup>

Birkaç geçerli alışverişi yakalayın ve hem decode edilmiş baytları hem de ham zamanlamayı koruyun. Yinelenen frame'ler, sonraki serializer'lar için bilinen yanıt testleri olarak işe yarar; istekler arasındaki değişiklikler ise olası opcode, index, offset, length, sequence veya checksum alanlarını ortaya çıkarabilir.<sup>[[4]](#references)</sup>

### Host firmware'inden framing'i çıkarma

Çevre birimi firmware'ine erişilemiyorsa **host** firmware'ini çıkarın ve I2C cihazını açan bileşeni bulun. Çevre biriminin adını, `/dev/i2c-` ifadesini, komut oluşturucuları, yanıt parser'larını, reset/initialization rutinlerini ve checksum fonksiyonlarını içeren string ve sembolleri arayın. Her oluşturucu için formatı fonksiyon adlarından çıkarsamak yerine alanların tam offset'lerini, sabit değerleri, kabul edilen argüman boyutlarını, payload uzunluğunu, checksum kapsamını, checksum bayt sırasını ve döndürülen frame uzunluğunu kaydedin.<sup>[[4]](#references)</sup>

`crc16_ccitt` adlı bir checksum fonksiyonu, bir preset seçmek için yeterli değildir. Kaydırma yönünü, tablo indeks baytını, tabloda temsil edilen polynomial'i, başlangıç register'ını, giriş/çıkış yansıtmasını, son XOR/inversion işlemini ve serializer'ın wire endianness'ını belirleyin. Örneğin, ters çevrilmiş `0x8408` polynomial'ine dayalı, sağa kaydırılan düşük bayt tablosu kullanan, `0xFFFF` ile başlatılan ve sonunda tümleyen alınan bir yöntem **CRC-16/X-25 (IBM-SDLC)**'yi tanımlar. Test senaryolarının integrity validation aşamasını geçip komut parser'ına ulaşması için genellikle doğru bir checksum gerekir.<sup>[[4]](#references)</sup>

Formatı yeniden oluşturduktan sonra, ayırt edici sembol adlarını ve sabit değerleri herkese açık kodlarda arayın. MJA1 örneğinde, bağımsız olarak bulunan bir SDK wrapper'ı komut ID'lerini, argüman doğrulamasını, yanıt tanımlarını ve kopyalanmış CRC implementasyonunu doğruladı; bu tür kaynakları, hedef binary'yi ve hat üzerindeki bayt sırasını kontrol etmenin yerine değil, doğrulama amacıyla kullanın.<sup>[[4]](#references)[[5]](#references)</sup>

### Root edilmiş bir Linux host'tan frame gönderme

Ele geçirilmiş bir embedded Linux host, başka bir bus controller eklemeden çevre birimini test edebilir. İlgili adapter'ı açın, `I2C_SLAVE` ile 7 bitlik adresi seçin ve özel bir serializer tarafından oluşturulmuş frame'i gönderin; mutasyon ve fuzzing için ham frame modunu da koruyun.<sup>[[4]](#references)</sup>

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

Hedef CPU ve libc ile uyumlu bir toolchain kullanarak çapraz derleme yapın ve test istemcisinden alınan analyzer izlerini meşru trafikle karşılaştırın. Görünen baytlar eşleşse bile işlem sınırları, yazma/okuma sırası, gecikmeler ve çevre biriminin durumu önemli olabilir.<sup>[[4]](#references)</sup>

### Yanıta göre opcode listeleme

En kısa geçerli çerçeve ve checksum belirlendikten sonra opcode genişliğinin tamamını listeleyin ve protokolün açık **desteklenmeyen komut** yanıtını negatif temel karşılaştırma olarak kullanın. Geçersiz bağımsız değişkenler, geçersiz durum veya belgelenmemiş bir durum kodu gibi farklı bir sonuç, kod çözmenin uygulanmış ya da kısmen uygulanmış bir işleyiciye ulaştığını düşündürür. Bu, açığın istismar edilebilir olduğunu **kanıtlamaz**; adayı yapılandırılmış uzunluk, bağımsız değişken, durum ve komut dizisi fuzzing'i için önceliklendirin.<sup>[[4]](#references)</sup>

Bir test çevre birimini kilitlerse harici bir denetleyiciden, her açılışta tek bir yalıtılmış vaka çalıştıracak şekilde otomasyon kurun: SSH üzerinden bağlanın, vakayı çalıştırın, ham istek/yanıtı ve zamanlamayı kaydedin, yeniden başlatın veya gücü kesip verin, sağlık kontrollerinin normale dönmesini bekleyin ve devam edin. Bileşeni daha sonra mikrodenetleyici kontrollü bir test düzeneğine taşımak; deterministik sıfırlamalar, doğrudan güç kontrolü ve daha hızlı fuzzing sağlayabilir.<sup>[[4]](#references)</sup>

## References

- [1] [Bus Pirate belgeleri — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — I²C-bus belirtimi ve kullanıcı kılavuzu](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — AT24C256C I²C seri EEPROM veri sayfası](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Kara Kutu Yoklaması: Xiaomi'nin MJA1 Güvenli Yongasının Güvenlik Analizi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Mijia BLE SDK MJA1 kriptografi sarmalayıcısı](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
