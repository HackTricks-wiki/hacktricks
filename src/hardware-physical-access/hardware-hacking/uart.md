# UART

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

UART, çerçevelenmiş bir bit akışını ortak saat sinyali olmadan aktaran asenkron bir seri arayüzdür. Mantık seviyeli UART'ı RS-232 ile karıştırmayın: RS-232 farklı, çoğunlukla negatif gerilim seviyeleri kullanır ve bir alıcı-verici gerektirir.<sup>[[1]](#references)[[3]](#references)</sup>

UART boşta durumdayken hat genellikle yüksek seviyede (mantıksal 1 değerinde) tutulur. Ardından, veri aktarımının başladığını belirtmek için verici alıcıya bir başlangıç biti gönderir; bu sırada sinyal düşük seviyede (mantıksal 0 değerinde) tutulur. Sonra verici, gerçek mesajı içeren beş ila sekiz veri biti gönderir. Yapılandırmaya bağlı olarak bunları isteğe bağlı bir parity biti ve bir veya iki durdurma biti (mantıksal 1 değerinde) izler. Hata denetimi için kullanılan parity biti pratikte nadiren görülür. Durdurma biti (veya bitleri) iletimin sonunu belirtir.

En yaygın yapılandırma 8N1'dir: sekiz veri biti, parity biti yok ve bir durdurma biti. UART, en düşük anlamlı veri bitini önce gönderir. Bu nedenle ASCII `C` (`0x43`) şu şekilde iletilir: başlangıç `0`; veri `1, 1, 0, 0, 0, 0, 1, 0`; durdurma `1`.<sup>[[1]](#references)</sup>

![UART: En yaygın yapılandırmaya 8N1 diyoruz: sekiz veri biti, parity biti yok ve bir durdurma biti. Örneğin, 8N1 UART ile C karakterini (ASCII'de 0x43) göndermek isteseydik](<../../images/image (764).png>)

UART ile iletişim kurmak için kullanılabilecek donanım araçları:

- USB-to-serial adapter
- CP2102 veya PL2303 yongalarını kullanan adaptörler
- Şu gibi çok amaçlı araçlar: Bus Pirate, Adafruit FT232H, Shikra veya Attify Badge

### UART Portlarını Belirleme

Tipik bir debug başlığı **TX**, **RX** ve **GND** uçlarını sunar; ayrıca bir **Vcc/Vref** pini, reset veya akış denetimi pinleri de bulunabilir. Vcc bir UART sinyali değildir ve normalde yalnızca gerilim referansı olarak kullanılmalıdır; kartın şeması ve akım gereksinimleri bilinmiyorsa güç kaynağı olarak bağlanmamalıdır.<sup>[[2]](#references)[[3]](#references)</sup>

Cihazın **gücü kapalı** ve bağlantısı kesilmiş durumdayken başlayın:

- Süreklilik modunda, bilinen bir toprak düzlemi, konektör kılıfı veya güç kaynağı toprağı üzerinden **GND**'yi belirleyin. Güç verilen bir kartta süreklilik/direnç modunu asla kullanmayın.
- Hedefe güç vermeden önce DC gerilim moduna geçin. Mantık gerilimini belirlemek için aday pinleri toprağa göre ölçün. Sabit bir hat Vcc/Vref olabilir; bağlamanın güvenli olduğunu varsaymayın.
- Açılış sırasında aday pinleri bir logic analyzer veya osiloskopla gözlemleyin. **TX** genellikle boşta yüksek seviyededir ve çerçevelenmiş veri paketleri gösterir. Multimetre ortalama dalgalanmayı gösterebilir ancak çerçevelemeyi veya baud hızını doğrulayamaz.
- **RX** boşta kalabilir ve yalnızca TX'in yanında bulunduğu için güvenli şekilde tanımlanamaz. PCB yollarını izleyin, SoC veri sayfasına başvurun veya pine sinyal vermeden önce yüksek empedanslı bir analizör kullanın.

TX ve RX'in yerlerini değiştirmek normalde iletişimi engeller; güç, toprak veya sinyal seviyelerini karıştırmak hedefe ya da adaptöre kalıcı hasar verebilir. Önce toprağı bağlayın ve **yalnızca alım** ile başlayın (hedef TX'i adaptör RX'ine bağlayın).

Üreticiler başlığı yerleştirmeyebilir, seri dirençleri takılmamış bırakabilir, konsolu firmware'de devre dışı bırakabilir veya yalnızca TX'i erişilebilir kılabilir. Yakındaki test pad'lerini ve direnç yuvalarını SoC'ye kadar izleyin ve elektrik seviyesini doğruladıktan sonra geçici, yüksek empedanslı bir bağlantı ekleyin. Garanti bulunması, erişilebilir bir UART'ın mutlaka mevcut olduğu anlamına gelmez.

### UART Baud Hızını Belirleme

Doğru baud hızını belirlemenin en kolay yolu **TX pininin çıkışına bakıp veriyi okumaya çalışmaktır**. Aldığınız veri okunabilir değilse, okunabilir hale gelene kadar sıradaki olası baud hızını deneyin. Bunun için bir USB-to-serial adapter veya Bus Pirate gibi çok amaçlı bir cihazı [baudrate.py](https://github.com/devttys0/baudrate/) gibi yardımcı bir betikle birlikte kullanabilirsiniz. En yaygın baud hızları 9600, 38400, 19200, 57600 ve 115200'dür.

> [!CAUTION]
> Bu protokolde bir cihazın TX pinini diğer cihazın RX pinine bağlamanız gerektiğini unutmayın!

## CP210X UART - TTY Adaptörü

CP210x USB-to-UART köprüleri birçok prototipleme kartında ve ucuz adaptörde bulunur. Yaygın modüllerde GND, RXD ve TXD'nin yanı sıra güç pinleri de yer alır; ancak başlıkları ve G/Ç seviyeleri değişiklik gösterebilir. Gerçek gerilimi kart tasarımından veya veri sayfasından doğrulayın. Genellikle yalnızca GND'yi ve adaptör RX'ini hedef TX'e bağlayın; yalnızca alım bağlantısını doğruladıktan sonra adaptör TX'ini hedef RX'e bağlayın. Hedefi bilerek çalıştırmıyorsanız ve hedefin bu gerilimi kaldırabildiğinden emin değilseniz adaptörün 5 V/3.3 V güç pinini bağlamayın.<sup>[[3]](#references)</sup>

Adaptör algılanmıyorsa ana sistemde CP210X sürücülerinin kurulu olduğundan emin olun. Adaptör algılanıp bağlandıktan sonra picocom, minicom veya screen gibi araçları kullanabilirsiniz.

Linux/MacOS sistemlerine bağlı cihazları listelemek için:

```
ls /dev/
```

UART arayüzüyle temel etkileşim için aşağıdaki komutu kullanın:

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom'u yapılandırmak için aşağıdaki komutu kullanın:

```
minicom -s
```

`Serial port setup` seçeneğinde baudrate ve cihaz adı gibi ayarları yapılandırın.

Yapılandırmadan sonra UART konsolunu açmak için `minicom` çalıştırın.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

UART Serial to USB adaptörleri mevcut değilse, Arduino UNO R3 hızlı bir hack ile kullanılabilir. Arduino UNO R3 genellikle her yerde bulunduğundan bu, çok zaman kazandırabilir.

Arduino UNO R3'ün kartın üzerinde yerleşik bir USB to Serial adaptörü vardır. UART bağlantısı kurmak için Atmel 328p mikrodenetleyici çipini karttan çıkarın. Bu hack, Atmel 328p'nin karta lehimlenmediği (SMD sürümünün kullanıldığı) Arduino UNO R3 çeşitlerinde çalışır. Arduino'nun RX pinini (Digital Pin 0) UART Interface'in TX pinine, Arduino'nun TX pinini (Digital Pin 1) ise UART interface'in RX pinine bağlayın.

Hedef baud rate'te Arduino IDE **Serial Monitor**'ü veya özel bir terminal kullanın. Klasik Uno R3 seri sinyalleri 5 V lojik seviyesindedir; bu nedenle 3.3 V veya daha düşük voltajlı bir hedefe bağlamadan önce seviye dönüştürücü ya da gerilim bölücü kullanın.

## Bus Pirate

Aşağıdaki kayıt, UART çıktısını izlemek için legacy Bus Pirate firmware arayüzünü kullanır. Daha yeni Bus Pirate firmware'leri `m uart`, `{`/`}`, `monitor` veya `bridge` gibi komutlar kullanır; yüklü sürüme ait belgelere başvurun.<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
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

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## UART Konsoluyla Firmware Dökümü Alma

UART konsolu, önyükleme günlüklerine ve bazen bir bootloader'a veya işletim sistemi shell'ine çalışma zamanı erişimi sağlar. Salt okunur bir konsol bile bellek haritalarını, flash sürücülerini, önyükleme argümanlarını, bölüm düzenlerini ve firmware sürümlerini açığa çıkarır. Firmware SPI NOR/NAND, eMMC veya başka bir aygıtta bulunabilir; genellikle EEPROM'dan çalıştırılmaz ve bağlı kalıcı bir dosya sistemine yazılan dosyalar yeniden başlatma sırasında mutlaka silinmez.

Birkaç edinim yöntemi vardır ve SPI bölümü harici flash'tan doğrudan okumaları kapsar. Bootloader zaten güvenli bir okuma komutu sunuyorsa konsol destekli edinim daha az müdahaleci olabilir; ancak önyüklemeyi kesintiye uğratmak veya bir flash komutu çalıştırmak erişilebilirliği etkileyebilir. Bu nedenle ilk durumu kaydedin ve yazma/silme işlemlerinden kaçının.

Konsol destekli firmware dökümü alma işlemi genellikle bir bootloader'ın önyüklemesini kesintiye uğratmakla başlar. Birçok gömülü Linux aygıtı **Das U-Boot** kullanır; ancak diğerleri özel bootloader'lar kullanır veya etkileşimli konsolu devre dışı bırakır.

Etkileşimli bir bootloader olup olmadığını test etmek için hedef kapalıyken UART alım yolunu ve terminali bağlayın, günlük kaydını başlatın ve aygıta güç verin. Görüntülenen otomatik önyükleme istemini izleyin; derlemeye bağlı olarak önyüklemeyi kesmek için bir tuşa, kısa bir tuş dizisine basmak gerekebilir ya da bu özellik tamamen devre dışı bırakılmış olabilir.

Kesinti başarılı olursa adreslere erişmeden önce o üreticinin bellek ve depolama düzenini anlamak için `help`, `printenv` ve salt okunur keşif komutlarını kullanın.

U-Boot'ta `md`, otomatik olarak “EEPROM'u” değil, **adreslenebilir belleği** görüntüler. Önce doğru eşlenmiş adresi belirlemek veya bir flash bölgesini RAM'e yüklemek için `mtd list`, `sf probe`, `mmc info`, `part list` gibi karta özgü komutları, ortam değişkenlerini ve önyükleme günlüklerini kullanın. Ardından bilinen bir aralığı bayt bayt görüntüleyin:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Başlamadan önce seri çıktıyı kaydedin. `md.b` çıktısı adresleri ve bir ASCII sütununu içerir; bu nedenle ham bir ROM görüntüsü değil, metinsel bir gösterimdir.

Adres ve ASCII sütunlarını kaldırın, yalnızca onaltılık bayt alanlarını birleştirin ve ikili veriye dönüştürün (örneğin, `xxd -r -p` ile). Analizden önce beklenen bayt sayısını doğrulayın ve bir hash kaydedin:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk daha sonra yeniden oluşturulan binary içindeki bilinen imzaları tanımlar. Konsol verileri güvenilir biçimde aktaramıyorsa, uygun SPI/eMMC/NAND arayüzü üzerinden doğrudan flash okuması genellikle daha hızlıdır ve hataya daha az açıktır.

U-Boot kesintiyi devre dışı bırakabilir, üreticiye özgü bir tuş dizisi gerektirebilir veya bellek/flash komutlarını kilitleyebilir. Karakterleri gelişigüzel göndermek yerine autoboot istemini ve önyükleme günlüğünü izleyin. Konsol kesilemiyorsa önyükleme günlüğünü saklayın ve müdahalesiz bir firmware edinme yöntemine geçin.

## References

- [1] [Microchip PIC32 Ailesi Başvuru Kılavuzu - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate belgeleri - UART modu ve elektriksel sınırlar](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C veri sayfası](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot belgeleri - `md` bellek görüntüleme komutu](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
