# SPI

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

SPI (Serial Peripheral Interface), entegre devreler arasında kısa mesafeli iletişim için yaygın olarak kullanılan eşzamanlı bir seri veri yoludur. Bir controller, clock sinyalini sağlar ve chip-select sinyali kullanarak EEPROM, sensör veya kontrol cihazı gibi bir peripheral seçer.<sup>[[1]](#references)</sup>

Birden fazla peripheral, genellikle her peripheral için ayrı bir chip-select hattı kullanılarak clock ve data hatlarını paylaşabilir. Aktarımları controller yönetir; peripheral’lar normalde SPI veri yolu üzerinden birbirleriyle doğrudan iletişim kurmaz. Chip-select polaritesi ve zamanlaması cihaza özeldir; aktif-düşük seçim yaygındır ancak evrensel değildir. SPI; keşif, adresleme, komutlar veya tek bir maksimum aktarım uzunluğu tanımlamaz. Bu nedenle daima hedefin datasheet’ine başvurun.<sup>[[1]](#references)</sup>

MOSI/COPI, controller’dan peripheral’a veri taşır; MISO/CIPO ise peripheral’dan controller’a veri taşır. Her iki yönde de aynı anda veri kaydırılabilir. Bir komut, adres, dummy cycle’lar ve döndürülen veri arasındaki ilişki SPI tarafından değil, peripheral tarafından belirlenir ve clock polaritesi ile fazına (mode 0–3) bağlıdır. Çıkışın, giriş sona erdikten tam bir clock sonra başladığını varsaymayın.<sup>[[1]](#references)</sup>

## EEPROM'lardan Firmware Dump Alma

Firmware dump’ı almak, firmware’i analiz etmek ve zafiyetleri bulmak için yararlı olabilir. Doğru imaj çevrimiçi olarak bulunamayabilir veya model, donanım revizyonu ya da sürüm bakımından farklılık gösterebilir. Bu nedenle imajı doğrudan fiziksel cihazdan çıkarmak, değerlendirme için tam olarak hedeflenen sürümü sağlar.

Seri konsol yardımcı olabilir ancak dosya sistemi salt okunur olabilir ve hedefte test trafiği gönderip/almak veya binary dosyaları kolayca çıkarmak için gereken yardımcı programlar da dahil olmak üzere analiz araçları bulunmayabilir. Çevrimdışı bir imaj, flash düzeninin tamamını korur ve çalışan hedefi değiştirmeden dosya sisteminin çıkarılmasına ve reverse engineering yapılmasına olanak tanır.

Yetkili bir fiziksel değerlendirme sırasında doğrulanmış bir dump, kontrollü değiştirme ve yeniden flashlama testlerini de destekleyebilir. Buna, firmware seviyesinde kalıcılığı göstermek için dosyaları değiştirmek veya bir test payload’ı/backdoor enjekte etmek dahildir. Herhangi bir yazma işleminden önce birden fazla eşleşen okuma ve orijinal imajı saklayın: yanlış voltaj, chip seçimi, düzen veya imaj cihazı brick edebilir.

### CH341A EEPROM Programmer and Reader

Bu ucuz USB aracı, uyumlu seri EEPROM ve SPI flash cihazlarını dump edip yeniden flashlayabilir. Genellikle PC BIOS/UEFI firmware’ini saklayan SPI NOR flash chip’lerle kullanılır ve süre kısıtlı fiziksel erişim sırasında kullanışlıdır.

![drawing](../../images/board_image_ch341a.jpg)

Flash belleği CH341A’ya bağlayın, ardından programmer’ı bilgisayara bağlayın. Programmer algılanmıyorsa hedef chip’te sorun aramadan önce USB kablosunu, OS izinlerini ve uygun CH341A driver’ını kontrol edin. Chip’in voltajını, pin 1’i, adaptör kablolarını ve programmer çıkışını datasheet’lerden veya bir ölçü aletinden yararlanarak doğrulayın; VCC’yi USB konektörünün karşısına yerleştirmek gibi bir kurala **güvenmeyin**. Yanlış yönlendirme veya 3.3/1.8 V bir parçaya 5 V uygulamak parçayı bozabilir. Devre üzerindeki okumalar, kartın geri kalan kısmı veri yolunu yüklediği veya beslediği için başarısız olabilir.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip’i okumak için `flashrom` veya G-Flash gibi yazılımlar kullanın. G-Flash minimal bir GUI’dir ve uyumlu cihazları otomatik algılayabilir; bu da hızlı edinim sırasında kullanışlı olabilir. Ancak algılanan modeli ve voltajı kendiniz doğrulayın. Tam programmer’ı ve gerektiğinde tam chip modelini belirtin; dump’ı güvenilir kabul etmeden önce en az iki kez okuyun ve hash değerlerini karşılaştırın.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump’ı alındıktan sonra binary dosyalar üzerinde analiz yapılabilir. Firmware ve tüm dosya sistemi hakkında çok miktarda bilgi çıkarmak için strings, hexdump, xxd, binwalk gibi araçlar kullanılabilir.

İlk inceleme için Binwalk, bilinen imzaları tarayabilir ve desteklenen gömülü içeriği çıkarabilir:

```
binwalk -e <filename>
```

Çıktı dosyası `.bin`, `.rom` veya başka bir uzantı kullanabilir; uzantı dosya biçimini belirlemez.

> [!CAUTION]
> Firmware çıkarma işleminin hassas olduğunu ve çok sabır gerektirdiğini unutmayın. Yanlış bir işlem firmware'i bozabilir, hatta tamamen silebilir ve cihazı kullanılamaz hâle getirebilir. Firmware'i çıkarmaya çalışmadan önce ilgili cihazı incelemeniz önerilir.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Bazı veri sayfalarında hedef pinler `DI` ve `DO` olarak etiketlenir: geleneksel tek veri hatlı bir flash bağlantısında, denetleyici **MOSI/COPI, DI'ye**; denetleyici **MISO/CIPO ise DO'ya** bağlanır. Çift/dörtlü I/O parçaları pinleri diğer kiplerde yeniden kullandığından hedefin veri sayfasını doğrulayın.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

Windows veya Linux'ta, flash belleğin içeriğini aşağıdakine benzer bir komutla dökmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanabilirsiniz:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Yakın tarihli Bus Pirate belgelerinde isteğe bağlı `serialspeed` ve `spispeed` parametreleri de gösteriliyor. Uzun kablolar veya devre içi yükleme okumaları kararsız hâle getiriyorsa temkinli başlayın.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI Arayüzüne Giriş](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom kılavuzu — CH341A SPI programlayıcısı ve okuma/yazma seçenekleri](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate belgeleri — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
