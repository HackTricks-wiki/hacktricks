# SPI

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

SPI (Serial Peripheral Interface), tümleşik devreler arasında kısa mesafeli iletişim için yaygın olarak kullanılan eşzamanlı bir seri veri yoludur. Bir controller saat sinyalini sağlar ve chip-select sinyali kullanarak EEPROM, sensör veya kontrol cihazı gibi bir peripheral'ı seçer.<sup>[[1]](#references)</sup>

Birden fazla peripheral, genellikle her peripheral için ayrı bir chip-select kullanılarak saat ve veri hatlarını paylaşabilir. Aktarımları controller yönetir; peripheral'lar normalde SPI veri yolu üzerinden birbirleriyle doğrudan iletişim kurmaz. Chip-select polaritesi ve zamanlaması cihaza özeldir; aktif-düşük seçim yaygındır, ancak evrensel değildir. SPI; keşif, adresleme, komutlar veya tek bir maksimum aktarım uzunluğu tanımlamaz. Bu nedenle her zaman hedefin datasheet'ine başvurun.<sup>[[1]](#references)</sup>

MOSI/COPI, controller'dan peripheral'a veri taşır; MISO/CIPO ise peripheral'dan controller'a veri taşır. Her iki yönde de aynı anda veri kaydırılabilir. Komut, adres, dummy cycle'lar ve döndürülen veri arasındaki ilişki SPI tarafından değil peripheral tarafından tanımlanır ve saat polaritesiyle fazına (mod 0–3) bağlıdır. Çıktının, girdi biter bitmez tam olarak bir saat döngüsü sonra başladığını varsaymayın.<sup>[[1]](#references)</sup>

## EEPROM'lardan Firmware Dump Alma

Firmware dump'ı almak, firmware'i analiz etmek ve açıkları bulmak için faydalı olabilir. Doğru imaj çevrimiçi olarak mevcut olmayabilir ya da model, donanım revizyonu veya sürüme göre farklılık gösterebilir. Bu nedenle imajı doğrudan fiziksel cihazdan çıkarmak, değerlendirme için birebir hedef sağlar.

Seri konsol yardımcı olabilir, ancak dosya sistemi salt okunur olabilir ve hedefte test trafiği gönderip almaya veya binary dosyaları kolayca çıkarmaya yarayan yardımcı programlar dâhil analiz araçları bulunmayabilir. Çevrimdışı bir imaj, flash'ın tüm düzenini korur ve çalışan hedefi değiştirmeden dosya sistemi çıkarmaya ve reverse engineering yapmaya olanak tanır.

Yetkili bir fiziksel değerlendirme sırasında doğrulanmış bir dump, kontrollü değiştirme ve yeniden flash etme testlerini de destekleyebilir. Buna, firmware düzeyinde kalıcılığı göstermek için dosyaları değiştirmek veya bir test payload'ı/backdoor eklemek de dâhildir. Herhangi bir yazma işleminden önce birbiriyle eşleşen birden fazla okuma ve orijinal imajı saklayın: yanlış voltaj, chip seçimi, düzen veya imaj cihazı kullanılmaz hâle getirebilir.

### CH341A EEPROM Programlayıcı ve Okuyucu

Bu uygun fiyatlı USB aracı, uyumlu seri EEPROM ve SPI flash cihazlarının dump'ını alıp yeniden flash edebilir. PC BIOS/UEFI firmware'ini depolayan SPI NOR flash chip'leriyle yaygın olarak kullanılır ve kısıtlı süreli fiziksel erişim sırasında pratiktir.

![drawing](../../images/board_image_ch341a.jpg)

Flash belleği CH341A'ya bağlayın, ardından programlayıcıyı bilgisayara bağlayın. Programlayıcının kendisi algılanmazsa hedef chip'te sorun gidermeden önce USB kablosunu, işletim sistemi izinlerini ve uygun CH341A driver'ını kontrol edin. Datasheet'lere veya bir ölçüm cihazına başvurarak chip'in voltajını, pin 1'i, adaptör bağlantılarını ve programlayıcı çıkışını doğrulayın; VCC'yi USB konektörünün karşısına yerleştirmek gibi bir kurala **güvenmeyin**. Yanlış yönde takmak veya 3.3/1.8 V'luk bir parçaya 5 V uygulamak parçayı bozabilir. Devre üzerindeki okumalar, kartın geri kalanının veri yolunu yüklemesi veya beslemesi nedeniyle başarısız olabilir.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip'i okumak için `flashrom` veya G-Flash gibi yazılımlar kullanın. G-Flash minimal bir GUI sunar ve uyumlu cihazları otomatik algılayabilir; bu, hızlı edinim sırasında kullanışlı olabilir. Ancak algılanan modeli ve voltajı kendiniz doğrulayın. Programlayıcıyı tam olarak belirtin ve gerektiğinde tam chip modelini girin; bir dump'ı güvenilir kabul etmeden önce en az iki okuma yapıp hash'lerini karşılaştırın.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump'ı alındıktan sonra analiz binary dosyalar üzerinde yapılabilir. Firmware ve tüm dosya sistemi hakkında çok miktarda bilgi çıkarmak için strings, hexdump, xxd, binwalk vb. araçlar kullanılabilir.

İlk inceleme için Binwalk, bilinen imzaları tarayabilir ve desteklenen gömülü içerikleri çıkarabilir:

```
binwalk -e <filename>
```

Çıktı dosyasında `.bin`, `.rom` veya başka bir uzantı kullanılabilir; uzantı, dosya biçimini belirlemez.

> [!CAUTION]
> Firmware çıkarma işleminin hassas olduğunu ve çok sabır gerektirdiğini unutmayın. Yanlış bir işlem firmware'i bozabilir, hatta tamamen silebilir ve cihazı kullanılamaz hâle getirebilir. Firmware'i çıkarmaya çalışmadan önce ilgili cihazı incelemeniz önerilir.

### Bus Pirate + flashrom

![CH341A EEPROM Programlayıcı ve Okuyucu - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Bazı veri sayfalarında hedef pinler `DI` ve `DO` olarak etiketlenir: tek veri hattı kullanan standart bir flash bağlantısında denetleyici **MOSI/COPI**, `DI` pinine; denetleyici **MISO/CIPO** ise `DO` pinine bağlanır. Çift/kuad I/O bileşenlerinde pinler diğer modlarda yeniden kullanıldığından, hedefin veri sayfasını kontrol edin.

![CH341A EEPROM Programlayıcı ve Okuyucu - Bus Pirate + flashrom: Pirate Bus'ın PINOUT'u SPI'ye bağlanacak MOSI ve MISO pinlerini gösterse bile bazı SPI'lar...](<../../images/image (360).png>)

Windows veya Linux'ta, flash belleğin içeriğini aşağıdakine benzer bir komutla dökmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanabilirsiniz:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Güncel Bus Pirate belgelerinde isteğe bağlı `serialspeed` ve `spispeed` parametreleri de gösteriliyor. Uzun kablolar veya devre içi yükleme okumaları kararsız hâle getiriyorsa düşük hızla başlayın.<sup>[[3]](#references)</sup>

### Kontrolcü flash veri yolunu paylaşıyorsa devre içi okumalar

SOIC klipsi, flash beslemesini PCB'nin geri kalanına aktarabilir. MCU bu durumda güç alıp aynı çipe erişirse SPI aktarımları harici programlayıcının aktarımlarıyla çakışabilir. Bu nedenle `No EEPROM/flash device found` sonucu, flash'ın mevcut olmadığını veya desteklenmediğini kanıtlamaz. Önce pin dizilimini, gerilimi ve teması kontrol edin; ardından kart üzerindeki kontrolcünün de etkin olup olmadığını belirleyin.<sup>[[4]](#references)</sup>

Bir reset test pedi varsa, reset uygulamadan önce ölçü aletiyle polaritesini ve gerilimini doğrulayın. MCU'yu reset durumunda tutmak, rakip SPI ana makinesini durdururken flash'a erişimi mümkün kılabilir. Alternatifler arasında çipi sökmek veya MCU'nun okumalarını pasif olarak kaydetmek bulunur. İkinci yöntem, henüz okunmamış bölgelere erişemez veya çipe yazamaz; ayrıca ek prob kabloları yüksek hızlı veri yolunu bozabilir. Osilatöre veya önyükleme moduna müdahale hedefe özgüdür; şemayı ve sinyalleri kontrol etmenin yerini tutmaz.<sup>[[4]](#references)</sup>

MCU devre dışı tutulduğunda, etkinleştirilmiş `spidev` arabirimine sahip bir Raspberry Pi, flashrom'un `linux_spi` programlayıcısı üzerinden okuma yapabilir. Farklı bir adaptör kullanıyorsanız `-p` değerini değiştirin. Okumayı tekrarlayın ve sonuca güvenmeden önce hash'leri karşılaştırın; SFDP otomatik algılaması ve başarılı bir okuma, aksi hâlde desteklenmeyen bir parçada silme, yazma veya yazma koruması işlemlerinin çalıştığını **kanıtlamaz**.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Logic analyzer ile SPI flash okumalarını yeniden oluşturma

Aktif okuma mümkün olmadığında, açılış sırasında veya seçilen bir UI eylemi sırasında chip select, clock, denetleyiciden flash'a giden veriyi ve flash'tan denetleyiciye giden veriyi yakalayın. PulseView'de önce etkin chip-select aralığını ve clock'u belirleyin, ardından flash pinout'unu kullanarak SPI decoder'ın veri kanallarını yapılandırın ve makul bir komut/adresin ardından döndürülen baytların geldiğini doğrulayın. **MISO/flash-output** baytlarını Binary Decoder Output View ile dışa aktarın ve her yanıtın ilgili flash offset'ine yerleştirilebilmesi için çözümlenen okuma adreslerini koruyun. Yalnızca menü üzerinden yapılan okumaları yakalamak, tam bir flash imajı değil, yalnızca istenen bölgeleri verir; adresleri kontrol etmeden yanıtları bitişikmiş gibi birleştirmeyin.<sup>[[4]](#references)</sup>

Bir dump, çalıştırılabilir kod yerine grafik içeriyor gibi görünüyorsa [ham ekran varlığı triyajı](../firmware-analysis/#raw-display-assets-in-external-flash) ile devam edin.<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — SPI Arayüzüne Giriş](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom kılavuzu — CH341A SPI programlayıcısı ve okuma/yazma seçenekleri](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate belgeleri — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Donanım Hacking Bilgilerini Tazeleme, Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
