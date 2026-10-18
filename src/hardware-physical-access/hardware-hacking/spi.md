# SPI

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

SPI (Serial Peripheral Interface), tümleşik devreler arasında kısa mesafeli iletişim için yaygın olarak kullanılan eşzamanlı bir seri veri yoludur. Bir controller saat sinyalini sağlar ve chip-select sinyali kullanarak EEPROM, sensör veya kontrol cihazı gibi bir peripheral'ı seçer.<sup>[[1]](#references)</sup>

Birden fazla peripheral, genellikle her peripheral için ayrı bir chip-select kullanılarak saat ve veri hatlarını paylaşabilir. Aktarımları controller yönetir; peripheral'lar normalde SPI veri yolu üzerinden doğrudan birbirleriyle iletişim kurmaz. Chip-select polaritesi ve zamanlaması cihaza özeldir; aktif-düşük seçim yaygın olsa da evrensel değildir. SPI; aygıt keşfi, adresleme, komutlar veya tek bir maksimum aktarım uzunluğu tanımlamaz. Bu nedenle her zaman hedefin datasheet'ine başvurun.<sup>[[1]](#references)</sup>

MOSI/COPI, controller'dan peripheral'a veri taşır; MISO/CIPO ise peripheral'dan controller'a veri taşır. Her iki yönde de aynı anda veri kaydırılabilir. Komut, adres, dummy cycle'lar ve döndürülen veriler arasındaki ilişki SPI tarafından değil, peripheral tarafından tanımlanır ve saat polaritesiyle fazına (mod 0–3) bağlıdır. Çıkışın, giriş sona erdikten tam bir saat darbesi sonra başlayacağını varsaymayın.<sup>[[1]](#references)</sup>

## EEPROM'lardan Firmware Dump Alma

Firmware dump'ı almak, firmware'i analiz etmek ve güvenlik açıkları bulmak için yararlı olabilir. Doğru imaj çevrimiçi olarak bulunamayabilir veya model, donanım revizyonu ya da sürüme göre farklılık gösterebilir. Bu nedenle imajı doğrudan fiziksel cihazdan çıkarmak, değerlendirme için kesin hedefi sağlar.

Bir seri konsol yardımcı olabilir; ancak dosya sistemi salt okunur olabilir ve hedefte test trafiği gönderip almak ya da ikili dosyaları kolayca çıkarmak için gereken araçlar da dahil olmak üzere analiz araçları bulunmayabilir. Çevrimdışı bir imaj, flash'ın tamamının düzenini korur ve çalışan hedefi değiştirmeden dosya sistemi çıkarma ve reverse engineering yapmaya olanak tanır.

Yetkili bir fiziksel değerlendirme sırasında doğrulanmış bir dump, kontrollü değiştirme ve yeniden flashlama testlerini de destekleyebilir. Buna dosyaları değiştirmek veya firmware seviyesinde kalıcılığı göstermek için bir test payload/backdoor enjekte etmek dahildir. Herhangi bir yazma işlemi yapmadan önce birbiriyle eşleşen birden fazla okuma ve orijinal imajı saklayın: yanlış voltaj, chip seçimi, düzen veya imaj cihazı kullanılmaz hâle getirebilir.

### CH341A EEPROM Programlayıcısı ve Okuyucusu

Bu uygun fiyatlı USB aracı, uyumlu seri EEPROM ve SPI flash cihazlarını dump edip yeniden flashlayabilir. Genellikle PC BIOS/UEFI firmware'ini saklayan SPI NOR flash chip'leriyle kullanılır ve fiziksel erişim süresi kısıtlı olduğunda kullanışlıdır.

![drawing](../../images/board_image_ch341a.jpg)

Flash belleği CH341A'ya bağlayın, ardından programlayıcıyı bilgisayara bağlayın. Programlayıcı algılanmazsa hedef chip'te sorun gidermeden önce USB kablosunu, işletim sistemi izinlerini ve uygun CH341A driver'ını kontrol edin. Chip'in voltajını, pin 1'i, adaptör kablolarını ve programlayıcı çıkışını datasheet'lerle veya bir ölçü aletiyle doğrulayın; VCC'yi USB konektörünün karşı tarafına yerleştirmek gibi bir kurala **güvenmeyin**. Yanlış yönde takmak veya 3.3/1.8 V'luk bir parçaya 5 V uygulamak parçayı bozabilir. Devre üzerindeki okumalar, kartın geri kalanının veri yoluna yük bindirmesi veya veri yoluna güç vermesi nedeniyle başarısız olabilir.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Chip'i okumak için `flashrom` veya G-Flash gibi yazılımlar kullanın. G-Flash, uyumlu cihazları otomatik algılayabilen basit bir GUI'dir ve hızlı edinim sırasında kullanışlı olabilir; ancak algılanan modeli ve voltajı kendiniz doğrulayın. Tam programlayıcıyı ve gerektiğinde tam chip modelini belirtin; dump'ı güvenilir kabul etmeden önce en az iki kez okuyun ve hash değerlerini karşılaştırın.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump'ı alındıktan sonra analiz ikili dosyalar üzerinde yapılabilir. Firmware ve tüm dosya sistemi hakkında çok miktarda bilgi çıkarmak için strings, hexdump, xxd, binwalk gibi araçlar kullanılabilir.

İlk inceleme için Binwalk, bilinen imzaları tarayabilir ve desteklediği gömülü içeriği çıkarabilir:

```
binwalk -e <filename>
```

Çıktı dosyası `.bin`, `.rom` veya başka bir uzantı kullanabilir; uzantı dosya biçimini belirlemez.

> [!CAUTION]
> Firmware çıkarma işleminin hassas olduğunu ve çok sabır gerektirdiğini unutmayın. Yanlış bir işlem firmware'i bozabilir, hatta tamamen silebilir ve cihazı kullanılamaz hâle getirebilir. Firmware'i çıkarmaya çalışmadan önce ilgili cihazı incelemeniz önerilir.

### Bus Pirate + flashrom

![CH341A EEPROM Programlayıcı ve Okuyucu - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Bazı veri sayfalarında hedef pinler `DI` ve `DO` olarak etiketlenir: geleneksel tek veri hatlı bir flash bağlantısında denetleyicinin **MOSI/COPI** pini **DI**'ye, denetleyicinin **MISO/CIPO** pini ise **DO**'ya bağlanır. Çift/quad I/O bileşenleri diğer modlarda aynı pinleri farklı amaçlarla kullanabildiğinden hedefin veri sayfasını doğrulayın.

![CH341A EEPROM Programlayıcı ve Okuyucu - Bus Pirate + flashrom: Pirate Bus'ın PINOUT'u SPI'ye bağlanmak için MOSI ve MISO pinlerini gösterse bile bazı SPI'lar...](<../../images/image (360).png>)

Windows veya Linux'ta, flash belleğin içeriğini dökmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını aşağıdakine benzer bir komutla kullanabilirsiniz:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

Güncel Bus Pirate belgeleri isteğe bağlı `serialspeed` ve `spispeed` parametrelerini de gösteriyor. Uzun kablolar veya devre içi yükleme okumaları kararsız hâle getiriyorsa düşük hızla başlayın.<sup>[[3]](#references)</sup>

### Denetleyici flash bus'ını paylaştığında devre içi okumalar

Bir SOIC klipsi, flash beslemesini PCB'nin geri kalanına iletebilir. MCU bu durumda güç alıyor ve aynı çipe erişiyorsa SPI aktarımları harici programlayıcının aktarımlarıyla çakışabilir. Bu nedenle `No EEPROM/flash device found` sonucu, flash'ın bulunmadığını veya desteklenmediğini kanıtlamaz. Önce pin dizilimini, gerilimi ve teması kontrol edin; ardından kart üzerindeki denetleyicinin de etkin olup olmadığını belirleyin.<sup>[[4]](#references)</sup>

Bir reset test pad'i varsa, reset uygulamadan önce bir ölçü aletiyle kutuplamasını ve gerilimini doğrulayın. MCU'yu reset durumunda tutmak, çakışan SPI ana bilgisayarını durdururken flash'a erişimi mümkün kılabilir. Alternatifler çipi sökmek veya MCU'nun okumalarını pasif olarak kaydetmektir; ikinci yöntem daha önce okunmamış bölgelere erişemez veya çipe yazamaz ve ek prob kabloları hızlı bir bus'ı bozabilir. Osilatöre veya boot mode'a müdahale etmek hedefe özgüdür; şemayı ve sinyalleri kontrol etmenin yerine geçmez.<sup>[[4]](#references)</sup>

MCU etkisiz hâle getirilmişken, `spidev` arayüzü etkinleştirilmiş bir Raspberry Pi, flashrom'un `linux_spi` programlayıcısı aracılığıyla okuma yapabilir. Farklı bir adaptör için `-p` seçeneğini değiştirin. Okumayı tekrarlayın ve güvenmeden önce hash'leri karşılaştırın; SFDP otomatik algılama ve başarılı bir okuma, başka açılardan desteklenmeyen bir parçada silme, yazma veya yazma koruması işlemlerinin çalıştığını **kanıtlamaz**.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### Logic analyzer ile SPI flash okumalarını yeniden oluşturma

Aktif okuma mümkün olmadığında, açılış sırasında veya seçilen bir UI eylemi esnasında chip select, clock, controller-to-flash data ve flash-to-controller data sinyallerini yakalayın. PulseView'da önce aktif chip-select aralığını ve clock sinyalini belirleyin, ardından flash pin dizilimini kullanarak SPI decoder'ın veri kanallarını yapılandırın ve makul bir komut/adresin ardından döndürülen baytların geldiğini doğrulayın. **MISO/flash-output** baytlarını Binary Decoder Output View ile dışa aktarın ve her yanıtın karşılık gelen flash offset'ine yerleştirilebilmesi için çözümlenen okuma adreslerini koruyun. Yalnızca menü üzerinden yapılan okumaları yakalamak, flash'ın tamamını değil, sadece istenen bölgeleri verir; adresleri kontrol etmeden yanıtları bitişikmiş gibi birleştirmeyin.<sup>[[4]](#references)</sup>

Grafik yerine yürütülebilir kod içeriyor gibi görünen bir dump için [raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash) ile devam edin.<sup>[[4]](#references)</sup>

#### Scapy ve karışık SPI/QSPI yakalamaları

Etiketlenmemiş problarda, yanıt verilerinden önce opcode taşıyan hattı bularak MOSI'yi MISO'dan ayırın, ardından komutu flash datasheet'iyle doğrulayın. Clock darbesinden daha kısa darbeler örneklenmiş bitler yerine prob gürültüsü olabilir; ayrıca klips kabloları yüksek hızlı yakalamaları güvenilmez hâle getirebilir.<sup>[[5]](#references)</sup>

Saleae'nin SPI CSV dışa aktarımı, chip-select aralığını sınırlamak için `enable` ve `disable` kullanır; MOSI/MISO baytları ise `result` satırlarında bulunur. Baytları çözümlemeden önce aralıklarına göre gruplayın; tüm MISO verilerini birleştirmek işlem adreslerini kaybettirir.<sup>[[5]](#references)</sup> Bir Scapy `Packet`, MOSI başlığını `ByteEnumField` opcode'u ve koşullu adres ve dummy alanlarıyla modelleyebilir. 24-bit NOR okumalarında `0x03`, bir opcode ve üç adres baytı içerirken `0x0B` buna bir dummy baytı ekler. `len(req.self_build())` modellenen başlık uzunluğunu verir: tek hatlı bir okumada `miso[header_length:]` flash yanıtıdır; başlıktan sonraki MOSI ise controller tarafında önemsenmeyen verilerdir.<sup>[[5]](#references)</sup> Yanıtları `0xFF` ile doldurulmuş bir imajda çözümlenen adreslerine yerleştirin ve kapsanan offset'leri ayrıca takip edin. Gözlemlenmeyen bir bayt, flash'ın o konumda `0xFF` tuttuğunun kanıtı değildir.<sup>[[5]](#references)[[6]](#references)</sup>

W25Q tarzı bir `0x6B` (1-1-4) okumasında opcode ve adres için tek hat, yanıt verisi içinse IO0–IO3 kullanılır. Eski `/WP` ve `/HOLD` pinlerindeki etkinlik, tek başına daha hızlı bir clock'tan daha güçlü bir quad-mode geçişi kanıtıdır; tek hatlı bir analyzer quad yanıtını yanlış çözümleyebilir.<sup>[[5]](#references)</sup> Bu aşamayı, komutun hat genişlikleri ve dummy cycle'larıyla yapılandırılmış bir QSPI analyzer ile dışa aktarın, ardından tek ve quad hatlı okumaları flash adreslerine göre birleştirin.<sup>[[5]](#references)[[7]](#references)</sup> `spidump` her iki dışa aktarım biçimini otomatik algılar, yanlış hat genişliğinde çözümlenen okumaları atar ve okuma kapsamını raporlar.<sup>[[6]](#references)</sup> Depodan, bağımlılıklarını yükledikten sonra, yakalamaları şu komutla birleştirin:<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

Sonuç, tam bir chip dump değil, sınırlı bir gözlem olarak kalır.<sup>[[5]](#references)[[6]](#references)</sup> Yazma işlemlerini ayrı incelemek için `0x06` write-enable, `0x05` durum sorgularını, silme opcode’larını ve `0x02` page-program komutlarını ilişkilendirin. Page-program verileri MOSI üzerinden adresin ardından gelir ve yalnızca okuma yapan yeniden yapılandırmaya dahil edilmez.<sup>[[5]](#references)</sup> Ortaya çıkan imajı, okuma kapsamı bilgilerini koruyarak [firmware analysis](../firmware-analysis/) ile analiz edin.

## References

- [1] [Analog Devices — SPI Arayüzüne Giriş](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom kılavuzu — CH341A SPI programlayıcısı ve okuma/yazma seçenekleri](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate belgeleri — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — Donanım Hacking Bilgilerini Tazeleme, Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — Donanım Tersine Mühendisliği için Scapy’yi Genişletme](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI iz yakalama ve yeniden yapılandırma](https://github.com/wrongbaud/spidump)
- [7] [Saleae Logic/KingstVIS için QSPI Analyzer](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
