# SPI

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

SPI (Serial Peripheral Interface), entegre devreler arasındaki kısa mesafeli iletişimde yaygın olarak kullanılan senkron bir serial bus'tır. Bir controller clock sinyalini sağlar ve chip-select sinyali kullanarak EEPROM, sensor veya control device gibi bir peripheral'ı seçer.<sup>[[1]](#references)</sup>

Birden fazla peripheral, clock ve data hatlarını paylaşabilir; normalde her peripheral için ayrı bir chip-select bulunur. Transferleri controller yönetir; peripheral'lar SPI bus üzerinden genellikle birbirleriyle doğrudan iletişim kurmaz. Chip-select polarity ve timing cihaza özeldir; active-low selection yaygındır ancak evrensel değildir. SPI; discovery, addressing, commands veya tek bir maximum transfer length tanımlamaz, bu nedenle her zaman hedef datasheet'ine başvurun.<sup>[[1]](#references)</sup>

MOSI/COPI, controller-to-peripheral data taşır; MISO/CIPO ise peripheral-to-controller data taşır. Her iki yön de aynı anda shift edilebilir. Bir command, address, dummy cycles ve döndürülen data arasındaki ilişki peripheral tarafından tanımlanır; SPI tarafından değil. Bu ilişki clock polarity ve phase'e (modes 0–3) bağlıdır. Output'un input sona erdikten tam olarak bir clock sonra başladığını varsaymayın.<sup>[[1]](#references)</sup>

## Dumping Firmware from EEPROMs

Firmware dumping, firmware'i analiz etmek ve vulnerabilities bulmak için yararlı olabilir. Doğru image çevrimiçi olarak bulunamayabilir veya model, hardware revision ya da version'a göre farklılık gösterebilir; bu nedenle firmware'i doğrudan physical device'dan çıkarmak, tam bir assessment target sağlar.

Bir serial console yardımcı olabilir, ancak filesystem'i read-only olabilir ve target'ta test traffic göndermek/almak veya binaries'leri uygun şekilde extract etmek için gereken utilities dahil olmak üzere analysis tools bulunmayabilir. Offline image, complete flash layout'u korur ve running target'ı değiştirmeden filesystem extraction ile reverse engineering yapılmasına olanak tanır.

Yetkili bir physical assessment sırasında verified dump, controlled modification ve reflashing tests için de kullanılabilir. Buna, firmware-level persistence'ı göstermek amacıyla dosyaları değiştirmek veya bir test payload/backdoor inject etmek dahildir. Herhangi bir write işleminden önce birbiriyle eşleşen birden fazla read'i ve original image'ı koruyun: yanlış voltage, chip selection, layout veya image cihazı brick edebilir.

### CH341A EEPROM Programmer and Reader

Bu düşük maliyetli USB tool, uyumlu serial EEPROM ve SPI flash device'larını dump ve reflash edebilir. PC BIOS/UEFI firmware'ini depolayan SPI NOR flash chip'leriyle yaygın olarak kullanılır ve süreyle sınırlı physical access sırasında kullanışlıdır.

![çizim](../../images/board_image_ch341a.jpg)

Flash memory'yi CH341A'ya bağlayın ve ardından programmer'ı computer'a bağlayın. Programmer'ın kendisi detect edilmezse target chip'i troubleshoot etmeden önce USB cable'ı, OS permissions'ı ve uygun CH341A driver'ını kontrol edin. Datasheet'ler veya bir meter kullanarak chip'in voltage'ını, pin 1'i, adapter wiring'ini ve programmer output'unu doğrulayın—**VCC'yi USB connector'ın karşısına yerleştirmek** gibi bir kurala güvenmeyin. Yanlış orientation veya 3.3/1.8 V'luk bir parçaya 5 V uygulanması parçayı bozabilir. In-circuit read işlemleri, board'un geri kalanının bus'ı yüklemesi veya beslemesi nedeniyle başarısız olabilir.<sup>[[2]](#references)</sup>

![çizim](../../images/connect_wires_ch341a.jpg) ![çizim](../../images/eeprom_plugged_ch341a.jpg)

Chip'i okumak için `flashrom` veya G-Flash gibi software'ler kullanın. G-Flash minimal bir GUI'dir ve uyumlu device'ları otomatik olarak detect edebilir; bu, hızlı acquisition sırasında kullanışlı olabilir, ancak detect edilen model ve voltage'ı kendiniz doğrulayın. Exact programmer'ı ve gerektiğinde exact chip model'ini belirtin; bir dump'ı reliable kabul etmeden önce en az iki read gerçekleştirin ve hash'lerini karşılaştırın.<sup>[[2]](#references)</sup>

![çizim](../../images/connected_status_ch341a.jpg)

Firmware dump edildikten sonra analysis binary files üzerinde yapılabilir. Firmware ve tüm filesystem hakkında çok miktarda information extract etmek için strings, hexdump, xxd, binwalk vb. tools kullanılabilir.

Initial triage için Binwalk, known signatures'ları tarayabilir ve supported embedded content'i extract edebilir:
```
binwalk -e <filename>
```
Çıktı dosyası `.bin`, `.rom` veya başka bir uzantı kullanabilir; uzantı formatı belirlemez.

> [!CAUTION]
> Firmware çıkarma işleminin hassas bir süreç olduğunu ve büyük ölçüde sabır gerektirdiğini unutmayın. Herhangi bir yanlış işlem firmware'i bozabilir, hatta tamamen silebilir ve cihazı kullanılamaz hâle getirebilir. Firmware'i çıkarmayı denemeden önce ilgili cihazı incelemeniz önerilir.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Bazı datasheet'lerde hedef pinleri `DI` ve `DO` olarak adlandırılır: geleneksel tek veri hatlı flash bağlantısında kontrolcü **MOSI/COPI, DI'ye bağlanır** ve kontrolcü **MISO/CIPO, DO'ya bağlanır**. Dual/quad I/O parçaları diğer modlarda pinleri yeniden kullandığından hedef datasheet'ini doğrulayın.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

Windows veya Linux'ta, flash belleğin içeriğini aşağıdakine benzer bir komut çalıştırarak almak için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanabilirsiniz:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Recent Bus Pirate dokümantasyonu isteğe bağlı `serialspeed` ve `spispeed` parametrelerini de gösterir. Uzun kablolar veya devre içi yükleme okumaların kararsız olmasına neden oluyorsa temkinli bir hızla başlayın.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI Arayüzüne Giriş](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom kılavuzu — CH341A SPI programlayıcısı ve okuma/yazma seçenekleri](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate dokümantasyonu — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
