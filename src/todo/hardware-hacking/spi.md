# SPI

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

SPI (Serial Peripheral Interface), embedded systems içinde IC'ler (Integrated Circuits) arasındaki kısa mesafeli iletişim için kullanılan Synchronous Serial Communication Protocol'dür. SPI Communication Protocol, Clock ve Chip Select Signal tarafından yönetilen master-slave mimarisini kullanır. Master-slave mimarisi, EEPROM, sensörler, kontrol cihazları vb. harici peripheral'ları yöneten bir master'dan (genellikle bir microprocessor) oluşur; bu harici peripheral'lar slave olarak kabul edilir.

Bir master'a birden fazla slave bağlanabilir, ancak slave'ler birbirleriyle iletişim kuramaz. Slave'ler clock ve chip select olmak üzere iki pin tarafından yönetilir. SPI bir synchronous communication protocol olduğundan, input ve output pin'leri clock signal'larını takip eder. Chip select, master tarafından bir slave'i seçmek ve onunla etkileşim kurmak için kullanılır. Chip select high olduğunda slave device seçilmemiştir; low olduğunda ise chip seçilmiştir ve master slave ile etkileşim kurar.

MOSI (Master Out, Slave In) ve MISO (Master In, Slave Out), veri gönderme ve alma işlemlerinden sorumludur. Veri, chip select low tutulurken MOSI pini üzerinden slave device'a gönderilir. Input data, slave device vendor'ının datasheet'ine göre instruction'lar, memory address'ler veya data içerir. Geçerli bir input alındığında MISO pini, master'a data iletmekten sorumludur. Output data, input sona erdikten sonraki clock cycle'da gönderilir. MISO pin'leri, data tamamen iletilene veya master chip select pin'ini high yapana kadar data iletir (bu durumda slave iletimi durdurur ve master bu clock cycle'dan sonra dinlemez).

## EEPROM'lardan Firmware Dumping

Firmware dumping, firmware'i analiz etmek ve içindeki vulnerability'leri bulmak için faydalı olabilir. Çoğu zaman firmware internet üzerinde mevcut değildir veya model number, version vb. faktörlerdeki farklılıklar nedeniyle geçersizdir. Bu nedenle firmware'i doğrudan physical device'dan çıkarmak, threat hunting sırasında spesifik sonuçlar elde etmek için faydalı olabilir.

Serial Console edinmek faydalı olabilir, ancak çoğu zaman dosyaların read-only olduğu görülür. Bu durum, çeşitli nedenlerden dolayı analizi kısıtlar. Örneğin package göndermek ve almak için gerekli tool'lar firmware'de bulunmayabilir. Bu nedenle binary'leri reverse engineer etmek üzere çıkarmak uygulanabilir değildir. Dolayısıyla tüm firmware'in system'e dump edilmesi ve analiz için binary'lerin çıkarılması çok faydalı olabilir.

Ayrıca red teaming sırasında ve device'lara physical access elde edildiğinde firmware dumping, dosyaların değiştirilmesine veya malicious file'ların inject edilmesine ve ardından memory'ye yeniden flash'lanmasına yardımcı olabilir. Bu da device'a backdoor implant etmek için faydalı olabilir. Bu nedenle firmware dumping ile çok sayıda olasılığın önü açılabilir.

### CH341A EEPROM Programmer ve Reader

Bu device, EEPROM'lardan firmware dump etmek ve firmware file'larıyla yeniden flash'lamak için kullanılan ucuz bir tool'dur. Computer BIOS chip'leriyle (bunlar yalnızca EEPROM'dur) çalışmak için popüler bir tercihtir. Bu device USB üzerinden bağlanır ve çalışmaya başlamak için minimum tool gerektirir. Ayrıca genellikle işlemi hızlıca tamamlar; bu nedenle physical device access sırasında da faydalı olabilir.

![drawing](../../images/board_image_ch341a.jpg)

EEPROM memory'yi CH341a Programmer'a bağlayın ve device'ı computer'a takın. Device algılanmıyorsa computer'a driver yüklemeyi deneyin. Ayrıca EEPROM'un doğru yönde bağlandığından emin olun (genellikle VCC Pin'ini USB connector'a göre ters yönde yerleştirin); aksi takdirde software chip'i algılayamaz. Gerekirse diyagrama bakın:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Son olarak firmware'i dump etmek için flashrom, G-Flash (GUI) vb. software'leri kullanın. G-Flash, hızlı çalışan ve EEPROM'u otomatik olarak algılayan minimal bir GUI tool'udur. Firmware'in çok fazla documentation ile uğraşmadan hızlıca çıkarılması gerektiğinde faydalı olabilir.

![drawing](../../images/connected_status_ch341a.jpg)

Firmware dump edildikten sonra analiz binary file'lar üzerinde yapılabilir. strings, hexdump, xxd, binwalk vb. tool'lar firmware ve hatta tüm file system hakkında çok miktarda information çıkarmak için kullanılabilir.

Firmware içeriğini çıkarmak için binwalk kullanılabilir. Binwalk hex signature'larını analiz eder, binary file içindeki file'ları tespit eder ve bunları çıkarabilir.
```
binwalk -e <filename>
```
Bu, kullanılan araçlara ve yapılandırmalara bağlı olarak `.bin` veya `.rom` olabilir.

> [!CAUTION]
> Firmware extraction işleminin hassas bir süreç olduğunu ve büyük ölçüde sabır gerektirdiğini unutmayın. Yanlış bir işlem firmware'i bozabilir, hatta tamamen silebilir ve cihazı kullanılamaz hâle getirebilir. Firmware extraction işlemine başlamadan önce belirli cihazı incelemeniz önerilir.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Pirate Bus'un PINOUT'unda SPI'ye bağlanmak için **MOSI** ve **MISO** pinleri gösterilse bile bazı SPI'larda pinler DI ve DO olarak gösterilebilir. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Bus'un PINOUT'unda SPI'ye bağlanmak için MOSI ve MISO pinleri gösterilse bile bazı SPI'larda pinler...](<../../images/image (360).png>)

Windows veya Linux'ta, aşağıdakine benzer bir komut çalıştırarak flash memory içeriğini dump etmek için [**`flashrom`**](https://www.flashrom.org/Flashrom) programını kullanabilirsiniz:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
