# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

## **Giriş**

Firmware, cihazların doğru bir şekilde çalışmasını sağlayan ve donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasında iletişimi yönetip kolaylaştıran temel yazılımdır. Kalıcı bellekte depolanır, böylece cihaz açıldığında kritik talimatlara erişebilir ve işletim sisteminin başlatılmasını sağlar. Firmware'i incelemek ve potansiyel olarak değiştirmek, güvenlik açıklarını belirlemede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik bir başlangıç adımıdır. Bu süreç, aşağıdaki verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştığı işletim sistemi
- Bootloader ayrıntıları
- Donanım düzeni ve veri sayfaları
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen açıklar

Bu amaçla, **açık kaynak istihbaratı (OSINT)** araçları çok değerlidir; ayrıca mevcut açık kaynak yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analizi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’nin LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware edinmek, her biri kendi karmaşıklık seviyesine sahip çeşitli yollarla gerçekleştirilebilir:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
- Verilen talimatlardan **oluşturarak**
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorguları kullanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **bulut depolama** alanlarına doğrudan erişerek
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalayarak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar aracılığıyla cihazdan **çıkararak**
- Cihaz iletişimi içinde güncelleme taleplerini **dinleyerek**
- **Sabit kodlu güncelleme uç noktalarını** tanımlayıp kullanarak
- Bootloader veya ağdan **dump** alarak
- Tüm bunlar başarısız olursa, uygun donanım araçları kullanarak depolama çipini **çıkartıp okuyarak**

## Firmware'i Analiz Etme

Artık **firmware'e sahip olduğunuzda**, ona nasıl yaklaşacağınızı bilmek için bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok şey bulamazsanız, görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin, düşük entropi varsa, muhtemelen şifrelenmemiştir. Yüksek entropi varsa, muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları **firmware içinde gömülü dosyaları çıkarmak için** kullanabilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki yorumlanan araçlarla `binwalk -ev <bin>` kullanarak **dosya sistemini çıkarmış olmalısınız**.\
Binwalk genellikle bunu **dosya sistemi türüyle adlandırılan bir klasörün içine çıkarır**, bu genellikle aşağıdakilerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkartma

Bazen, binwalk **dosya sisteminin sihirli baytını imzalarında bulamayabilir**. Bu durumlarda, binwalk'ı kullanarak **dosya sisteminin ofsetini bulun ve sıkıştırılmış dosya sistemini** ikili dosyadan çıkarın ve **aşağıdaki adımları kullanarak** dosya sistemini türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd komutunu** çalıştırarak Squashfs dosya sistemini çıkarın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs için (yukarıdaki örnekte kullanılmıştır)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra "`squashfs-root`" dizininde olacaktır.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash ile ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve potansiyel zayıflıklarını anlamak için parçalanması önemlidir. Bu süreç, firmware görüntüsünden değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İlk inceleme için bir dizi komut sağlanmıştır ( `<bin>` olarak adlandırılan ikili dosya için). Bu komutlar dosya türlerini tanımlamaya, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ve dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için **entropy** `binwalk -E <bin>` ile kontrol edilir. Düşük entropy, şifreleme eksikliğini gösterirken, yüksek entropy olası şifreleme veya sıkıştırmayı belirtir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanarak, genellikle dosya sistemini çıkarmak mümkündür, genellikle dosya sistemi türüyle adlandırılan bir dizine (örneğin, squashfs, ubifs) çıkarılır. Ancak, **binwalk** sihirli baytların eksikliği nedeniyle dosya sistemi türünü tanımadığında, manuel çıkarma gereklidir. Bu, dosya sisteminin ofsetini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini çıkarmak için `dd` komutunu kullanmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Sonrasında, dosya sistemi türüne (örneğin, squashfs, cpio, jffs2, ubifs) bağlı olarak, içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıkları arayışına başlanır. Güvensiz ağ daemon'larına, hardcoded kimlik bilgilerine, API uç noktalarına, güncelleme sunucusu işlevlerine, derlenmemiş koda, başlangıç betiklerine ve çevrimdışı analiz için derlenmiş ikililere dikkat edilir.

**Ana konumlar** ve **incelemesi gereken öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Potansiyel güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha fazla analiz için gömülü ikililer
- Yaygın IoT cihazı web sunucuları ve ikilileri

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan birkaç araç vardır:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker) hassas bilgi arayışı için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba) statik ve dinamik analiz için

### Derlenmiş İkililer Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikililer güvenlik açıkları açısından incelenmelidir. Unix ikilileri için **checksec.sh** ve Windows ikilileri için **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikilileri tanımlamaya yardımcı olur.

## Dinamik Analiz için Firmware Taklit Etme

Firmware taklit etme süreci, bir cihazın çalışmasını veya bireysel bir programı **dinamik analiz** etmeyi sağlar. Bu yaklaşım, donanım veya mimari bağımlılıkları ile zorluklarla karşılaşabilir, ancak kök dosya sistemini veya belirli ikilileri, Raspberry Pi gibi eşleşen mimari ve endianlıkta bir cihaza veya önceden oluşturulmuş bir sanal makineye aktarmak, daha fazla test yapmayı kolaylaştırabilir.

### Bireysel İkilileri Taklit Etme

Tek programları incelemek için, programın endianlığını ve CPU mimarisini belirlemek kritik öneme sahiptir.

#### MIPS Mimarisi ile Örnek

MIPS mimarisi ikilisini taklit etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılırken, little-endian ikili dosyalar için `qemu-mipsel` tercih edilir.

#### ARM Mimari Emülasyonu

ARM ikili dosyaları için süreç benzerdir, emülasyon için `qemu-arm` emülatörü kullanılır.

### Tam Sistem Emülasyonu

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tam firmware emülasyonunu kolaylaştırarak süreci otomatikleştirir ve dinamik analize yardımcı olur.

## Pratikte Dinamik Analiz

Bu aşamada, analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve dosya sistemine shell erişimini sürdürmek önemlidir. Emülasyon, donanım etkileşimlerini mükemmel bir şekilde taklit etmeyebilir, bu nedenle ara sıra emülasyonun yeniden başlatılması gerekebilir. Analiz, dosya sistemini yeniden gözden geçirmeli, açığa çıkan web sayfalarını ve ağ hizmetlerini istismar etmeli ve önyükleyici zafiyetlerini keşfetmelidir. Firmware bütünlüğü testleri, potansiyel arka kapı zafiyetlerini belirlemek için kritik öneme sahiptir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya ikili dosya ile işletim ortamında etkileşimde bulunmayı içerir; gdb-multiarch, Frida ve Ghidra gibi araçlar, kesme noktaları ayarlamak ve fuzzing ve diğer teknikler aracılığıyla zafiyetleri tanımlamak için kullanılır.

## İkili İstismar ve Kanıt Konsepti

Belirlenen zafiyetler için bir PoC geliştirmek, hedef mimarinin derin bir anlayışını ve daha düşük seviyeli dillerde programlama bilgisi gerektirir. Gömülü sistemlerde ikili çalışma zamanı korumaları nadirdir, ancak mevcut olduğunda, Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

## Firmware Analizi için Hazırlanmış İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış firmware güvenlik testleri için önceden yapılandırılmış ortamlar sağlar.

## Firmware Analiz Etmek için Hazırlanmış OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının güvenlik değerlendirmesi ve penetrasyon testini gerçekleştirmenize yardımcı olmak için tasarlanmış bir dağıtımdır. Tüm gerekli araçların yüklü olduğu önceden yapılandırılmış bir ortam sunarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Gömülü güvenlik test işletim sistemi, firmware güvenlik test araçları ile önceden yüklenmiş Ubuntu 18.04 tabanlıdır.

## Pratik Yapmak için Zayıf Firmware

Firmware'deki zafiyetleri keşfetmek için pratik yapmak amacıyla aşağıdaki zayıf firmware projelerini başlangıç noktası olarak kullanın.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Damn Vulnerable Router Firmware Projesi
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referanslar

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
