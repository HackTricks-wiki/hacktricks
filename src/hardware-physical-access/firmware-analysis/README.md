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


Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yöneterek cihazların doğru çalışmasını sağlayan hayati öneme sahip yazılımdır. Kalıcı bellekte saklanır ve cihazın açıldığı andan itibaren gerekli talimatlara erişmesini sağlayarak işletim sisteminin başlatılmasına olanak tanır. Firmware'in incelenmesi ve potansiyel olarak değiştirilmesi, güvenlik açıklarını tespit etmede kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç şu verileri toplamayı içerir:

- Çalıştığı CPU mimarisi ve işletim sistemi
- Bootloader ile ilgili detaylar
- Donanım düzeni ve veri sayfaları
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen zayıflıklar

Bu amaç için, **open-source intelligence (OSINT)** araçları çok değerlidir; mevcut açık kaynak yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de aynen önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware Edinme**

Firmware elde etme çeşitli yollarla yaklaşılabilir ve her birinin kendi zorluk seviyesi vardır:

- **Doğrudan** kaynaktan (geliştiriciler, üreticiler)
- Sağlanan talimatlardan **derleyerek** oluşturma
- **Resmi destek sitelerinden indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlar kullanarak **bulut depolamaya** doğrudan erişim
- man-in-the-middle teknikleriyle **güncellemeleri** yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkartma**
- Cihaz iletişiminde **sniffing** ile güncelleme isteklerini yakalama
- **Sabit kodlanmış güncelleme uç noktalarını** tespit edip kullanma
- Bootloader'dan veya ağdan **dump alma**
- Başka çare kalmadığında uygun donanım araçları kullanarak **depolama çipini çıkarma ve okuma**

## Firmware'i Analiz Etme

Artık **firmware'e sahip olduğunuzda**, nasıl işlem yapacağınızı bilmek için ondan bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Ayrıca, bu araçları **firmware içine gömülü dosyaları** çıkarmak için kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Dosya Sistemi Elde Etme

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd command** ile Squashfs filesystem carving yapın.
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

## Firmware Analizi

Firmware elde edildikten sonra yapısını ve olası zafiyetlerini anlamak için detaylı inceleme yapmak önemlidir. Bu süreç, firmware imajından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın (`<bin>` olarak anılacaktır) ilk incelenmesi için bir dizi komut verilmiştir. Bu komutlar dosya türlerini belirlemeye, stringleri çıkarmaya, ikili veriyi analiz etmeye ve partition ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın şifreleme durumunu değerlendirmek için, **entropi** `binwalk -E <bin>` ile kontrol edilir. Düşük entropi şifreleme eksikliğine işaret ederken, yüksek entropi olası şifreleme veya sıkıştırma olduğunu gösterir.

Gömülü dosyaları çıkarmak için, dosya incelemesi için **file-data-carving-recovery-tools** dokümantasyonu ve **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; çoğu zaman dosya sistemi türünün adına göre bir dizine (ör. squashfs, ubifs) yerleştirilir. Ancak **binwalk** magic bytes eksikliği nedeniyle dosya sistemi türünü tanıyamadığında, manuel çıkarma gerekir. Bu, dosya sisteminin offset'ini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini çıkarmak için `dd` komutunu çalıştırmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ardından, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak, içeriği elle çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıkları aranmaya başlanır. Dikkat, güvensiz network daemon'ları, hardcoded kimlik bilgileri, API endpoint'leri, update server işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş ikili dosyalara verilir.

**İncelenmesi gereken önemli konumlar** ve **öğeler** şunlardır:

- **etc/shadow** ve **etc/passwd** kullanıcı kimlik bilgileri için
- **etc/ssl** içindeki SSL sertifikaları ve anahtarlar
- Potansiyel güvenlik açıkları için yapılandırma ve betik dosyaları
- İleri analiz için gömülü ikili dosyalar
- Yaygın IoT cihaz web sunucuları ve ikili dosyalar

Dosya sistemi içinde hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan birkaç araç:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker) hassas bilgi arama için
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kapsamlı firmware analizi için
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba) statik ve dinamik analiz için

### Derlenmiş İkili Dosyalarda Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş ikili dosyalar güvenlik açıkları açısından dikkatle incelenmelidir. Unix ikili dosyaları için **checksec.sh**, Windows ikili dosyaları için **PESecurity** gibi araçlar, istismar edilebilecek korumasız ikili dosyaları tespit etmeye yardımcı olur.

## Firmware'i Emüle Etme (dynamic analysis için)

Firmware emülasyonu süreci, bir cihazın çalışmasının veya bireysel bir programın **dynamic analysis**'ına olanak sağlar. Bu yaklaşım donanım veya mimari bağımlılıklarla karşılaşabilir, ancak root dosya sistemini veya belirli ikili dosyaları, mimarisi ve endianness'i eşleşen bir cihaza (ör. Raspberry Pi) veya önceden hazırlanmış bir sanal makineye aktarmak, ek testleri kolaylaştırabilir.

### Bireysel İkili Dosyaların Emülasyonu

Tek bir programı incelerken, programın endianness ve CPU mimarisini belirlemek kritik önemdedir.

#### MIPS Mimarisi ile Örnek

MIPS mimarili bir ikili dosyayı emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

ARM ikili dosyaları için süreç benzer; emülasyon için `qemu-arm` emulator kullanılır.

### Full System Emulation

Firmadyne, Firmware Analysis Toolkit ve benzeri araçlar tam firmware emülasyonunu kolaylaştırır; süreci otomatikleştirir ve dynamic analysis sırasında yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analiz için ya gerçek bir cihaz ya da emüle edilmiş bir device ortamı kullanılır. OS ve filesystem üzerinde shell access sağlamayı sürdürmek kritiktir. Emulation donanım etkileşimlerini tam olarak taklit etmeyebilir; bu yüzden zaman zaman emulation yeniden başlatılması gerekebilir. Analiz sırasında filesystem yeniden incelenmeli, açığa çıkan webpages ve network services üzerinden exploit denenmeli ve bootloader zafiyetleri araştırılmalıdır. Firmware integrity tests, potansiyel backdoor zafiyetlerini tespit etmek için kritiktir.

## Runtime Analysis Techniques

Runtime analysis, bir process veya binary ile onun işletim ortamında etkileşim kurmayı içerir; gdb-multiarch, Frida ve Ghidra gibi araçlarla breakpoint koyma ve fuzzing ile zayıflıkları tespit etme gibi yöntemler kullanılır.

## Binary Exploitation and Proof-of-Concept

Belirlenen zafiyetler için PoC geliştirmek, hedef architecture hakkında derin bilgi ve düşük seviyeli dillerde programlama gerektirir. Embedded sistemlerde binary runtime protections nadirdir, ancak mevcutsa Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, gerekli araçlarla ön-yapılandırılmış firmware security testing ortamları sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerine yardımcı olmak için tasarlanmış bir distro. Ön-yapılandırılmış bir environment ve gerekli tüm araçları sağlayarak çokça zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 tabanlı, firmware security testing araçları ile ön-yüklü embedded security testing işletim sistemi.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **sürüm geri alma (downgrade) koruması sıklıkla ihmal edilir**. Eğer boot- veya recovery-loader embedded public key ile sadece signature doğrulaması yapıyor ama flash edilen imajın *version* (veya monotonic counter) karşılaştırmasını yapmıyorsa, attacker geçerli bir signature taşıyan **daha eski, vulnerable firmware** yükleyerek patched zafiyetleri yeniden sisteme sokabilir.

Typical attack workflow:

1. **Obtain an older signed image**
* Vendor’ın public download portalı, CDN veya support sitesinden alın.
* Companion mobile/desktop uygulamalarından çıkartın (ör. bir Android APK içinde `assets/firmware/`).
* VirusTotal, internet archives, forumlar gibi third-party repository’lerden temin edin.
2. **Upload or serve the image to the device** herhangi bir exposed update channel üzerinden:
* Web UI, mobile-app API, USB, TFTP, MQTT, vb.
* Birçok consumer IoT device, Base64-encoded firmware blob’larını kabul eden, sunucu tarafında decode eden ve recovery/upgrade tetikleyen *unauthenticated* HTTP(S) endpoint’leri açar.
3. Downgrade sonrası, yeni sürümde patchlenmiş olan bir zafiyeti exploit edin (örneğin sonradan eklenen bir command-injection filter’ı).
4. İsteğe bağlı olarak persistence sağlandıktan sonra detection’ı engellemek için en son image’i tekrar flash edin veya updates’i disable edin.

### Örnek: Downgrade Sonrası Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Zafiyetli (downgraded) firmware'de, `md5` parametresi temizlenmeden doğrudan bir shell komutuna eklenir; bu da rastgele komut enjeksiyonuna izin verir (burada – SSH anahtar tabanlı root erişimini etkinleştirme). Daha sonraki firmware sürümleri temel bir karakter filtresi ekledi, ancak downgrade protection'un olmaması bu düzeltmeyi anlamsız kılıyor.

### Mobil Uygulamalardan Firmware Çıkarma

Birçok satıcı, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için eşlik eden mobil uygulamalarının içinde tam firmware görüntülerini paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya hatta basit `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalanmış imajları çıkarmanıza olanak tanır.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirme Kontrol Listesi

* *update endpoint*'in transport/authentication'ı yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter**'ı karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. imzalar ROM code tarafından kontrol ediliyor mu)?
* Userland code ek sağlamlık kontrolleri yapıyor mu (ör. allowed partition map, model number)?
* *partial* veya *backup* update flows aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Eğer yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback attacks'e karşı savunmasızdır.

## Pratik için zafiyetli firmware

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
