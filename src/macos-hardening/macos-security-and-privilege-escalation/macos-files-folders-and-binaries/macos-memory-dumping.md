# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, such as `/private/var/vm/swapfile0`, **fiziksel bellek dolduğunda önbellek olarak** görev yapar. Fiziksel bellekte artık yer kalmadığında, verisi bir swap file’a aktarılır ve gerektiğinde tekrar fiziksel belleğe geri getirilir. swapfile0, swapfile1 ve benzeri adlarla birden fazla swap file bulunabilir.

### Hibernate Image

`/private/var/vm/sleepimage` konumundaki dosya, **hibernation mode** sırasında kritik öneme sahiptir. **OS X hibernate olduğunda bellek verisi bu dosyada saklanır**. Bilgisayar uyandığında, sistem bu dosyadan bellek verilerini alır ve kullanıcının kaldığı yerden devam etmesini sağlar.

Modern MacOS sistemlerinde bu dosyanın güvenlik nedenleriyle genellikle şifrelendiğini ve bu yüzden kurtarmanın zor olduğunu belirtmek gerekir.

- sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifreli olup olmadığını gösterir.

### Memory Pressure Logs

MacOS sistemlerinde bellekle ilgili bir diğer önemli dosya **memory pressure log**’dur. Bu loglar `/var/log` içinde bulunur ve sistemin bellek kullanımına ve pressure olaylarına dair ayrıntılı bilgi içerir. Özellikle bellekle ilgili sorunları teşhis etmek veya sistemin zaman içinde belleği nasıl yönettiğini anlamak için çok faydalı olabilirler.

## Dumping memory with osxpmem

Bir MacOS makinede belleği dump etmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Bu yöntem artık büyük ölçüde **legacy workflow** sayılır. `osxpmem` bir kernel extension yüklemeye bağlıdır, [Rekall](https://github.com/google/rekall) projesi arşivlenmiştir, en son sürüm **2017** tarihli ve yayımlanan binary **Intel Macs** hedefler. Güncel macOS sürümlerinde, özellikle **Apple Silicon** üzerinde, kext tabanlı tam RAM acquisition genellikle modern kernel-extension kısıtlamaları, SIP ve platform-signing gereksinimleri nedeniyle engellenir. Pratikte, modern sistemlerde çoğu zaman tüm RAM image yerine **process-scoped dump** almak zorunda kalırsınız.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer şu hatayı bulursanız: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Bunu şu şekilde düzeltebilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar** "Security & Privacy --> General" içinde **kext’in yüklenmesine izin vererek** düzeltilebilir, sadece **izin verin**.

Uygulamayı indirmek, kext’i yüklemek ve belleği dökmek için bu **oneliner**’ı da kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB ile canlı süreç dökümü

**Son macOS sürümleri** için, en pratik yaklaşım genellikle tüm fiziksel belleği görüntülemeye çalışmak yerine **belirli bir sürecin** belleğini dökmektir.

LLDB, canlı bir hedeften Mach-O core dosyası kaydedebilir:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Varsayılan olarak bu genellikle bir **skinny core** oluşturur. LLDB'nin tüm eşlenmiş process memory'yi dahil etmesini zorlamak için:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Döküm almadan önce yararlı takip komutları:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Bu genellikle, amaç kurtarmak olduğunda yeterlidir:

- Decrypted configuration blobs
- In-memory tokenlar, cookie'ler veya credentials
- Yalnızca at rest korunmuş plaintext secrets
- Unpacking / JIT / runtime patching sonrası decrypted Mach-O sayfaları

Hedef **hardened runtime** ile korunuyorsa veya `taskgated` attach işlemini reddediyorsa, genellikle şu koşullardan birine ihtiyacınız olur:

- Hedefte **`get-task-allow`** vardır
- Debugger’ınız uygun **debugger entitlement** ile imzalanmıştır
- **root** olarak çalışıyorsunuz ve hedef hardened olmayan bir third-party process’tir

Bir task port elde etme ve onunla neler yapılabileceği hakkında daha fazla arka plan için:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida için zaman harcamadan önce, hedefin gerçekten **dumpable** olup olmadığını hızlıca doğrulayın:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operasyonel olarak bu genellikle şunlar anlamına gelir:

- **`get-task-allow`** ile dağıtılan üçüncü taraf bir app, çoğu zaman LLDB ile doğrudan dump edilebilir ve ortaya çıkan dump, app’in zaten erişmiş olduğu TCC-korumalı verileri açığa çıkarabilir.
- **hardened** bir hedef, `get-task-allow` olmadan, ilgili debugger entitlements / policy yolunu kontrol etmediğiniz sürece, **root** olarak bile attach isteklerini genellikle reddeder.
- Unhardened üçüncü taraf process’ler, `lldb`, `vmmap`, Frida veya özel `task_for_pid`/`vm_read` okuyucuları kullanmak için hâlâ en kolay yerdir.

## Frida veya userland reader’larla seçici dump’lar

Tam bir core çok gürültülüyse, yalnızca **ilginç okunabilir aralıkları** dump etmek çoğu zaman daha hızlıdır. Frida özellikle kullanışlıdır çünkü process’e attach olabildiğiniz anda **hedefli extraction** için iyi çalışır.

Örnek yaklaşım:

1. Okunabilir/yazılabilir aralıkları enumerate et
2. module, heap, stack veya anonymous memory’ye göre filtrele
3. Yalnızca aday string’ler, key’ler, protobuf’lar, plist/XML blob’ları veya decrypt edilmiş code/data içeren region’ları dump et

Tüm okunabilir anonymous range’leri dump etmek için minimal Frida örneği:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Bu, devasa core dosyalarından kaçınmak ve yalnızca şunları toplamak istediğinizde kullanışlıdır:

- Secrets içeren App heap chunks
- Custom packers veya loaders tarafından oluşturulan anonymous regions
- Protections değiştirildikten sonra JIT / unpacked code pages

[`readmem`](https://github.com/gdbinit/readmem) gibi eski userland tools da vardır, ancak bunlar esas olarak doğrudan `task_for_pid`/`vm_read` tarzı dumping için **source references** olarak kullanışlıdır ve modern Apple Silicon workflows için iyi bakımı yapılmamıştır.

## Heap / VM snapshots with `.memgraph`

Eğer öncelikle **heap objects**, **allocation provenance** veya başka bir makineye taşınabilen bir snapshot ile ilgileniyorsanız, `.memgraph` çoğu zaman devasa bir Mach-O core dosyasından daha pratiktir. `leaks` tooling bunu canlı bir process’ten oluşturabilir:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Sonra standart Apple tooling ile bunu offline olarak triage edin:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups`, `-fullContent` capture’ı saklamanın ana nedenidir, çünkü bellek içeriğini açıklayan etiketler minimal bir `.memgraph` içinde çıkarılır.

Bu özellikle şu durumlarda faydalıdır:

- Tam bir core yerine **daha küçük, paylaşılabilir bir snapshot** istediğinizde
- `MallocStackLogging` etkinleştirildiğinde ve **allocation backtraces** istediğinizde
- Zaten **ilginç bir heap address** biliyorsanız ve `malloc_history` ile pivot yapmak istediğinizde
- Tam dump’ın gürültüye değip değmeyeceğine karar vermeden önce hızlı bir **VM/heap breakdown** gerektiğinde

## Swift-heavy targets: `swift-inspect`

Yüksek değerli veriyi **Swift runtime objects** içinde tutan uygulamalar için `swift-inspect`, LLDB veya Frida’ya iyi bir tamamlayıcı olabilir. Önce her şeyi dump etmek yerine, canlı bir süreçten belirli Swift runtime yapıları sorgulayabilirsiniz:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Bu, şunları belirlemek için kullanışlıdır:

- İlginç verileri tamponlayan büyük Swift dizileri
- Runtime sırasında yüklenen type'ları ortaya çıkaran metadata allocations
- Daha hedefli bir dump yapmadan önce Swift concurrency state (`Task`, actor, thread relationships)

Process'i zaten inceleyebildiğiniz durumlarda daha fazla object-level runtime triage için [memory içindeki objects üzerine ayrılmış sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.

## Hızlı triage notları

- `sysctl vm.swapusage`, **swap usage** ve swap'ın **encrypted** olup olmadığını kontrol etmek için hâlâ hızlı bir yoldur.
- `sleepimage` daha çok **hibernate/safe sleep** senaryoları için geçerlidir, ancak modern sistemler bunu yaygın olarak korur; bu yüzden güvenilir bir acquisition path olarak değil, **kontrol edilecek bir artifact kaynağı** olarak ele alınmalıdır.
- Yeni macOS sürümlerinde, **process-level dumping**, boot policy, SIP state ve kext loading üzerinde kontrolünüz yoksa, genellikle **full physical memory imaging**'den daha gerçekçidir.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
