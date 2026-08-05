# macOS Bellek Dökümü

{{#include ../../../banners/hacktricks-training.md}}

## Bellek Artefaktları

### Swap Dosyaları

`/private/var/vm/swapfile0` gibi swap dosyaları, **fiziksel bellek dolduğunda cache görevi görür**. Fiziksel bellekte daha fazla yer kalmadığında veriler bir swap dosyasına aktarılır ve gerektiğinde fiziksel belleğe geri getirilir. swapfile0, swapfile1 gibi adlara sahip birden fazla swap dosyası bulunabilir.

### Hibernate Image

`/private/var/vm/sleepimage` konumunda bulunan dosya, **hibernation mode** sırasında kritik bir rol oynar. **OS X hibernate olduğunda bellek verileri bu dosyada depolanır**. Bilgisayar uyandırıldığında sistem bellek verilerini bu dosyadan alır ve kullanıcının kaldığı yerden devam etmesini sağlar.

Modern MacOS sistemlerinde bu dosyanın güvenlik nedenleriyle genellikle şifreli olduğunu belirtmek gerekir; bu da kurtarmayı zorlaştırır.

- sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek üzere `sysctl vm.swapusage` komutu çalıştırılabilir. Bu komut dosyanın şifreli olup olmadığını gösterir.

### Memory Pressure Logları

MacOS sistemlerindeki bellekle ilgili bir diğer önemli dosya **memory pressure log** dosyasıdır. Bu loglar `/var/log` konumunda bulunur ve sistemin bellek kullanımı ile bellek pressure olayları hakkında ayrıntılı bilgiler içerir. Bellekle ilgili sorunları teşhis etmek veya sistemin zaman içinde belleği nasıl yönettiğini anlamak için özellikle yararlı olabilirler.

## osxpmem ile Bellek Dump Etme

Bir MacOS makinesinin belleğini dump etmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Bu artık çoğunlukla bir **legacy workflow**'dur. `osxpmem`, bir kernel extension yüklenmesine bağlıdır; [Rekall](https://github.com/google/rekall) projesi arşivlenmiştir, en son release **2017** yılına aittir ve yayımlanan binary **Intel Mac** cihazlarını hedefler. Güncel macOS release'lerinde, özellikle **Apple Silicon** üzerinde, kext tabanlı full-RAM acquisition genellikle modern kernel-extension kısıtlamaları, SIP ve platform-signing gereksinimleri tarafından engellenir. Pratikte modern sistemlerde çoğunlukla tüm RAM image'ı yerine **process-scoped dump** elde edersiniz.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Bu hatayla karşılaşırsanız: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Şunu yaparak düzeltebilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Security & Privacy --> General" bölümünde **kext'in yüklenmesine izin verilerek** düzeltilebilir; yalnızca **izin verin**.

Uygulamayı indirmek, kext'i yüklemek ve belleği dump etmek için şu **oneliner**'ı da kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB ile canlı process dumping

**recent macOS versions** için genellikle en pratik yaklaşım, tüm physical memory'yi image almaya çalışmak yerine **specific process** memory'sini dump etmektir.

LLDB, canlı bir target'tan Mach-O core file kaydedebilir:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Varsayılan olarak bu genellikle bir **skinny core** oluşturur. LLDB'yi eşlenen tüm process memory'yi dahil etmeye zorlamak için:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Dumping öncesi yararlı follow-up komutları:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Bu, amaç aşağıdakileri kurtarmak olduğunda genellikle yeterlidir:

- Decrypted configuration blobs
- Bellek içi token'lar, cookie'ler veya kimlik bilgileri
- Yalnızca at-rest korumasına sahip plaintext secret'lar
- Unpacking / JIT / runtime patching sonrasında decrypted Mach-O sayfaları

Hedef **hardened runtime** tarafından korunuyorsa veya `taskgated` attach işlemini reddediyorsa genellikle aşağıdaki koşullardan birine ihtiyacınız vardır:

- Hedefte **`get-task-allow`** bulunması
- Debugger'ınızın uygun **debugger entitlement** ile imzalanmış olması
- **root** olmanız ve hedefin hardened olmayan bir üçüncü taraf process'i olması

Bir task port elde etme ve bununla neler yapılabileceği hakkında daha fazla bilgi için:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida üzerinde zaman harcamadan önce, hedefin gerçekçi olarak **dumpable** olup olmadığını hızlıca doğrulayın:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Operasyonel olarak bu genellikle şu anlama gelir:

- **`get-task-allow`** ile gönderilen üçüncü taraf bir uygulama çoğu zaman LLDB ile doğrudan dump edilebilir ve ortaya çıkan dump, uygulamanın daha önce eriştiği TCC-korumalı verileri açığa çıkarabilir.<sup>[[1]](#references)</sup>
- **Hardened** bir hedef, ilgili debugger entitlements / policy path üzerinde kontrolünüz yoksa, **`root`** olsanız bile attach işlemlerini genellikle reddeder.
- Hardened olmayan üçüncü taraf process'ler, `lldb`, `vmmap`, Frida veya özel `task_for_pid`/`vm_read` reader'ları kullanmak için hâlâ en kolay yerdir.

### Dump edilebilir iç içe helper'ları arayın

Notarized macOS uygulamalarıyla ilgili güncel araştırmalar, ana GUI binary'si yerine iç içe helper'larda **`get-task-allow`** bulunduğunu göstermeye devam ediyor. Üst düzey bir uygulama hardened göründüğünde, vazgeçmeden önce **XPC services**, **login items**, **helper tools** ve bundle içindeki CLI'ları listeleyin:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` içeren iç içe bir executable, ana uygulama daha iyi hardening edilmiş olsa bile `lldb` ile attach olmak, bir core dump almak veya özel bir `task_for_pid` client ile memory çekmek için çoğu zaman en kolay yerdir.

## Frida veya userland readers ile seçici dump'lar

Tam bir core fazla gürültülü olduğunda yalnızca **ilgi çekici okunabilir aralıkları** dump etmek çoğu zaman daha hızlıdır. Frida özellikle, process'e attach olabildiğinizde **hedefli extraction** için oldukça kullanışlıdır.

Örnek yaklaşım:

1. Okunabilir/yazılabilir aralıkları enumerate edin
2. Module, heap, stack veya anonymous memory'e göre filtreleyin
3. Yalnızca candidate string'leri, key'leri, protobuf'ları, plist/XML blob'larını veya decrypted code/data içeren region'ları dump edin

Tüm okunabilir anonymous range'leri dump etmek için minimal Frida örneği:
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

- Secret içeren app heap chunk'ları
- Custom packer veya loader'lar tarafından oluşturulan anonymous region'lar
- Protection'ları değiştirdikten sonraki JIT / unpacked code page'leri

Target dump sırasında **allocation / free** işlemlerini sürdürüyorsa, unstable range'ler için `readByteArray()` yerine Frida'nın **`readVolatile()`** primitive'ini tercih edin. Daha yavaştır, ancak read işlemi sırasında bir page okunamaz hâle gelirse target'ın sonlanmasını önler. Daha büyük acquisition işlemlerinde, chunk'ları `send(..., data)` ile geri stream etmek ve target içinde binlerce küçük file oluşturmak yerine controller tarafında compress etmek de daha düzenli olabilir.

[`readmem`](https://github.com/gdbinit/readmem) gibi daha eski userland tool'ları da mevcuttur, ancak bunlar çoğunlukla doğrudan `task_for_pid`/`vm_read` tarzı dumping için **source reference** olarak kullanışlıdır ve modern Apple Silicon workflow'ları için iyi şekilde maintain edilmemektedir.

## `.memgraph` ile Heap / VM snapshot'ları

Öncelikli olarak **heap object'leri**, **allocation provenance** veya başka bir machine'e taşınabilecek bir snapshot ile ilgileniyorsanız, `.memgraph` genellikle devasa bir Mach-O core'dan daha pratiktir. `leaks` tooling, canlı bir process'ten bir tane oluşturabilir:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Ardından standart Apple araçlarını kullanarak offline triage edin:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups`, bellek içeriklerini açıklayan etiketler minimal bir `.memgraph` içinde bulunmadığından, `-fullContent` capture'ını saklamanın başlıca nedenidir.

Bu özellikle şu durumlarda faydalıdır:

- Full core yerine **daha küçük, paylaşılabilir bir snapshot** istediğinizde
- `MallocStackLogging` etkinleştirildiğinde ve **allocation backtraces** istediğinizde
- Zaten **ilginç bir heap adresi** bildiğinizde ve `malloc_history` ile pivot yapmak istediğinizde
- Full dump'ın oluşturacağı gürültüye değip değmeyeceğine karar vermeden önce hızlı bir **VM/heap dökümü** gerektiğinde

### Differential memgraph triage

Hedefin başlatılma şeklini kontrol ediyorsanız sonraki snapshot'ların yararlı alloc/free backtraces bilgilerini koruması için launch öncesinde **historical allocation logging** özelliğini etkinleştirin:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Ardından ilgi çekici eylem etrafında snapshot'lar yakalayın ve bunları offline olarak karşılaştırın:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Bu, yalnızca bir şifre çözme, unpacking veya secret-retrieval aşamasından sonra ortaya çıkan **post-authentication objects**, **large `CFData` buffers** veya **anonymous VM regions** öğelerini izole etmek için pratik bir yöntemdir.

## Swift-heavy hedefler: `swift-inspect`

Yüksek değerli verileri **Swift runtime objects** içinde tutan uygulamalar için `swift-inspect`, LLDB veya Frida'yı iyi şekilde tamamlayabilir. Önce her şeyi dump etmek yerine, çalışan bir process içindeki belirli Swift runtime yapılarını sorgulayabilirsiniz:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Bu, aşağıdakileri belirlemek için kullanışlıdır:

- İlgi çekici verileri tamponlayan büyük Swift dizileri
- Runtime'da yüklenen türleri ortaya çıkaran metadata allocations
- Daha hedefli bir dump gerçekleştirmeden önce Swift concurrency durumu (`Task`, actor, thread relationships)

Process'i zaten inceleyebildiğiniz durumlarda daha ayrıntılı object-level runtime triage için [bellekteki nesneler hakkındaki özel sayfaya](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.

## Hızlı triage notları

- `sysctl vm.swapusage`, **swap usage** durumunu ve swap'in **encrypted** olup olmadığını kontrol etmek için hâlâ hızlı bir yöntemdir.
- `sleepimage`, temel olarak **hibernate/safe sleep** senaryolarında önemini korur; ancak modern sistemler genellikle onu korur. Bu nedenle güvenilir bir acquisition path olarak değil, **kontrol edilmesi gereken bir artifact source** olarak ele alınmalıdır.
- Güncel macOS sürümlerinde, **full physical memory imaging** yerine **process-level dumping** genellikle daha gerçekçidir; ancak boot policy, SIP durumu ve kext loading üzerinde kontrolünüz varsa durum değişebilir.

## Referanslar

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
