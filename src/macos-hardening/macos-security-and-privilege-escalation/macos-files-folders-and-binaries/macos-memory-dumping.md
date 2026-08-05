# macOS Bellek Dökümü

{{#include ../../../banners/hacktricks-training.md}}

## Bellek Artefaktları

### Swap Dosyaları

`/private/var/vm/swapfile0` gibi swap dosyaları, **fiziksel bellek dolduğunda cache görevi görür**. Fiziksel bellekte daha fazla yer kalmadığında veriler bir swap dosyasına aktarılır ve gerektiğinde fiziksel belleğe geri getirilir. swapfile0, swapfile1 gibi adlara sahip birden fazla swap dosyası bulunabilir.

### Hibernate Image

`/private/var/vm/sleepimage` konumundaki dosya, **hibernation mode** sırasında kritik öneme sahiptir. **OS X hibernate olduğunda bellekteki veriler bu dosyada depolanır**. Bilgisayar uyandırıldığında sistem bellek verilerini bu dosyadan alır ve kullanıcının kaldığı yerden devam etmesini sağlar.

Modern MacOS sistemlerinde bu dosyanın güvenlik nedenleriyle genellikle şifreli olduğunu ve bu nedenle kurtarılmasının zor olduğunu belirtmek gerekir.

- sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek amacıyla `sysctl vm.swapusage` komutu çalıştırılabilir. Bu komut dosyanın şifreli olup olmadığını gösterir.

### Bellek Pressure Log'ları

MacOS sistemlerindeki bellekle ilgili bir diğer önemli dosya **memory pressure log**'udur. Bu log'lar `/var/log` konumunda bulunur ve sistemin bellek kullanımına ve pressure event'lerine ilişkin ayrıntılı bilgiler içerir. Bellekle ilgili sorunları teşhis etmek veya sistemin zaman içinde belleği nasıl yönettiğini anlamak için özellikle yararlı olabilirler.

## osxpmem ile Bellek Dökümü Alma

Bir MacOS makinesindeki belleği dump etmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Not**: Bu artık çoğunlukla **legacy bir workflow**'dur. `osxpmem`, bir kernel extension yüklenmesine bağlıdır; [Rekall](https://github.com/google/rekall) projesi arşivlenmiştir, en son release **2017** yılına aittir ve yayınlanan binary **Intel Mac'leri** hedefler. Güncel macOS sürümlerinde, özellikle **Apple Silicon** üzerinde, kext tabanlı full-RAM acquisition genellikle modern kernel-extension kısıtlamaları, SIP ve platform-signing gereksinimleri tarafından engellenir. Uygulamada modern sistemlerde çoğunlukla tüm RAM image'ı yerine **process-scoped dump** alırsınız.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Şu hatayla karşılaşırsanız: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` şu şekilde düzeltebilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Güvenlik ve Gizlilik --> Genel" bölümünden **kext yüklenmesine izin verilerek** düzeltilebilir; yalnızca **izin verin**.

Uygulamayı indirmek, kext'i yüklemek ve belleği dump etmek için bu **oneliner**'ı da kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB ile canlı process dökümü

**Güncel macOS sürümleri** için genellikle en pratik yaklaşım, tüm fiziksel belleği image etmeye çalışmak yerine **belirli bir process**'in belleğini dump etmektir.

LLDB, canlı bir target'tan Mach-O core file kaydedebilir:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Varsayılan olarak bu işlem genellikle bir **skinny core** oluşturur. LLDB'yi eşlenen tüm process memory'yi dahil etmeye zorlamak için:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Dumping işleminden önce kullanılabilecek yararlı devam komutları:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Bu, genellikle aşağıdakileri kurtarma amacı için yeterlidir:

- Decrypted configuration blobs
- Bellek içindeki tokens, cookies veya credentials
- Yalnızca at-rest korumasına sahip plaintext secrets
- Unpacking / JIT / runtime patching sonrasında decrypted Mach-O pages

Hedef **hardened runtime** ile korunuyorsa veya `taskgated` attach işlemini reddediyorsa genellikle aşağıdaki koşullardan birine ihtiyacınız vardır:

- Hedefte **`get-task-allow`** bulunması
- Debugger'ınızın uygun **debugger entitlement** ile imzalanmış olması
- **root** olmanız ve hedefin hardened olmayan üçüncü taraf bir process olması

Task port edinme ve bununla yapılabilecekler hakkında daha fazla bilgi için:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Hızlı attach öncesi kontroller

LLDB/Frida ile zaman harcamadan önce, hedefin gerçekçi olarak **dumpable** olup olmadığını hızlıca doğrulayın:
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

- **`get-task-allow`** ile gönderilen üçüncü taraf bir app, çoğunlukla LLDB ile doğrudan dump alınabilir ve ortaya çıkan dump, app'in daha önce eriştiği TCC-korumalı verileri açığa çıkarabilir.<sup>[1]</sup>
- **Hardened** bir hedef, ilgili debugger entitlements / policy path'ini kontrol etmediğiniz sürece, **`root`** olsanız bile attach işlemlerini genellikle reddeder.
- Hardened olmayan üçüncü taraf process'ler, `lldb`, `vmmap`, Frida veya özel `task_for_pid`/`vm_read` reader'ları kullanmak için hâlâ en kolay yerdir.

### Dump alınabilir nested helper'ları ara

Notarized macOS app'leri üzerine yapılan güncel araştırmalar, ana GUI binary yerine nested helper'larda **`get-task-allow`** bulunduğunu göstermeye devam ediyor. Üst düzey bir app hardened görünüyorsa pes etmeden önce **XPC services**, **login items**, **helper tools** ve bundle içindeki CLI'ları listeleyin:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` içeren iç içe bir executable, ana uygulama daha iyi hardened olsa bile, `lldb` ile bağlanmak, bir core dökümü almak veya özel bir `task_for_pid` client ile memory çekmek için genellikle en kolay yerdir.

## Frida veya userland readers ile seçici dökümler

Tam bir core dökümü çok fazla gürültü içerdiğinde, yalnızca **ilginç okunabilir aralıkları** dökmek genellikle daha hızlıdır. Frida özellikle kullanışlıdır, çünkü process'e bağlanabildiğinizde **hedefli extraction** işlemlerinde iyi çalışır.

Örnek yaklaşım:

1. Okunabilir/yazılabilir aralıkları enumerate edin
2. Module, heap, stack veya anonymous memory'ye göre filtreleyin
3. Candidate string'leri, key'leri, protobuf'ları, plist/XML blob'larını veya decrypted code/data içeren bölgeleri dökün

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

- Secret içeren App heap chunk'ları
- Özel packer veya loader'lar tarafından oluşturulan anonim bölgeler
- Protections değiştirildikten sonraki JIT / unpacked code sayfaları

Hedef dump sırasında **allocation / free** işlemlerini sürdürüyorsa, kararsız aralıklar için Frida'nın **`readVolatile()`** primitive'ini **`readByteArray()`** yerine tercih edin. Daha yavaştır, ancak okuma sırasında bir sayfa okunamaz hâle gelirse hedefin sonlandırılmasını önler. Daha büyük acquisition işlemleri için chunk'ları `send(..., data)` ile geri stream etmek ve hedef içinde binlerce küçük dosya oluşturmak yerine bunları controller tarafında compress etmek de daha temiz olabilir.

[`readmem`](https://github.com/gdbinit/readmem) gibi daha eski userland araçları da mevcuttur, ancak bunlar temel olarak doğrudan `task_for_pid`/`vm_read` tarzı dumping için **source reference** olarak kullanışlıdır ve modern Apple Silicon workflow'ları için iyi şekilde maintain edilmemektedir.

## `.memgraph` ile Heap / VM snapshot'ları

Temel olarak **heap object'leri**, **allocation provenance** veya başka bir makineye taşınabilecek bir snapshot ile ilgileniyorsanız, `.memgraph` genellikle devasa bir Mach-O core'dan daha pratiktir. `leaks` tooling'i çalışan bir process'ten bunu oluşturabilir:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Ardından standart Apple araçlarıyla offline olarak triage edin:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups`, minimal bir `.memgraph` içinde memory contents'i açıklayan etiketler bulunmadığından, `-fullContent` capture'ını saklamanın başlıca nedenidir.

Bu özellikle şu durumlarda kullanışlıdır:

- Full core yerine **daha küçük, paylaşılabilir bir snapshot** istediğinizde
- `MallocStackLogging` etkinleştirildiğinde ve **allocation backtrace'leri** istediğinizde
- Zaten **ilginç bir heap adresi** bildiğinizde ve `malloc_history` ile pivot yapmak istediğinizde
- Full dump'ın oluşturacağı gürültüye değip değmeyeceğine karar vermeden önce hızlı bir **VM/heap breakdown** gerektiğinde

### Differential memgraph triage

Target'ın başlatılma şeklini kontrol ediyorsanız, sonraki snapshot'ların yararlı alloc/free backtrace'lerini koruması için launch öncesinde **historical allocation logging** etkinleştirin:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Ardından, ilgi çekici eylem öncesinde ve sonrasında snapshot'lar alın ve bunları offline olarak diff'leyin:
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
Bu, yalnızca bir şifre çözme, unpacking veya secret-retrieval aşamasından sonra ortaya çıkan **post-authentication objects**, **large `CFData` buffers** ya da **anonymous VM regions** öğelerini izole etmenin pratik bir yoludur.

## Swift ağırlıklı hedefler: `swift-inspect`

Yüksek değerli verileri **Swift runtime objects** içinde tutan uygulamalar için `swift-inspect`, LLDB veya Frida'ya iyi bir tamamlayıcı olabilir. Önce her şeyi dump etmek yerine, çalışan bir process içindeki belirli Swift runtime structures öğelerini sorgulayabilirsiniz:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Bunlar aşağıdakileri belirlemek için kullanışlıdır:

- İlginç verileri buffer'layan büyük Swift dizileri
- Runtime'da yüklenen türleri ortaya çıkaran metadata allocations
- Daha hedefli bir dump almadan önce Swift concurrency durumu (`Task`, actor, thread ilişkileri)

Process'i zaten inspect edebiliyorsanız, object-level runtime triage hakkında daha fazla bilgi için [memory'deki objects sayfasına](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) bakın.

## Hızlı triage notları

- `sysctl vm.swapusage`, **swap kullanımını** ve swap'in **encrypted** olup olmadığını kontrol etmek için hâlâ hızlı bir yöntemdir.
- `sleepimage`, temel olarak **hibernate/safe sleep** senaryolarında geçerliliğini korur; ancak modern sistemler genellikle onu korur. Bu nedenle güvenilir bir acquisition path olarak değil, **kontrol edilmesi gereken bir artifact source** olarak değerlendirilmelidir.
- Güncel macOS sürümlerinde, **full physical memory imaging** yerine **process-level dumping** genellikle daha gerçekçidir; bunun istisnası boot policy, SIP durumu ve kext loading üzerinde kontrol sahibi olduğunuz durumlardır.

## Referanslar

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
