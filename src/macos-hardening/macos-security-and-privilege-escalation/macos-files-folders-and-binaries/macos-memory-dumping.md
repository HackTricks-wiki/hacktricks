# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

`/private/var/vm/swapfile0` gibi swap files, **physical memory dolduğunda cache görevi görür**. Physical memory'de daha fazla yer kalmadığında verileri bir swap file'a aktarılır ve gerektiğinde physical memory'ye geri getirilir. swapfile0, swapfile1 ve benzeri adlara sahip birden fazla swap file bulunabilir.

### Hibernate Image

`/private/var/vm/sleepimage` konumundaki file, **hibernation mode** sırasında kritik öneme sahiptir. **OS X hibernate olduğunda memory'deki veriler bu file'da saklanır**. Bilgisayar uyandırıldığında system memory verilerini bu file'dan alır ve kullanıcının kaldığı yerden devam etmesini sağlar.

Modern MacOS system'lerinde bu file'ın genellikle security nedenleriyle encrypted olduğunu ve bunun recovery işlemini zorlaştırdığını belirtmek gerekir.

- sleepimage için encryption'ın etkin olup olmadığını kontrol etmek üzere `sysctl vm.swapusage` command'ı çalıştırılabilir. Bu, file'ın encrypted olup olmadığını gösterir.

### Memory Pressure Logs

MacOS system'lerindeki memory ile ilgili bir diğer önemli file, **memory pressure log**'udur. Bu log'lar `/var/log` konumunda bulunur ve system'in memory kullanımı ile pressure event'leri hakkında ayrıntılı bilgiler içerir. Memory ile ilgili sorunları teşhis etmek veya system'in memory'yi zaman içinde nasıl yönettiğini anlamak için özellikle yararlı olabilirler.

## osxpmem ile memory dumping

Bir MacOS machine'inde memory dump etmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanabilirsiniz.

**Note**: Bu artık çoğunlukla bir **legacy workflow**'dur. `osxpmem`, bir kernel extension yüklenmesine bağlıdır; [Rekall](https://github.com/google/rekall) project'i arşivlenmiştir, en son release **2017** yılına aittir ve yayınlanan binary **Intel Mac'leri** hedefler. Güncel macOS release'lerinde, özellikle **Apple Silicon** üzerinde, kext tabanlı full-RAM acquisition genellikle modern kernel-extension restrictions, SIP ve platform-signing requirements tarafından engellenir. Pratikte modern system'lerde whole-RAM image yerine daha sık **process-scoped dump** gerçekleştirirsiniz.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Bu hatayı görürseniz: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` şu şekilde düzeltebilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Security & Privacy --> General" bölümünde **kext'in yüklenmesine izin verilerek** düzeltilebilir; sadece **izin verin**.

Uygulamayı indirmek, kext'i yüklemek ve memory dump almak için bu **oneliner**'ı da kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB ile canlı process dumping

**Güncel macOS sürümleri** için genellikle en pratik yaklaşım, tüm fiziksel belleği image etmeye çalışmak yerine **belirli bir process** belleğini dump etmektir.

LLDB, canlı bir target'tan Mach-O core file kaydedebilir:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Varsayılan olarak bu genellikle bir **skinny core** oluşturur. LLDB'yi eşlenen tüm işlem belleğini dahil etmeye zorlamak için:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Dumping öncesi faydalı takip komutları:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Bu genellikle aşağıdakileri kurtarma amacı için yeterlidir:

- Şifresi çözülmüş configuration blob'ları
- Bellek içindeki token'lar, cookie'ler veya kimlik bilgileri
- Yalnızca at-rest durumunda korunan plaintext secret'lar
- Unpacking / JIT / runtime patching sonrasında şifresi çözülmüş Mach-O sayfaları

Hedef **hardened runtime** tarafından korunuyorsa veya `taskgated` attach işlemini reddediyorsa genellikle aşağıdaki koşullardan birine ihtiyaç duyarsınız:

- Hedefte **`get-task-allow`** bulunur
- Debugger'ınız uygun **debugger entitlement** ile imzalanmıştır
- **root** yetkisine sahipsiniz ve hedef, hardened olmayan bir üçüncü taraf process'idir

Task port elde etme ve bununla yapılabilecekler hakkında daha fazla bilgi için:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

LLDB/Frida ile zaman harcamadan önce hedefin gerçekçi olarak **dump alınabilir** olup olmadığını hızlıca doğrulayın:
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

- **`get-task-allow`** ile dağıtılan bir third-party app, çoğu zaman LLDB ile doğrudan dump alınabilir ve ortaya çıkan dump, app'in daha önce eriştiği TCC-korumalı verileri açığa çıkarabilir.<sup>[[1]](#references)</sup>
- **hardened** bir hedef, **`get-task-allow`** olmadan, ilgili debugger entitlements / policy path'ini kontrol etmediğiniz sürece, **`root`** olsanız bile çoğunlukla attach işlemlerini reddeder.
- Unhardened third-party process'ler, `lldb`, `vmmap`, Frida veya özel `task_for_pid`/`vm_read` reader'ları kullanmak için hâlâ en kolay yerdir.

### Dump alınabilir iç içe helper'ları arayın

Notarized macOS app'leri üzerine yapılan güncel araştırmalar, ana GUI binary'si yerine iç içe helper'larda **`get-task-allow`** bulunduğunu sürekli ortaya koyuyor. Üst düzey bir app hardened göründüğünde, vazgeçmeden önce app'in **XPC services**'lerini, **login items**'larını, **helper tools**'larını ve paketlenmiş CLI'larını listeleyin:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
`get-task-allow` içeren iç içe bir executable, ana uygulama daha iyi harden edilmiş olsa bile `lldb` ile attach olmak, bir core dump'ı almak veya özel bir `task_for_pid` client ile memory çekmek için genellikle en kolay yerdir.

## Frida veya userland readers ile seçici dump'lar

Tam bir core çok fazla gürültü içerdiğinde, yalnızca **ilgi çekici okunabilir aralıkları** dump etmek genellikle daha hızlıdır. Frida, sürece attach olabildiğinizde **hedefli extraction** için özellikle kullanışlıdır.

Örnek yaklaşım:

1. Okunabilir/yazılabilir aralıkları enumerate edin
2. Module, heap, stack veya anonymous memory ile filtreleyin
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

- Gizli bilgiler içeren App heap parçaları
- Özel packer veya loader'lar tarafından oluşturulan anonim bölgeler
- Protections değiştirildikten sonraki JIT / unpacked code sayfaları

Hedef dump sırasında **allocation / free** işlemlerini sürdürüyorsa kararsız aralıklar için `readByteArray()` yerine Frida'nın **`readVolatile()`** primitive'ini tercih edin. Daha yavaştır, ancak okuma sırasında bir sayfa okunamaz hâle gelirse hedefin sonlandırılmasını önler. Daha büyük acquisition işlemleri için parçaları `send(..., data)` ile geri stream etmek ve hedef içinde binlerce küçük dosya oluşturmak yerine controller tarafında compress etmek de daha temiz olabilir.

[`readmem`](https://github.com/gdbinit/readmem) gibi daha eski userland araçları da mevcuttur, ancak bunlar çoğunlukla doğrudan `task_for_pid`/`vm_read` tarzı dumping için **source reference** olarak kullanışlıdır ve modern Apple Silicon workflow'ları için iyi şekilde maintain edilmemektedir.

## `.memgraph` ile Heap / VM snapshot'ları

Öncelikli olarak **heap object'leri**, **allocation provenance** veya başka bir makineye taşınabilecek bir snapshot ile ilgileniyorsanız, `.memgraph` genellikle devasa bir Mach-O core'dan daha pratiktir. `leaks` tooling'i çalışan bir process'ten bunlardan birini oluşturabilir:<sup>[[2]](#references)</sup>
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
`stringdups`, minimal bir `.memgraph` içinde memory contents'i açıklayan label'lar atlandığı için `-fullContent` capture'ını saklamanın başlıca nedenidir.

Bu özellikle şu durumlarda kullanışlıdır:

- Full core yerine **daha küçük, paylaşılabilir bir snapshot** istediğinizde
- `MallocStackLogging` etkinleştirildiğinde ve **allocation backtrace'leri** istediğinizde
- Zaten **ilginç bir heap address** bildiğinizde ve `malloc_history` ile pivot yapmak istediğinizde
- Full dump'ın oluşturacağı gürültünün buna değip değmeyeceğine karar vermeden önce hızlı bir **VM/heap breakdown** gerektiğinde

### Differential memgraph triage

Target'ın başlatılma şeklini kontrol ediyorsanız, daha sonraki snapshot'ların yararlı alloc/free backtrace'lerini koruması için launch öncesinde **historical allocation logging** özelliğini etkinleştirin:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Ardından ilginç eylem öncesi ve sonrası anlık görüntüler yakalayın ve bunları çevrimdışı olarak karşılaştırın:
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
Bu, yalnızca bir şifre çözme, unpacking veya secret-retrieval aşamasından sonra ortaya çıkan **post-authentication objects**, **büyük `CFData` buffers** veya **anonymous VM regions** öğelerini izole etmek için pratik bir yöntemdir.

## Swift ağırlıklı hedefler: `swift-inspect`

Yüksek değerli verileri **Swift runtime objects** içinde tutan uygulamalar için `swift-inspect`, LLDB veya Frida'yı iyi şekilde tamamlayabilir. Önce her şeyi dump etmek yerine, canlı bir process içindeki belirli Swift runtime yapılarını sorgulayabilirsiniz:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Bu, aşağıdakileri belirlemek için kullanışlıdır:

- İlgi çekici verileri buffer'layan büyük Swift dizileri
- Runtime'da yüklenen türleri açığa çıkaran Metadata allocations
- Daha hedefli bir dump gerçekleştirmeden önce Swift concurrency durumu (`Task`, actor, thread ilişkileri)

Süreci zaten inceleyebildiğiniz durumda, object-level runtime triage hakkında daha fazla bilgi için [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md) sayfasına bakın.

## Hızlı triage notları

- `sysctl vm.swapusage`, **swap kullanımını** ve swap'in **encrypted** olup olmadığını kontrol etmenin hâlâ hızlı bir yoludur.
- `sleepimage` esas olarak **hibernate/safe sleep** senaryolarında önemini korur; ancak modern sistemler genellikle onu korur. Bu nedenle güvenilir bir acquisition path olarak değil, **kontrol edilmesi gereken bir artifact source** olarak değerlendirilmelidir.
- Güncel macOS sürümlerinde, **full physical memory imaging** işlemi; boot policy, SIP durumu ve kext loading üzerinde kontrolünüz olmadığı sürece, genellikle **process-level dumping** işleminden daha gerçekçi değildir.

## Referanslar

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
