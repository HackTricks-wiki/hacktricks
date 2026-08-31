# Object Manager Slow Paths üzerinden Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window'ını genişletmek neden önemlidir

Birçok Windows kernel LPE'si klasik şu modeli izler: `check_state(); NtOpenX("name"); privileged_action();`. Modern donanımlarda cold bir `NtOpenEvent`/`NtOpenSection`, kısa bir adı yaklaşık 2 µs içinde çözümler ve secure action gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. Object Manager Namespace (OMNS) lookup işlemini 2. adımda kasıtlı olarak onlarca mikrosaniye sürecek şekilde yavaşlatarak attacker, binlerce denemeye ihtiyaç duymadan normalde güvenilmez olan race condition'ları tutarlı biçimde kazanmak için yeterli zaman elde eder.<sup>[[1]](#references)</sup>

## Object Manager lookup internals kısaca

* **OMNS yapısı** – `\BaseNamedObjects\Foo` gibi adlar directory-by-directory çözülür. Her bileşen, kernel'in bir *Object Directory* bulup/açmasını ve Unicode string'lerini karşılaştırmasını gerektirir. Symbolic link'ler (ör. drive letter'ları) yol üzerinde takip edilebilir.
* **UNICODE_STRING sınırı** – OM path'leri, `Length` değeri 16-bit olan bir `UNICODE_STRING` içinde taşınır. Mutlak sınır 65 535 byte'tır (32 767 UTF-16 codepoint). `\BaseNamedObjects\` gibi prefix'lerle birlikte attacker hâlâ yaklaşık 32 000 karakteri kontrol eder.
* **Attacker ön koşulları** – Her user, `\BaseNamedObjects` gibi yazılabilir directory'lerin altında object oluşturabilir. Vulnerable code içerideki bir adı kullandığında veya bu konuma ulaşan bir symbolic link'i takip ettiğinde attacker, özel privilege'lar olmadan lookup performansını kontrol eder.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Tek bir maksimum uzunlukta component

Bir component'i çözümlemenin maliyeti, uzunluğuyla yaklaşık lineer orantılıdır; çünkü kernel'in parent directory'deki her entry'ye karşı Unicode comparison gerçekleştirmesi gerekir. 32 kB uzunluğunda bir ada sahip event oluşturmak, Windows 11 24H2 üzerinde (`Snapdragon X Elite` testbed'i) `NtOpenEvent` latency'sini hemen yaklaşık 2 µs'den 35 µs'ye çıkarır.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Pratik notlar*

- Herhangi bir adlandırılmış kernel object (events, sections, semaphores…) kullanarak length limit'e ulaşabilirsiniz.
- Symbolic links veya reparse points, kısa bir “victim” adını bu dev bileşene yönlendirebilir; böylece slowdown şeffaf bir şekilde uygulanır.
- Her şey user-writable namespace'lerde bulunduğundan payload, standard user integrity level'dan çalışır.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Derin recursive directories

Daha agresif bir varyant, binlerce directory'den oluşan bir zincir (`\BaseNamedObjects\A\A\...\X`) ayırır. Her hop, directory resolution logic'i (ACL checks, hash lookups, reference counting) tetiklediğinden, level başına latency tek bir string compare işlemine göre daha yüksektir. Aynı `UNICODE_STRING` size ile sınırlı olan yaklaşık 16.000 level ile empirical timings, uzun single component'lerle elde edilen 35 µs barrier'ını aşar.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
İpuçları:

* Üst dizin duplicate'leri reddetmeye başlarsa, her level için karakteri (`A/B/C/...`) değiştirin.
* Exploitation sonrasında chain'i temiz şekilde silebilmek ve namespace'i kirletmemek için bir handle array tutun.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (mikrosaniyeler yerine dakikalar)

Object directories, **shadow directories** (fallback lookups) ve entries için bucket'lara ayrılmış hash tablolarını destekler. Her ikisini, ayrıca 64 bileşenli symbolic-link reparse limitini kötüye kullanarak `UNICODE_STRING` uzunluğunu aşmadan slowdown'u katlayın:

1. `\BaseNamedObjects` altında örneğin `A` (shadow) ve `A\A` (target) olmak üzere iki directory oluşturun. İkinci directory'yi birinciyi shadow directory olarak kullanarak (`NtCreateDirectoryObjectEx`) oluşturun; böylece `A` içindeki missing lookup'lar `A\A`'ya düşer.
2. Her directory'yi aynı hash bucket'ına düşen binlerce **colliding name** ile doldurun (örneğin, aynı `RtlHashUnicodeString` değerini korurken sondaki rakamları değiştirin). Lookup işlemleri artık tek bir directory içinde O(n) linear scan'lere dönüşür.
3. Uzun `A\A\…` suffix'ine tekrar tekrar reparse olan yaklaşık 63 **Object Manager symbolic link** chain'i oluşturun ve reparse budget'ını tüketin. Her reparse parsing işlemini baştan başlatır ve collision maliyetini katlar.
4. Final component (`...\\0`) lookup işlemi, directory başına 16.000 collision bulunduğunda Windows 11'de artık **dakikalar** sürer ve one-shot kernel LPE'leri için pratikte garantili bir race win sağlar.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Why it matters*: Dakikalar süren bir yavaşlama, tek seferlik race tabanlı LPE'leri deterministik exploit'lere dönüştürür.<sup>[[1]](#references)</sup>

### 2025 yeniden test notları ve hazır tooling

- James Forshaw, tekniği Windows 11 24H2 (ARM64) üzerinde güncellenmiş zamanlamalarla yeniden yayımladı. Baseline açılışları yaklaşık 2 µs seviyesinde kalıyor; 32 kB'lık bir component bu süreyi yaklaşık 35 µs'ye çıkarıyor ve shadow-dir + collision + 63-reparse zincirleri hâlâ yaklaşık 3 dakikaya ulaşıyor. Bu da primitive'lerin güncel build'lerde çalışmaya devam ettiğini doğruluyor. Source code ve perf harness, yenilenmiş Project Zero gönderisinde bulunuyor.<sup>[[1]](#references)</sup>
- Herkese açık `symboliclink-testing-tools` bundle'ını kullanarak kurulumu script'leyebilirsiniz: shadow/target çiftini oluşturmak için `CreateObjectDirectory.exe`'yi, 63-hop zincirini üretmek içinse `NativeSymlink.exe`'yi bir loop içinde çalıştırın. Bu yöntem, elle yazılmış `NtCreate*` wrapper'larına olan ihtiyacı ortadan kaldırır ve ACL'leri tutarlı tutar.<sup>[[2]](#references)</sup>

## Race window'ınızı ölçme

Victim donanımında window'un ne kadar büyüdüğünü ölçmek için exploit'inize hızlı bir harness ekleyin. Aşağıdaki snippet, hedef object'i `iterations` kez açar ve `QueryPerformanceCounter` kullanarak açılış başına ortalama maliyeti döndürür.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Sonuçlar doğrudan race orchestration stratejinize beslenir (ör. gereken worker thread sayısı, sleep aralıkları ve paylaşılan durumu ne kadar erken değiştirmeniz gerektiği).

## Exploitation workflow

1. **Locate the vulnerable open** – Kernel yolunu (symbols, ETW, hypervisor tracing veya reversing aracılığıyla) izleyerek, attacker-controlled bir name veya user-writable bir directory içindeki symbolic link üzerinde gezinip işlem yapan bir `NtOpen*`/`ObOpenObjectByName` çağrısı bul.
2. **Replace that name with a slow path**
- `\BaseNamedObjects` (veya başka bir writable OM root) altında uzun component veya directory chain oluştur.
- Kernel'ın beklediği name'in artık slow path'e çözülmesi için bir symbolic link oluştur. Vulnerable driver'ın directory lookup işlemini, original target'a dokunmadan kendi yapına yönlendirebilirsin.
3. **Trigger the race**
- Thread A (victim), vulnerable code'u çalıştırır ve slow lookup içinde bloklanır.
- Thread B (attacker), Thread A meşgulken guarded state'i değiştirir (ör. bir file handle'ı değiştirir, symbolic link'i yeniden yazar veya object security'yi değiştirir).
- Thread A devam edip privileged action'ı gerçekleştirdiğinde stale state'i görür ve attacker-controlled operation'ı gerçekleştirir.
4. **Clean up** – Şüpheli artifact'ler bırakmamak veya legitimate IPC kullanıcılarını bozmamak için directory chain'i ve symbolic link'leri sil.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), RoguePlanet için bir bypass (CVE-2026-50656) olarak yayımlanmış olup daha geniş bir exploitation pattern'i gösterir: privileged scanner'ın logical file'ın bir representation'ını sınıflandırmasını sağlamak, ardından remediation bunu kullanmadan önce hem byte'larını hem de namespace resolution'ını değiştirmek. PoC; bir Cloud Files hydration TOCTOU'sunu, bir Object Manager shadow-directory fallback'ini, CLFS-generated-name capture'ı ve local administrative-share link'ini birleştirerek Defender cleanup işlemini protected DLL write'a dönüştürür.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

Attacker-writable bir directory'yi Cloud Files sync root olarak kaydet, bir `CF_CALLBACK_TYPE_FETCH_DATA` callback'i bağla ve advertised size'ı EICAR ZIP gibi deterministic bir detection trigger'ıyla eşleşen bir placeholder oluştur. İlk fetch trigger'ı döndürür ve callback state'i değiştirir; sonraki fetch'ler payload'ı döndürür. Scanner ilk representation'ı sınıflandırdıktan sonra transfer key'i al ve payload-sized metadata ile hydration'ı yeniden başlat; ardından hydration'ı EOF'ye zorla.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Güvenlik sınırı, scan, verdict ve remediation yalnızca bir pathname veya placeholder identity'ye başvuruyorsa başarısız olur: bunların hiçbiri, daha sonraki bir hydration işleminin incelenen byte'ları döndüreceğini garanti etmez.<sup>[[4]](#references)</sup>

### 2. Bir invariant path'i shadow-directory fallback üzerinden değiştirin

`NtCreateDirectoryObjectEx` ile bir hedef Object Manager dizini ve ikinci bir dizin oluşturun; hedef handle'ını shadow/fallback directory olarak geçirin. Her iki çözümleme katmanına da aynı adlı bir `WD_SCAN` girdisi yerleştirin: görünür girdi normal working directory'yi gösterirken fallback girdisi `\CLFS\??\<working-directory>` konumunu gösterir. Defender'a yalnızca aşağıdaki invariant path'i sağlayın; işlem etkinken görünür link'in silinmesi, aynı string'in CLFS destekli girdiye düşmesine neden olur.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Bu, lookup işlemini yalnızca yavaşlatmak için shadow directories kullanmaktan farklıdır: attacker, dizesini değiştirmeden daha önce kabul edilmiş bir path’in **anlamını** değiştirir.<sup>[[4]](#references)</sup>

### 3. Oluşturulan adı yakalayın ve filename-specific bir link oluşturun

`ReadDirectoryChangesW` ile çalışma dizinini izleyin. İlk `FILE_ACTION_ADDED` olayında fallback lookup’ı etkinleştirmek için görünür `WD_SCAN` linkini kaldırın. Oluşturulan ikinci filename’ı yakalayın, CLFS ile ilgili bu dosyayı açın ve `LockFileEx` ile `0..MAXLONGLONG` aralığını kilitleyin. Privileged operation stalled durumdayken, görünür dizindeki `WD_SCAN` öğesini gerçek bir Object Manager directory ile değiştirin ve gözlemlenen filename’dan türetilen bir child symbolic link oluşturun (PoC, son dört karakterini kaldırır). Linki local SMB üzerinden protected destination’a yönlendirin:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Ayrıcalıksız işlem bu hedefe kendisi yazamaz; ancak Defender'ın SYSTEM bağlamı loopback yönetim paylaşımında dolaşabilir. Oluşturulan adların gözlemlenmesini dosyaya özgü bir Object Manager bağlantısıyla birleştirmek, remediation artifact'ını önceden tahmin etme gereksinimini ortadan kaldırır.<sup>[[4]](#references)</sup>

### 4. Cleanup race'i stabilize etme ve ayrıcalıklı bir loader tetikleme

Tarama öncesinde PoC, geçerli bir PE (`ntdll.dll`) dosyasını placeholder'ın `:stream` NTFS alternate data stream'inde depolar. Redirection korumalı base file'ı oluşturduktan sonra `phoneinfo.dll:stream` dosyasını execute erişimiyle açar ve cleanup devam ederken bir `PAGE_EXECUTE_READ | SEC_IMAGE` mapping'ini canlı tutar; canlı file/section object'leri son race sırasında silme veya değiştirme işlemlerini kısıtlar. Yeniden başlatılan hydration artık EICAR yerine payload DLL'i döndürür; böylece korumalı base file, saldırgan kontrollü kod içerir.<sup>[[4]](#references)</sup>

Daha sonra korumalı bir write, `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` altında hazırlanmış bir `Report.wer` yerleştirilerek ve Task Scheduler COM API aracılığıyla `\Microsoft\Windows\Windows Error Reporting\QueueReporting` çağrılarak SYSTEM execution'a dönüştürülür. Bu chain'de ayrıcalıklı WER işleme, yerleştirilen `C:\Windows\System32\phoneinfo.dll` dosyasını yükler; payload execution signal olarak named-pipe bağlantısı kullanılır.<sup>[[4]](#references)</sup>

### Detection pivots

Kullanışlı correlation'lar, tek bir temporary filename'den daha özeldir ve chain'deki tüm namespace geçişlerini kapsar:<sup>[[4]](#references)</sup>

- Aynı placeholder üzerinde yeni kaydedilmiş bir Cloud Files provider'ın ardından EICAR detection ve `CF_OPERATION_TYPE_RESTART_HYDRATION` görülmesi.
- `WD_TARGET_*`, `WD_SHADOW_*` veya `WD_SCAN` içeren Object Manager path'leri; özellikle `\\.\globalroot\BaseNamedObjects\Restricted\` altındaki bir scan path'i.
- CLFS file creation işleminin ardından exclusive whole-file lock ve ayrıcalıklı bir security process'ten `\\127.0.0.1\C$\Windows\System32\*.dll` adresine loopback erişimi.
- Bir System32 DLL'in NTFS ADS ile birlikte oluşturulması ve ardından stream üzerinde `SEC_IMAGE` mapping yapılması.
- Saldırgan tarafından oluşturulmuş bir WER queue entry'nin ardından `\Microsoft\Windows\Windows Error Reporting\QueueReporting` için olağandışı bir manual run ve yerleştirilen DLL'in image load edilmesi.

## Operational considerations

- **Combine primitives** – Daha yüksek latency elde etmek için `UNICODE_STRING` boyutunu tüketene kadar directory chain'de *her seviye için* uzun bir name kullanabilirsiniz.
- **One-shot bugs** – Genişletilmiş window (onlarca mikrosaniyeden dakikalara kadar), CPU affinity pinning veya hypervisor-assisted preemption ile birleştirildiğinde “single trigger” bug'larını gerçekçi hale getirir.
- **Side effects** – Slowdown yalnızca malicious path'i etkiler; bu nedenle genel system performance etkilenmez. Defenders, namespace growth'u izlemedikleri sürece bunu nadiren fark eder.
- **Cleanup** – Oluşturduğunuz her directory/object için handle'ları saklayarak sonrasında `NtMakeTemporaryObject`/`NtClose` çağırabilirsiniz. Aksi takdirde sınırsız directory chain'leri reboot'lar arasında kalabilir.
- **File-system races** – Vulnerable path sonunda NTFS üzerinden çözülüyorsa, OM slowdown çalışırken backing file üzerinde bir Oplock (ör. aynı toolkit'teki `SetOpLock.exe`) oluşturabilirsiniz. Böylece OM graph'ını değiştirmeden consumer'ı ek milisaniyeler boyunca dondurabilirsiniz.<sup>[[2]](#references)</sup>

## Defensive notes

- Named object'lere dayanan kernel code, open işleminden *sonra* security-sensitive state'i yeniden doğrulamalı veya check işleminden önce bir reference almalıdır (TOCTOU gap'ini kapatmak için).
- User-controlled name'leri dereference etmeden önce OM path depth/length için upper bound'lar uygulayın. Aşırı uzun name'leri reddetmek, saldırganları yeniden mikrosaniyelik window'a zorlar.
- Şüpheli binlerce component içeren chain'leri `\BaseNamedObjects` altında tespit etmek için Object Manager namespace growth'u (ETW `Microsoft-Windows-Kernel-Object`) instrument edin.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookup'larıyla Race Condition'ları Kazanma](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
