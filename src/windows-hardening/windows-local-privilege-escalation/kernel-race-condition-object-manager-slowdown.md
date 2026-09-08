# Object Manager Slow Paths ile Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window'ını genişletmek neden önemlidir

Birçok Windows kernel LPE'si klasik şu modeli izler: `check_state(); NtOpenX("name"); privileged_action();`. Modern donanımlarda cold bir `NtOpenEvent`/`NtOpenSection`, kısa bir adı yaklaşık 2 µs içinde çözümler ve güvenli işlem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. 2. adımdaki Object Manager Namespace (OMNS) lookup işlemini kasıtlı olarak onlarca mikrosaniye sürecek şekilde yavaşlatarak attacker, binlerce deneme yapmasına gerek kalmadan normalde flaky olan race condition'ları tutarlı biçimde kazanacak kadar zaman elde eder.<sup>[[1]](#references)</sup>

## Object Manager lookup internals kısaca

* **OMNS yapısı** – `\BaseNamedObjects\Foo` gibi adlar directory-by-directory çözülür. Her bileşen, kernel'in bir *Object Directory* bulup açmasını ve Unicode string'lerini karşılaştırmasını gerektirir. Symbolic link'ler (ör. drive letters) yol üzerinde takip edilebilir.
* **UNICODE_STRING limiti** – OM path'leri, `Length` alanı 16 bit olan bir `UNICODE_STRING` içinde taşınır. Mutlak limit 65 535 byte'tır (32 767 UTF-16 codepoint). `\BaseNamedObjects\` gibi prefix'lerle attacker hâlâ yaklaşık 32 000 karakteri kontrol eder.
* **Attacker ön koşulları** – Her user, `\BaseNamedObjects` gibi yazılabilir directory'lerin altında object oluşturabilir. Vulnerable code içeride bulunan bir name kullandığında veya buraya ulaşan bir symbolic link'i takip ettiğinde attacker, özel privilege'lar olmadan lookup performansını kontrol eder.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Tek bir maksimal component

Bir component'i çözümlemenin maliyeti, uzunluğuyla kabaca lineer orantılıdır; çünkü kernel, parent directory'deki her entry'ye karşı Unicode comparison gerçekleştirmelidir. 32 kB uzunluğunda bir name'e sahip event oluşturmak, Windows 11 24H2'de (Snapdragon X Elite testbed) `NtOpenEvent` latency'sini anında yaklaşık 2 µs'den 35 µs'ye çıkarır.
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
- Symbolic links veya reparse points, kısa bir “victim” adını bu devasa component'e yönlendirebilir; böylece slowdown transparan biçimde uygulanır.
- Her şey user-writable namespace'lerde bulunduğundan payload, standard user integrity level'dan çalışır.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Derin recursive dizinler

Daha agresif bir varyant, binlerce dizinden oluşan bir zincir ayırır (`\BaseNamedObjects\A\A\...\X`). Her hop, directory resolution logic'i (ACL kontrolleri, hash lookups, reference counting) tetiklediğinden, level başına latency tek bir string compare işleminden daha yüksektir. ~16 000 level ile (aynı `UNICODE_STRING` size tarafından sınırlandırılır) yapılan empirical timings, uzun tek component'lerle elde edilen 35 µs barrier'ını aşar.
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

* Üst dizin duplicate'leri reddetmeye başlarsa her seviye için karakteri (`A/B/C/...`) değiştirin.
* Exploitation sonrasında zinciri temiz şekilde silebilmek ve namespace'i kirletmemek için bir handle array tutun.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (mikrosaniyeler yerine dakikalar)

Object directories, **shadow directories** (fallback lookups) ve entries için bucket'lara ayrılmış hash tablolarını destekler. `UNICODE_STRING` uzunluğunu aşmadan slowdown'u katlamak için her ikisini ve 64 bileşenli symbolic-link reparse limitini birlikte abuse edin:

1. `\BaseNamedObjects` altında, örneğin `A` (shadow) ve `A\A` (target) olmak üzere iki directory oluşturun. İkinci directory'yi birincisini shadow directory olarak kullanacak şekilde (`NtCreateDirectoryObjectEx`) oluşturun; böylece `A` içindeki eksik lookuplar `A\A`'ya aktarılır.
2. Her directory'yi aynı hash bucket'a düşen binlerce **colliding name** ile doldurun (örneğin, aynı `RtlHashUnicodeString` değerini korurken sondaki rakamları değiştirin). Lookuplar artık tek bir directory içindeki O(n) linear scan'lere dönüşür.
3. Uzun `A\A\…` suffix'ine tekrar tekrar reparse yapan yaklaşık 63 **Object Manager symbolic link** zinciri oluşturun ve reparse budget'ını tüketin. Her reparse parsing işlemini en baştan başlattığı için collision maliyeti katlanır.
4. Final component'in (`...\\0`) lookup işlemi, directory başına 16 000 collision mevcut olduğunda Windows 11'de artık **dakikalar** sürer ve one-shot kernel LPE'leri için pratikte garanti edilmiş bir race win sağlar.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Neden önemli*: Dakikalar süren bir yavaşlama, tek seferlik race tabanlı LPE'leri deterministic exploit'lere dönüştürür.<sup>[[1]](#references)</sup>

### 2025 yeniden test notları ve hazır araçlar

- James Forshaw, tekniği Windows 11 24H2 (ARM64) üzerinde güncellenmiş zamanlamalarla yeniden yayımladı. Baseline açılışları yaklaşık 2 µs olarak kalırken, 32 kB'lık bir component bu süreyi yaklaşık 35 µs'ye çıkarıyor ve shadow-dir + collision + 63-reparse chain'leri hâlâ yaklaşık 3 dakikaya ulaşıyor; bu da primitive'lerin mevcut build'lerde çalışmaya devam ettiğini doğruluyor. Source code ve perf harness, güncellenmiş Project Zero gönderisinde bulunuyor.<sup>[[1]](#references)</sup>
- Public `symboliclink-testing-tools` bundle'ını kullanarak kurulumu script'le gerçekleştirebilirsiniz: shadow/target pair'i oluşturmak için `CreateObjectDirectory.exe`, 63-hop chain'i üretmek içinse bir döngü içinde `NativeSymlink.exe` kullanın. Bu yöntem, elle yazılmış `NtCreate*` wrapper'larına olan ihtiyacı ortadan kaldırır ve ACL'lerin tutarlı kalmasını sağlar.<sup>[[2]](#references)</sup>

## Race window'ınızı ölçme

Window'un victim hardware üzerinde ne kadar büyüdüğünü ölçmek için exploit'inize hızlı bir harness ekleyin. Aşağıdaki snippet, target object'i `iterations` kez açar ve `QueryPerformanceCounter` kullanarak açılış başına ortalama maliyeti döndürür.<sup>[[1]](#references)</sup>
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

## İstismar iş akışı

1. **Vulnerable open işlemini bulun** – Saldırgan tarafından kontrol edilen bir adı veya kullanıcı tarafından yazılabilir bir dizindeki symbolic link'i izleyen `NtOpen*`/`ObOpenObjectByName` çağrısını bulana kadar kernel yolunu (symbols, ETW, hypervisor tracing veya reversing aracılığıyla) takip edin.
2. **Bu adı yavaş bir yolla değiştirin**
- Uzun component'i veya dizin zincirini `\BaseNamedObjects` (ya da yazılabilir başka bir OM root) altında oluşturun.
- Kernel'in beklediği adın artık yavaş yola çözülmesi için bir symbolic link oluşturun. Vulnerable driver'ın directory lookup işlemini, original target'a dokunmadan kendi yapınıza yönlendirebilirsiniz.
3. **Race'i tetikleyin**
- Thread A (victim), vulnerable code'u çalıştırır ve yavaş lookup içinde bloklanır.
- Thread B (attacker), Thread A meşgulken guarded state'i değiştirir (ör. bir file handle'ı değiştirir, bir symbolic link'i yeniden yazar veya object security'yi değiştirir).
- Thread A devam edip privileged action'ı gerçekleştirdiğinde stale state'i görür ve attacker-controlled operation'ı gerçekleştirir.
4. **Temizleyin** – Şüpheli artifact'ler bırakmamak veya legitimate IPC kullanıcılarını bozmamak için dizin zincirini ve symbolic link'leri silin.<sup>[[1]](#references)</sup>

## Uygulamalı zincir: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), RoguePlanet (CVE-2026-50656) için bir bypass olarak yayımlanmış olup daha geniş bir exploitation pattern'i gösterir: privileged scanner'ın logical file'ın bir temsilini sınıflandırmasını sağlayın, ardından remediation bunu kullanmadan önce hem byte'larını hem de namespace resolution'ını değiştirin. PoC; Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture ve local administrative-share link'i birleştirerek Defender cleanup işlemini protected DLL write'a dönüştürür.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Cloud Files hydration aracılığıyla içeriği değiştirin

Attacker-writable bir dizini Cloud Files sync root olarak kaydedin, bir `CF_CALLBACK_TYPE_FETCH_DATA` callback'i bağlayın ve advertised size'ı EICAR ZIP gibi deterministik bir detection trigger ile eşleşen bir placeholder oluşturun. İlk fetch trigger'ı döndürür ve callback state'i değiştirir; sonraki fetch'ler payload'ı döndürür. Scanner ilk representation'ı sınıflandırdıktan sonra transfer key'i alın ve payload-sized metadata ile hydration'ı yeniden başlatın, ardından hydration'ı EOF'ye zorlayın.<sup>[[4]](#references)</sup>
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
Güvenlik sınırı; scan, verdict ve remediation yalnızca bir pathname veya placeholder identity'ye başvuruyorsa başarısız olur: bunların hiçbiri, daha sonra yapılacak bir hydration işleminin incelenen byte'ları döndüreceğini garanti etmez.<sup>[[4]](#references)</sup>

### 2. Bir shadow-directory fallback aracılığıyla invariant path'i değiştirin

`NtCreateDirectoryObjectEx` ile bir hedef Object Manager directory ve ikinci bir directory oluşturun; hedef handle'ını shadow/fallback directory olarak geçirin. Her iki çözümleme katmanına da aynı ada sahip bir `WD_SCAN` entry'si yerleştirin: görünür entry normal working directory'yi gösterirken fallback entry `\CLFS\??\<working-directory>` yolunu göstersin. Defender'a yalnızca aşağıdaki invariant path'i sağlayın; işlem etkinken görünür link'in silinmesi, aynı string'in CLFS-backed entry'ye düşmesini sağlar.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Bu, yalnızca aramayı yavaşlatmak için shadow directories kullanmaktan farklıdır: saldırgan, dizesini değiştirmeden daha önce kabul edilmiş bir path'in **anlamını** değiştirir.<sup>[[4]](#references)</sup>

### 3. Oluşturulan adı yakalayın ve filename-specific bir link yükleyin

`ReadDirectoryChangesW` ile çalışma dizinini izleyin. İlk `FILE_ACTION_ADDED` olayında, fallback lookup'u etkinleştirmek için görünür `WD_SCAN` linkini kaldırın. Oluşturulan ikinci filename'i yakalayın, CLFS ile ilgili bu dosyayı açın ve `LockFileEx` ile `0..MAXLONGLONG` aralığını kilitleyin. Privileged operation durdurulmuşken, görünür dizindeki `WD_SCAN` öğesini gerçek bir Object Manager diziniyle değiştirin ve gözlemlenen filename'den türetilen bir child symbolic link oluşturun (PoC, son dört karakterini kaldırır). Bunu local SMB üzerinden protected destination'a yönlendirin:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Ayrıcalıksız işlem bu hedefe kendisi yazamaz, ancak Defender'ın SYSTEM bağlamı loopback administrative share üzerinden geçiş yapabilir. Oluşturulan adların gözlemlenmesini dosyaya özgü bir Object Manager bağlantısıyla birleştirmek, remediation artifact'ını önceden tahmin etme gereksinimini ortadan kaldırır.<sup>[[4]](#references)</sup>

### 4. Cleanup race'i stabilize etme ve ayrıcalıklı bir loader tetikleme

Tarama öncesinde PoC, geçerli bir PE (`ntdll.dll`) dosyasını placeholder'ın `:stream` NTFS alternate data stream'inde depolar. Redirection korumalı base file'ı oluşturduktan sonra `phoneinfo.dll:stream` dosyasını execute erişimiyle açar ve `PAGE_EXECUTE_READ | SEC_IMAGE` mapping'ini cleanup devam ederken canlı tutar; canlı file/section nesneleri son race sırasında silme veya değiştirme işlemlerini kısıtlar. Yeniden başlatılan hydration artık EICAR yerine payload DLL'i döndürür; böylece korumalı base file attacker-controlled code içerir.<sup>[[4]](#references)</sup>

Korumalı bir write işlemi, `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` altına hazırlanmış bir `Report.wer` yerleştirilip Task Scheduler COM API üzerinden `\Microsoft\Windows\Windows Error Reporting\QueueReporting` çağrılarak SYSTEM execution'a dönüştürülür. Bu chain'de ayrıcalıklı WER processing, yerleştirilen `C:\Windows\System32\phoneinfo.dll` dosyasını yükler; payload execution signal olarak named pipe bağlantısı kullanılır.<sup>[[4]](#references)</sup>

### Detection pivots

Yararlı korelasyonlar tek bir temporary filename'den daha özeldir ve chain'deki tüm namespace geçişlerini kapsar:<sup>[[4]](#references)</sup>

- Aynı placeholder üzerinde yeni kaydedilmiş bir Cloud Files provider'ın ardından EICAR detection ve `CF_OPERATION_TYPE_RESTART_HYDRATION`.
- `WD_TARGET_*`, `WD_SHADOW_*` veya `WD_SCAN` içeren Object Manager path'leri; özellikle `\\.\globalroot\BaseNamedObjects\Restricted\` altında bulunan bir scan path'i.
- CLFS file creation'ın ardından exclusive whole-file lock ve ayrıcalıklı bir security process'ten `\\127.0.0.1\C$\Windows\System32\*.dll` adresine loopback erişimi.
- Bir System32 DLL'i ile birlikte NTFS ADS oluşturulması ve ardından stream'in `SEC_IMAGE` mapping'i.
- Attacker-created WER queue entry'nin ardından `\Microsoft\Windows\Windows Error Reporting\QueueReporting` için alışılmadık bir manual run ve yerleştirilen DLL'in image load edilmesi.

## Uygulanan chain: ayrıcalıklı remediation'a karşı oplock-gated mount-point switch

Ayrıcalıklı bir scanner attacker-controlled file'ı kontrol edip daha sonra validated handle'lar üzerinden devam etmek yerine **pathname**'i yeniden açarak remediation uyguladığında yeniden kullanılabilir bir LPE pattern'i ortaya çıkar. FalconFlank, CrowdStrike Falcon'ın Office macro-removal workflow'unu hedefleyen herkese açık bir örnektir; repository, ilgili policy etkin durumdayken Windows 11 25H2 ve Windows Server 2025 üzerinde test edildiğini iddia eder, ancak CVE, affected-build range, vendor advisory veya patch status yayımlamaz; bu nedenle ürüne özgü claim'i doğrulanmamış ve build'e bağlı olarak değerlendirin.<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. Son relative name'i hedeflenen destination'da kullanışlı olacak şekilde writable bir tree oluşturun. Örnekte `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll` kullanılır, ancak başlangıçta `bcrypt.dll` dosyasına bir OLE macro document yazılır; PE DLL yazılmaz. Content-based detection remediation'ı tetiklerken attacker-controlled basename daha sonraki side-load için korunur.<sup>[[5]](#references)</sup>
2. Directory'leri geniş sharing ve `FILE_OPEN_REPARSE_POINT` ile açın, ardından trigger üzerinde `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` ve `REQUEST_OPLOCK_INPUT_FLAG_REQUEST` kullanarak asynchronous RH oplock isteyin. Overlapped event'i bekleyin ve completion'ını path-switch cue olarak kullanın. RH oplock-break notification, her conflicting operation'ın engellendiğine dair kanıt değil, advisory bir bildirimdir; bu nedenle exploitability hâlâ victim'ın kesin open/remediation sequence'ına bağlıdır.<sup>[[5]](#references)[[7]](#references)</sup>
3. Break sonrasında leaf directory'yi delete ve POSIX-semantics flag'leriyle `FileDispositionInformationEx` (information class 64) kullanarak kaldırın, handle'ını kapatın ve `FSCTL_SET_REPARSE_POINT_EX` ile artık boş olan parent'a `IO_REPARSE_TAG_MOUNT_POINT` uygulayın. Mount point, unchanged suffix'i `\\SystemRoot\\System32\\WindowsPowerShell` gibi korumalı bir tree'ye yönlendirir; directory boş değilse reparse point ayarlanamaz, önceki deletion adımının nedeni budur.<sup>[[5]](#references)[[8]](#references)</sup>
4. Ayrıcalıklı workflow'u sürdürün. Eğer directory chain'in ve final object'in daha önce incelenenlerle aynı olduğunu kanıtlamadan string'i yeniden resolve ederse, aynı logical pathname artık attacker-selected protected directory'ye ulaşır. Örnekte başarı, original process'ten `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` dosyasını read/write olarak yeniden açarak test edilir; bu, confused-deputy write primitive'ini sonraki code-execution aşamasından ayırır.<sup>[[5]](#references)</sup>
5. Ortaya çıkan file'ı gerçek DLL ile değiştirin ve ayrıcalıklı bir loader'ı etkinleştirin. PoC, `CreateTransaction` + `CreateFileTransacted` kullanır, file'ı truncate eder, DLL boyutunda replacement map eder, PE'yi kopyalar ve commit eder; TxF, file handle'ını ve sonraki handle-based operation'ları transaction'a bağlar, ancak privilege boundary failure'ın kaynağı değil, race sonrası bir replacement mechanism'idir.<sup>[[5]](#references)[[9]](#references)</sup>
6. Son olarak, executable'ı yerleştirilen adjacent filename'ı probe eden mevcut bir ayrıcalıklı scheduled task'ı çalıştırın. FalconFlank `\\Microsoft\\Windows\\Application Experience\\MareBackup`'ı çağırır, DLL'in `\\??\\pipe\\FALCONFLANK`'a bağlanmasını bekler ve ardından yerleştirilen file'ı siler. Yalnızca task name'e dayanarak belirli bir resulting token varsaymayın; test edilen build üzerinde launched process'i, module path'i, integrity level'ı ve token'ı doğrulayın.<sup>[[5]](#references)</sup>

Bu nedenle temel audit sorusu “service original input path'i validate ediyor mu?” değil, “her privileged mutation, validate edilen aynı opened file ve directory object'lerine bağlı kalıyor mu?” sorusudur. Check ve use boyunca handle'ları tutmak, child object'leri trusted directory handle'a relative olarak açmak, beklenmeyen reparse tag'lerini reddetmek ve mutation öncesinde file identity'yi yeniden doğrulamak bu pathname-substitution bug sınıfını kapatır.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection ve PoC triage

High-signal detection, namespace transition'ı privileged consumer ile korele eder: GUID-named temporary tree altında DLL basename'i taşıyan bir OLE header, oplock break, leaf directory'nin POSIX-style removal'ı, protected Windows directory'yi hedefleyen bir mount point'in oluşturulması ve destination altında aynı basename'in oluşturulması veya değiştirilmesi. Public example için `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, `MareBackup`'ın manual execution'ı ve `FALCONFLANK` named pipe'ını daha dar pivot'lar olarak ekleyin; bunların hiçbiri tek başına yeterli değildir.<sup>[[5]](#references)</sup>

PoC'yi yeniden üretirken yayımlanmış source'taki üç reliability defect'i dikkate alın: `FlushFileBuffers`'ı file handle yerine embedded byte-array pointer'ı ile çağırır, `GetFolder`, `GetTask` ve `Run` sonrasında stale bir `HRESULT` test eder ve directory deletion, reparse creation, oplock event ile pipe connection için unbounded retry/wait loop'ları kullanır.<sup>[[5]](#references)</sup>

## Operational considerations

- **Primitive'leri birleştirin** – `UNICODE_STRING` size sınırına ulaşana kadar daha yüksek latency için directory chain'deki *her level*'da long name kullanabilirsiniz.
- **One-shot bug'lar** – Genişletilmiş window (onlarca microsecond'dan dakikalara kadar), CPU affinity pinning veya hypervisor-assisted preemption ile birleştirildiğinde “single trigger” bug'larını gerçekçi hâle getirir.
- **Side effect'ler** – Slowdown yalnızca malicious path'i etkiler; bu nedenle genel system performance etkilenmez. Defenders, namespace growth'ı izlemedikleri sürece bunu nadiren fark eder.
- **Cleanup** – Oluşturduğunuz her directory/object için handle'ları tutun; böylece sonrasında `NtMakeTemporaryObject`/`NtClose` çağırabilirsiniz. Aksi hâlde unbounded directory chain'leri reboot'lar arasında kalabilir.
- **File-system race'leri** – Vulnerable path sonunda NTFS üzerinden resolve ediliyorsa, OM slowdown çalışırken backing file üzerine bir Oplock (ör. aynı toolkit'teki `SetOpLock.exe`) yerleştirebilirsiniz; bu, OM graph'ını değiştirmeden consumer'ı ek milliseconds boyunca dondurur.<sup>[[2]](#references)</sup>

## Defensive notes

- Named object'lere dayanan kernel code, security-sensitive state'i open işleminden *sonra* yeniden validate etmeli veya check öncesinde bir reference almalıdır (TOCTOU gap'ini kapatmak için).
- User-controlled name'leri dereference etmeden önce OM path depth/length için upper bound'lar uygulayın. Aşırı uzun name'leri reddetmek attacker'ları yeniden microsecond window'una zorlar.
- Şüpheli thousands-of-components chain'lerini `\BaseNamedObjects` altında tespit etmek için Object Manager namespace growth'ı (ETW `Microsoft-Windows-Kernel-Object`) instrument edin.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Path Lookup'larıyla Race Condition'ları Kazanma](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Transactional NTFS Nasıl Kullanılır](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
