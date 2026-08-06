# Object Manager Slow Paths ile Kernel Race Condition Exploitation

{{#include ../../banners/hacktricks-training.md}}

## Race window'u genişletmek neden önemlidir?

Birçok Windows kernel LPE'si klasik şu kalıbı izler: `check_state(); NtOpenX("name"); privileged_action();`. Modern donanımlarda cold bir `NtOpenEvent`/`NtOpenSection`, kısa bir adı yaklaşık 2 µs içinde çözümler ve güvenli işlem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. 2. adımdaki Object Manager Namespace (OMNS) aramasını kasıtlı olarak onlarca mikrosaniye sürecek şekilde yavaşlatarak saldırgan, binlerce denemeye ihtiyaç duymadan normalde güvenilmez olan race condition'ları tutarlı şekilde kazanmak için yeterli zaman elde eder.<sup>[[1]](#references)</sup>

## Object Manager lookup internals kısaca

* **OMNS yapısı** – `\BaseNamedObjects\Foo` gibi adlar dizin bazında çözülür. Her bileşen, kernel'in bir *Object Directory* bulup açmasını ve Unicode string'lerini karşılaştırmasını gerektirir. Yol üzerinde symbolic link'ler (ör. sürücü harfleri) takip edilebilir.
* **UNICODE_STRING sınırı** – OM yolları, `Length` alanı 16 bitlik bir değer olan bir `UNICODE_STRING` içinde taşınır. Mutlak sınır 65.535 byte'tır (32.767 UTF-16 codepoint). `\BaseNamedObjects\` gibi prefix'lerle bile saldırgan yaklaşık 32.000 karakteri kontrol edebilir.
* **Saldırganın ön koşulları** – Herhangi bir kullanıcı, `\BaseNamedObjects` gibi yazılabilir dizinlerin altında nesneler oluşturabilir. Vulnerable code içerideki bir adı kullandığında veya bu dizine ulaşan bir symbolic link'i takip ettiğinde saldırgan, özel ayrıcalıklar olmadan lookup performansını kontrol edebilir.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Tek bir maksimum uzunlukta component

Bir component'i çözümlemenin maliyeti, uzunluğuyla yaklaşık doğrusal olarak artar; bunun nedeni kernel'in parent directory içindeki her entry ile Unicode karşılaştırması yapmak zorunda olmasıdır. 32 kB uzunluğunda bir ada sahip event oluşturmak, Windows 11 24H2'de `NtOpenEvent` latency'sini yaklaşık 2 µs'den 35 µs'ye hemen çıkarır (Snapdragon X Elite test sistemi).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Pratik notlar*

- Uzunluk sınırına herhangi bir named kernel object (events, sections, semaphores…) kullanarak ulaşabilirsiniz.
- Symbolic link'ler veya reparse point'ler, kısa bir “victim” adını bu dev bileşene yönlendirebilir; böylece slowdown şeffaf bir şekilde uygulanır.
- Her şey user-writable namespace'lerde bulunduğundan payload, standard user integrity level'dan çalışır.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Derin özyinelemeli dizinler

Daha agresif bir varyant, binlerce dizinden oluşan bir zincir ayırır (`\BaseNamedObjects\A\A\...\X`). Her geçiş, dizin çözümleme mantığını (ACL kontrolleri, hash aramaları, referans sayımı) tetikler; bu nedenle seviye başına gecikme, tek bir string karşılaştırmasından daha yüksektir. Aynı `UNICODE_STRING` boyutuyla sınırlı olan yaklaşık 16.000 seviyede, ampirik ölçümler uzun tek bileşenlerle elde edilen 35 µs bariyerini aşar.
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

* Üst dizin duplicate'leri reddetmeye başlarsa seviye başına karakteri (`A/B/C/...`) değiştirin.
* Exploitation sonrasında zinciri temiz şekilde silebilmek ve namespace'i kirletmemek için bir handle dizisi tutun.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (mikrosaniyeler yerine dakikalar)

Object directories, **shadow directories** (fallback lookups) ve entry'ler için bucket'lanmış hash tablolarını destekler. `UNICODE_STRING` uzunluğunu aşmadan slowdown'u artırmak için her ikisini ve 64 bileşenli symbolic-link reparse limitini birlikte abuse edin:

1. `\BaseNamedObjects` altında örneğin `A` (shadow) ve `A\A` (target) olmak üzere iki dizin oluşturun. İkincisini, birincisini shadow directory olarak kullanarak (`NtCreateDirectoryObjectEx`) oluşturun; böylece `A` içindeki eksik lookup'lar `A\A`'ya fall through eder.
2. Her dizini aynı hash bucket'ına düşen binlerce **colliding name** ile doldurun (örneğin aynı `RtlHashUnicodeString` değerini korurken sondaki rakamları değiştirin). Lookup'lar artık tek bir dizin içinde O(n) linear scan işlemlerine dönüşür.
3. Uzun `A\A\…` suffix'ine tekrar tekrar reparse eden yaklaşık 63 **object manager symbolic link** zinciri oluşturun ve reparse budget'ını tüketin. Her reparse parsing işlemini baştan başlatarak collision maliyetini katlar.
4. Final component (`...\\0`) lookup'ı, dizin başına 16 000 collision bulunduğunda Windows 11 üzerinde artık **dakikalar** sürer ve one-shot kernel LPE'leri için pratik olarak guaranteed bir race win sağlar.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Neden önemli*: Dakikalar süren bir yavaşlama, tek atımlık race tabanlı LPE'leri deterministik exploit'lere dönüştürür.<sup>[[1]](#references)</sup>

### 2025 retest notları ve hazır tooling

- James Forshaw, tekniği Windows 11 24H2 (ARM64) üzerinde güncellenmiş zamanlamalarla yeniden yayımladı. Baseline open işlemleri yaklaşık 2 µs seviyesinde kalırken, 32 kB'lık bir bileşen bu süreyi yaklaşık 35 µs'ye çıkarıyor ve shadow-dir + collision + 63-reparse zincirleri hâlâ yaklaşık 3 dakikaya ulaşarak primitive'lerin güncel build'lerde de çalıştığını doğruluyor. Source code ve perf harness, güncellenmiş Project Zero gönderisinde yer alıyor.<sup>[[1]](#references)</sup>
- Kurulumu public `symboliclink-testing-tools` bundle'ını kullanarak script'leyebilirsiniz: shadow/target pair'ini oluşturmak için `CreateObjectDirectory.exe`, 63-hop zincirini üretmek için de döngü içinde `NativeSymlink.exe` kullanın. Bu yöntem, elle yazılmış `NtCreate*` wrapper'larına olan ihtiyacı ortadan kaldırır ve ACL'leri tutarlı tutar.<sup>[[2]](#references)</sup>

## Race window'ınızı ölçme

Victim hardware üzerinde window'un ne kadar büyüdüğünü ölçmek için exploit'inize hızlı bir harness ekleyin. Aşağıdaki snippet, target object'i `iterations` kez açar ve `QueryPerformanceCounter` kullanarak her açma işleminin ortalama maliyetini döndürür.<sup>[[1]](#references)</sup>
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
Sonuçlar doğrudan race orchestration stratejinize beslenir (ör. gereken worker thread sayısı, sleep aralıkları ve paylaşılan state’i ne kadar erken değiştirmeniz gerektiği).

## Exploitation workflow

1. **Vulnerable open işlemini bulun** – Kernel yolunu (symbols, ETW, hypervisor tracing veya reversing aracılığıyla) izleyerek, user-writable bir dizindeki attacker-controlled name veya symbolic link üzerinde gezinerek çalışan bir `NtOpen*`/`ObOpenObjectByName` çağrısı bulana kadar ilerleyin.
2. **Bu name’i yavaş bir path ile değiştirin**
- `\BaseNamedObjects` (veya yazılabilir başka bir OM root) altında uzun component ya da directory chain oluşturun.
- Kernel’in beklediği name’in artık slow path’e resolve edilmesi için bir symbolic link oluşturun. Vulnerable driver’ın directory lookup işlemini, original target’a dokunmadan kendi yapınıza yönlendirebilirsiniz.
3. **Race’i tetikleyin**
- Thread A (victim), vulnerable code’u çalıştırır ve slow lookup içinde bloklanır.
- Thread B (attacker), Thread A meşgulken guarded state’i değiştirir (ör. bir file handle’ı değiştirir, symbolic link’i yeniden yazar veya object security’yi değiştirir).
- Thread A devam edip privileged action’ı gerçekleştirdiğinde stale state’i görür ve attacker-controlled operation’ı gerçekleştirir.
4. **Temizleyin** – Şüpheli artifact’ler bırakmamak veya legitimate IPC kullanıcılarını bozmamak için directory chain ve symbolic link’leri silin.<sup>[[1]](#references)</sup>

## Operational considerations

- **Primitive’leri birleştirin** – `UNICODE_STRING` size sınırına ulaşana kadar daha yüksek latency elde etmek için bir directory chain içindeki *her level* için uzun bir name kullanabilirsiniz.
- **One-shot bug’lar** – Genişletilmiş window (onlarca microsecond ile dakikalar arası), CPU affinity pinning veya hypervisor-assisted preemption ile birlikte kullanıldığında “single trigger” bug’larını gerçekçi hâle getirir.
- **Side effect’ler** – Slowdown yalnızca malicious path’i etkiler; bu nedenle genel sistem performansı etkilenmez. Defenders, namespace growth’u izlemedikleri sürece bunu nadiren fark eder.
- **Cleanup** – Oluşturduğunuz her directory/object için handle’ları saklayarak sonrasında `NtMakeTemporaryObject`/`NtClose` çağırabilin. Aksi hâlde sınırsız directory chain’leri reboot sonrasında da kalabilir.
- **File-system race’leri** – Vulnerable path sonunda NTFS üzerinden resolve ediliyorsa, OM slowdown çalışırken backing file üzerinde bir Oplock (ör. aynı toolkit’teki `SetOpLock.exe`) kurabilirsiniz. Böylece OM graph’ını değiştirmeden consumer’ı ek milliseconds boyunca dondurabilirsiniz.<sup>[[2]](#references)</sup>

## Defensive notes

- Named object’lere dayanan kernel code, security-sensitive state’i open işleminden *sonra* yeniden doğrulamalı veya check işleminden önce bir reference almalıdır (TOCTOU gap’ini kapatmak için).
- User-controlled name’leri dereference etmeden önce OM path depth/length için üst sınırlar uygulayın. Aşırı uzun name’leri reddetmek, attacker’ları yeniden microsecond window’una zorlar.
- Şüpheli binlerce component içeren chain’leri `\BaseNamedObjects` altında tespit etmek için object manager namespace growth’u (ETW `Microsoft-Windows-Kernel-Object`) instrument edin.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
