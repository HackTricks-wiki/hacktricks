# Kernel Yarış Durumu Sömürüsü — Object Manager Yavaş Yolları Üzerinden

{{#include ../../banners/hacktricks-training.md}}

## Neden yarış penceresini genişletmek önemli

Birçok Windows kernel LPE klasik `check_state(); NtOpenX("name"); privileged_action();` desenini izler. Modern donanımda soğuk bir `NtOpenEvent`/`NtOpenSection` kısa bir ismi ~2 µs içinde çözer; bu, güvenli işlem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. Adım 2'de Object Manager Namespace (OMNS) aramasını kasten onlarca mikrosaniyeye uzatarak, saldırgan binlerce denemeye ihtiyaç duymadan aksi takdirde belirsiz olan yarışları tutarlı şekilde kazanmak için yeterli zamanı elde eder.

## Object Manager arama içyapısı kısaca

* **OMNS structure** – `\BaseNamedObjects\Foo` gibi isimler dizin-dizin çözümlenir. Her bileşen kernelin bir *Object Directory* bulup/açmasına ve Unicode dizgilerini karşılaştırmasına neden olur. Yol üzerinde sembolik linkler (ör. sürücü harfleri) izlenebilir.
* **UNICODE_STRING limit** – OM yolları `UNICODE_STRING` içinde taşınır; bunun `Length` alanı 16-bitlik bir değerdir. Mutlak limit 65 535 byte (32 767 UTF-16 codepoint)dir. `\BaseNamedObjects\` gibi öneklerle saldırgan hâlâ ≈32 000 karakteri kontrol edebilir.
* **Attacker prerequisites** – Herhangi bir kullanıcı `\BaseNamedObjects` gibi yazılabilir dizinlerin altına nesneler oluşturabilir. Zafiyetli kod içinde bir isim kullanıldığında veya yol bir sembolik link takip ederek oraya geldiğinde, saldırgan herhangi bir özel ayrıcalık olmadan arama performansını kontrol eder.

## Slowdown primitive #1 – Tek maksimal bileşen

Bir bileşeni çözümlemenin maliyeti, kernelin üst dizindeki her girişle bir Unicode karşılaştırması yapması gerektiği için yaklaşık olarak uzunluğuyla doğru orantılıdır. 32 kB uzunluğunda bir ada sahip bir event oluşturmak, Windows 11 24H2 (Snapdragon X Elite testbed) üzerinde `NtOpenEvent` gecikmesini hemen ~2 µs'ten ~35 µs'e yükseltir.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Pratik notlar*

- Herhangi bir named kernel object (events, sections, semaphores…) kullanarak uzunluk sınırına ulaşabilirsiniz.
- Symbolic links veya reparse points, kısa bir “victim” adını bu dev bileşene yönlendirerek slowdown'un şeffaf şekilde uygulanmasını sağlar.
- Her şey user-writable namespaces içinde bulunduğundan, payload standart bir user integrity level'dan çalışır.

## Slowdown primitive #2 – Deep recursive directories

Daha agresif bir varyant, binlerce dizinden oluşan bir zincir ayırır (`\BaseNamedObjects\A\A\...\X`). Her atlayış directory resolution logic'i tetikler (ACL checks, hash lookups, reference counting), bu yüzden seviye başına gecikme tek bir string compare'den daha yüksektir. Yaklaşık 16 000 seviyeye (aynı `UNICODE_STRING` boyutuyla sınırlı) ulaşıldığında, ampirik zamanlamalar uzun tek bileşenlerle elde edilen 35 µs eşiğini aşıyor.
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
Tips:

* Üst dizin aynı isimleri reddetmeye başlarsa, her seviyede karakteri sırayla değiştirin (`A/B/C/...`).
* Zinciri exploitation sonrası temizce silebilmek ve namespace'i kirletmemek için bir handle array tutun.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (mikrosaniyeler yerine dakikalar)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **minutes** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Neden önemli*: Dakikalar süren bir yavaşlama, one-shot race-based LPEs'i deterministik exploit'lere dönüştürür.

## Yarış penceresini ölçme

Exploit'inizin içine, hedef donanımda pencerenin ne kadar genişlediğini ölçmek için kısa bir harness gömün. Aşağıdaki kod parçası hedef nesneyi `iterations` kez açar ve `QueryPerformanceCounter` kullanarak açma başına ortalama maliyeti döndürür.
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
Sonuçlar doğrudan race orkestrasyon stratejinize girer (ör. ihtiyaç duyulan worker thread sayısı, uyku aralıkları, paylaşılan durumu ne kadar erken değiştirmemiz gerektiği).

## Exploitation workflow

1. **Locate the vulnerable open** – Kernel yolunu izleyin (symbols, ETW, hypervisor tracing veya reversing ile) ta ki attacker-controlled bir isim veya user-writable dizindeki bir symbolic link'i dolaşan `NtOpen*`/`ObOpenObjectByName` çağrısını bulana kadar.
2. **Replace that name with a slow path**
- `\BaseNamedObjects` altında (veya başka bir yazılabilir OM root) uzun bileşen veya dizin zinciri oluşturun.
- Kernel'in beklediği ismin artık slow path'e çözülmesi için bir symbolic link oluşturun. Orijinal hedefe dokunmadan vulnerable driver’ın directory lookup'unu yapınıza yönlendirebilirsiniz.
3. **Trigger the race**
- Thread A (victim) zafiyetli kodu çalıştırır ve slow lookup içinde bloke olur.
- Thread B (attacker) Thread A meşgulken guarded state'i değiştirir (ör. bir file handle değiş tokuşu, symbolic link yeniden yazma, object security değişikliği).
- Thread A devam edip ayrıcalıklı işlemi gerçekleştirdiğinde eski (stale) state'i görür ve attacker-controlled işlemi yapar.
4. **Clean up** – Şüpheli artefakt bırakmamak veya meşru IPC kullanıcılarını bozmemek için dizin zincirini ve symbolic linkleri silin.

## Operational considerations

- **Combine primitives** – Dizin zincirinde *per level* uzun bir isim kullanarak `UNICODE_STRING` boyutunu tüketene dek daha yüksek gecikme sağlayabilirsiniz.
- **One-shot bugs** – Genişleyen pencere (mikrosaniyelerden dakikalara kadar) CPU affinity pinning veya hypervisor-assisted preemption ile eşleştirildiğinde “single trigger” hatalarını gerçekçi kılar.
- **Side effects** – Yavaşlama sadece kötü amaçlı path'i etkiler, bu yüzden genel sistem performansı etkilenmez; savunucular namespace büyümesini izlemedikçe nadiren fark ederler.
- **Cleanup** – Oluşturduğunuz her dizin/objeye ilişkin handle'ları saklayın ki sonrasında `NtMakeTemporaryObject`/`NtClose` çağırabilesiniz. Aksi halde sınırsız dizin zincirleri yeniden başlatmalar arasında kalıcı olabilir.

## Defensive notes

- Named object'lara dayanan kernel kodu, open işleminden *sonra* güvenliğe duyarlı state'i yeniden doğrulamalı ya da kontrol öncesi bir referans almalıdır (TOCTOU açığını kapatmak için).
- User-controlled isimleri dereference etmeden önce OM path derinliği/uzunluğu için üst sınırlar uygulayın. Aşırı uzun isimleri reddetmek saldırganları mikro saniye penceresine geri iter.
- Object manager namespace büyümesini instrument edin (ETW `Microsoft-Windows-Kernel-Object`) ve `\BaseNamedObjects` altında binlerce bileşenli şüpheli zincirleri tespit edin.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
