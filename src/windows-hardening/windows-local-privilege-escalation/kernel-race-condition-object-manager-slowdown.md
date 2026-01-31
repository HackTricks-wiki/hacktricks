# Nesne Yöneticisi (Object Manager) Yavaş Yollarıyla Çekirdek Yarış Koşulu Sömürüsü

{{#include ../../banners/hacktricks-training.md}}

## Yarış zaman penceresini uzatmanın önemi

Birçok Windows kernel LPE'si klasik deseni izler `check_state(); NtOpenX("name"); privileged_action();`. Modern donanımda soğuk bir `NtOpenEvent`/`NtOpenSection` kısa bir ismi ~2 µs içinde çözer, bu da güvenli işlem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. Adım 2'de Object Manager Namespace (OMNS) aramasını kasıtlı olarak onlarca mikrosaniye sürdürerek, saldırgan binlerce denemeye gerek kalmadan aksi takdirde kararsız olan yarışları tutarlı şekilde kazanacak kadar zaman kazanır.

## Object Manager arama iç detayları (kısaca)

* **OMNS structure** – `\BaseNamedObjects\Foo` gibi isimler dizin-dizin çözülür. Her bileşen kernel'in bir *Object Directory* bulup/açmasına ve Unicode dizelerini karşılaştırmasına neden olur. Yol üzerinde sembolik linkler (örn. sürücü harfleri) takip edilebilir.
* **UNICODE_STRING limit** – OM yolları `Length` alanı 16-bit olan bir `UNICODE_STRING` içinde taşınır. Mutlak limit 65 535 byte (32 767 UTF-16 kod noktası)dir. `\BaseNamedObjects\` gibi öneklerle saldırgan hâlâ ≈32 000 karakter kontrol edebilir.
* **Attacker prerequisites** – Her kullanıcı `\BaseNamedObjects` gibi yazılabilir dizinlerin altında nesneler oluşturabilir. Zafiyetli kod içerideki bir adı kullandığında veya oraya çıkan bir sembolik linki takip ettiğinde, saldırgan özel ayrıcalık olmadan arama performansını kontrol eder.

## Yavaşlatma ilkel #1 – Tek maksimum bileşen

Bir bileşeni çözmenin maliyeti kabaca uzunluğuyla orantılıdır çünkü kernel üst dizindeki her girişe karşı Unicode karşılaştırması yapmak zorundadır. 32 kB uzunluğunda bir ada sahip bir event oluşturarak `NtOpenEvent` gecikmesini Windows 11 24H2 (Snapdragon X Elite testbed) üzerinde ~2 µs'den ~35 µs'ye anında yükseltebilirsiniz.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Pratik notlar*

- İsimlendirilmiş herhangi bir kernel object kullanarak uzunluk limitine ulaşabilirsiniz (events, sections, semaphores…).
- Symbolic links veya reparse points kısa bir “victim” adını bu dev bileşene yönlendirebilir, böylece yavaşlama şeffaf şekilde uygulanır.
- Her şey user-writable namespaces içinde olduğu için payload standart bir user integrity level’dan çalışır.

## Slowdown primitive #2 – Deep recursive directories

Daha agresif bir varyant binlerce diziden oluşan bir zincir ayırır (`\BaseNamedObjects\A\A\...\X`). Her adım dizin çözümleme mantığını (ACL checks, hash lookups, reference counting) tetikler; bu yüzden seviye başına gecikme tek bir string karşılaştırmasından daha yüksektir. Yaklaşık 16 000 seviyede (aynı `UNICODE_STRING` boyutuyla sınırlı), deneysel zamanlamalar uzun tek bileşenlerle elde edilen 35 µs bariyerini aşar.
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

* Eğer üst dizin aynı isimleri reddetmeye başlarsa, her seviyede karakteri değiştirin (`A/B/C/...`).
* İstismar sonrasında zinciri temiz bir şekilde silmek ve namespace'i kirletmemek için bir handle array tutun.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories, girişler için **shadow directories** (fallback lookups) ve bucketed hash tables'ı destekler. Her ikisini ve 64-component symbolic-link reparse limitini kötüye kullanarak, `UNICODE_STRING` uzunluğunu aşmadan gecikmeyi katlayın:

1. `\BaseNamedObjects` altında iki dizin oluşturun, örn. `A` (shadow) ve `A\A` (target). İkinciyi ilkini shadow directory olarak kullanarak (`NtCreateDirectoryObjectEx`) oluşturun, böylece `A` içindeki eksik aramalar `A\A`'ya düşer.
2. Her dizini aynı hash bucket'a düşen binlerce **çakışan isim** ile doldurun (örn. aynı `RtlHashUnicodeString` değerini koruyarak sondaki rakamları değiştirerek). Aramalar artık tek bir dizin içinde O(n) doğrusal taramalara düşer.
3. Uzun `A\A\…` son ekine tekrar tekrar reparse olan ve reparse bütçesini tüketen yaklaşık 63'lü bir **object manager symbolic links** zinciri oluşturun. Her reparse ayrıştırmayı en baştan yeniden başlattığı için çakışma maliyetini katlar.
4. Son bileşenin (`...\\0`) aranması, her dizinde 16 000 çakışma olduğunda Windows 11'de artık **dakikalar** sürer; bu da one-shot kernel LPEs için pratikte garanti bir race galibiyeti sağlar.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Why it matters*: Dakikalar süren bir yavaşlama, one-shot race-based LPEs'i deterministic exploits'e dönüştürür.

## Measuring your race window

Hedef donanımında pencerenin ne kadar genişlediğini ölçmek için exploit'inizin içine kısa bir harness yerleştirin. Aşağıdaki kod parçası hedef nesneyi `iterations` kez açar ve `QueryPerformanceCounter` kullanarak açma başına ortalama maliyeti döndürür.
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
Sonuçlar doğrudan yarış orkestrasyon stratejinize yansır (örn. gereken worker thread sayısı, uyku aralıkları, paylaşılan durumu ne kadar erken değiştirmeniz gerektiği).

## İstismar iş akışı

1. **Zayıf open çağrısını bulun** – Kernel yolunu (symbols, ETW, hypervisor tracing veya reversing yoluyla) izleyin ta ki bir saldırgan-kontrollü ismi veya kullanıcı tarafından yazılabilir bir dizindeki bir sembolik bağlantıyı gezen bir `NtOpen*`/`ObOpenObjectByName` çağrısı bulana kadar.
2. **O ismi yavaş bir yolla değiştirin**
- `\BaseNamedObjects` altında (veya başka bir yazılabilir OM root altında) uzun bileşen veya dizin zinciri oluşturun.
- Kernel'in beklediği ismin artık yavaş yola çözülmesi için bir sembolik link oluşturun. Orijinal hedefe dokunmadan, zayıf sürücünün dizin aramasını yapınızı işaret edecek şekilde yönlendirebilirsiniz.
3. **Yarışı tetikleyin**
- Thread A (kurban) zayıf kodu çalıştırır ve yavaş arama içinde bloke olur.
- Thread B (saldırgan) Thread A meşgulken korunan durumu değiştirir (örn. bir file handle'ı değiştirir, bir sembolik linki yeniden yazar, nesne güvenliğini değiştirir).
- Thread A devam edip ayrıcalıklı işlemi gerçekleştirdiğinde, eski durumu gözlemler ve saldırgan-kontrollü işlemi yapar.
4. **Temizlik** – Şüpheli artefaktlar bırakmamak veya meşru IPC kullanıcılarını bozmamak için dizin zincirini ve sembolik linkleri silin.

## Operasyonel hususlar

- **Primitive'leri birleştirme** – `UNICODE_STRING` boyutunu tüketene kadar, daha yüksek gecikme için dizin zincirindeki *her seviye* için uzun bir isim kullanabilirsiniz.
- **Tek seferlik hatalar** – Genişleyen pencere (onlarca mikrosaniyeden dakikalara kadar), CPU affinity pinning veya hypervisor destekli preemption ile eşleştirildiğinde “tek tetiklemeli” hataları gerçekçi kılar.
- **Yan etkiler** – Yavaşlama yalnızca kötü amaçlı yolu etkiler, bu yüzden genel sistem performansı etkilenmez; savunucular namespace büyümesini izlemedikçe nadiren fark ederler.
- **Temizlik** – Oluşturduğunuz her dizin/nesne için tutamaçları saklayın ki sonrasında `NtMakeTemporaryObject`/`NtClose` çağırabilesiniz. Aksi takdirde sınırsız dizin zincirleri yeniden başlatmalarda kalıcı olabilir.

## Savunma notları

- Adlandırılmış nesnelere dayanan kernel kodu, güvenlik açısından hassas durumu open işleminden *sonra* yeniden doğrulamalı veya kontrol öncesi bir referans almalıdır (TOCTOU boşluğunu kapatmak için).
- Kullanıcı kontrollü isimleri dereference etmeden önce OM yol derinliği/uzunluğu için üst sınırlar uygulayın. Aşırı uzun isimleri reddetmek, saldırganları tekrar mikrosaniye aralığına zorlar.
- `\BaseNamedObjects` altında şüpheli binlerce-bileşen zincirlerini tespit etmek için object manager namespace büyümesini (ETW `Microsoft-Windows-Kernel-Object`) izleyin.

## Referanslar

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
