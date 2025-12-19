# Çekirdek Yarış Durumu İstismarı — Object Manager Slow Paths üzerinden

{{#include ../../banners/hacktricks-training.md}}

## Neden yarış zaman aralığını uzatmak önemli

Birçok Windows çekirdek LPE'si klasik deseni takip eder `check_state(); NtOpenX("name"); privileged_action();`. Modern donanımda soğuk bir `NtOpenEvent`/`NtOpenSection` kısa bir ismi ~2 µs içinde çözer, güvenli eylem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. Adım 2'de Object Manager Namespace (OMNS) aramasını kasıtlı olarak onlarca mikro saniyeye uzatarak, saldırgan binlerce denemeye gerek kalmadan aksi takdirde güvenilmez yarışları tutarlı şekilde kazanmak için yeterli zaman kazanır.

## Object Manager arama iç işleyişi kısaca

* **OMNS yapısı** – `\BaseNamedObjects\Foo` gibi isimler dizin-dizin çözülür. Her bileşen kernel'in bir *Object Directory* bulup/açmasını ve Unicode dizelerini karşılaştırmasını gerektirir. Yol üzerinde sembolik linkler (ör. sürücü harfleri) izlenebilir.
* **UNICODE_STRING limit** – OM yolları `UNICODE_STRING` içinde taşınır ve bunun `Length` alanı 16-bitlik bir değerdir. Mutlak limit 65 535 byte (32 767 UTF-16 kod noktası). `\BaseNamedObjects\` gibi öneklerle saldırgan hâlâ ≈32 000 karakter kontrolüne sahiptir.
* **Saldırgan önkoşulları** – Herhangi bir kullanıcı `\BaseNamedObjects` gibi yazılabilir dizinlerin altına nesneler oluşturabilir. Zafiyetli kod içerideki bir ismi kullandığında veya oraya giden bir sembolik linki takip ettiğinde, saldırgan özel ayrıcalık olmadan arama performansını kontrol eder.

## Yavaşlatma yöntemi #1 – Tek maksimum bileşen

Bir bileşeni çözmenin maliyeti, kernel'in üst dizindeki her girdiye karşı bir Unicode karşılaştırması yapması gerektiğinden uzunluğuyla yaklaşık olarak lineerdir. 32 kB uzunluğunda bir isimle bir event oluşturmak, `NtOpenEvent` gecikmesini Windows 11 24H2 (Snapdragon X Elite testbed) üzerinde ~2 µs'den ~35 µs'ye anında artırır.
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
- Symbolic links veya reparse points, kısa bir “victim” adını bu dev bileşene yönlendirerek yavaşlamanın şeffaf şekilde uygulanmasını sağlar.
- Her şey user-writable namespaces içinde bulunduğundan, payload standart user integrity level'da çalışır.

## Slowdown primitive #2 – Derin özyinelemeli dizinler

Daha agresif bir varyant, binlerce dizinden oluşan bir zincir tahsis eder (`\BaseNamedObjects\A\A\...\X`). Her adım directory resolution logic'i (ACL checks, hash lookups, reference counting) tetikler; bu yüzden seviye başına gecikme tek bir string karşılaştırmasından daha yüksektir. Aynı `UNICODE_STRING` boyutu ile sınırlı yaklaşık 16 000 seviye ile deneysel zamanlamalar, uzun tek bileşenlerle elde edilen 35 µs eşiğini aşar.
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

* Üst dizin aynı isimleri/tekrarları reddetmeye başlarsa, seviye başına karakteri (`A/B/C/...`) değiştirin.
* Exploitation sonrasında zinciri temizce silebilmek için bir handle array tutun; böylece namespace'i kirletmekten kaçınmış olursunuz.

## Race window'unuzu ölçme

Exploit'inizin içine hızlı bir harness yerleştirin, böylece victim hardware üzerindeki pencerenin ne kadar genişlediğini ölçebilirsiniz. Aşağıdaki kod parçası hedef objeyi `iterations` kez açar ve `QueryPerformanceCounter` kullanarak her açma başına ortalama maliyeti döndürür.
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
The results feed directly into your race orchestration strategy (e.g., number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Sömürme iş akışı

1. **Kırılgan open çağrısını bulun** – Kernel yolunu (via symbols, ETW, hypervisor tracing, or reversing) izleyin; saldırganın kontrol ettiği bir isim veya kullanıcı tarafından yazılabilen bir dizindeki sembolik linki dolaşan `NtOpen*`/`ObOpenObjectByName` çağrısını bulana kadar.
2. **O ismi yavaş bir path ile değiştirin**
- `\BaseNamedObjects` (veya başka bir writable OM kökü) altında uzun bileşen veya dizin zinciri oluşturun.
- Kernel'in beklediği ismin şimdi yavaş yola çözümlenmesini sağlayacak bir sembolik link oluşturun. Orijinal hedefe dokunmadan zafiyetli sürücünün dizin aramasını kendi yapınıza yönlendirebilirsiniz.
3. **Yarışı tetikleyin**
- Thread A (kurban) zafiyetli kodu çalıştırır ve yavaş arama sırasında engellenir.
- Thread B (saldırgan) Thread A meşgulken korunmuş durumu değiştirir (ör. bir file handle değiştirir, sembolik linki yeniden yazar, nesne güvenliğini değiştirir).
- Thread A devam edip ayrıcalıklı işlemi gerçekleştirdiğinde, eski durumu görür ve saldırganın kontrolündeki işlemi yapar.
4. **Temizlik** – Şüpheli izler bırakmamak veya meşru IPC kullanıcılarını bozmemek için dizin zincirini ve sembolik linkleri silin.

## Operasyonel hususlar

- **Primitifleri birleştirin** – `UNICODE_STRING` boyutunu tüketene kadar, dizin zincirinde seviye başına uzun bir isim kullanarak daha yüksek gecikme elde edebilirsiniz.
- **Tek atımlık hatalar** – Genişleyen pencere (onlarca mikro saniye), CPU affinity pinning veya hypervisor-assisted preemption ile eşleştirildiğinde “single trigger” hataları gerçekçi kılar.
- **Yan etkiler** – Yavaşlama yalnızca kötü amaçlı yolu etkiler, bu nedenle genel sistem performansı etkilenmez; savunucular namespace büyümesini izlemedikçe nadiren fark ederler.
- **Temizlik** – Oluşturduğunuz her dizin/nesne için handle'ları saklayın, böylece sonra `NtMakeTemporaryObject`/`NtClose` çağırabilirsiniz. Aksi takdirde sınırsız dizin zincirleri yeniden başlatmalarda kalıcı olabilir.

## Savunma notları

- İsimlendirilmiş nesnelere dayanan kernel kodu, güvenlik açısından hassas durumu open işleminden *sonra* yeniden doğrulamalı veya kontrol öncesinde bir referans almalıdır (TOCTOU açığını kapatmak için).
- Kullanıcı kontrollü isimleri dereference etmeden önce OM yol derinliği/uzunluğu için üst sınırlar uygulayın. Aşırı uzun isimleri reddetmek saldırganları mikro saniyelik pencereye geri zorlar.
- `\BaseNamedObjects` altında şüpheli binlerce bileşenli zincirleri tespit etmek için object manager namespace büyümesini (ETW `Microsoft-Windows-Kernel-Object`) izleyin.

## Referanslar

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
