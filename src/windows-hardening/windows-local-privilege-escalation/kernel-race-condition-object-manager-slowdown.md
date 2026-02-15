# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Neden race penceresini genişletmek önemli

Birçok Windows kernel LPE'si klasik şablonu `check_state(); NtOpenX("name"); privileged_action();` izler. Modern donanımda soğuk bir `NtOpenEvent`/`NtOpenSection` kısa bir ismi ~2 µs civarında çözer; bu da güvenli işlem gerçekleşmeden önce kontrol edilen durumu değiştirmek için neredeyse hiç zaman bırakmaz. Adım 2'de Object Manager Namespace (OMNS) aramasını kasıtlı olarak onlarca mikro­saniye sürecek şekilde yavaşlatmak, saldırganın binlerce denemeye gerek duymadan aksi takdirde kararsız olan race'leri tutarlı şekilde kazanmak için yeterli zamanı kazanmasını sağlar.

## Object Manager lookup içyapısı kısaca

* **OMNS structure** – `\BaseNamedObjects\Foo` gibi isimler dizin-dizin çözülür. Her bileşen kernel'in bir *Object Directory* bulmasına/açmasına ve Unicode dizelerini karşılaştırmasına neden olur. Sembolik linkler (ör. sürücü harfleri) yol boyunca takip edilebilir.
* **UNICODE_STRING limit** – OM yolları `UNICODE_STRING` içinde taşınır ve bunun `Length` alanı 16-bit bir değerdir. Mutlak limit 65 535 byte (32 767 UTF-16 kod noktasıdır). `\BaseNamedObjects\` gibi öneklerle, saldırgan hâlâ ≈32 000 karakter üzerinde kontrol sahibidir.
* **Attacker prerequisites** – Her kullanıcı `\BaseNamedObjects` gibi yazılabilir dizinlerin altına nesneler oluşturabilir. Zafiyetli kod içerideki bir ismi kullandığında veya oraya yönlenen bir sembolik linki takip ettiğinde, saldırgan özel ayrıcalık gerektirmeden lookup performansını kontrol eder.

## Slowdown primitive #1 – Tek maksimum bileşen

Bir bileşeni çözmenin maliyeti uzunluğuyla yaklaşık olarak lineerdir çünkü kernel ebeveyn dizindeki her girişe karşı Unicode karşılaştırması yapmak zorundadır. 32 kB uzunluğunda bir isimle bir event oluşturmak, `NtOpenEvent` gecikmesini Windows 11 24H2 (Snapdragon X Elite testbed) üzerinde ~2 µs'den ~35 µs'ye hemen artırır.
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Pratik notlar*

- İsimlendirilmiş herhangi bir kernel nesnesi (events, sections, semaphores…) kullanarak uzunluk sınırına ulaşabilirsiniz.
- Symbolic links veya reparse points, kısa bir “victim” adını bu dev bileşene yönlendirebilir; böylece yavaşlama şeffaf şekilde uygulanır.
- Çünkü her şey user-writable namespaces içinde bulunduğundan, payload standart bir user integrity level'dan çalışır.

## Slowdown primitive #2 – Derin özyinelemeli dizinler

Daha agresif bir varyant, binlerce dizinden oluşan bir zincir (`\BaseNamedObjects\A\A\...\X`) ayırır. Her atlama dizin çözümleme mantığını (ACL checks, hash lookups, reference counting) tetikler; bu yüzden seviye başına gecikme tek bir string karşılaştırmasından daha yüksektir. Yaklaşık 16 000 seviye ile (aynı `UNICODE_STRING` boyutu ile sınırlı), ampirik zamanlamalar uzun tek bileşenlerle elde edilen 35 µs eşiğini aşar.
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

* Parent dizini tekrar eden öğeleri reddetmeye başlıyorsa, seviye başına karakteri (`A/B/C/...`) değiştirin.
* İstismar sonrası ad alanını kirletmemek için zinciri temiz şekilde silebilmek adına bir handle dizisi tutun.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Object directories destekler **shadow directories** (fallback lookups) ve girişler için kova tabanlı hash tablolarını. Her ikisini ve 64-bileşenli symbolic-link reparse limitini kötüye kullanarak, `UNICODE_STRING` uzunluğunu aşmadan yavaşlamayı katlayabilirsiniz:

1. `\BaseNamedObjects` altında iki dizin oluşturun, örneğin `A` (shadow) ve `A\A` (target). İkincisini birincisini shadow directory olarak kullanarak oluşturun (`NtCreateDirectoryObjectEx`), böylece `A` içindeki eksik aramalar `A\A`'ya düşer.
2. Her dizini aynı hash kovasına düşen binlerce **çakışan isim** ile doldurun (ör. son basamakları değiştirirken aynı `RtlHashUnicodeString` değerini koruyarak). Aramalar artık tek bir dizin içinde O(n) lineer taramalara dönüşür.
3. Yaklaşık ~63 uzunluğunda bir **object manager symbolic links** zinciri oluşturun; bunlar tekrar tekrar uzun `A\A\…` sonekine reparse olur ve reparse bütçesini tüketir. Her reparse, ayrıştırmayı baştan başlatarak çakışma maliyetini katlar.
4. Son bileşenin (`...\\0`) aranması, her dizinde 16 000 çakışma olduğunda Windows 11'de artık **dakikalar** sürer; bu da tek seferlik kernel LPE'leri için pratikte garanti bir yarış kazanımı sağlar.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Neden önemli*: Dakikalar süren bir yavaşlama, one-shot race-based LPE'leri deterministik exploit'lere dönüştürür.

### 2025 retest notes & ready-made tooling

- James Forshaw, Windows 11 24H2 (ARM64) üzerinde güncellenmiş zamanlamalarla tekniği yeniden yayımladı. Baseline open'lar ~2 µs civarında kalıyor; 32 kB bir bileşen bunu ~35 µs'ye çıkarıyor ve shadow-dir + collision + 63-reparse zincirleri hâlâ ~3 dakika seviyelerine ulaşıyor; bu, primitive'lerin mevcut build'lerde yaşadığını doğruluyor. Source code ve perf harness yenilenmiş Project Zero gönderisinde mevcut.
- Kurulumu halka açık `symboliclink-testing-tools` paketini kullanarak scriptleyebilirsiniz: shadow/hedef çiftini spawn etmek için `CreateObjectDirectory.exe` ve 63-hop zincirini çıkarmak için döngü içinde `NativeSymlink.exe`. Bu, elle yazılmış `NtCreate*` wrapper'larından kaçınır ve ACL'leri tutarlı tutar.

## Yarış penceresini ölçme

Hedef donanımda pencerenin ne kadar genişlediğini ölçmek için exploit'inizin içine hızlı bir harness gömün. Aşağıdaki snippet hedef objeyi `iterations` kere açar ve `QueryPerformanceCounter` kullanarak her açma başına ortalama maliyeti döndürür.
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
Sonuçlar doğrudan sizin race orchestration stratejinize yansır (ör. kaç worker thread gerektiği, sleep aralıkları, paylaşılan durumu ne kadar erken flip etmeniz gerektiği).

## İstismar iş akışı

1. **Zafiyetli open çağrısını bulun** – Semboller, ETW, hypervisor tracing veya reversing aracılığıyla kernel yolunu izleyin; saldırgan tarafından kontrol edilen bir ismi veya kullanıcı tarafından yazılabilir bir dizindeki sembolik link'i dolaşan bir `NtOpen*`/`ObOpenObjectByName` çağrısı bulana kadar.
2. **O ismi bir slow path ile değiştirin**
- `\BaseNamedObjects` altında (veya başka bir yazılabilir OM root altında) uzun bir bileşen ya da dizin zinciri oluşturun.
- Kernel’in beklediği ismin artık slow path'e çözülmesini sağlayacak bir sembolik link oluşturun. Hedefi ellemeden, zafiyetli sürücünün dizin aramasını kendi yapınıza yönlendirebilirsiniz.
3. **Race'i tetikleyin**
- Thread A (kurban) zafiyetli kodu çalıştırır ve slow lookup içinde bloklanır.
- Thread B (saldırgan) Thread A meşgulken guarded state'i değiştirir (ör. bir file handle takas eder, sembolik link'i yeniden yazar, object security'yi değiştirir).
- Thread A devam edip ayrıcalıklı işlemi gerçekleştirdiğinde, eski durumu görür ve saldırgan kontrollü işlemi yapar.
4. **Temizlik** – Şüpheli artefakt bırakmamak veya meşru IPC kullanıcılarını bozmemek için dizin zincirini ve sembolik linkleri silin.

## Operasyonel hususlar

- **Primitifleri birleştirin** – `UNICODE_STRING` boyutunu tüketene dek, dizin zincirinde *seviye başına* uzun bir isim kullanarak daha yüksek gecikme elde edebilirsiniz.
- **Tek-seferlik (one-shot) buglar** – Genişleyen pencere (mikrosaniyelerden dakikalara) CPU affinity pinning veya hypervisor-assisted preemption ile eşleştirildiğinde “single trigger” bugları gerçekçi kılar.
- **Yan etkiler** – Yavaşlama yalnızca kötü amaçlı yolu etkiler, bu yüzden genel sistem performansı etkilenmez; savunucular ancak namespace büyümesini izlerlerse fark ederler.
- **Temizlik** – Oluşturduğunuz her dizin/objeye ait handle’ları saklayın ki sonra `NtMakeTemporaryObject`/`NtClose` çağırabilesiniz. Aksi halde sınırı olmayan dizin zincirleri yeniden başlatmalar arasında kalıcı olabilir.
- **Dosya sistemi yarışları** – Eğer zafiyetli yol nihayetinde NTFS üzerinden çözümleniyorsa, OM slowdown çalışırken backing file üzerinde bir Oplock (ör. aynı toolkit’ten `SetOpLock.exe`) istiflemesi yaparak tüketiciyi ek milisaniyelerce dondurabilirsiniz; OM grafını değiştirmeden.

## Savunma notları

- Named object’lara dayanan kernel kodu, open’dan *sonra* güvenlik açısından hassas durumu yeniden doğrulamalı veya kontrol öncesi bir referans almalıdır (TOCTOU boşluğunu kapatmak için).
- User-controlled isimleri dereference etmeden önce OM yol derinliği/uzunluğu için üst sınırlar uygulayın. Aşırı uzun isimleri reddetmek saldırganları mikro-saniye penceresine geri zorlar.
- Nesne yöneticisi namespace büyümesini (ETW `Microsoft-Windows-Kernel-Object`) enstrümante ederek `\BaseNamedObjects` altında binlerce bileşenli şüpheli zincirleri tespit edin.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
