# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużenie race window ma znaczenie

Wiele przypadków kernel LPE korzysta z klasycznego schematu `check_state(); NtOpenX("name"); privileged_action();`. Na współczesnym sprzęcie cold `NtOpenEvent`/`NtOpenSection` rozwiązuje krótką nazwę w około 2 µs, pozostawiając niemal zero czasu na zmianę sprawdzanego stanu przed wykonaniem bezpiecznej akcji. Celowe wymuszenie, aby wyszukiwanie w Object Manager Namespace (OMNS) w kroku 2 trwało dziesiątki mikrosekund, daje attackerowi wystarczająco dużo czasu, aby niezawodnie wygrać skądinąd niestabilne race conditions bez potrzeby wykonywania tysięcy prób.<sup>[[1]](#references)</sup>

## Podstawy mechanizmu lookup w Object Manager

* **Struktura OMNS** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy komponent wymaga od kernela znalezienia/otwarcia *Object Directory* i porównania ciągów Unicode. Po drodze mogą być przemierzane symbolic links (np. litery dysków).
* **Limit UNICODE_STRING** – Ścieżki OM są przechowywane w `UNICODE_STRING`, którego `Length` jest wartością 16-bitową. Bezwzględny limit wynosi 65 535 bajtów (32 767 codepoints UTF-16). W przypadku prefiksów takich jak `\BaseNamedObjects\` attacker nadal kontroluje około 32 000 znaków.
* **Wymagania po stronie attackera** – Każdy user może tworzyć obiekty w zapisywalnych katalogach, takich jak `\BaseNamedObjects`. Gdy vulnerable code używa nazwy znajdującej się w takim katalogu lub podąża za symbolic link, który do niego prowadzi, attacker kontroluje wydajność lookup bez specjalnych uprawnień.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Pojedynczy maksymalny komponent

Koszt rozwiązywania komponentu jest w przybliżeniu liniowy względem jego długości, ponieważ kernel musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa latency `NtOpenEvent` z około 2 µs do około 35 µs w Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Uwagi praktyczne*

- Limit długości można osiągnąć przy użyciu dowolnego nazwanego kernel object (events, sections, semaphores…).
- Symbolic links lub reparse points mogą wskazywać zwięzłą nazwę „victim” na ten ogromny komponent, dzięki czemu slowdown jest stosowany w sposób transparentny.
- Ponieważ wszystko znajduje się w user-writable namespaces, payload działa ze standardowego user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Głęboko rekurencyjne katalogi

Bardziej agresywny wariant alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy hop uruchamia logikę rozwiązywania ścieżki katalogu (ACL checks, hash lookups, reference counting), dlatego latency na poziom jest wyższe niż w przypadku pojedynczego porównania stringów. Przy około 16 000 poziomów (ograniczone przez ten sam rozmiar `UNICODE_STRING`) pomiary empiryczne przekraczają barierę 35 µs osiągniętą przez długie pojedyncze komponenty.
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
Wskazówki:

* Zmieniaj znak na każdym poziomie (`A/B/C/...`), jeśli katalog nadrzędny zacznie odrzucać duplikaty.
* Zachowaj tablicę uchwytów, aby po exploitation móc poprawnie usunąć cały łańcuch i uniknąć zanieczyszczania namespace.<sup>[[1]](#references)</sup>

## Primitive spowalniający nr 3 – Shadow directories, kolizje hashy i symlink reparses (minuty zamiast mikrosekund)

Katalogi obiektów obsługują **shadow directories** (wyszukiwanie awaryjne) oraz bucketowane tabele hashy dla wpisów. Wykorzystaj oba mechanizmy wraz z limitem 64 komponentów dla symlink reparse, aby zwielokrotnić spowolnienie bez przekraczania długości `UNICODE_STRING`:

1. Utwórz dwa katalogi w `\BaseNamedObjects`, np. `A` (shadow) oraz `A\A` (target). Utwórz drugi, używając pierwszego jako shadow directory (`NtCreateDirectoryObjectEx`), aby brakujące wyszukiwania w `A` przechodziły do `A\A`.
2. Wypełnij każdy katalog tysiącami **nazw powodujących kolizje**, trafiających do tego samego bucketu hashy (np. zmieniając końcowe cyfry przy zachowaniu tej samej wartości `RtlHashUnicodeString`). Wyszukiwanie spada teraz do liniowego skanowania O(n) wewnątrz pojedynczego katalogu.
3. Zbuduj łańcuch około 63 **symbolic links Object Managera**, które wielokrotnie wykonują reparse do długiego sufiksu `A\A\…`, zużywając budżet reparse. Każdy reparse rozpoczyna parsowanie od początku, zwielokrotniając koszt obsługi kolizji.
4. Wyszukanie końcowego komponentu (`...\\0`) trwa teraz **minuty** w systemie Windows 11, gdy w każdym katalogu występuje 16 000 kolizji, zapewniając praktycznie gwarantowane zwycięstwo w race dla jednorazowych kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Dlaczego to ma znaczenie*: Spowolnienie trwające kilka minut zmienia jednorazowe LPEs oparte na race condition w deterministyczne exploity.<sup>[[1]](#references)</sup>

### Uwagi z ponownego testu w 2025 r. i gotowe narzędzia

- James Forshaw opublikował ponownie tę technikę wraz ze zaktualizowanymi czasami dla Windows 11 24H2 (ARM64). Bazowe otwarcia nadal trwają około 2 µs; komponent o rozmiarze 32 kB zwiększa ten czas do około 35 µs, a shadow-dir + collision + łańcuchy 63 reparse nadal osiągają około 3 minut, co potwierdza, że primitives działają również w obecnych buildach. Kod źródłowy i perf harness znajdują się w zaktualizowanym wpisie Project Zero.<sup>[[1]](#references)</sup>
- Konfigurację można zautomatyzować za pomocą publicznego pakietu `symboliclink-testing-tools`: `CreateObjectDirectory.exe` tworzy parę shadow/target, a `NativeSymlink.exe` uruchamiany w pętli generuje łańcuch 63 hopów. Eliminuje to konieczność ręcznego pisania wrapperów `NtCreate*` i zapewnia spójność ACLs.<sup>[[2]](#references)</sup>

## Pomiar race window

Umieść szybki harness w swoim exploicie, aby zmierzyć, jak duże okno uzyskuje się na sprzęcie ofiary. Poniższy snippet otwiera obiekt docelowy `iterations` razy i zwraca średni koszt pojedynczego otwarcia za pomocą `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Wyniki bezpośrednio wpływają na strategię orkiestracji race (np. liczbę wymaganych worker threads, interwały uśpienia oraz to, jak wcześnie należy przełączyć współdzielony stan).

## Workflow exploitation

1. **Zlokalizuj podatne otwarcie** – Prześledź ścieżkę kernela (za pomocą symboli, ETW, śledzenia hypervisora lub reverse engineeringu), aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przechodzi przez nazwę kontrolowaną przez atakującego lub symbolic link w katalogu zapisywalnym przez użytkownika.
2. **Zastąp tę nazwę ścieżką slow path**
- Utwórz długi komponent lub łańcuch katalogów pod `\BaseNamedObjects` (albo innym zapisywalnym katalogiem głównym OM).
- Utwórz symbolic link, aby nazwa oczekiwana przez kernel wskazywała teraz na slow path. Możesz skierować wyszukiwanie katalogu przez podatny driver do swojej struktury bez modyfikowania oryginalnego celu.
3. **Uruchom race**
- Thread A (victim) wykonuje podatny kod i blokuje się wewnątrz slow lookup.
- Thread B (attacker) przełącza chroniony stan (np. zamienia file handle, przepisuje symbolic link lub zmienia security obiektu), gdy Thread A jest zajęty.
- Gdy Thread A wznowi działanie i wykona uprzywilejowaną operację, odczyta nieaktualny stan i wykona operację kontrolowaną przez atakującego.
4. **Wykonaj cleanup** – Usuń łańcuch katalogów i symbolic links, aby nie pozostawiać podejrzanych artefaktów ani nie zakłócać działania legalnych użytkowników IPC.<sup>[[1]](#references)</sup>

## Kwestie operacyjne

- **Łącz primitives** – Możesz użyć długiej nazwy *na każdym poziomie* łańcucha katalogów, aby uzyskać jeszcze większe opóźnienie, aż do wyczerpania rozmiaru `UNICODE_STRING`.
- **Błędy one-shot** – Poszerzone okno (od dziesiątek mikrosekund do minut) sprawia, że błędy typu „single trigger” stają się realistyczne po połączeniu z przypisaniem CPU affinity lub preemption wspomaganym przez hypervisor.
- **Skutki uboczne** – Spowolnienie wpływa wyłącznie na złośliwą ścieżkę, więc ogólna wydajność systemu pozostaje bez zmian; defenders rzadko to zauważą, chyba że monitorują wzrost namespace.
- **Cleanup** – Zachowaj handles do każdego utworzonego katalogu/obiektu, aby później móc wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać reboot.
- **File-system races** – Jeśli podatna ścieżka ostatecznie przechodzi przez NTFS, możesz założyć Oplock (np. `SetOpLock.exe` z tego samego toolkitu) na pliku bazowym podczas działania spowolnienia OM, zamrażając consumer na dodatkowe milisekundy bez modyfikowania grafu OM.<sup>[[2]](#references)</sup>

## Uwagi defensive

- Kod kernela korzystający z named objects powinien ponownie zweryfikować stan wrażliwy pod względem bezpieczeństwa *po* otwarciu albo pobrać reference przed sprawdzeniem (eliminując lukę TOCTOU).
- Wymuś górne limity głębokości/długości ścieżki OM przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucanie zbyt długich nazw zmusza atakujących do powrotu do okna mikrosekundowego.
- Instrumentuj wzrost namespace object managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy składające się z tysięcy komponentów pod `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
