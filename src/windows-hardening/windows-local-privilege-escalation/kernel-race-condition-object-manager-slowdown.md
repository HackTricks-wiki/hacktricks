# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Why stretching the race window matters

Many Windows kernel LPEs follow the classic pattern `check_state(); NtOpenX("name"); privileged_action();`. On modern hardware a cold `NtOpenEvent`/`NtOpenSection` resolves a short name in ~2 µs, leaving almost no time to flip the checked state before the secure action happens. By deliberately forcing the Object Manager Namespace (OMNS) lookup in step 2 to take tens of microseconds, the attacker gains enough time to consistently win otherwise flaky races without needing thousands of attempts.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Names such as `\BaseNamedObjects\Foo` are resolved directory-by-directory. Each component causes the kernel to find/open an *Object Directory* and compare Unicode strings. Symbolic links (e.g., drive letters) may be traversed en route.
* **UNICODE_STRING limit** – OM paths are carried inside a `UNICODE_STRING` whose `Length` is a 16-bit value. The absolute limit is 65 535 bytes (32 767 UTF-16 codepoints). With prefixes like `\BaseNamedObjects\`, an attacker still controls ≈32 000 characters.
* **Attacker prerequisites** – Any user can create objects underneath writable directories such as `\BaseNamedObjects`. When the vulnerable code uses a name inside, or follows a symbolic link that lands there, the attacker controls the lookup performance with no special privileges.

## Slowdown primitive #1 – Single maximal component

The cost of resolving a component is roughly linear with its length because the kernel must perform a Unicode comparison against every entry in the parent directory. Creating an event with a 32 kB-long name immediately increases the `NtOpenEvent` latency from ~2 µs to ~35 µs on Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktyczne uwagi*

- Możesz osiągnąć limit długości, używając dowolnego nazwanego obiektu jądra (events, sections, semaphores…).
- Symbolic links lub reparse points mogą wskazywać krótką nazwę „victim” na ten ogromny komponent, dzięki czemu spowolnienie jest stosowane w sposób przezroczysty.
- Ponieważ wszystko znajduje się w przestrzeniach nazw zapisywalnych przez użytkownika, payload działa z poziomu standardowego poziomu integralności użytkownika.

## Slowdown primitive #2 – Deep recursive directories

Bardziej agresywny wariant alokuje łańcuch składający się z tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy krok wyzwala logikę rozwiązywania katalogu (ACL checks, hash lookups, reference counting), więc opóźnienie na poziom jest większe niż przy pojedynczym porównaniu ciągów. Przy ~16 000 poziomach (ograniczonych przez ten sam rozmiar `UNICODE_STRING`) empiryczne pomiary przekraczają barierę 35 µs osiąganą przez długie pojedyncze komponenty.
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
* Przechowuj handle array, aby po exploitation móc czysto usunąć łańcuch i uniknąć polluting the namespace.

## Primityw spowolnienia #3 – Shadow directories, hash collisions & symlink reparses (minuty zamiast mikrosekund)

Katalogi obiektów obsługują **shadow directories** (fallback lookups) i kubełkowe tablice haszujące dla wpisów. Wykorzystaj oba oraz limit 64-komponentowego symbolic-link reparse, aby pomnożyć spowolnienie bez przekraczania długości `UNICODE_STRING`:

1. Utwórz dwa katalogi pod `\BaseNamedObjects`, np. `A` (shadow) i `A\A` (target). Utwórz drugi używając pierwszego jako shadow directory (`NtCreateDirectoryObjectEx`), tak aby brakujące wyszukiwania w `A` przechodziły do `A\A`.
2. Wypełnij każdy katalog tysiącami **colliding names**, które trafiają do tego samego kubełka haszującego (np. zmieniając końcowe cyfry przy zachowaniu tej samej wartości `RtlHashUnicodeString`). Wyszukiwania teraz pogarszają się do O(n) skanów liniowych w obrębie jednego katalogu.
3. Zbuduj łańcuch ~63 **object manager symbolic links**, które wielokrotnie reparse into długi sufiks `A\A\…`, zużywając reparse budget. Każde reparse restartuje parsowanie od początku, mnożąc koszt kolizji.
4. Wyszukiwanie końcowego składnika (`...\\0`) teraz zajmuje **minuty** na Windows 11, gdy w każdym katalogu występuje 16 000 kolizji, co praktycznie gwarantuje zwycięstwo w race dla one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Dlaczego to ma znaczenie*: Spowolnienie trwające minuty zamienia one-shot race-based LPEs w deterministyczne exploits.

## Mierzenie race window

Wbuduj krótki harness w exploit, aby zmierzyć, jak duże okno powstaje na sprzęcie ofiary. Poniższy fragment otwiera docelowy obiekt `iterations` razy i zwraca średni koszt jednego otwarcia z użyciem `QueryPerformanceCounter`.
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
Wyniki bezpośrednio wpływają na twoją strategię orkiestracji wyścigów (np. liczbę wątków roboczych, interwały uśpienia, jak wcześnie trzeba zmienić stan współdzielony).

## Przebieg eksploatacji

1. **Locate the vulnerable open** – Śledź ścieżkę w kernelu (przez symbols, ETW, hypervisor tracing lub reversing) aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przechodzi po nazwie kontrolowanej przez atakującego lub symbolic link w katalogu zapisywalnym przez użytkownika.
2. **Replace that name with a slow path**
- Utwórz długi komponent lub łańcuch katalogów pod `\BaseNamedObjects` (lub innym zapisywalnym OM root).
- Utwórz symbolic link tak, aby nazwa oczekiwana przez kernel teraz rozwiązywała się do slow path. Możesz skierować vulnerable driver’s directory lookup na swoją strukturę bez dotykania oryginalnego targetu.
3. **Trigger the race**
- Thread A (victim) wykonuje podatny kod i blokuje się podczas slow lookup.
- Thread B (attacker) zmienia chroniony stan (np. zamienia file handle, przepisuje symbolic link, przełącza object security) podczas gdy Thread A jest zajęty.
- Kiedy Thread A wznawia działanie i wykonuje uprzywilejowaną operację, obserwuje przestarzały stan i wykonuje operację kontrolowaną przez atakującego.
4. **Clean up** – Usuń łańcuch katalogów i symbolic links, aby nie zostawić podejrzanych artefaktów ani nie zakłócać legalnych użytkowników IPC.

## Aspekty operacyjne

- **Combine primitives** – Możesz użyć długiej nazwy *na każdym poziomie* łańcucha katalogów, aby uzyskać jeszcze większą latencję, aż wyczerpiesz rozmiar `UNICODE_STRING`.
- **One-shot bugs** – Powiększone okno (dziesiątki mikrosekund do minut) sprawia, że błędy „single trigger” stają się realistyczne, gdy są sparowane z przypięciem CPU affinity lub preempcją wspieraną przez hypervisor.
- **Side effects** – Spowolnienie dotyczy tylko złośliwej ścieżki, więc ogólna wydajność systemu pozostaje nienaruszona; obrońcy rzadko to zauważą, chyba że monitorują wzrost namespace.
- **Cleanup** – Zachowaj uchwyty do każdego katalogu/obiektu, który utworzysz, aby potem móc wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać po restarcie.

## Uwagi defensywne

- Kod jądra, który polega na named objects, powinien ponownie walidować stany istotne dla bezpieczeństwa *po* otwarciu, albo pobrać referencję przed sprawdzeniem (zamykanie luki TOCTOU).
- Narzuć górne ograniczenia na głębokość/długość ścieżki OM przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucenie nadmiernie długich nazw zmusza atakujących do powrotu do okna mikrosekundowego.
- Instrumentuj wzrost namespace Object Managera (ETW `Microsoft-Windows-Kernel-Object`) aby wykrywać podejrzane łańcuchy z tysiącami komponentów pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
