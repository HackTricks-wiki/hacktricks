# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużanie okna wyścigu ma znaczenie

Wiele Windows kernel LPEs podąża za klasycznym schematem `check_state(); NtOpenX("name"); privileged_action();`. Na nowoczesnym sprzęcie zimne `NtOpenEvent`/`NtOpenSection` rozwiązuje krótką nazwę w ~2 µs, zostawiając niemalże zero czasu na zmianę sprawdzonego stanu przed wykonaniem chronionej akcji. Celowo wymuszając, by lookup w Object Manager Namespace (OMNS) w kroku 2 trwał dziesiątki mikrosekund, atakujący zyskuje wystarczająco dużo czasu, by konsekwentnie wygrywać inaczej zawodzące warunki wyścigu bez potrzeby tysięcy prób.

## W skrócie: wewnętrzne mechanizmy rozwiązywania Object Managera

* **OMNS structure** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy element powoduje, że kernel musi znaleźć/otworzyć *Object Directory* i porównać ciągi Unicode. Po drodze mogą być przetwarzane odnośniki symboliczne (np. litery dysków).
* **UNICODE_STRING limit** – Ścieżki OM są przechowywane w `UNICODE_STRING`, którego `Length` jest wartością 16-bitową. Absolutny limit to 65 535 bajtów (32 767 punktów kodowych UTF-16). Z prefiksami takimi jak `\BaseNamedObjects\` atakujący nadal kontroluje ≈32 000 znaków.
* **Attacker prerequisites** – Każdy użytkownik może tworzyć obiekty w obrębie zapisywalnych katalogów, takich jak `\BaseNamedObjects`. Kiedy podatny kod użyje nazwy znajdującej się tam, lub podąży za odnośnikiem symbolicznym prowadzącym tam, atakujący kontroluje szybkość lookupu bez specjalnych uprawnień.

## Prymityw spowalniający #1 – pojedynczy maksymalny komponent

Koszt rozwiązywania jednego elementu jest w przybliżeniu liniowy względem jego długości, ponieważ kernel musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa opóźnienie `NtOpenEvent` z ~2 µs do ~35 µs na Windows 11 24H2 (platforma testowa Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktyczne uwagi*

- Możesz osiągnąć limit długości używając dowolnego nazwanego obiektu jądra (events, sections, semaphores…).
- Symbolic links lub reparse points mogą kierować krótką nazwę „victim” do tego olbrzymiego komponentu, dzięki czemu slowdown jest stosowany przezroczysto.
- Ponieważ wszystko znajduje się w user-writable namespaces, payload działa z poziomu standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Bardziej agresywna odmiana alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy hop wywołuje logikę rozwiązywania katalogu (ACL checks, hash lookups, reference counting), więc opóźnienie na poziom jest większe niż przy pojedynczym porównaniu łańcucha. Przy ~16 000 poziomach (ograniczonych tym samym rozmiarem `UNICODE_STRING`) empiryczne czasy przekraczają barierę 35 µs osiąganą przez długie pojedyncze komponenty.
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
* Przechowuj tablicę uchwytów, aby po eksploatacji móc usunąć łańcuch i nie zanieczyścić przestrzeni nazw.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

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
*Dlaczego to ważne*: Kilkuminutowe spowolnienie zamienia jednorazowe, oparte na wyścigu LPEs w deterministyczne exploity.

### Notatki z retestu 2025 & gotowe narzędzia

- James Forshaw opublikował ponownie technikę z zaktualizowanymi czasami na Windows 11 24H2 (ARM64). Bazowe otwarcia pozostają ~2 µs; komponent 32 kB podnosi to do ~35 µs, a shadow-dir + collision + 63-reparse chains nadal dochodzą do ~3 minut, potwierdzając, że prymitywy przetrwały obecne buildy. Kod źródłowy i perf harness znajdują się we odświeżonym poście Project Zero.
- Możesz zautomatyzować konfigurację używając publicznego pakietu `symboliclink-testing-tools`: `CreateObjectDirectory.exe` do wygenerowania pary shadow/target i `NativeSymlink.exe` w pętli do emisji 63-skokowego łańcucha. To eliminuje ręcznie pisane wrappery `NtCreate*` i zachowuje spójność ACLs.

## Mierzenie okna wyścigu

Osadź krótki harness jako część exploit, aby zmierzyć, jak duże okno pojawia się na sprzęcie ofiary. Poniższy fragment otwiera obiekt docelowy `iterations` razy i zwraca średni koszt na otwarcie przy użyciu `QueryPerformanceCounter`.
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
Wyniki bezpośrednio wpływają na twoją strategię orkiestracji race (np. number of worker threads needed, sleep intervals, how early you need to flip the shared state).

## Przebieg eksploatacji

1. **Locate the vulnerable open** – Śledź ścieżkę w kernelu (przez symbols, ETW, hypervisor tracing, lub reversing), aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przetwarza nazwę kontrolowaną przez atakującego lub symbolic link w katalogu zapisywalnym przez użytkownika.
2. **Replace that name with a slow path**
- Utwórz długi komponent lub łańcuch katalogów pod `\BaseNamedObjects` (lub innym zapisywalnym OM root).
- Utwórz symbolic link tak, aby nazwa oczekiwana przez kernel teraz rozwiązywała się do wolnej ścieżki. Możesz skierować wyszukiwanie katalogu podatnego drivera na swoją strukturę bez dotykania oryginalnego celu.
3. **Trigger the race**
- Thread A (victim) wykonuje podatny kod i blokuje się wewnątrz wolnego lookupu.
- Thread B (attacker) zmienia guarded state (np. swaps a file handle, rewrites a symbolic link, toggles object security) podczas gdy Thread A jest zajęty.
- Gdy Thread A wznowi działanie i wykona uprzywilejowaną operację, zobaczy przestarzały stan i przeprowadzi operację kontrolowaną przez atakującego.
4. **Clean up** – Usuń łańcuch katalogów i symbolic linki, aby nie zostawiać podejrzanych artefaktów ani nie zakłócać legalnych użytkowników IPC.

## Aspekty operacyjne

- **Łączenie prymitywów** – Możesz użyć długiej nazwy na każdym poziomie w łańcuchu katalogów, aby uzyskać jeszcze większą latencję, aż do wyczerpania rozmiaru `UNICODE_STRING`.
- **One-shot bugs** – Rozszerzone okno (dziesiątki mikrosekund do minut) sprawia, że „single trigger” bugs są realistyczne w połączeniu z przypinaniem affinities CPU lub hypervisor-assisted preemption.
- **Skutki uboczne** – Spowolnienie dotyczy tylko złośliwej ścieżki, więc ogólna wydajność systemu pozostaje nienaruszona; obrońcy rzadko to zauważą, chyba że monitorują wzrost namespace.
- **Cleanup** – Zachowaj handle do każdego katalogu/obiektu, który tworzysz, aby móc potem wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać przez rebooty.
- **File-system races** – Jeśli podatna ścieżka ostatecznie rozwiązuje się przez NTFS, możesz nałożyć Oplock (np. `SetOpLock.exe` z tego samego toolkit) na plik zapasowy podczas działania OM slowdown, zamrażając konsumenta na dodatkowe milisekundy bez zmiany OM graph.

## Uwagi obronne

- Kod jądra, który polega na named objects, powinien ponownie weryfikować security-sensitive state *po* open, lub pobrać referencję przed sprawdzeniem (zamykanie TOCTOU gap).
- Egzekwuj górne granice dla głębokości/długości OM path przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucenie zbyt długich nazw zmusza atakujących do powrotu do okna mikrosekundowego.
- Instrumentuj growth namespace object managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy tysięcy komponentów pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
