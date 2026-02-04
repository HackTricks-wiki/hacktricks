# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużanie okna wyścigu ma znaczenie

Wiele Windows kernel LPEs stosuje klasyczny schemat `check_state(); NtOpenX("name"); privileged_action();`. Na nowoczesnym sprzęcie zimne `NtOpenEvent`/`NtOpenSection` rozwiązuje krótką nazwę w ~2 µs, pozostawiając praktycznie żaden czas na zmianę sprawdzanego stanu zanim nastąpi uprzywilejowana akcja. Celowe wymuszenie, aby wyszukiwanie w przestrzeni nazw Object Manager (OMNS) w kroku 2 zajęło dziesiątki mikrosekund, daje atakującemu wystarczająco dużo czasu, by konsekwentnie wygrać inaczej niestabilne wyścigi bez potrzeby tysięcy prób.

## Mechanika rozwiązywania nazw Object Manager w skrócie

* **OMNS structure** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy komponent powoduje, że jądro musi znaleźć/otworzyć *Object Directory* i porównać łańcuchy Unicode. Symboliczne linki (np. litery dysków) mogą być przemierzane po drodze.
* **UNICODE_STRING limit** – Ścieżki OM są przenoszone w `UNICODE_STRING`, którego `Length` to 16-bitowa wartość. Absolutny limit to 65 535 bajtów (32 767 kodopunktów UTF-16). Z prefiksami takimi jak `\BaseNamedObjects\`, atakujący nadal kontroluje ≈32 000 znaków.
* **Attacker prerequisites** – Każdy użytkownik może tworzyć obiekty pod zapisywalnymi katalogami, takimi jak `\BaseNamedObjects`. Gdy podatny kod użyje nazwy znajdującej się tam, albo podąży za symbolicznym linkiem, który tam trafia, atakujący kontroluje wydajność wyszukiwania bez specjalnych uprawnień.

## Slowdown primitive #1 – Single maximal component

Koszt rozwiązywania komponentu jest mniej więcej liniowy względem jego długości, ponieważ jądro musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa opóźnienie `NtOpenEvent` z ~2 µs do ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktyczne uwagi*

- Można osiągnąć limit długości, używając dowolnego nazwanego obiektu jądra (events, sections, semaphores…).
- Symbolic links or reparse points mogą wskazywać krótką nazwę „victim” na ten ogromny komponent, dzięki czemu spowolnienie jest stosowane przezroczysto.
- Ponieważ wszystko znajduje się w user-writable namespaces, payload działa z poziomu standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Bardziej agresywna odmiana alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy skok wywołuje logikę rozwiązywania katalogu (ACL checks, hash lookups, reference counting), więc opóźnienie na poziom jest większe niż przy pojedynczym porównaniu łańcuchów. Przy ~16 000 poziomach (ograniczonych tym samym rozmiarem `UNICODE_STRING`) pomiary empiryczne przekraczają barierę 35 µs osiąganą przez długie pojedyncze komponenty.
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

* Zmieniaj znak na każdym poziomie (`A/B/C/...`) jeśli katalog nadrzędny zacznie odrzucać duplikaty.
* Przechowuj tablicę handle'ów, aby móc po eksploatacji czysto usunąć łańcuch i nie zaśmiecać namespace'u.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuty zamiast mikrosekund)

Katalogi obiektów obsługują **shadow directories** (fallback lookups) oraz segmentowane tablice haszujące (bucketed hash tables) dla wpisów. Wykorzystaj oba mechanizmy oraz limit 64 komponentów dla symbolic-link reparse, aby pomnożyć spowolnienie bez przekraczania długości `UNICODE_STRING`:

1. Utwórz dwa katalogi pod `\BaseNamedObjects`, np. `A` (shadow) i `A\A` (target). Utwórz drugi używając pierwszego jako katalogu shadow (`NtCreateDirectoryObjectEx`), tak aby brakujące wyszukiwania w `A` przechodziły do `A\A`.
2. Wypełnij każdy katalog tysiącami **colliding names** trafiającymi do tego samego kubełka hasza (np. zmieniając końcowe cyfry przy zachowaniu tej samej wartości `RtlHashUnicodeString`). Wyszukiwania teraz degradują do liniowego skanowania O(n) wewnątrz pojedynczego katalogu.
3. Zbuduj łańcuch ~63 **object manager symbolic links**, które wielokrotnie reparse'ują do długiego sufiksu `A\A\…`, zużywając budżet reparse. Każde reparse zaczyna parsowanie od początku, mnożąc koszt kolizji.
4. Wyszukiwanie ostatniego komponentu (`...\\0`) zajmuje teraz **minuty** na Windows 11, gdy w każdym katalogu występuje 16 000 kolizji, co daje praktycznie gwarantowaną wygraną wyścigu (race) dla jednorazowych kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Dlaczego to ma znaczenie*: Spowolnienie trwające minuty zamienia one-shot race-based LPEs w deterministic exploits.

## Pomiar twojego race window

Osadź krótkie narzędzie testowe wewnątrz swojego exploita, aby zmierzyć, jak duże staje się okno na sprzęcie ofiary. Poniższy fragment otwiera obiekt docelowy `iterations` razy i zwraca średni koszt na jedno otwarcie, mierząc czas przy użyciu `QueryPerformanceCounter`.
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
Wyniki bezpośrednio wpływają na twoją race orchestration strategy (np. liczbę worker threads, sleep intervals, jak wcześnie musisz przełączyć stan współdzielony).

## Exploitation workflow

1. **Locate the vulnerable open** – Śledź ścieżkę w jądrze (via symbols, ETW, hypervisor tracing, or reversing) aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które rozchodzi się po nazwie kontrolowanej przez atakującego lub po symbolicznym linku w katalogu zapisywalnym przez użytkownika.
2. **Replace that name with a slow path**
- Utwórz długi komponent lub łańcuch katalogów pod `\BaseNamedObjects` (lub innym zapisywalnym OM root).
- Stwórz symbolic link tak, aby nazwa, której oczekuje kernel, teraz rozwiązywała się do slow path. Możesz skierować wyszukiwanie katalogu w podatnym driverze do swojej struktury bez dotykania oryginalnego celu.
3. **Trigger the race**
- Thread A (victim) wykonuje podatny kod i blokuje się wewnątrz slow lookup.
- Thread B (attacker) przełącza guarded state (np. zamienia file handle, nadpisuje symbolic link, przełącza object security) podczas gdy Thread A jest zajęty.
- Gdy Thread A wznowi działanie i wykona uprzywilejowaną operację, zobaczy przestarzały stan i wykona operację kontrolowaną przez atakującego.
4. **Clean up** – Usuń łańcuch katalogów i symbolic linki, aby nie zostawić podejrzanych artefaktów ani nie zakłócić legalnych użytkowników IPC.

## Operational considerations

- **Combine primitives** – Możesz użyć długiej nazwy *na każdym poziomie* w łańcuchu katalogów, aby uzyskać jeszcze większą latencję, aż wyczerpiesz rozmiar `UNICODE_STRING`.
- **One-shot bugs** – Rozszerzone okno (dziesiątki mikrosekund do minut) sprawia, że błędy „single trigger” są realistyczne, gdy sparujesz je z CPU affinity pinning lub hypervisor-assisted preemption.
- **Side effects** – To spowolnienie wpływa tylko na złośliwą ścieżkę, więc ogólna wydajność systemu pozostaje niezmieniona; obrońcy rzadko to zauważą, o ile nie monitorują wzrostu namespace.
- **Cleanup** – Trzymaj uchwyty do każdego katalogu/obiektu, który tworzysz, aby móc potem wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać po restarcie.

## Defensive notes

- Kod jądra, który polega na named objects, powinien ponownie zweryfikować security-sensitive state *po* open, lub wziąć referencję przed sprawdzeniem (zamykanie luki TOCTOU).
- Wymuszaj górne limity na OM path depth/length przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucanie nadmiernie długich nazw zmusza atakujących do powrotu do okna mierzonego w mikrosekundach.
- Instrumentuj wzrost namespace object managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy składające się z tysięcy komponentów pod `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
