# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużanie okna wyścigu ma znaczenie

Wiele Windows kernel LPE podąża klasycznym wzorcem `check_state(); NtOpenX("name"); privileged_action();`. Na nowoczesnym sprzęcie niebuforowane `NtOpenEvent`/`NtOpenSection` rozwiązuje krótką nazwę w ~2 µs, zostawiając niemalże żadnego czasu na zmianę sprawdzanego stanu przed wykonaniem bezpiecznej akcji. Celowe spowolnienie wyszukiwania w Object Manager Namespace (OMNS) w kroku 2 do dziesiątek mikrosekund daje atakującemu wystarczająco dużo czasu, by konsekwentnie wygrywać inaczej niestabilne race’y bez potrzeby tysięcy prób.

## Wewnętrzne działanie wyszukiwania w Object Manager — w skrócie

* **OMNS structure** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy komponent powoduje, że kernel musi odnaleźć/otworzyć *Object Directory* i porównać łańcuchy Unicode. Po drodze mogą być przetwarzane łącza symboliczne (np. litery dysków).
* **UNICODE_STRING limit** – Ścieżki OM są przechowywane wewnątrz `UNICODE_STRING`, którego `Length` jest wartością 16-bitową. Absolutny limit to 65 535 bajtów (32 767 punktów kodowych UTF-16). Z prefiksami takimi jak `\BaseNamedObjects\` atakujący nadal kontroluje ≈32 000 znaków.
* **Attacker prerequisites** – Każdy użytkownik może tworzyć obiekty pod zapisywalnymi katalogami, takimi jak `\BaseNamedObjects`. Gdy podatny kod używa nazwy tam zawartej, lub podąża za łączem symbolicznym prowadzącym tam, atakujący bez specjalnych uprawnień kontroluje wydajność wyszukiwania.

## Slowdown primitive #1 – Single maximal component

Koszt rozwiązywania komponentu jest w przybliżeniu liniowy względem jego długości, ponieważ kernel musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa latencję `NtOpenEvent` z ~2 µs do ~35 µs na Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Uwagi praktyczne*

- Możesz osiągnąć limit długości, używając dowolnego named kernel object (events, sections, semaphores…).
- Symbolic links lub reparse points mogą wskazywać krótką nazwę „victim” na ten ogromny komponent, dzięki czemu slowdown jest stosowany transparentnie.
- Ponieważ wszystko znajduje się w user-writable namespaces, payload działa z poziomu standardowego user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Bardziej agresywna odmiana alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy krok wywołuje logikę rozwiązywania katalogów (ACL checks, hash lookups, reference counting), więc opóźnienie na poziom jest większe niż przy pojedynczym porównaniu łańcucha znaków. Przy ~16 000 poziomach (ograniczonych przez ten sam `UNICODE_STRING`), empiryczne pomiary przekraczają barierę 35 µs osiągniętą przez długie pojedyncze komponenty.
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

* Na każdym poziomie zmieniaj znak (`A/B/C/...`) jeśli katalog nadrzędny zaczyna odrzucać duplikaty.
* Przechowuj tablicę uchwytów, aby po exploitation móc usunąć łańcuch czysto i nie zaśmiecać przestrzeni nazw.

## Measuring your race window

Wstaw krótki harness do swojego exploit, aby zmierzyć, jak duże okno pojawia się na sprzęcie ofiary. Poniższy fragment otwiera docelowy obiekt `iterations` razy i zwraca średni koszt na otwarcie, mierząc za pomocą `QueryPerformanceCounter`.
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
Wyniki wprost wpływają na twoją strategię orkiestracji race (np. liczba potrzebnych wątków roboczych, interwały sleep, jak wcześnie trzeba przełączyć współdzielony stan).

## Przebieg eksploatacji

1. **Zlokalizuj podatne wywołanie open** – Śledź ścieżkę jądra (via symbols, ETW, hypervisor tracing, or reversing) aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przechodzi przez nazwę kontrolowaną przez atakującego lub dowiązanie symboliczne w katalogu zapisywalnym przez użytkownika.
2. **Zamień tę nazwę na ścieżkę spowalniającą**
- Utwórz długi komponent lub łańcuch katalogów pod `\BaseNamedObjects` (lub innym zapisywalnym OM root).
- Utwórz dowiązanie symboliczne tak, aby nazwa, której oczekuje jądro, teraz rozwiązywała się do ścieżki spowalniającej. Możesz skierować wyszukiwanie katalogu podatnego drivera na swoją strukturę bez dotykania oryginalnego celu.
3. **Wywołaj race**
- Wątek A (ofiara) wykonuje podatny kod i blokuje się wewnątrz spowolnionego wyszukiwania.
- Wątek B (atakujący) zmienia chroniony stan (np. zamienia uchwyt pliku, nadpisuje dowiązanie symboliczne, przełącza zabezpieczenia obiektu), gdy Wątek A jest zajęty.
- Gdy Wątek A wznowi działanie i wykona uprzywilejowaną operację, zobaczy przestarzały stan i wykona operację kontrolowaną przez atakującego.
4. **Sprzątanie** – Usuń łańcuch katalogów i dowiązania symboliczne, aby nie pozostawić podejrzanych artefaktów lub nie zakłócić prawidłowych użytkowników IPC.

## Uwagi operacyjne

- **Łącz prymitywy** – Możesz użyć długiej nazwy *na poziom* w łańcuchu katalogów, by uzyskać jeszcze większe opóźnienie, aż wyczerpiesz rozmiar `UNICODE_STRING`.
- **Błędy jednorazowe** – Powiększone okno (dziesiątki mikrosekund) sprawia, że błędy typu „single trigger” stają się realistyczne w połączeniu z przypięciem afinitetu CPU lub preempcją wspomaganą przez hypervisor.
- **Efekty uboczne** – Spowolnienie dotyczy tylko złośliwej ścieżki, więc ogólna wydajność systemu pozostaje nienaruszona; obrońcy rzadko to zauważą, chyba że monitorują wzrost przestrzeni nazw.
- **Sprzątanie** – Zachowaj uchwyty do każdego katalogu/obiektu, które tworzysz, aby móc później wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą utrzymywać się po ponownych uruchomieniach.

## Uwagi obronne

- Kod jądra, który polega na obiektach z nazwami, powinien ponownie weryfikować wrażliwy na bezpieczeństwo stan po otwarciu, lub pobrać referencję przed sprawdzeniem (zamykanie luki TOCTOU).
- Wymuszaj górne granice głębokości/długości ścieżki OM przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucenie nadmiernie długich nazw zmusza atakujących do powrotu do okna mikrosekundowego.
- Instrumentuj wzrost przestrzeni nazw Object Managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy z tysiącami komponentów pod `\BaseNamedObjects`.

## Źródła

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
