# Eksploatacja Kernel Race Condition przez wolne ścieżki Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużanie race window ma znaczenie

Wiele przypadków Windows kernel LPE opiera się na klasycznym schemacie `check_state(); NtOpenX("name"); privileged_action();`. Na nowoczesnym sprzęcie cold `NtOpenEvent`/`NtOpenSection` rozwiązuje krótką nazwę w około 2 µs, pozostawiając niemal zerowy czas na zmianę sprawdzanego stanu przed wykonaniem bezpiecznej akcji. Celowe wymuszenie, aby wyszukiwanie w Object Manager Namespace (OMNS) w kroku 2 trwało dziesiątki mikrosekund, daje attackerowi wystarczająco dużo czasu, aby konsekwentnie wygrywać w przeciwnym razie niestabilne race conditions bez potrzeby wykonywania tysięcy prób.<sup>[[1]](#references)</sup>

## Wewnętrzne działanie wyszukiwania Object Manager w skrócie

* **Struktura OMNS** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy komponent powoduje, że kernel musi znaleźć/otworzyć *Object Directory* i porównać ciągi Unicode. Po drodze mogą być przechodzone symbolic links, takie jak litery dysków.
* **Limit UNICODE_STRING** – Ścieżki OM są przechowywane w `UNICODE_STRING`, którego `Length` jest wartością 16-bitową. Absolutny limit wynosi 65 535 bajtów (32 767 codepoints UTF-16). Przy prefiksach takich jak `\BaseNamedObjects\` attacker nadal kontroluje około 32 000 znaków.
* **Wymagania po stronie attackera** – Każdy użytkownik może tworzyć obiekty w zapisywalnych katalogach, takich jak `\BaseNamedObjects`. Gdy vulnerable code używa nazwy znajdującej się w takim katalogu lub podąża za symbolic linkiem prowadzącym do niego, attacker kontroluje wydajność wyszukiwania bez specjalnych uprawnień.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Pojedynczy maksymalny komponent

Koszt rozwiązywania komponentu jest w przybliżeniu liniowy względem jego długości, ponieważ kernel musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa opóźnienie `NtOpenEvent` z około 2 µs do około 35 µs w Windows 11 24H2 (testbed Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktyczne uwagi*

- Możesz osiągnąć limit długości, używając dowolnego named kernel object (eventów, sekcji, semaforów…).
- Symbolic links lub reparse points mogą wskazywać krótką nazwę „victim” na ten ogromny komponent, dzięki czemu slowdown jest stosowany w sposób transparentny.
- Ponieważ wszystko znajduje się w przestrzeniach nazw zapisywalnych przez użytkownika, payload działa ze standardowego user integrity level.<sup>[[1]](#references)</sup>

## Primitive spowalniający nr 2 – Głębokie katalogi rekurencyjne

Bardziej agresywny wariant alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy krok uruchamia logikę rozwiązywania katalogów (sprawdzanie ACL, wyszukiwanie w hashach, zliczanie odwołań), dlatego opóźnienie na poziom jest większe niż w przypadku pojedynczego porównania ciągu znaków. Przy około 16 000 poziomach (ograniczonych tym samym rozmiarem `UNICODE_STRING`) pomiary empiryczne przekraczają barierę 35 µs osiągniętą przez długie pojedyncze komponenty.
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
* Zachowaj tablicę uchwytów, aby po exploitation móc czysto usunąć cały łańcuch i uniknąć zanieczyszczania namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuty zamiast mikrosekund)

Katalogi obiektów obsługują **shadow directories** (wyszukiwanie awaryjne) oraz haszowane tabele kubełkowe dla wpisów. Wykorzystaj oba mechanizmy oraz limit 64 ponownych解析 symbolic-link reparse, aby zwielokrotnić spowolnienie bez przekraczania długości `UNICODE_STRING`:

1. Utwórz dwa katalogi pod `\BaseNamedObjects`, np. `A` (shadow) oraz `A\A` (target). Utwórz drugi, używając pierwszego jako shadow directory (`NtCreateDirectoryObjectEx`), aby brakujące wyszukiwania w `A` przechodziły do `A\A`.
2. Wypełnij każdy katalog tysiącami **colliding names**, które trafiają do tego samego hash bucket (np. zmieniając końcowe cyfry przy zachowaniu tej samej wartości `RtlHashUnicodeString`). Wyszukiwanie ulega teraz degradacji do liniowego skanowania O(n) wewnątrz pojedynczego katalogu.
3. Zbuduj łańcuch około 63 **object manager symbolic links**, które wielokrotnie wykonują reparse do długiego sufiksu `A\A\…`, zużywając budżet reparse. Każdy reparse rozpoczyna parsowanie od początku, zwielokrotniając koszt kolizji.
4. Wyszukiwanie końcowego komponentu (`...\\0`) trwa teraz **minuty** w Windows 11, gdy w każdym katalogu występuje 16 000 kolizji, zapewniając praktycznie gwarantowaną wygraną w race dla jednorazowych kernel LPE.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Dlaczego ma to znaczenie*: Spowolnienie trwające kilka minut zmienia jednorazowe race-based LPEs w deterministyczne exploity.<sup>[[1]](#references)</sup>

### Notatki z ponownego testu w 2025 r. i gotowe narzędzia

- James Forshaw ponownie opublikował tę technikę wraz ze zaktualizowanymi czasami dla Windows 11 24H2 (ARM64). Bazowe otwarcia nadal trwają około 2 µs; komponent o rozmiarze 32 kB zwiększa ten czas do około 35 µs, a łańcuchy shadow-dir + collision + 63-reparse nadal osiągają około 3 minut, co potwierdza, że primitives działają również w obecnych buildach. Kod źródłowy i perf harness znajdują się w zaktualizowanym poście Project Zero.<sup>[[1]](#references)</sup>
- Konfigurację można oskryptować za pomocą publicznego pakietu `symboliclink-testing-tools`: `CreateObjectDirectory.exe` tworzy parę shadow/target, a `NativeSymlink.exe` uruchamiany w pętli generuje łańcuch 63-hop. Eliminuje to konieczność ręcznego pisania wrapperów `NtCreate*` i zapewnia spójność ACL.<sup>[[2]](#references)</sup>

## Pomiar race window

Dodaj szybki harness do swojego exploita, aby zmierzyć, jak duże staje się okno na sprzęcie ofiary. Poniższy snippet otwiera obiekt docelowy `iterations` razy i zwraca średni koszt pojedynczego otwarcia za pomocą `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Wyniki bezpośrednio wpływają na strategię orkiestracji race (np. liczbę wymaganych worker threads, interwały uśpienia oraz to, jak wcześnie trzeba zmienić współdzielony stan).

## Workflow exploitation

1. **Zlokalizuj podatny open** – Prześledź ścieżkę kernela (za pomocą symbols, ETW, śledzenia hypervisora lub reverse engineeringu), aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przechodzi przez kontrolowaną przez attackera nazwę lub symbolic link w katalogu z prawem zapisu dla usera.
2. **Zastąp tę nazwę ścieżką slow path**
- Utwórz długi component lub łańcuch katalogów pod `\BaseNamedObjects` (albo w innym zapisywalnym root OM).
- Utwórz symbolic link, aby nazwa oczekiwana przez kernel rozwiązywała się teraz do slow path. Możesz skierować lookup katalogu podatnego drivera do swojej struktury bez modyfikowania oryginalnego targetu.
3. **Wywołaj race**
- Thread A (victim) wykonuje podatny kod i blokuje się wewnątrz slow lookup.
- Thread B (attacker) zmienia guarded state (np. podmienia file handle, przepisuje symbolic link lub przełącza object security), gdy Thread A jest zajęty.
- Gdy Thread A wznowi działanie i wykona uprzywilejowaną akcję, odczyta nieaktualny stan i przeprowadzi operację kontrolowaną przez attackera.
4. **Posprzątaj** – Usuń łańcuch katalogów i symbolic links, aby nie pozostawiać podejrzanych artefaktów ani nie zakłócać działania legalnych użytkowników IPC.<sup>[[1]](#references)</sup>

## Applied chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), opublikowany jako bypass dla RoguePlanet (CVE-2026-50656), demonstruje szerszy wzorzec exploitation: spraw, aby uprzywilejowany scanner sklasyfikował jedną reprezentację logicznego pliku, a następnie zmień zarówno jego bytes, jak i resolution namespace, zanim remediation zacznie z niego korzystać. PoC łączy TOCTOU hydration w Cloud Files, fallback shadow-directory Object Managera, przechwycenie nazwy wygenerowanej przez CLFS oraz link do lokalnego administrative share, aby zamienić cleanup Defendera w zapis chronionej biblioteki DLL.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

Zarejestruj zapisywalny przez attackera katalog jako Cloud Files sync root, podłącz callback `CF_CALLBACK_TYPE_FETCH_DATA` i utwórz placeholder, którego deklarowany rozmiar odpowiada deterministycznemu triggerowi detekcji, takiemu jak EICAR ZIP. Pierwszy fetch zwraca trigger i zmienia stan callbacku; kolejne fetches zwracają payload. Po sklasyfikowaniu pierwszej reprezentacji przez scanner uzyskaj transfer key i uruchom hydration ponownie z metadanymi o rozmiarze payloadu, a następnie wymuś hydration do EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Granica bezpieczeństwa zawodzi, jeśli skanowanie, werdykt i remediacja odnoszą się wyłącznie do ścieżki lub tożsamości zastępczej: żadna z tych metod nie gwarantuje, że późniejsze pobranie zawartości zwróci bajty, które zostały poddane inspekcji.<sup>[[4]](#references)</sup>

### 2. Przełączanie niezmiennej ścieżki za pośrednictwem shadow-directory fallback

Utwórz docelowy katalog Object Manager oraz drugi katalog za pomocą `NtCreateDirectoryObjectEx`, przekazując uchwyt celu jako jego katalog shadow/fallback. Umieść wpis `WD_SCAN` o tej samej nazwie w obu warstwach rozwiązywania nazw: widoczny wpis wskazuje zwykły katalog roboczy, natomiast wpis fallback wskazuje `\CLFS\??\<working-directory>`. Przekaż Defenderowi wyłącznie poniższą niezmienną ścieżkę; usunięcie widocznego łącza podczas trwania operacji powoduje, że ten sam ciąg znaków przejdzie do wpisu opartego na CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Różni się to od używania shadow directories wyłącznie do spowalniania wyszukiwania: attacker zmienia **znaczenie** wcześniej zaakceptowanej ścieżki bez modyfikowania jej ciągu znaków.<sup>[[4]](#references)</sup>

### 3. Przechwyć wygenerowaną nazwę i zainstaluj link specyficzny dla nazwy pliku

Monitoruj katalog roboczy za pomocą `ReadDirectoryChangesW`. Przy pierwszym `FILE_ACTION_ADDED` usuń widoczny link `WD_SCAN`, aby aktywować fallback lookup. Przechwyć drugą wygenerowaną nazwę pliku, otwórz ten plik związany z CLFS i zablokuj zakres `0..MAXLONGLONG` za pomocą `LockFileEx`. Gdy uprzywilejowana operacja jest wstrzymana, zastąp `WD_SCAN` w widocznym katalogu rzeczywistym katalogiem Object Manager i utwórz podrzędny symbolic link nazwany na podstawie zaobserwowanej nazwy pliku (PoC usuwa jego cztery końcowe znaki). Wskaż go na chronione miejsce docelowe za pośrednictwem lokalnego SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Nieuprzywilejowany proces nie może samodzielnie zapisać w tym miejscu docelowym, ale kontekst SYSTEM programu Defender może przejść przez pętlę zwrotną udziału administracyjnego. Połączenie obserwacji generowanych nazw z dowiązaniem Object Managera specyficznym dla nazwy pliku eliminuje konieczność wcześniejszego przewidywania artefaktu naprawczego.<sup>[[4]](#references)</sup>

### 4. Stabilizacja race condition podczas czyszczenia i uruchomienie uprzywilejowanego loadera

Przed skanowaniem PoC zapisuje poprawny plik PE (`ntdll.dll`) w zastępczym alternatywnym strumieniu danych NTFS `:stream`. Po utworzeniu przez przekierowanie chronionego pliku bazowego otwiera `phoneinfo.dll:stream` z dostępem do wykonywania i utrzymuje aktywne mapowanie `PAGE_EXECUTE_READ | SEC_IMAGE` podczas wznowienia czyszczenia; aktywne obiekty pliku/sekcji ograniczają usunięcie lub zastąpienie podczas końcowej race condition. Ponownie uruchomione nawodnienie zwraca teraz payload DLL zamiast EICAR, przez co chroniony plik bazowy zawiera kod kontrolowany przez atakującego.<sup>[[4]](#references)</sup>

Chroniony zapis zostaje następnie przekształcony w wykonanie z uprawnieniami SYSTEM przez umieszczenie spreparowanego `Report.wer` w `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` i wywołanie `\Microsoft\Windows\Windows Error Reporting\QueueReporting` za pośrednictwem API COM Task Scheduler. W tym łańcuchu uprzywilejowane przetwarzanie WER ładuje umieszczony plik `C:\Windows\System32\phoneinfo.dll`; połączenie named pipe jest używane jako sygnał wykonania payloadu.<sup>[[4]](#references)</sup>

### Punkty detekcji

Przydatne korelacje są bardziej szczegółowe niż pojedyncza tymczasowa nazwa pliku i obejmują wszystkie przejścia między przestrzeniami nazw w tym łańcuchu:<sup>[[4]](#references)</sup>

- Nowo zarejestrowany dostawca Cloud Files, a następnie wykrycie EICAR i `CF_OPERATION_TYPE_RESTART_HYDRATION` dla tego samego zastępnika.
- Ścieżki Object Managera zawierające `WD_TARGET_*`, `WD_SHADOW_*` lub `WD_SCAN`, szczególnie ścieżkę skanowania poniżej `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Utworzenie pliku CLFS, a następnie uzyskanie wyłącznej blokady całego pliku i dostęp loopback do `\\127.0.0.1\C$\Windows\System32\*.dll` z uprzywilejowanego procesu bezpieczeństwa.
- Utworzenie biblioteki DLL w System32 wraz z NTFS ADS, a następnie mapowanie strumienia za pomocą `SEC_IMAGE`.
- Utworzony przez atakującego wpis kolejki WER, a następnie nietypowe ręczne uruchomienie `\Microsoft\Windows\Windows Error Reporting\QueueReporting` i załadowanie obrazu umieszczonej biblioteki DLL.

## Kwestie operacyjne

- **Łączenie prymitywów** – Możesz użyć długiej nazwy *na każdym poziomie* łańcucha katalogów, aby uzyskać jeszcze większe opóźnienie, aż do wyczerpania rozmiaru `UNICODE_STRING`.
- **Błędy jednorazowe** – Poszerzone okno czasowe (od dziesiątek mikrosekund do minut) sprawia, że błędy typu „single trigger” stają się realistyczne po połączeniu z przypięciem do CPU lub wywłaszczaniem wspomaganym przez hypervisor.
- **Skutki uboczne** – Spowolnienie wpływa wyłącznie na złośliwą ścieżkę, więc ogólna wydajność systemu pozostaje niezmieniona; obrońcy rzadko je zauważą, chyba że monitorują wzrost przestrzeni nazw.
- **Czyszczenie** – Zachowuj uchwyty do każdego utworzonego katalogu/obiektu, aby później wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać ponowne uruchomienie systemu.
- **Race conditions systemu plików** – Jeśli podatna ścieżka ostatecznie rozwiązuje się przez NTFS, możesz założyć Oplock (np. `SetOpLock.exe` z tego samego toolkitu) na pliku bazowym podczas działania spowolnienia OM, zamrażając konsumenta na dodatkowe milisekundy bez modyfikowania grafu OM.<sup>[[2]](#references)</sup>

## Uwagi dotyczące obrony

- Kod jądra, który opiera się na nazwanych obiektach, powinien ponownie zweryfikować stan wrażliwy z punktu widzenia bezpieczeństwa *po* otwarciu albo pobrać referencję przed sprawdzeniem (eliminując lukę TOCTOU).
- Wymuszaj górne limity głębokości/długości ścieżek OM przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucanie zbyt długich nazw zmusza atakujących do powrotu do okna mikrosekundowego.
- Instrumentuj wzrost przestrzeni nazw Object Managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy zawierające tysiące komponentów poniżej `\BaseNamedObjects`.

## References

- [1] [Project Zero – Techniki exploitacji Windows: wygrywanie race conditions za pomocą wyszukiwania ścieżek](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
