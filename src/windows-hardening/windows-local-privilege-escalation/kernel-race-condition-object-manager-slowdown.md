# Eksploatacja Race Condition w jądrze za pośrednictwem wolnych ścieżek Object Manager

{{#include ../../banners/hacktricks-training.md}}

## Dlaczego wydłużenie okna wyścigu ma znaczenie

Wiele przypadków LPE w jądrze Windows stosuje klasyczny schemat `check_state(); NtOpenX("name"); privileged_action();`. Na nowoczesnym sprzęcie wyszukanie krótkiej nazwy przez zimne `NtOpenEvent`/`NtOpenSection` zajmuje około 2 µs, pozostawiając niemal zero czasu na zmianę sprawdzanego stanu przed wykonaniem bezpiecznej akcji. Celowe wymuszenie, aby wyszukiwanie w Object Manager Namespace (OMNS) w kroku 2 trwało dziesiątki mikrosekund, daje atakującemu wystarczająco dużo czasu, aby konsekwentnie wygrywać w przeciwnym razie niestabilne wyścigi bez potrzeby wykonywania tysięcy prób.<sup>[[1]](#references)</sup>

## W skrócie o wewnętrznym działaniu wyszukiwania Object Manager

* **Struktura OMNS** – Nazwy takie jak `\BaseNamedObjects\Foo` są rozwiązywane katalog po katalogu. Każdy komponent powoduje, że kernel musi znaleźć/otworzyć *Object Directory* i porównać ciągi Unicode. Po drodze mogą być przechodzone symbolic links, takie jak litery dysków.
* **Limit UNICODE_STRING** – Ścieżki OM są przechowywane w `UNICODE_STRING`, którego `Length` jest wartością 16-bitową. Bezwzględny limit wynosi 65 535 bajtów (32 767 codepointów UTF-16). Przy użyciu prefiksów takich jak `\BaseNamedObjects\` atakujący nadal kontroluje około 32 000 znaków.
* **Wymagania wstępne atakującego** – Każdy użytkownik może tworzyć obiekty w zapisywalnych katalogach, takich jak `\BaseNamedObjects`. Gdy podatny kod używa nazwy znajdującej się w takim katalogu lub podąża za symbolic linkiem prowadzącym do niego, atakujący może kontrolować wydajność wyszukiwania bez specjalnych uprawnień.<sup>[[1]](#references)</sup>

## Prymityw spowalniający nr 1 – Pojedynczy maksymalny komponent

Koszt rozwiązywania komponentu jest w przybliżeniu liniowy względem jego długości, ponieważ kernel musi wykonać porównanie Unicode z każdym wpisem w katalogu nadrzędnym. Utworzenie eventu z nazwą o długości 32 kB natychmiast zwiększa opóźnienie `NtOpenEvent` z około 2 µs do około 35 µs w Windows 11 24H2 (platforma testowa Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktyczne uwagi*

- Limit długości można osiągnąć przy użyciu dowolnego nazwanego obiektu jądra (zdarzeń, sekcji, semaforów…).
- Symbolic links lub reparse points mogą wskazywać z krótkiej nazwy „victim” na ten ogromny komponent, dzięki czemu spowolnienie jest stosowane w sposób transparentny.
- Ponieważ wszystko znajduje się w przestrzeniach nazw zapisywalnych przez użytkownika, payload działa ze standardowym poziomem integralności użytkownika.<sup>[[1]](#references)</sup>

## Prymityw spowalniania nr 2 – głęboko zagnieżdżone katalogi

Bardziej agresywny wariant alokuje łańcuch tysięcy katalogów (`\BaseNamedObjects\A\A\...\X`). Każdy poziom uruchamia logikę rozwiązywania katalogów (sprawdzanie ACL, wyszukiwanie hashy, zliczanie referencji), dlatego opóźnienie na poziom jest większe niż w przypadku pojedynczego porównania ciągów. Przy około 16 000 poziomach (ograniczonych przez ten sam rozmiar `UNICODE_STRING`) pomiary empiryczne przekraczają barierę 35 µs osiągniętą przez długie pojedyncze komponenty.
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
* Zachowaj tablicę uchwytów, aby po exploitacji móc czysto usunąć cały łańcuch i uniknąć zanieczyszczania namespace'u.<sup>[[1]](#references)</sup>

## Primitive slowdown #3 – Shadow directories, hash collisions & symlink reparses (minuty zamiast mikrosekund)

Object directories obsługują **shadow directories** (wyszukiwanie awaryjne) oraz haszowane tabele kubełkowe dla wpisów. Wykorzystaj oba mechanizmy wraz z limitem 64 reparsowań symbolic-linków, aby zwielokrotnić slowdown bez przekraczania długości `UNICODE_STRING`:

1. Utwórz dwa katalogi w `\BaseNamedObjects`, np. `A` (shadow) oraz `A\A` (target). Utwórz drugi, używając pierwszego jako shadow directory (`NtCreateDirectoryObjectEx`), dzięki czemu brakujące wyszukiwania w `A` będą przechodzić do `A\A`.
2. Wypełnij każdy katalog tysiącami **colliding names**, które trafiają do tego samego hash bucket (np. zmieniając końcowe cyfry przy zachowaniu tej samej wartości `RtlHashUnicodeString`). Wyszukiwania ulegają teraz degradacji do liniowych skanów O(n) wewnątrz pojedynczego katalogu.
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

- James Forshaw opublikował ponownie tę technikę wraz ze zaktualizowanymi wartościami czasów dla Windows 11 24H2 (ARM64). Bazowe otwarcia nadal trwają około 2 µs; komponent o rozmiarze 32 kB zwiększa ten czas do około 35 µs, a shadow-dir + collision + łańcuchy 63 reparse nadal osiągają około 3 minut, co potwierdza, że primitives działają także w obecnych buildach. Kod źródłowy i perf harness znajdują się w zaktualizowanym poście Project Zero.<sup>[[1]](#references)</sup>
- Konfigurację można zautomatyzować za pomocą publicznego pakietu `symboliclink-testing-tools`: `CreateObjectDirectory.exe` tworzy parę shadow/target, a `NativeSymlink.exe` uruchamiane w pętli generuje łańcuch 63-hop. Eliminuje to konieczność ręcznego pisania wrapperów `NtCreate*` i zapewnia spójność ACL.<sup>[[2]](#references)</sup>

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
Wyniki bezpośrednio wpływają na strategię orchestracji race (np. liczbę wymaganych worker threads, interwały uśpienia oraz to, jak wcześnie trzeba przełączyć współdzielony stan).

## Workflow exploitacji

1. **Locate the vulnerable open** – Prześledź ścieżkę kernela (za pomocą symbols, ETW, hypervisor tracing lub reverse engineeringu), aż znajdziesz wywołanie `NtOpen*`/`ObOpenObjectByName`, które przechodzi przez kontrolowaną przez atakującego nazwę lub symbolic link w katalogu z prawem zapisu dla użytkownika.
2. **Replace that name with a slow path**
- Utwórz długi komponent lub łańcuch katalogów w `\BaseNamedObjects` (albo w innym zapisywalnym katalogu OM).
- Utwórz symbolic link, aby nazwa oczekiwana przez kernel wskazywała teraz na slow path. Możesz skierować directory lookup podatnego drivera do swojej struktury bez modyfikowania oryginalnego celu.
3. **Trigger the race**
- Thread A (victim) wykonuje podatny kod i blokuje się wewnątrz slow lookup.
- Thread B (attacker) przełącza chroniony stan (np. zamienia file handle, przepisuje symbolic link lub przełącza object security), gdy Thread A jest zajęty.
- Gdy Thread A wznowi działanie i wykona uprzywilejowaną akcję, odczyta nieaktualny stan i wykona operację kontrolowaną przez atakującego.
4. **Clean up** – Usuń łańcuch katalogów i symbolic links, aby nie pozostawiać podejrzanych artefaktów ani nie zakłócać działania legalnych użytkowników IPC.<sup>[[1]](#references)</sup>

## Zastosowany łańcuch: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), opublikowany jako bypass dla RoguePlanet (CVE-2026-50656), demonstruje szerszy wzorzec exploitacji: doprowadź do tego, aby uprzywilejowany scanner sklasyfikował jedną reprezentację logicznego pliku, a następnie zmień zarówno jego bajty, jak i rozwiązywanie namespace, zanim remediation go użyje. PoC łączy TOCTOU podczas Cloud Files hydration, Object Manager shadow-directory fallback, przechwytywanie nazw generowanych przez CLFS oraz local administrative-share link, aby zamienić cleanup Defendera w zapis chronionej biblioteki DLL.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Substitute content through Cloud Files hydration

Zarejestruj katalog zapisywalny przez atakującego jako Cloud Files sync root, podłącz callback `CF_CALLBACK_TYPE_FETCH_DATA` i utwórz placeholder, którego deklarowany rozmiar odpowiada deterministycznemu triggerowi detekcji, takiemu jak EICAR ZIP. Pierwszy fetch zwraca trigger i przełącza stan callbacku; kolejne fetches zwracają payload. Po sklasyfikowaniu pierwszej reprezentacji przez scanner uzyskaj transfer key i uruchom hydration ponownie z metadanymi o rozmiarze payloadu, a następnie wymuś hydration do EOF.<sup>[[4]](#references)</sup>
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
Granica bezpieczeństwa zawodzi, jeśli skanowanie, werdykt i remediacja odnoszą się wyłącznie do pathname lub tożsamości zastępczej: żaden z tych elementów nie gwarantuje, że późniejsze hydration zwróci bajty, które zostały poddane inspekcji.<sup>[[4]](#references)</sup>

### 2. Przełącz niezmienną ścieżkę przez fallback shadow-directory

Utwórz docelowy katalog Object Manager oraz drugi katalog za pomocą `NtCreateDirectoryObjectEx`, przekazując uchwyt celu jako jego katalog shadow/fallback. Umieść wpis `WD_SCAN` o tej samej nazwie w obu warstwach rozpoznawania: widoczny wpis wskazuje na normalny katalog roboczy, podczas gdy wpis fallback wskazuje na `\CLFS\??\<working-directory>`. Przekaż Defenderowi wyłącznie poniższą niezmienną ścieżkę; usunięcie widocznego linku podczas trwania operacji powoduje, że ten sam ciąg znaków przechodzi do wpisu opartego na CLFS.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Różni się to od używania shadow directories wyłącznie w celu spowolnienia wyszukiwania: attacker zmienia **znaczenie** wcześniej zaakceptowanej ścieżki bez modyfikowania jej ciągu znaków.<sup>[[4]](#references)</sup>

### 3. Przechwycenie wygenerowanej nazwy i utworzenie linku zależnego od nazwy pliku

Monitoruj working directory za pomocą `ReadDirectoryChangesW`. Po pierwszym `FILE_ACTION_ADDED` usuń widoczny link `WD_SCAN`, aby aktywować fallback lookup. Przechwyć drugą wygenerowaną nazwę pliku, otwórz ten plik związany z CLFS i zablokuj zakres `0..MAXLONGLONG` za pomocą `LockFileEx`. Gdy uprzywilejowana operacja jest wstrzymana, zastąp `WD_SCAN` w widocznym katalogu rzeczywistym katalogiem Object Manager i utwórz child symbolic link o nazwie utworzonej na podstawie zaobserwowanej nazwy pliku (PoC usuwa jej cztery końcowe znaki). Wskaż go na chronione miejsce docelowe przez lokalny SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Nieuprzywilejowany proces nie może samodzielnie zapisywać w tym miejscu docelowym, ale kontekst SYSTEM programu Defender może przechodzić przez loopback administrative share. Połączenie obserwacji wygenerowanej nazwy z właściwym dla nazwy pliku linkiem Object Manager eliminuje konieczność wcześniejszego przewidywania artefaktu remediacji.<sup>[[4]](#references)</sup>

### 4. Stabilizacja race cleanup i uruchomienie uprzywilejowanego loadera

Przed skanowaniem PoC zapisuje poprawny plik PE (`ntdll.dll`) w placeholderze, w alternatywnym strumieniu danych NTFS `:stream`. Po utworzeniu przez redirection chronionego pliku bazowego otwiera `phoneinfo.dll:stream` z uprawnieniami execute i utrzymuje aktywne mapowanie `PAGE_EXECUTE_READ | SEC_IMAGE`, podczas gdy cleanup jest kontynuowany; aktywne obiekty pliku/sekcji ograniczają możliwość usunięcia lub zastąpienia podczas finalnego race. Ponowne hydration zwraca teraz payload DLL zamiast EICAR, więc chroniony plik bazowy zawiera kod kontrolowany przez atakującego.<sup>[[4]](#references)</sup>

Chroniony zapis jest następnie przekształcany w wykonanie przez SYSTEM poprzez umieszczenie spreparowanego `Report.wer` w `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` i wywołanie `\Microsoft\Windows\Windows Error Reporting\QueueReporting` za pośrednictwem Task Scheduler COM API. W tym łańcuchu uprzywilejowane przetwarzanie WER ładuje umieszczony `C:\Windows\System32\phoneinfo.dll`; połączenie named pipe służy jako sygnał wykonania payloadu.<sup>[[4]](#references)</sup>

### Pivots wykrywania

Użyteczne korelacje są bardziej szczegółowe niż jakakolwiek pojedyncza tymczasowa nazwa pliku i obejmują wszystkie przejścia między przestrzeniami nazw w tym łańcuchu:<sup>[[4]](#references)</sup>

- Nowo zarejestrowany provider Cloud Files, a następnie wykrycie EICAR i `CF_OPERATION_TYPE_RESTART_HYDRATION` na tym samym placeholderze.
- Ścieżki Object Manager zawierające `WD_TARGET_*`, `WD_SHADOW_*` lub `WD_SCAN`, szczególnie ścieżka skanowania poniżej `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Utworzenie pliku CLFS, a następnie wyłączna blokada całego pliku i dostęp loopback do `\\127.0.0.1\C$\Windows\System32\*.dll` z uprzywilejowanego procesu bezpieczeństwa.
- Utworzenie biblioteki DLL w System32 wraz z NTFS ADS, a następnie mapowanie strumienia `SEC_IMAGE`.
- Utworzenie przez atakującego wpisu w kolejce WER, a następnie nietypowe ręczne uruchomienie `\Microsoft\Windows\Windows Error Reporting\QueueReporting` i załadowanie obrazu umieszczonej biblioteki DLL.

## Applied chain: przełączanie mount point sterowane przez oplock przeciwko uprzywilejowanej remediacji

Powtarzalny wzorzec LPE pojawia się, gdy uprzywilejowany skaner sprawdza plik kontrolowany przez atakującego, a następnie przeprowadza remediation, ponownie otwierając **pathname**, zamiast kontynuować operację za pomocą zweryfikowanych handle. FalconFlank jest publicznym przykładem wymierzonym w workflow usuwania makr Office przez CrowdStrike Falcon; repozytorium deklaruje testy na Windows 11 25H2 i Windows Server 2025 przy włączonej odpowiedniej polityce, ale nie publikuje CVE, zakresu podatnych buildów, advisory vendora ani statusu patcha, dlatego twierdzenie dotyczące konkretnego produktu należy traktować jako niezweryfikowane i zależne od builda.<sup>[[5]](#references)[[6]](#references)</sup>

### Układ race

1. Utwórz zapisywalne drzewo, którego końcowa nazwa względna jest użyteczna w zamierzonym miejscu docelowym. Przykład wykorzystuje `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, ale początkowo zapisuje dokument OLE z makrem — a nie bibliotekę DLL PE — do `bcrypt.dll`. Detekcja oparta na zawartości uruchamia remediation, a basename kontrolowany przez atakującego zostaje zachowany na potrzeby późniejszego side-loadingu.<sup>[[5]](#references)</sup>
2. Otwórz katalogi z szerokim współdzieleniem i `FILE_OPEN_REPARSE_POINT`, a następnie zażądaj asynchronicznego RH oplock na triggerze za pomocą `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` oraz `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Zaczekaj na overlapped event i użyj jego zakończenia jako sygnału przełączenia ścieżki. Powiadomienie o przerwaniu RH oplock jest wskazówką, a nie dowodem, że każda kolidująca operacja została zablokowana, dlatego możliwość wykorzystania nadal zależy od dokładnej sekwencji open/remediation po stronie ofiary.<sup>[[5]](#references)[[7]](#references)</sup>
3. Po przerwaniu usuń katalog leaf za pomocą `FileDispositionInformationEx` (information class 64), używając flag usuwania oraz semantyki POSIX, zamknij jego handle i zastosuj `IO_REPARSE_TAG_MOUNT_POINT` do pustego już katalogu nadrzędnego za pomocą `FSCTL_SET_REPARSE_POINT_EX`. Mount point przekierowuje niezmieniony suffix do chronionego drzewa, takiego jak `\\SystemRoot\\System32\\WindowsPowerShell`; ustawienie reparse point kończy się niepowodzeniem, jeśli katalog nie jest pusty, co wyjaśnia poprzedzający krok usunięcia.<sup>[[5]](#references)[[8]](#references)</sup>
4. Wznów uprzywilejowany workflow. Jeśli ponownie rozwiązuje string bez potwierdzenia, że łańcuch katalogów i końcowy obiekt są tymi samymi elementami, które wcześniej sprawdzono, ta sama logiczna pathname prowadzi teraz do wybranego przez atakującego chronionego katalogu. W przykładzie powodzenie jest testowane przez ponowne otwarcie `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` z uprawnieniami read/write z oryginalnego procesu; odróżnia to primitive confused-deputy write od późniejszego etapu code execution.<sup>[[5]](#references)</sup>
5. Zastąp wynikowy plik prawdziwą biblioteką DLL i aktywuj uprzywilejowany loader. PoC używa `CreateTransaction` + `CreateFileTransacted`, skraca plik, mapuje zamiennik o rozmiarze DLL, kopiuje PE i wykonuje commit; TxF wiąże file handle oraz kolejne operacje oparte na handle z transakcją, ale jest mechanizmem zastąpienia po race, a nie źródłem naruszenia granicy uprawnień.<sup>[[5]](#references)[[9]](#references)</sup>
6. Na koniec uruchom istniejące uprzywilejowane scheduled task, którego executable wyszukuje sąsiednią nazwę pliku. FalconFlank wywołuje `\\Microsoft\\Windows\\Application Experience\\MareBackup`, czeka, aż biblioteka DLL połączy się z `\\??\\pipe\\FALCONFLANK`, a następnie usuwa umieszczony plik. Nie zakładaj konkretnego tokena wynikającego wyłącznie z nazwy taska — zweryfikuj uruchomiony proces, ścieżkę modułu, poziom integralności i token na testowanym buildzie.<sup>[[5]](#references)</sup>

Podstawowe pytanie audytowe nie brzmi zatem „czy usługa weryfikuje pierwotną ścieżkę wejściową?”, lecz „czy każda uprzywilejowana mutacja pozostaje powiązana z tymi samymi otwartymi obiektami pliku i katalogu, które zostały zweryfikowane?”. Utrzymywanie handle między sprawdzeniem a użyciem, otwieranie obiektów potomnych względem zaufanego directory handle, odrzucanie nieoczekiwanych reparse tags oraz ponowna walidacja tożsamości pliku przed mutacją zamykają tę klasę błędów pathname-substitution.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection and PoC triage

Wysokosygnałowe wykrywanie koreluje przejście między przestrzeniami nazw z uprzywilejowanym konsumentem: nagłówek OLE pod basename biblioteki DLL w tymczasowym drzewie nazwanym GUID-em, przerwanie oplock, usunięcie katalogu leaf w stylu POSIX, utworzenie mount point wskazującego chroniony katalog Windows oraz utworzenie lub modyfikacja tego samego basename poniżej miejsca docelowego. W publicznym przykładzie dodaj `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, ręczne wykonanie `MareBackup` oraz named pipe `FALCONFLANK` jako węższe pivots; żaden z nich nie jest samodzielnie wystarczający.<sup>[[5]](#references)</sup>

Podczas odtwarzania PoC uwzględnij trzy defekty niezawodności w opublikowanym źródle: wywołuje `FlushFileBuffers` ze wskaźnikiem osadzonej tablicy bajtów zamiast file handle, sprawdza nieaktualny `HRESULT` po `GetFolder`, `GetTask` i `Run`, a także używa nieograniczonych pętli retry/wait dla usuwania katalogu, tworzenia reparse, eventu oplock i połączenia pipe.<sup>[[5]](#references)</sup>

## Kwestie operacyjne

- **Łączenie primitives** – Możesz użyć długiej nazwy *na każdym poziomie* w łańcuchu katalogów, aby uzyskać jeszcze większe opóźnienie, aż do wyczerpania rozmiaru `UNICODE_STRING`.
- **Błędy one-shot** – Powiększone okno (od dziesiątek mikrosekund do minut) sprawia, że błędy typu „single trigger” są realistyczne w połączeniu z przypinaniem affinity CPU lub preemption wspomaganym przez hypervisor.
- **Skutki uboczne** – Spowolnienie dotyczy wyłącznie złośliwej ścieżki, więc ogólna wydajność systemu pozostaje bez zmian; obrońcy rzadko to zauważą, chyba że monitorują wzrost przestrzeni nazw.
- **Cleanup** – Zachowaj handle do każdego utworzonego katalogu/obiektu, aby później móc wywołać `NtMakeTemporaryObject`/`NtClose`. W przeciwnym razie nieograniczone łańcuchy katalogów mogą przetrwać ponowne uruchomienie systemu.
- **File-system races** – Jeśli podatna ścieżka ostatecznie jest rozwiązywana przez NTFS, możesz założyć Oplock (np. `SetOpLock.exe` z tego samego toolkitu) na pliku bazowym podczas działania spowolnienia OM, zamrażając konsumenta na dodatkowe milisekundy bez modyfikowania grafu OM.<sup>[[2]](#references)</sup>

## Uwagi dotyczące obrony

- Kod kernela, który opiera się na named objects, powinien ponownie zweryfikować stan wrażliwy z punktu widzenia bezpieczeństwa *po* otwarciu albo pobrać referencję przed sprawdzeniem (eliminując lukę TOCTOU).
- Wymuszaj górne limity głębokości/długości ścieżki OM przed dereferencją nazw kontrolowanych przez użytkownika. Odrzucanie zbyt długich nazw zmusza atakujących z powrotem do okna mikrosekundowego.
- Instrumentuj wzrost przestrzeni nazw object managera (ETW `Microsoft-Windows-Kernel-Object`), aby wykrywać podejrzane łańcuchy złożone z tysięcy komponentów pod `\BaseNamedObjects`.

## References

- [1] [Project Zero – Techniki exploitation systemu Windows: wygrywanie race conditions podczas wyszukiwania ścieżek](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Jak używać Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
