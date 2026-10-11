# Mythic

{{#include ../banners/hacktricks-training.md}}

## Czym jest Mythic?

Mythic to open-source, modularny, współpracujący framework command and control (C2) przeznaczony do red teamingu. Umożliwia operatorom zarządzanie agentami (payloadami) i wdrażanie ich w różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic udostępnia interfejs przeglądarkowy do przydzielania zadań wielu operatorom, obsługi plików, zarządzania SOCKS/rpfwd oraz generowania payloadów.

W przeciwieństwie do monolitycznych frameworków samo repozytorium Mythic **nie** zawiera typów payloadów ani profili C2. Agenty, wrappery i profile C2 są zazwyczaj instalowane jako zewnętrzne komponenty i mogą być aktualizowane niezależnie od rdzenia Mythic.

### Instalacja

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami w oficjalnym **[repozytorium Mythic](https://github.com/its-a-feature/Mythic)**. Typowy bootstrap z katalogu Mythic wygląda następująco:

```bash
sudo make
sudo ./mythic-cli start
```

Jeśli Mythic jest już uruchomiony, zazwyczaj możesz dodać nowego agenta lub profil za pomocą `./mythic-cli install github ...`, a następnie ponownie uruchomić Mythic albo po prostu uruchomić bezpośrednio nowy komponent.

### Agenci

Mythic obsługuje wielu agentów — są to **payloady wykonujące zadania na przejętych systemach**. Każdego agenta można dostosować do konkretnych potrzeb i uruchamiać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agentów. Agenci społeczności open source są dostępni w [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**macierz funkcji społeczności**](https://mythicmeta.github.io/overview/agent_matrix.html) pozwala szybko sprawdzić obsługiwane systemy operacyjne, formaty payloadów, wrappery i profile C2.<sup>[[1]](#references)</sup>

Aby zainstalować agenta z tej organizacji, możesz uruchomić:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Forma `sudo -E` jest przydatna podczas instalacji ze środowiska innego niż root. Możesz dodać nowe agenty za pomocą poprzedniego polecenia, nawet jeśli Mythic już działa.

### Profile C2

Profile C2 w Mythic definiują **sposób komunikacji agentów z serwerem Mythic**. Określają protokół komunikacyjny, metody szyfrowania i inne ustawienia. Profile C2 można tworzyć i zarządzać nimi za pośrednictwem interfejsu webowego Mythic.

Domyślnie Mythic jest instalowany bez żadnych profili, ale można pobrać niektóre profile z repozytorium [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), uruchamiając:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Aktualne profile istotne dla operatora, o których warto pamiętać:

- [`http`](https://github.com/MythicC2Profiles/http): podstawowy asynchroniczny ruch GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): bardziej elastyczny ruch HTTP z wieloma domenami callback, przełączaniem awaryjnym/rotacją round-robin, niestandardowymi nagłówkami/parametrami zapytania oraz transformacjami wiadomości (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) umieszczanymi w cookies, nagłówkach, parametrach zapytania lub treści.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): sterowane przez JSON/TOML kształtowanie wiadomości HTTP, gdy statyczny profil `http` jest zbyt łatwo rozpoznawalny.

### Aktualne informacje o platformie

- Wiele publicznych agentów i profili jest obecnie instalowanych z gotowymi obrazami zdalnych kontenerów.
  Jeśli utworzysz fork komponentu lub wprowadzisz w nim lokalne poprawki, a Mythic nadal będzie działać po staremu, sprawdź wygenerowane wpisy `.env` dla `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; ustawienie
  `*_USE_BUILD_CONTEXT="true"` zwykle powoduje, że Mythic przebudowuje komponent na podstawie lokalnego kontekstu Docker, zamiast po cichu ponownie używać zdalnego obrazu.
- Skrypty przeglądarki to jedna z najbardziej przydatnych funkcji Mythic dla operatorów: mogą przekształcać surowe wyniki poleceń w tabele, przeglądarki zrzutów ekranu, linki do pobierania, linki do wyszukiwania oraz przyciski, które bezpośrednio z interfejsu wysyłają kolejne zadania. Obecne wersje Mythic pozwalają każdemu operatorowi zachować własne skrypty, włączać je lub wyłączać globalnie albo dla poszczególnych zadań, a najlepsze efekty uzyskuje się, gdy agenci zwracają ustrukturyzowany JSON zamiast zwykłego tekstu. Jest to szczególnie przydatne w powtarzalnych procesach `ls`, `ps`, triage i przeglądania plików.<sup>[[4]](#references)[[6]](#references)</sup>
- Nowsze wersje Mythic obsługują również interaktywne tasking i wzorce Push C2, które ograniczają potrzebę odpytywania za pomocą `sleep 0` podczas operacji intensywnie wykorzystujących PTY/SOCKS/rpfwd. Gdy agent/profil to obsługuje, zwykle wiąże się to z mniejszym obciążeniem niż ciągłe odpytywanie serwera tylko po to, by utrzymać działający kanał interaktywny.<sup>[[3]](#references)</sup>
- Obecne buildery Mythic z serii 3.4 lepiej uwzględniają kontekst, niż sugerują starsze opisy: parametry kompilacji można teraz grupować lub ukrywać zależnie od wybranego systemu operacyjnego lub innych opcji kompilacji, typy payloadów mogą deklarować, czy obsługują wiele profili C2 lub wiele instancji tego samego C2 w jednej kompilacji, a odchylenia parametrów C2 pozwalają agentowi ukrywać pola, których faktycznie nie obsługuje. Ma to znaczenie przy przełączaniu się między `http`, `httpx`, `smb`,
  `tcp` i `websocket`, ponieważ zakres bezpiecznych/poprawnych konfiguracji nie jest już płaskim, statycznym formularzem.<sup>[[5]](#references)</sup>
- Jeśli tworzysz niestandardową parę agent/profil i nie chcesz używać formatu wiadomości JSON Mythic ani domyślnego szyfrowania przesyłanego przez sieć, użyj `translation_container`: Mythic usuwa UUID, przekazuje zaszyfrowany blob i materiały kluczowe do translatora przez gRPC, a następnie oczekuje bajtów w formacie natywnym dla agenta. To czysty sposób na obsługę protokołów binarnych, niestandardowego formatowania ramek lub szyfrowania po stronie agenta bez przepisywania całego serwera.
- Pamiętaj, że callbacki połączone/P2P nie tylko przekazują tasking. Przepływ `get_tasking` w Mythic może również przenosić odpowiedzi oraz dane `delegates`, `socks`, `rpfwd` i `interactive`. W praktyce jeden callback wychodzący może obsługiwać wewnętrzne callbacki i kanały pivotingu w tej samej pętli odpytywania; jeśli agenty potomne wykonują własne okresowe check-iny, `get_delegate_tasks=false` zapobiega przypadkowemu pobieraniu przez agenta nadrzędnego zadań z kolejki wewnętrznego callbacku.

### Payloady opakowujące

Payloady opakowujące pozwalają zachować tę samą logikę agenta, zmieniając jedynie reprezentację na dysku, która jest dostarczana lub utrwalana.

- `service_wrapper`: przekształca inny payload w plik wykonywalny usługi Windows, co jest przydatne, gdy ścieżka wykonania wymaga prawidłowego pliku binarnego usługi.
- `scarecrow_wrapper`: opakowuje zgodny shellcode za pomocą loadera ScareCrow, generując wyniki obsługiwane przez loader, takie jak EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo to agent dla Windows napisany w C# z użyciem .NET Framework 4.0, przeznaczony do wykorzystania w szkoleniach SpecterOps.<sup>[[2]](#references)</sup>

Zainstaluj go za pomocą:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Aktualne uwagi dotyczące buildów i profili

- Apollo może obecnie generować payloady `WinExe`, `Shellcode`, `Service` i `Source`.
- Powszechnie używane profile Apollo to `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` jest zazwyczaj bardziej elastyczną opcją, gdy potrzebujesz rotacji domen, obsługi proxy, niestandardowego umieszczania wiadomości i transformacji wiadomości zamiast starszego, statycznego profilu `http`.
- Apollo to jeden z bardziej kompletnych funkcjonalnie agentów społecznościowych. Obecnie udostępnia integracje po stronie Mythic, takie jak skrypty przeglądarki, widoki przeglądarki plików/procesów, zrzuty ekranu, keylogging, SOCKS, rpfwd, Push C2 i routing P2P.
- Apollo obsługuje payloady wrapperów, takie jak `service_wrapper` i `scarecrow_wrapper`.
- Apollo obsługuje dynamiczne ładowanie komend, dzięki czemu początkowy payload może pozostać niewielki, a dodatkowe komendy lub moduły Forge można załadować później, zamiast kompilować wszystkie funkcje post-ex do pierwszego buildu.
- Podczas generowania wyjścia shellcode bieżący builder Apollo udostępnia również opcje formatu Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) oraz zachowanie Donut w przypadku bypassu (`None`, `Abort on fail`, `Continue on fail`). Jest to przydatne, jeśli docelowo chcesz ponownie opakować shellcode za pomocą `service_wrapper`, `scarecrow_wrapper` lub własnego loadera.
- `register_file` i `register_assembly` to prymitywy stagingu dla `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. W obecnych buildach Apollo te przygotowane artefakty są buforowane po stronie klienta jako bloby AES256 chronione przez DPAPI.
- Wyniki `ls` i `ps` szczególnie dobrze integrują się ze skryptami przeglądarki Mythic oraz przeglądarką plików/procesów, co znacznie przyspiesza triage operatorów podczas wspólnych operacji.
- Zadania fork-and-run dziedziczą ustawienia procesu ofiarnego z `spawnto_x86` / `spawnto_x64`, wybór procesu nadrzędnego z `ppid`, a następnie korzystają z aktualnie wybranego prymitywu injection. W praktyce oznacza to, że dostrajanie OPSEC dla jednej komendy często wpływa jednocześnie na `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i `spawn`.
- Obecnie udokumentowane backendy injection w Apollo obejmują `CreateRemoteThread`, `QueueUserAPC` (w stylu early-bird) oraz `NtCreateThreadEx` przez syscalls. Użyj `get_injection_techniques` przed głośnymi działaniami post-exploitation, a jeśli potrzebujesz zmienić prymityw, który koliduje z celem lub planowaną komendą, użyj `set_injection_technique`.
- `blockdlls` wpływa wyłącznie na procesy ofiarne tworzone na potrzeby zadań post-exploitation. W połączeniu z mniej podejrzanym celem `spawnto_x64` niż domyślny, goły `rundll32.exe`, jest to jedna z najprostszych zmian po stronie Apollo, które można wprowadzić przed uruchomieniem zadań intensywnie korzystających z assembly/PowerShell.

### Uwzględniający detekcje pipeline buildowania agenta .NET

Fork Apollo uwzględniający detekcje należy traktować jako problem dotyczący **całego systemu buildowania**, a nie jako końcowy krok `obfuscate.exe`. To studium przypadku uzupełnia ogólną [AV evasion methodology](av-bypass.md) i [narzędzia do inspekcji .NET](../reversing/reversing-tools-basic-methods/README.md): zmiany identyfikatorów komunikacji, metadanych IL, pakowania zależności, reflection i dynamicznie kompilowanych zadań tworzą jedną granicę zgodności.<sup>[[8]](#references)</sup>

#### Mutacja protokołu uwzględniająca YARA

Przed zmianą kodu sprawdź publiczne reguły skanowania plików/pamięci. Na przykład reguła Elastic `Multi_Trojan_Mythic_4beb7e17` dopasowuje próbkę, gdy obecnych jest dowolnych **7 z 11** ciągów JSON/akcji Mythic, w tym `task_id`, `post_response`, `c2_profile`, `get_tasking` i `get_delegate_tasks`. Zmiana nazw wystarczającej liczby pól może ominąć ten próg, ale są to wartości protokołu, a nie kosmetyczne symbole: agent oraz odpowiadająca mu implementacja serwera/profilu muszą być zmienione równocześnie.<sup>[[7]](#references)[[8]](#references)</sup>

Usuwa to tylko jeden statyczny zestaw cech. Częstotliwość check-inów, kształt wiadomości, przepływ zadań/odpowiedzi i odtwarzanie ciągów znaków w czasie działania mogą nadal stanowić wskaźniki behawioralne lub pamięciowe; dlatego zweryfikuj zarówno zbudowany artefakt, jak i wykonane połączenie zwrotne, zamiast uznawać czysty skan ciągów za sukces.<sup>[[8]](#references)</sup>

#### Scal przed zastosowaniem transformacji globalnych

Osadzanie zasobów za pomocą narzędzi takich jak Costura pozostawia towarzyszące zestawy jako skompresowane zasoby. Obfuscator analizujący wyłącznie zewnętrzny moduł nie obejmuje więc ich nazw typów i metadanych; niezależne obfuscowanie każdego DLL-a może natomiast przypisać niezgodne nazwy kontraktom między zestawami. Najpierw scal wyniki builda na poziomie IL (na przykład za pomocą [ILRepack](https://github.com/gluck/il-repack)), a następnie zastosuj jedną mapę zmian nazw do wynikowego modułu.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Niestandardowy pass może używać [dnlib](https://github.com/0xd4d/dnlib) do transformacji zarządzanego IL/metadanych oraz [AsmResolver](https://github.com/Washi1337/AsmResolver) do poprawiania PE/zasobów po zapisie. W analizowanym przypadku instrukcje `ldstr` spełniające kryteria zostały zamienione na wywołania z tokenem całkowitym/deszyfratorem, wykorzystujące nowy, 16-bajtowy klucz rolling-XOR, a symbole i przestrzenie nazw przypisano do wiarygodnie wyglądających nazw w stylu korporacyjnym zamiast krótkich, sekwencyjnych identyfikatorów. Inne passy usuwały wybrane atrybuty kompilatora/debuggera, czyściły odwołania do mergera/osadzania, zmieniały nazwy zasobów i poprawiały informacje o wersji. Przy każdym niezależnym buildzie generuj ponownie nazwy, dead code i materiał szyfrujący: zmiana ciphertext usuwa stabilne bajty, ale stabilny deszyfrator lub rozpoznawalny wzorzec transformacji sam w sobie stanowi sygnaturę.<sup>[[8]](#references)</sup>

#### Synchronizuj dynamiczne zadania z payloadem

Apollo może kompilować kod źródłowy zadań po stronie serwera, wysyłać bajty DLL i ładować je za pomocą `Assembly.Load()`. Gdy zmienią się nazwy typów publicznych base agenta, późniejsze zadania skompilowane z użyciem oryginalnego API nie będą już mogły ich rozpoznać. Traktuj eksportowaną mapę zmian nazw jako artefakt ABI specyficzny dla payloadu:<sup>[[8]](#references)</sup>

1. Powiąż mapę i kontekst typów z dokładnym identyfikatorem payloadu/produkcji.
2. Przy każdym buildzie zadania pobierz tę mapę i przepisz tymczasowe drzewo źródłowe.
3. Przepisuj wyłącznie odwołania do rozpoznanych przestrzeni nazw, typów, typów zagnieżdżonych/generycznych, pól i właściwości, a następnie kompiluj z użyciem zaciemnionego, scalonego assembly.
4. Odrzuć brakujące lub niezgodne mapy przed dostarczeniem zadania i po kompilacji przeprowadź test inicjalizacji.

Bezwarunkowe globalne zastępowanie jest niebezpieczne, ponieważ identyfikator może też występować w ciągu znaków, deklaracji lokalnej, dostępie do składowej, typie frameworka lub niepowiązanej przestrzeni nazw. Jeśli pozostawisz rewriter tekstowy/regexowy, jawnie zabezpiecz te konteksty i testuj regresyjnie po każdej zmianie schematu mapy lub passa zmieniającego nazwy.<sup>[[8]](#references)</sup>

#### Uniezależnij kontrakty refleksji od przestrzeni nazw

Kod wykrywania, który sprawdza `t.FullName.StartsWith("Tasks.")`, uzależnia działanie od przestrzeni nazw i przestaje działać po jej przemapowaniu. Zamiast tego wykrywaj typy na podstawie stabilnej relacji typów, zachowując nazwy klas poleceń, jeśli dispatch nadal używa `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Utrzymuj jawną allowlistę nazw widocznych przez reflection, pól serializera, entry pointów i API między assembly, których nie wolno zmieniać. Na koniec zdekompiluj wynik za pomocą ILSpy/dnSpy, przeskanuj reprezentacje plikowe i pamięciowe oraz przetestuj każdą ścieżkę command/loader w laboratorium EDR; build, który uruchamia się poprawnie, nadal może zawierać zadania zepsute przez zmianę nazw lub zachowanie wykrywane dopiero podczas wykonania.<sup>[[8]](#references)</sup>

Ten agent ma wiele komend, dzięki czemu przypomina Beacon z Cobalt Strike, ale zawiera też dodatkowe funkcje. Wśród nich obsługuje:

### Typowe działania

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący katalog roboczy
- `cp`: Kopiuje plik z jednej lokalizacji do drugiej
- `ls`: Wyświetla pliki i katalogi w bieżącym katalogu lub określonej ścieżce
- `ifconfig`: Pobiera informacje o kartach i interfejsach sieciowych
- `netstat`: Pobiera informacje o połączeniach TCP i UDP
- `pwd`: Wyświetla bieżący katalog roboczy
- `ps`: Wyświetla uruchomione procesy w systemie docelowym (z dodatkowymi informacjami)
- `jobs`: Wyświetla wszystkie uruchomione zadania powiązane z długotrwałym taskingiem
- `download`: Pobiera plik z systemu docelowego na lokalną maszynę
- `upload`: Wysyła plik z lokalnej maszyny do systemu docelowego
- `reg_query`: Odpytuje klucze i wartości rejestru w systemie docelowym
- `reg_write_value`: Zapisuje nową wartość w określonym kluczu rejestru
- `sleep`: Zmienia interwał uśpienia agenta, który określa, jak często agent kontaktuje się z serwerem Mythic
- I wiele innych — użyj `help`, aby zobaczyć pełną listę dostępnych komend.

### Eskalacja uprawnień

- `getprivs`: Włącza jak najwięcej uprawnień w tokenie bieżącego wątku
- `getsystem`: Otwiera uchwyt do winlogon i duplikuje token, skutecznie eskalując uprawnienia do poziomu SYSTEM
- `make_token`: Tworzy nową sesję logowania i przypisuje ją agentowi, umożliwiając podszywanie się pod innego użytkownika
- `steal_token`: Kradnie token podstawowy z innego procesu, umożliwiając agentowi podszywanie się pod użytkownika tego procesu
- `pth`: Atak Pass-the-Hash, który pozwala agentowi uwierzytelnić się jako użytkownik przy użyciu jego hasha NTLM bez konieczności posiadania hasła w postaci jawnego tekstu
- `mimikatz`: Uruchamia komendy Mimikatz w celu wyodrębnienia danych uwierzytelniających, hashy i innych poufnych informacji z pamięci lub bazy danych SAM
- `rev2self`: Przywraca agentowi jego token podstawowy, skutecznie obniżając uprawnienia do pierwotnego poziomu
- `ppid`: Zmienia proces nadrzędny dla zadań post-exploitation, wskazując nowy identyfikator procesu nadrzędnego, co umożliwia lepszą kontrolę nad kontekstem wykonywania zadań
- `printspoofer`: Wykonuje komendy PrintSpoofer, aby ominąć zabezpieczenia print spoolera i umożliwić eskalację uprawnień lub wykonanie kodu
- `dcsync`: Synchronizuje klucze Kerberos użytkownika z lokalną maszyną, umożliwiając łamanie haseł offline lub dalsze ataki
- `ticket_cache_add`: Dodaje ticket Kerberos do bieżącej lub wskazanej sesji logowania, umożliwiając ponowne użycie ticketu lub podszywanie się pod użytkownika

### Wykonywanie procesów

- `assembly_inject`: Umożliwia wstrzyknięcie loadera .NET assembly do zdalnego procesu
- `blockdlls`: Blokuje ładowanie niepodpisanych przez Microsoft bibliotek DLL do zadań post-exploitation
- `execute_assembly`: Wykonuje .NET assembly w kontekście agenta
- `execute_coff`: Wykonuje plik COFF w pamięci, umożliwiając wykonywanie skompilowanego kodu w pamięci
- `execute_pe`: Wykonuje niezarządzany plik wykonywalny (PE)
- `keylog_inject`: Wstrzykuje keylogger do innego procesu i przesyła naciśnięcia klawiszy do widoku keylog w Mythic
- `screenshot` / `screenshot_inject`: Przechwytuje bieżący pulpit bezpośrednio lub
  przez wstrzyknięcie assembly do wykonywania zrzutów ekranu do procesu/sesji docelowej
- `get_injection_techniques`: Wyświetla dostępne techniki injection oraz aktualnie wybraną technikę
- `inline_assembly`: Wykonuje .NET assembly w tymczasowej AppDomain, umożliwiając tymczasowe wykonanie kodu bez wpływu na główny proces agenta
- `register_assembly`: Rejestruje .NET assembly do późniejszego wykonania
- `register_file`: Rejestruje plik w cache agenta do późniejszego użycia przez `execute_*` lub tasking PowerShell
- `run`: Wykonuje plik binarny w systemie docelowym, używając systemowego PATH do znalezienia pliku wykonywalnego
- `set_injection_technique`: Zmienia primitive injection używany przez zadania post-exploitation
- `shinject`: Wstrzykuje shellcode do zdalnego procesu, umożliwiając wykonywanie dowolnego kodu w pamięci
- `inject`: Wstrzykuje shellcode agenta do zdalnego procesu, umożliwiając wykonywanie kodu agenta w pamięci
- `spawn`: Uruchamia nową sesję agenta w określonym pliku wykonywalnym, umożliwiając wykonanie shellcode w nowym procesie
- `spawnto_x64` i `spawnto_x86`: Zmienia domyślny plik binarny używany przez zadania post-exploitation na wskazaną ścieżkę zamiast używania `rundll32.exe` bez parametrów, co jest bardzo głośne.

### Mythic Forge

Umożliwia **ładowanie plików COFF/BOF** z Mythic Forge, repozytorium wstępnie skompilowanych payloadów i narzędzi, które można wykonywać w systemie docelowym. Dzięki wszystkim komendom, które można załadować, możliwe będzie wykonywanie typowych działań w bieżącym procesie agenta jako BOF (zwykle z lepszym OPSEC niż przy uruchamianiu osobnego procesu).

Rozpocznij instalację za pomocą:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Następnie użyj `forge_collections`, aby wyświetlić moduły COFF/BOF z Mythic Forge i móc wybrać je oraz załadować do pamięci agenta w celu wykonania. Domyślnie w Apollo dodane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu modułu pojawi się on na liście jako kolejne polecenie, np. `forge_bof_sa-whoami` lub `forge_bof_sa-netuser`.

W przypadku BOF pamiętaj, że Forge **nie** przekazuje Apollo jednego płaskiego ciągu argumentów.
Mapuje parametry BOF na format typed-array Mythic, a następnie przekazuje je do przepływu `execute_coff` w Apollo. Jeśli BOF załadowany z Forge działa dziwnie, sprawdź oczekiwane typy argumentów BOF i punkt wejścia, a nie tylko wpisany wiersz poleceń. Pamiętaj też, że nowszy loader BOF w Apollo zmienił obsługę argumentów w porównaniu ze znacznie starszymi kompilacjami z epoki 2.3.1, więc przestarzałe BOF lub stare kolekcje mogą nie działać wyłącznie z powodu zmiany oczekiwań dotyczących marshalingu.

### Wykonywanie PowerShell i skryptów

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do pamięci podręcznej agenta, aby można go było później wykonać
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skryptowanie i automatyzację
- `powerpick`: Wstrzykuje zestaw loadera PowerShell do procesu ofiarnego i wykonuje polecenie PowerShell (bez logowania PowerShell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając ukierunkowane uruchamianie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie powłoki w kontekście agenta, podobnie jak uruchomienie polecenia w cmd.exe

### Ruch lateralny

- `jump_psexec`: Używa techniki PsExec do przeniesienia się lateralnie na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go uruchamiając.
- `jump_wmi`: Używa techniki WMI do przeniesienia się lateralnie na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go uruchamiając.
- `link` i `unlink`: Tworzą i zrywają połączenia P2P (na przykład przez SMB/TCP) między callbackami.
- `wmiexecute`: Wykonuje polecenie w systemie lokalnym lub określonym systemie zdalnym za pomocą WMI, z opcjonalnymi poświadczeniami do podszywania się pod użytkownika.
- `net_dclist`: Pobiera listę kontrolerów domeny dla określonej domeny, co ułatwia identyfikację potencjalnych celów ruchu lateralnego.
- `net_localgroup`: Wyświetla grupy lokalne na określonym komputerze; jeśli nie podano komputera, domyślnie używa localhost.
- `net_localgroup_member`: Pobiera członków określonej grupy lokalnej na komputerze lokalnym lub zdalnym, umożliwiając enumerację użytkowników należących do konkretnych grup.
- `net_shares`: Wyświetla udziały zdalne i ich dostępność na określonym komputerze, co ułatwia identyfikację potencjalnych celów ruchu lateralnego.
- `socks`: Włącza proxy zgodne z SOCKS 5 w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Zgodne z narzędziami takimi jak proxychains.
- `rpfwd`: Rozpoczyna nasłuchiwanie na określonym porcie na hoście docelowym i przekazuje ruch przez Mythic do zdalnego adresu IP i portu, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `listpipes`: Wyświetla wszystkie nazwane potoki w systemie lokalnym; może to być przydatne w ruchu lateralnym lub eskalacji uprawnień poprzez interakcję z mechanizmami IPC.

Informacje o niskopoziomowych podstawowych mechanizmach wykonywania WMI używanych przez `jump_wmi` lub `wmiexecute` znajdziesz w [WmiExec](lateral-movement/wmiexec.md). Więcej informacji o ogólnych schematach pivotingu znajdziesz w [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Różne polecenia
- `help`: Wyświetla szczegółowe informacje o konkretnych poleceniach lub ogólne informacje o wszystkich poleceniach dostępnych w agencie.
- `clear`: Oznacza zadania jako „wyczyszczone”, aby agenci nie mogli ich pobrać. Możesz podać `all`, aby wyczyścić wszystkie zadania, albo `task Num`, aby wyczyścić konkretne zadanie.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon to agent napisany w Golang, który kompiluje się do plików wykonywalnych dla **Linux i macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Aktualne informacje o buildach/profilach

- Obecne buildy Poseidon obsługują Linux i macOS na architekturach `x86_64` i `arm64`.
- Obsługiwane formaty wyjściowe obejmują natywne pliki wykonywalne oraz formaty bibliotek współdzielonych, takie jak `dylib` i `so`.
- Poseidon obsługuje `http`, `websocket`, `tcp` i `dynamichttp`, a obecne buildery udostępniają ustawienia wielu kanałów egress, takie jak `egress_order` i progi failover.
- Metadane obecnych możliwości Poseidon obejmują również browser scripts, integrację przeglądarki plików/procesów, interactive tasking, keylogging, zrzuty ekranu, Push C2, SOCKS, rpfwd i P2P. Dzięki temu może działać jako pełnoprawny węzeł pivot w Linux/macOS, a nie tylko prosta zdalna powłoka.
- Warto sprawdzić opcje dostępne podczas budowania, takie jak `proxy_bypass` i `garble`, gdy potrzebujesz lepszego działania w sieci lub dodatkowej obfuskacji binariów Go.
- `pty` to jedno z najbardziej przydatnych nowszych poleceń poprawiających komfort pracy w operacjach na Linux/macOS, ponieważ otwiera interaktywny PTY i może udostępnić port po stronie Mythic, umożliwiając pełniejszą interakcję z terminalem bez stosowania starszego obejścia `sleep 0` + SOCKS.
- Obecna dokumentacja Poseidon jest szczególnie interesująca w kontekście tradecraftu ukierunkowanego na macOS: `jxa` wykonuje JavaScript for Automation w pamięci, `screencapture` przechwytuje pulpit zalogowanego użytkownika, `clipboard_monitor` przesyła zmiany w pasteboardzie, `execute_library` ładuje lokalny dylib i wywołuje jego funkcję, a `libinject` wymusza załadowanie dylib z dysku przez zdalny proces.
- W przypadku długo działających zadań pamiętaj, że Poseidon wykonuje działania post-exploitation w goroutines/wątkach, które kończą pracę kooperacyjnie, a nie przez wymuszone przerwanie. Dokumentacja wyraźnie zaznacza również, że obecnie nie ma wbudowanej obfuskacji agenta, więc tradecraft na poziomie builda/profilu ma większe znaczenie niż w przypadku komercyjnych implantów z zaawansowaną obfuskacją.

Aby poznać tradecraft specyficzny dla macOS, związany z operacjami opartymi na Mythic, nadużywaniem JAMF lub pomysłami na MDM jako C2, sprawdź [Red teaming macOS](../macos-hardening/macos-red-teaming/README.md).

W przypadku użycia w Linux lub macOS dostępnych jest kilka interesujących poleceń:

### Typowe działania

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący katalog roboczy
- `chmod`: Zmienia uprawnienia pliku
- `config`: Wyświetla bieżącą konfigurację i informacje o hoście
- `cp`: Kopiuje plik z jednej lokalizacji do drugiej
- `curl`: Wykonuje pojedyncze żądanie sieciowe z opcjonalnymi nagłówkami i metodą
- `upload`: Przesyła plik na cel
- `download`: Pobiera plik z systemu docelowego na maszynę lokalną
- I wiele innych

### Wyszukiwanie poufnych informacji

- `triagedirectory`: Wyszukuje interesujące pliki w katalogu na hoście, takie jak pliki poufne lub dane uwierzytelniające.
- `getenv`: Pobiera wszystkie bieżące zmienne środowiskowe.

### Tradecraft specyficzny dla macOS

- `jxa`: Wykonuje JavaScript for Automation w pamięci za pośrednictwem `OSAScript`, co
  jest przydatne przy natywnym post-exploitation na macOS bez zapisywania osobnych
  plików skryptów.
- `clipboard_monitor`: Odpytuje pasteboard i przekazuje zmiany do Mythic,
  co przydaje się w działaniach związanych z kradzieżą danych uwierzytelniających/tokenów
  wykorzystujących kopiowanie i wklejanie.
- `screencapture`: Przechwytuje pulpit użytkownika w macOS.
- `execute_library`: Ładuje dylib z dysku i wywołuje określoną eksportowaną funkcję.
- `libinject`: Wstrzykuje stub shellcode, który wymusza załadowanie dylib z dysku przez inny proces macOS.
- `persist_launchd`: Tworzy mechanizm persistence LaunchAgent / LaunchDaemon bezpośrednio z agenta.

### Ruch lateralny

- `ssh`: Łączy się z hostem przez SSH przy użyciu wskazanych danych uwierzytelniających i otwiera PTY bez uruchamiania ssh.
- `sshauth`: Łączy się z określonymi hostami przez SSH przy użyciu wskazanych danych uwierzytelniających. Można też użyć tego polecenia do wykonania określonego polecenia na zdalnych hostach przez SSH lub do kopiowania plików za pomocą SCP.
- `link_tcp`: Łączy się z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Łączy się z agentem przy użyciu profilu P2P webshell, umożliwiając zdalny dostęp do interfejsu webowego agenta.
- `rpfwd`: Uruchamia lub zatrzymuje Reverse Port Forward, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `socks`: Uruchamia lub zatrzymuje proxy SOCKS5 w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Jest kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuje hosty w poszukiwaniu otwartych portów, co pomaga identyfikować potencjalne cele ruchu lateralnego lub dalszych ataków.

### Wykonywanie procesów

- `shell`: Wykonuje pojedyncze polecenie powłoki za pośrednictwem /bin/sh, umożliwiając bezpośrednie wykonywanie poleceń w systemie docelowym.
- `run`: Uruchamia polecenie z dysku z argumentami, umożliwiając wykonywanie binariów lub skryptów w systemie docelowym.
- `pty`: Otwiera interaktywny PTY, umożliwiając bezpośrednią interakcję z powłoką w systemie docelowym.

## References

- [1] [Macierz funkcji agentów społeczności Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Plik README Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Najważniejsze zmiany w Mythic v3.2: Interactive Tasking, Push C2 i dynamiczna przeglądarka plików](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts — dokumentacja Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Aktualizacje Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformacja operacji Red Team dzięki ukrytym skarbom Mythic: skrypty przeglądarki](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: reguły YARA Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Od forka do frameworka: czego nauczyła nas modyfikacja Apollo o inwazji agentów](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
