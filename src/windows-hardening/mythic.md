# Mythic

{{#include ../banners/hacktricks-training.md}}

## Czym jest Mythic?

Mythic to open-source'owy, modułowy i kolaboracyjny framework command and control (C2) przeznaczony do red teamingu. Umożliwia operatorom zarządzanie agentami (payloads) i wdrażanie ich w różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic udostępnia interfejs przeglądarkowy do taskingu wielu operatorów, obsługi plików, zarządzania SOCKS/rpfwd oraz generowania payloadów.

W przeciwieństwie do monolitycznych frameworków, samo repozytorium Mythic **nie** zawiera typów payloadów ani profili C2. Agenty, wrappery i profile C2 są zazwyczaj instalowane jako komponenty zewnętrzne i mogą być aktualizowane niezależnie od Mythic core.

### Instalacja

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami w oficjalnym **[repozytorium Mythic](https://github.com/its-a-feature/Mythic)**. Typowy bootstrap wykonywany z katalogu Mythic wygląda następująco:
```bash
sudo make
sudo ./mythic-cli start
```
Jeśli Mythic już działa, zwykle możesz dodać nowego agenta lub profil za pomocą `./mythic-cli install github ...`, a następnie ponownie uruchomić Mythic albo po prostu uruchomić nowy komponent bezpośrednio.

### Agenci

Mythic obsługuje wielu agentów, czyli **payloady wykonujące zadania na zaatakowanych systemach**. Każdy agent może być dostosowany do konkretnych potrzeb i działać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agentów. Agenci open source rozwijani przez społeczność znajdują się w [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) umożliwia szybkie sprawdzenie obsługiwanych systemów operacyjnych, formatów payloadów, wrapperów i profili C2.<sup>[[1]](#references)</sup>

Aby zainstalować agenta z tej organizacji, możesz wykonać:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` jest przydatna podczas instalowania z środowiska innego niż root. Możesz dodawać nowe agents za pomocą poprzedniego polecenia, nawet jeśli Mythic jest już uruchomiony.

### C2 Profiles

C2 profiles w Mythic definiują **sposób komunikacji agents z serwerem Mythic**. Określają protokół komunikacji, metody szyfrowania i inne ustawienia. Możesz tworzyć i zarządzać C2 profiles za pośrednictwem interfejsu webowego Mythic.

Domyślnie Mythic jest instalowany bez profiles, jednak niektóre profiles można pobrać z repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), uruchamiając:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Aktualne profile istotne dla operatora, o których należy pamiętać:

- [`http`](https://github.com/MythicC2Profiles/http): podstawowy asynchroniczny ruch GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): bardziej elastyczny ruch HTTP z wieloma domenami callback, przełączaniem awaryjnym/rotacją round-robin, niestandardowymi nagłówkami/parametrami zapytań oraz transformacjami wiadomości (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) umieszczanymi w cookies, nagłówkach, parametrach zapytań lub body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): kształtowanie wiadomości HTTP sterowane przez JSON/TOML, gdy statyczny profile `http` jest zbyt rozpoznawalny.

### Aktualne informacje dotyczące platformy

- Wiele publicznych agentów i profili jest obecnie instalowanych przy użyciu wcześniej zbudowanych zdalnych obrazów kontenerów.
Jeśli wykonasz fork komponentu lub wprowadzisz lokalną poprawkę, a Mythic nadal będzie używać starego
zachowania, sprawdź wygenerowane wpisy `.env` dla `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; włączenie
`*_USE_BUILD_CONTEXT="true"` zwykle powoduje, że Mythic przebuduje komponent z użyciem lokalnego
kontekstu Docker zamiast po cichu ponownie użyć zdalnego obrazu.
- Browser scripts to jedna z najbardziej wartościowych funkcji poprawiających wygodę pracy operatorów w Mythic:
mogą przekształcać surowy output poleceń w tabele, przeglądarki screenshotów, linki do pobierania, linki wyszukiwania oraz przyciski, które bezpośrednio z UI wysyłają kolejne tasking. Obecne buildy Mythic pozwalają każdemu operatorowi zachować własne skrypty, włączać je globalnie lub per-task, a najlepsze rezultaty uzyskuje się, gdy agenci zwracają ustrukturyzowany JSON zamiast plaintext. Jest to szczególnie przydatne w powtarzalnych workflow związanych z `ls`, `ps`, triage i przeglądarką plików.<sup>[[4]](#references)[[6]](#references)</sup>
- Nowsze buildy Mythic obsługują również interactive tasking i wzorce Push C2,
które ograniczają potrzebę stosowania pollingu `sleep 0` podczas operacji intensywnie wykorzystujących PTY/SOCKS/rpfwd. Gdy agent/profile to obsługuje, rozwiązanie to zwykle generuje mniejsze obciążenie niż nieustanne odpytywanie serwera tylko po to, aby utrzymać działający kanał interaktywny.<sup>[[3]](#references)</sup>
- Obecne buildy Mythic z ery 3.4 są bardziej świadome kontekstu, niż sugerują starsze opracowania:
parametry buildów mogą być teraz grupowane lub ukrywane na podstawie wybranego systemu operacyjnego
albo innych opcji builda, typy payloadów mogą deklarować, czy obsługują
wiele profili C2 lub wiele instancji tego samego C2 w jednym buildzie,
a odchylenia parametrów C2 pozwalają agentowi ukrywać pola, których faktycznie
nie implementuje. Ma to znaczenie, gdy przełączasz się między `http`, `httpx`, `smb`,
`tcp` i `websocket`, ponieważ bezpieczny/prawidłowy zakres opcji builda nie jest już
płaskim, statycznym formularzem.<sup>[[5]](#references)</sup>
- Jeśli tworzysz niestandardową parę agent/profile i nie chcesz, aby format wiadomości JSON Mythic ani domyślne szyfrowanie były przesyłane przez sieć, użyj
`translation_container`: Mythic usuwa UUID, przekazuje zaszyfrowany blob i materiały kluczowe do translatora przez gRPC, a następnie oczekuje bajtów właściwych dla agenta. Jest to właściwy sposób obsługi protokołów binarnych, niestandardowego framingu lub szyfrowania po stronie agenta bez przepisywania całego serwera.
- Pamiętaj, że callbacki linked/P2P nie służą wyłącznie do przekazywania tasking. Przepływ
`get_tasking` może również przenosić responses oraz dane `delegates`,
`socks`, `rpfwd` i `interactive`. W praktyce jeden callback egress może obsługiwać wewnętrzne callbacki i kanały pivotowania w tej samej pętli pollingu; jeśli agenty potomne wykonują własne okresowe check-in, `get_delegate_tasks=false` zapobiega przypadkowemu pobieraniu przez rodzica zadań oczekujących w kolejce wewnętrznego callbacku.

### Wrapper payloads

Wrapper payloads pozwalają zachować tę samą logikę agenta, zmieniając jednocześnie reprezentację na dysku, która jest dostarczana lub utrwalana.

- `service_wrapper`: przekształca inny payload w plik wykonywalny usługi Windows, co jest przydatne, gdy ścieżka wykonania wymaga prawidłowego service binary.
- `scarecrow_wrapper`: opakowuje kompatybilny shellcode loaderem ScareCrow, aby generować outputy oparte na loaderze, takie jak EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo to agent Windows napisany w C# z użyciem .NET Framework 4.0, przeznaczony do wykorzystania w ofertach szkoleniowych SpecterOps.<sup>[[2]](#references)</sup>

Zainstaluj go za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Bieżące uwagi dotyczące buildów/profili

- Apollo może obecnie generować payloady `WinExe`, `Shellcode`, `Service` i `Source`.
- Często używane profile Apollo to `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` jest zwykle bardziej elastyczną opcją, gdy potrzebujesz rotacji domen, obsługi proxy, niestandardowego umieszczania wiadomości i transformacji wiadomości, zamiast starszego statycznego profilu `http`.
- Apollo jest jednym z bardziej kompletnych community agents i obecnie udostępnia integracje po stronie Mythic, takie jak browser scripts, widoki file/process browser, screenshots, keylogging, SOCKS, rpfwd, Push C2 i routing P2P.
- Apollo obsługuje wrapper payloads, takie jak `service_wrapper` i `scarecrow_wrapper`.
- Apollo obsługuje dynamiczne ładowanie commands, dzięki czemu możesz utrzymać początkowy payload w niewielkim rozmiarze i później ładować dodatkowe commands lub moduły Forge, zamiast kompilować każdą funkcję post-exploitation do pierwszego builda.
- Podczas generowania outputu shellcode bieżący builder Apollo udostępnia również opcje formatu Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) oraz zachowanie Donut bypass (`None`, `Abort on fail`, `Continue on fail`). Jest to przydatne, jeśli końcowym celem jest ponowne opakowanie shellcode za pomocą `service_wrapper`, `scarecrow_wrapper` lub custom loadera.
- `register_file` i `register_assembly` to staging primitives dla `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. W bieżących buildach Apollo te staged artifacts są buforowane po stronie klienta jako chronione przez DPAPI bloby AES256.
- Wyniki `ls` i `ps` szczególnie dobrze integrują się z browser scripts oraz file/process browser Mythic, co wyraźnie przyspiesza triage operatora podczas collaborative operations.
- Zadania fork-and-run dziedziczą ustawienia sacrificial process z
`spawnto_x86` / `spawnto_x64`, wybór procesu nadrzędnego z `ppid`, a następnie
używają aktualnie wybranego injection primitive. W praktyce oznacza to, że
dostrajanie OPSEC dla jednego command często wpływa jednocześnie na
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i
`spawn`.
- Obecnie udokumentowane injection backends Apollo obejmują
`CreateRemoteThread`, `QueueUserAPC` (w stylu early-bird) oraz
`NtCreateThreadEx` za pośrednictwem syscalls. Użyj `get_injection_techniques`
przed głośnym post-exploitation oraz `set_injection_technique`, jeśli musisz
zmienić primitive, który koliduje z celem lub command, który chcesz uruchomić.
- `blockdlls` wpływa wyłącznie na sacrificial processes tworzonych dla zadań
post-exploitation. W połączeniu z mniej podejrzanym celem `spawnto_x64` niż
domyślne, pozbawione parametrów `rundll32.exe`, jest to jedna z
najprostszych zmian po stronie Apollo, które można wprowadzić przed
uruchamianiem zadań intensywnie wykorzystujących assembly/PowerShell.

Ten agent ma wiele commands, dzięki czemu jest bardzo podobny do Beacon z Cobalt Strike, ale oferuje dodatkowe funkcje. Obsługuje między innymi:

### Common actions

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący katalog roboczy
- `cp`: Kopiuje plik z jednej lokalizacji do innej
- `ls`: Wyświetla pliki i katalogi w bieżącym katalogu lub podanej ścieżce
- `ifconfig`: Pobiera informacje o adapterach i interfejsach sieciowych
- `netstat`: Pobiera informacje o połączeniach TCP i UDP
- `pwd`: Wyświetla bieżący katalog roboczy
- `ps`: Wyświetla uruchomione procesy w systemie docelowym (z dodatkowymi informacjami)
- `jobs`: Wyświetla wszystkie uruchomione jobs powiązane z długotrwałym taskingiem
- `download`: Pobiera plik z systemu docelowego na lokalną maszynę
- `upload`: Przesyła plik z lokalnej maszyny do systemu docelowego
- `reg_query`: Odczytuje keys i values rejestru w systemie docelowym
- `reg_write_value`: Zapisuje nową value do określonego key rejestru
- `sleep`: Zmienia interwał sleep agenta, określający częstotliwość komunikowania się z serwerem Mythic
- Oraz wiele innych — użyj `help`, aby wyświetlić pełną listę dostępnych commands.

### Privilege escalation

- `getprivs`: Włącza maksymalną możliwą liczbę privileges w tokenie bieżącego threada
- `getsystem`: Otwiera handle do winlogon i duplikuje token, skutecznie podnosząc privileges do poziomu SYSTEM
- `make_token`: Tworzy nową logon session i stosuje ją do agenta, umożliwiając impersonation innego użytkownika
- `steal_token`: Kradnie primary token z innego procesu, umożliwiając agentowi impersonation użytkownika tego procesu
- `pth`: Atak Pass-the-Hash, umożliwiający agentowi uwierzytelnienie jako użytkownik przy użyciu jego hash NTLM bez znajomości hasła w postaci jawnego tekstu
- `mimikatz`: Uruchamia commands Mimikatz w celu wyodrębnienia credentials, hashes i innych wrażliwych informacji z pamięci lub bazy SAM
- `rev2self`: Przywraca token agenta do jego primary token, skutecznie obniżając privileges do pierwotnego poziomu
- `ppid`: Zmienia proces nadrzędny dla zadań post-exploitation przez podanie nowego process ID, umożliwiając lepszą kontrolę nad kontekstem wykonywania zadań
- `printspoofer`: Wykonuje commands PrintSpoofer w celu obejścia zabezpieczeń print spoolera, umożliwiając privilege escalation lub code execution
- `dcsync`: Synchronizuje Kerberos keys użytkownika z lokalną maszyną, umożliwiając offline password cracking lub dalsze attacks
- `ticket_cache_add`: Dodaje Kerberos ticket do bieżącej lub określonej logon session, umożliwiając ponowne użycie ticketu lub impersonation

### Process execution

- `assembly_inject`: Umożliwia wstrzyknięcie .NET assembly loadera do zdalnego procesu
- `blockdlls`: Blokuje ładowanie DLL niepodpisanych przez Microsoft do jobs post-exploitation
- `execute_assembly`: Wykonuje .NET assembly w kontekście agenta
- `execute_coff`: Wykonuje plik COFF w pamięci, umożliwiając in-memory execution skompilowanego kodu
- `execute_pe`: Wykonuje unmanaged executable (PE)
- `keylog_inject`: Wstrzykuje keylogger do innego procesu i przesyła keystrokes do widoku keylog w Mythic
- `screenshot` / `screenshot_inject`: Przechwytuje bieżący pulpit bezpośrednio lub
przez wstrzyknięcie screenshot assembly do docelowego procesu/session
- `get_injection_techniques`: Wyświetla dostępne injection techniques oraz aktualnie wybraną technikę
- `inline_assembly`: Wykonuje .NET assembly w disposable AppDomain, umożliwiając tymczasowe wykonywanie kodu bez wpływu na główny proces agenta
- `register_assembly`: Rejestruje .NET assembly do późniejszego wykonania
- `register_file`: Rejestruje plik w cache agenta na potrzeby późniejszych zadań `execute_*` lub PowerShell
- `run`: Wykonuje binary w systemie docelowym, używając systemowego `PATH` do znalezienia executable
- `set_injection_technique`: Zmienia injection primitive używany przez jobs post-exploitation
- `shinject`: Wstrzykuje shellcode do zdalnego procesu, umożliwiając in-memory execution dowolnego kodu
- `inject`: Wstrzykuje shellcode agenta do zdalnego procesu, umożliwiając in-memory execution kodu agenta
- `spawn`: Uruchamia nową agent session w określonym executable, umożliwiając wykonanie shellcode w nowym procesie
- `spawnto_x64` i `spawnto_x86`: Zmieniają domyślny binary używany przez jobs post-exploitation na określoną ścieżkę zamiast `rundll32.exe` bez parametrów, które jest bardzo głośne.

### Mythic Forge

Umożliwia **ładowanie plików COFF/BOF** z Mythic Forge, czyli repozytorium pre-compiled payloads i tools, które można wykonywać w systemie docelowym. Dzięki wszystkim commands, które można załadować, możliwe jest wykonywanie typowych działań w bieżącym procesie agenta jako BOFs (zwykle z lepszym OPSEC niż podczas uruchamiania oddzielnego procesu).

Rozpocznij ich instalację za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Następnie użyj `forge_collections`, aby wyświetlić moduły COFF/BOF z Mythic Forge, a następnie wybrać je i załadować do pamięci agenta w celu wykonania. Domyślnie w Apollo dodawane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu modułu pojawi się on na liście jako kolejne polecenie, takie jak `forge_bof_sa-whoami` lub `forge_bof_sa-netuser`.

W przypadku BOF pamiętaj, że Forge **nie** przekazuje do Apollo pojedynczego, płaskiego ciągu argumentów. Mapuje parametry BOF na format tablicy typów Mythic, a następnie przekazuje je do przepływu `execute_coff` w Apollo. Jeśli BOF załadowany przez Forge zachowuje się nietypowo, sprawdź oczekiwane typy argumentów BOF oraz entrypoint, a nie tylko wpisany wiersz poleceń. Pamiętaj również, że nowszy loader BOF w Apollo zmienił obsługę argumentów w porównaniu ze znacznie starszymi buildami z ery 2.3.1, więc nieaktualne BOF lub stare kolekcje mogą kończyć się niepowodzeniem wyłącznie z powodu zmiany oczekiwań dotyczących marshalingu.

### Wykonywanie PowerShell i skryptów

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do cache agenta w celu późniejszego wykonania
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skryptowanie i automatyzację
- `powerpick`: Wstrzykuje assembly loadera PowerShell do procesu ofiarnego i wykonuje polecenie PowerShell (bez logowania PowerShell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając ukierunkowane wykonywanie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie powłoki w kontekście agenta, podobnie jak uruchomienie polecenia w cmd.exe

### Ruch boczny

- `jump_psexec`: Wykorzystuje technikę PsExec do wykonania ruchu bocznego na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go uruchamiając.
- `jump_wmi`: Wykorzystuje technikę WMI do wykonania ruchu bocznego na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go uruchamiając.
- `link` i `unlink`: Tworzą i usuwają połączenia P2P (na przykład przez SMB/TCP) między callbackami.
- `wmiexecute`: Wykonuje polecenie w lokalnym lub określonym zdalnym systemie za pomocą WMI, opcjonalnie używając poświadczeń do impersonacji.
- `net_dclist`: Pobiera listę kontrolerów domeny dla określonej domeny, co jest przydatne do identyfikowania potencjalnych celów ruchu bocznego.
- `net_localgroup`: Wyświetla lokalne grupy na określonym komputerze, domyślnie używając localhost, jeśli nie podano komputera.
- `net_localgroup_member`: Pobiera członkostwo w lokalnej grupie dla określonej grupy na komputerze lokalnym lub zdalnym, umożliwiając enumerację użytkowników należących do określonych grup.
- `net_shares`: Wyświetla zdalne udziały i informacje o ich dostępności na określonym komputerze, co jest przydatne do identyfikowania potencjalnych celów ruchu bocznego.
- `socks`: Włącza zgodny z SOCKS 5 proxy w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Kompatybilne z narzędziami takimi jak proxychains.
- `rpfwd`: Rozpoczyna nasłuchiwanie na określonym porcie na hoście docelowym i przekazuje ruch przez Mythic do zdalnego adresu IP i portu, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `listpipes`: Wyświetla wszystkie nazwane potoki w systemie lokalnym, co może być przydatne w ruchu bocznym lub eskalacji uprawnień poprzez interakcję z mechanizmami IPC.

Informacje o niskopoziomowych prymitywach wykonywania WMI używanych przez `jump_wmi` lub `wmiexecute` znajdziesz w [WmiExec](lateral-movement/wmiexec.md). Szersze informacje o wzorcach pivotingu znajdziesz w [Tunelowaniu i przekierowywaniu portów](../generic-hacking/tunneling-and-port-forwarding.md).

### Różne polecenia
- `help`: Wyświetla szczegółowe informacje o określonych poleceniach lub ogólne informacje o wszystkich dostępnych poleceniach agenta.
- `clear`: Oznacza zadania jako „wyczyszczone”, aby agenci nie mogli ich pobrać. Możesz określić `all`, aby wyczyścić wszystkie zadania, lub `task Num`, aby wyczyścić konkretne zadanie.


## [Agent Poseidon](https://github.com/MythicAgents/poseidon)

Poseidon to agent napisany w języku Golang, który kompiluje się do plików wykonywalnych dla **Linux i macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Bieżące uwagi dotyczące buildów/profili

- Bieżące buildy Poseidon są przeznaczone dla systemów Linux i macOS na platformach `x86_64` oraz `arm64`.
- Obsługiwane formaty wyjściowe obejmują natywne pliki wykonywalne oraz formaty bibliotek współdzielonych, takie jak `dylib` i `so`.
- Poseidon obsługuje `http`, `websocket`, `tcp` i `dynamichttp`, a bieżące buildery udostępniają ustawienia multi-egress, takie jak `egress_order` i progi failover.
- Bieżące metadane możliwości Poseidon obejmują również browser scripts, integrację z file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd i P2P, dzięki czemu może działać jako rzeczywisty węzeł pivot dla Linux/macOS, a nie tylko jako prosty remote shell.
- Opcje build-time, takie jak `proxy_bypass` i `garble`, warto sprawdzić, gdy potrzebujesz czystszego zachowania sieciowego lub dodatkowej obfuskacji binarki Go.
- `pty` to jedno z najbardziej przydatnych nowszych usprawnień jakości życia podczas operacji na Linux/macOS, ponieważ otwiera interaktywny PTY i może udostępnić port po stronie Mythic dla pełniejszej interakcji z terminalem bez korzystania ze starszego obejścia `sleep 0` + SOCKS.
- Bieżąca dokumentacja Poseidon jest szczególnie interesująca w kontekście tradecraft skoncentrowanego na macOS: `jxa` wykonuje JavaScript for Automation w pamięci, `screencapture` przechwytuje pulpit zalogowanego użytkownika, `clipboard_monitor` przesyła zmiany pasteboard, `execute_library` ładuje lokalny dylib i wywołuje jego funkcję, a `libinject` wymusza załadowanie dylib z dysku przez zdalny proces.
- W przypadku długotrwałych zadań pamiętaj, że Poseidon wykonuje działania post-exploitation w goroutines/threads, które są kooperacyjne, a nie możliwe do twardego zakończenia. Dokumentacja wyraźnie zaznacza również, że obecnie nie ma wbudowanej obfuskacji agenta, dlatego tradecraft na poziomie build/profile ma większe znaczenie niż w przypadku silnie obfuskowanych implantów komercyjnych.

W przypadku tradecraft specyficznego dla macOS, dotyczącego operacji opartych na Mythic, nadużywania JAMF lub koncepcji MDM-as-C2, sprawdź [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Podczas użycia w systemie Linux lub macOS udostępnia kilka interesujących commands:

### Typowe działania

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący katalog roboczy
- `chmod`: Zmienia uprawnienia pliku
- `config`: Wyświetla bieżącą konfigurację i informacje o hoście
- `cp`: Kopiuje plik z jednej lokalizacji do innej
- `curl`: Wykonuje pojedyncze żądanie webowe z opcjonalnymi nagłówkami i metodą
- `upload`: Przesyła plik do celu
- `download`: Pobiera plik z systemu docelowego na maszynę lokalną
- I wiele innych

### Wyszukiwanie poufnych informacji

- `triagedirectory`: Wyszukuje interesujące pliki w katalogu na hoście, takie jak poufne pliki lub credentials.
- `getenv`: Pobiera wszystkie bieżące zmienne środowiskowe.

### Tradecraft specyficzny dla macOS

- `jxa`: Wykonuje JavaScript for Automation w pamięci za pośrednictwem `OSAScript`, co jest przydatne podczas native macOS post-exploitation bez upuszczania oddzielnych plików skryptów.
- `clipboard_monitor`: Odpytuje pasteboard i zgłasza zmiany do Mythic, co jest przydatne w workflow kradzieży credentials/tokenów opartych na kopiowaniu i wklejaniu.
- `screencapture`: Przechwytuje pulpit użytkownika w systemie macOS.
- `execute_library`: Ładuje dylib z dysku i wywołuje określoną wyeksportowaną funkcję.
- `libinject`: Wstrzykuje stub shellcode, który wymusza załadowanie dylib z dysku przez inny proces macOS.
- `persist_launchd`: Tworzy persistence LaunchAgent / LaunchDaemon bezpośrednio z agenta.

### Ruch boczny

- `ssh`: Łączy się przez SSH z hostem przy użyciu wyznaczonych credentials i otwiera PTY bez uruchamiania ssh.
- `sshauth`: Łączy się przez SSH z określonymi hostami przy użyciu wyznaczonych credentials. Można go również użyć do wykonania określonego polecenia na zdalnych hostach przez SSH lub do kopiowania plików za pomocą SCP.
- `link_tcp`: Łączy się z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Łączy się z agentem przy użyciu profilu webshell P2P, umożliwiając zdalny dostęp do web interface agenta.
- `rpfwd`: Uruchamia lub zatrzymuje Reverse Port Forward, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `socks`: Uruchamia lub zatrzymuje proxy SOCKS5 w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuje hosty pod kątem otwartych portów, co jest przydatne do identyfikowania potencjalnych celów ruchu bocznego lub dalszych ataków.

### Wykonywanie procesów

- `shell`: Wykonuje pojedyncze polecenie shell za pośrednictwem /bin/sh, umożliwiając bezpośrednie wykonywanie poleceń w systemie docelowym.
- `run`: Wykonuje polecenie z dysku wraz z argumentami, umożliwiając wykonywanie binariów lub skryptów w systemie docelowym.
- `pty`: Otwiera interaktywny PTY, umożliwiając bezpośrednią interakcję z shellem w systemie docelowym.

## Odnośniki

- [1] [Macierz funkcji agentów społeczności Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - dokumentacja Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Aktualizacje Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
