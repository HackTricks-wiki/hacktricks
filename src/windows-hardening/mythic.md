# Mythic

{{#include ../banners/hacktricks-training.md}}

## Czym jest Mythic?

Mythic to open-source'owy, modułowy i umożliwiający współpracę framework command and control (C2) przeznaczony do red teamingu. Umożliwia operatorom zarządzanie agentami (payloadami) i wdrażanie ich w różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic udostępnia interfejs przeglądarkowy do taskingu wielu operatorów, obsługi plików, zarządzania SOCKS/rpfwd oraz generowania payloadów.

W przeciwieństwie do monolitycznych frameworków samo repozytorium Mythic **nie zawiera** typów payloadów ani profili C2. Agenty, wrappery i profile C2 są zwykle instalowane jako komponenty zewnętrzne i mogą być aktualizowane niezależnie od core Mythic.

### Instalacja

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami w oficjalnym **[repozytorium Mythic](https://github.com/its-a-feature/Mythic)**. Typowa procedura bootstrap z katalogu Mythic wygląda następująco:
```bash
sudo make
sudo ./mythic-cli start
```
Jeśli Mythic już działa, zazwyczaj możesz dodać nowego agenta lub profil za pomocą `./mythic-cli install github ...`, a następnie ponownie uruchomić Mythic albo po prostu uruchomić bezpośrednio nowy komponent.

### Agenci

Mythic obsługuje wielu agentów, czyli **payloady wykonujące zadania na zaatakowanych systemach**. Każdego agenta można dostosować do konkretnych potrzeb i może on działać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agentów. Agenci społeczności open source znajdują się w organizacji [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**macierz funkcji społeczności**](https://mythicmeta.github.io/overview/agent_matrix.html) jest przydatna do szybkiego sprawdzania obsługiwanych systemów operacyjnych, formatów payloadów, wrapperów i profili C2.

Aby zainstalować agenta z tej organizacji, uruchom:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` jest przydatna podczas instalowania z non-root environment. Możesz dodawać nowe agents za pomocą poprzedniego polecenia, nawet jeśli Mythic jest już uruchomiony.

### C2 Profiles

C2 profiles w Mythic definiują **sposób komunikacji agents z serwerem Mythic**. Określają protokół komunikacyjny, metody szyfrowania i inne ustawienia. Możesz tworzyć i zarządzać C2 profiles za pośrednictwem web interface Mythic.

Domyślnie Mythic jest instalowany bez profiles, jednak możliwe jest pobranie niektórych profiles z repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), uruchamiając:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Aktualne profile istotne dla operatora, o których należy pamiętać:

- [`http`](https://github.com/MythicC2Profiles/http): podstawowy asynchroniczny ruch GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): bardziej elastyczny ruch HTTP z wieloma domenami callback, przełączaniem awaryjnym/rotacją round-robin, niestandardowymi nagłówkami/parametrami zapytań oraz transformacjami wiadomości (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) umieszczanymi w cookies, nagłówkach, parametrach zapytań lub body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): kształtowanie wiadomości HTTP sterowane przez JSON/TOML, gdy statyczny profil `http` jest zbyt rozpoznawalny.

### Aktualne informacje dotyczące platformy

- Wiele publicznych agentów i profili instaluje się obecnie przy użyciu gotowych zdalnych obrazów kontenerów.
Jeśli wykonasz fork komponentu lub wprowadzisz lokalną poprawkę, a Mythic nadal będzie używał starego
zachowania, sprawdź wygenerowane wpisy `.env` dla `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` i `*_USE_VOLUME`; włączenie
`*_USE_BUILD_CONTEXT="true"` zwykle powoduje, że Mythic przebuduje komponent z użyciem lokalnego
kontekstu Docker zamiast po cichu ponownie użyć zdalnego obrazu.
- Browser scripts to jedna z najbardziej wartościowych funkcji Mythic poprawiających wygodę pracy
operatorów: mogą przekształcać surowe wyniki poleceń w tabele, przeglądarki screenshotów,
linki do pobierania, linki wyszukiwania i przyciski, które bezpośrednio z UI wydają kolejne
tasking. Aktualne kompilacje Mythic pozwalają każdemu operatorowi przechowywać własne skrypty,
włączać je globalnie lub dla poszczególnych tasków, a najlepsze rezultaty uzyskuje się, gdy agenci
zwracają ustrukturyzowany JSON zamiast plaintextu. Jest to szczególnie przydatne w powtarzalnych
workflowach `ls`, `ps`, triage i przeglądania plików.
- Nowsze kompilacje Mythic obsługują również interactive tasking i wzorce Push C2,
które ograniczają potrzebę stosowania pollingu `sleep 0` podczas operacji intensywnie wykorzystujących
PTY/SOCKS/rpfwd. Gdy agent/profil to obsługuje, jest to zwykle rozwiązanie o mniejszym narzucie
niż ciągłe zasypywanie serwera check-inami tylko po to, aby utrzymać użyteczność interaktywnego
kanału.
- Aktualne buildery Mythic z ery 3.4 są bardziej świadome kontekstu, niż sugerują starsze materiały:
parametry buildów można teraz grupować lub ukrywać w zależności od wybranego systemu operacyjnego
lub innych opcji builda, typy payloadów mogą deklarować, czy obsługują wiele profili C2 lub wiele
instancji tego samego C2 w jednym buildzie, a odchylenia parametrów C2 pozwalają agentowi ukrywać
pola, których faktycznie nie implementuje. Ma to znaczenie podczas przełączania się między `http`, `httpx`, `smb`,
`tcp` i `websocket`, ponieważ bezpieczny/prawidłowy zakres opcji builda nie jest już płaskim,
statycznym formularzem.
- Jeśli tworzysz niestandardową parę agenta/profilu i nie chcesz, aby Mythic używał swojego formatu
wiadomości JSON ani domyślnego szyfrowania w transmisji, użyj `translation_container`: Mythic usuwa UUID,
przekazuje zaszyfrowany blob i materiał kluczowy do translatora przez gRPC, a następnie oczekuje
bajtów właściwych dla agenta. Jest to właściwy sposób obsługi protokołów binarnych, niestandardowego
framingu lub szyfrowania po stronie agenta bez przepisywania całego serwera.
- Pamiętaj, że callbacki linked/P2P nie służą wyłącznie do przekazywania taskingu. Przepływ Mythic
`get_tasking` może również przenosić odpowiedzi oraz dane `delegates`, `socks`,
`rpfwd` i `interactive`. W praktyce jeden callback egress może obsługiwać wewnętrzne callbacki
i kanały pivotingu w tej samej pętli pollingu; jeśli agenci potomni wykonują własne okresowe
check-iny, `get_delegate_tasks=false` zapobiega przypadkowemu pobieraniu przez rodzica zadań
oczekujących w kolejce wewnętrznego callbacka.

### Wrapper payloads

Wrapper payloads pozwalają zachować tę samą logikę agenta, zmieniając jednocześnie reprezentację
na dysku, która jest dostarczana lub utrwalana.

- `service_wrapper`: przekształca inny payload w plik wykonywalny usługi Windows, co jest przydatne,
gdy ścieżka wykonania wymaga prawidłowego pliku binarnego usługi.
- `scarecrow_wrapper`: opakowuje kompatybilny shellcode za pomocą loadera ScareCrow w celu wygenerowania
wyników obsługiwanych przez loader, takich jak EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo to agent Windows napisany w C# z użyciem .NET Framework 4.0, przeznaczony do wykorzystania
w ofertach szkoleniowych SpecterOps.

Zainstaluj go za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Bieżące informacje o buildach/profilach

- Apollo może obecnie emitować payloady `WinExe`, `Shellcode`, `Service` i `Source`.
- Często używane profile Apollo to `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` jest zwykle bardziej elastyczną opcją, gdy potrzebujesz rotacji domen, obsługi proxy, niestandardowego umieszczania wiadomości i transformacji wiadomości, zamiast starszego statycznego profilu `http`.
- Apollo jest jednym z bardziej kompletnych community agents i obecnie udostępnia integracje po stronie Mythic, takie jak browser scripts, widoki file/process browser, screenshots, keylogging, SOCKS, rpfwd, Push C2 i routing P2P.
- Apollo obsługuje wrapper payloads, takie jak `service_wrapper` i `scarecrow_wrapper`.
- Apollo obsługuje dynamic command loading, dzięki czemu możesz utrzymywać początkowy payload w niewielkim rozmiarze i później ładować dodatkowe commands lub moduły Forge, zamiast kompilować każdą funkcję post-exploitation do pierwszego builda.
- Podczas generowania outputu shellcode bieżący builder Apollo udostępnia również wybór formatów Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) oraz zachowanie Donut bypass (`None`, `Abort on fail`, `Continue on fail`). Jest to przydatne, jeśli końcowym celem jest ponowne opakowanie shellcode za pomocą `service_wrapper`, `scarecrow_wrapper` lub custom loadera.
- `register_file` i `register_assembly` to staging primitives dla `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. W bieżących buildach Apollo te staged artifacts są buforowane po stronie klienta jako bloby AES256 chronione przez DPAPI.
- Wyniki `ls` i `ps` szczególnie dobrze integrują się z browser scripts Mythic oraz file/process browser, co zauważalnie przyspiesza triage operatora podczas collaborative operations.
- Jobs fork-and-run dziedziczą ustawienia sacrificial process z
`spawnto_x86` / `spawnto_x64`, dziedziczą wybór parenta z `ppid`,
a następnie używają aktualnie wybranego injection primitive. W praktyce oznacza to,
że dostosowanie OPSEC dla jednego command często wpływa jednocześnie na
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i
`spawn`.
- Obecnie udokumentowane injection backends Apollo obejmują `CreateRemoteThread`,
`QueueUserAPC` (w stylu early-bird) oraz `NtCreateThreadEx` za pośrednictwem syscalls. Użyj
`get_injection_techniques` przed głośnym post-exploitation oraz
`set_injection_technique`, jeśli potrzebujesz zmienić primitive, który koliduje z celem lub
command, który chcesz uruchomić.
- `blockdlls` wpływa wyłącznie na sacrificial processes tworzone dla jobs post-exploitation. W połączeniu z mniej podejrzanym celem `spawnto_x64` niż domyślny
goły `rundll32.exe` jest to jedna z najprostszych zmian po stronie Apollo, które można wprowadzić
przed uruchamianiem taskingu opartego na assembly/PowerShell.

Ten agent ma wiele commands, dzięki czemu jest bardzo podobny do Beacona z Cobalt Strike, ale oferuje także dodatkowe funkcje. Obsługuje między innymi:

### Common actions

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący working directory
- `cp`: Kopiuje plik z jednej lokalizacji do innej
- `ls`: Wyświetla pliki i katalogi w bieżącym katalogu lub we wskazanej ścieżce
- `ifconfig`: Pobiera informacje o network adapters i interfaces
- `netstat`: Pobiera informacje o połączeniach TCP i UDP
- `pwd`: Wyświetla bieżący working directory
- `ps`: Wyświetla uruchomione processes w systemie docelowym (z dodatkowymi informacjami)
- `jobs`: Wyświetla wszystkie uruchomione jobs związane z long-running tasking
- `download`: Pobiera plik z systemu docelowego na maszynę lokalną
- `upload`: Wysyła plik z maszyny lokalnej do systemu docelowego
- `reg_query`: Odczytuje registry keys i values w systemie docelowym
- `reg_write_value`: Zapisuje nową value do wskazanego registry key
- `sleep`: Zmienia sleep interval agenta, który określa, jak często agent komunikuje się z Mythic serverem
- I wiele innych; użyj `help`, aby wyświetlić pełną listę dostępnych commands.

### Privilege escalation

- `getprivs`: Włącza jak najwięcej privileges na bieżącym thread tokenie
- `getsystem`: Otwiera handle do winlogon i duplikuje token, skutecznie eskalując privileges do poziomu SYSTEM
- `make_token`: Tworzy nową logon session i stosuje ją do agenta, umożliwiając impersonation innego użytkownika
- `steal_token`: Kradnie primary token z innego process, umożliwiając agentowi impersonation użytkownika tego process
- `pth`: Atak Pass-the-Hash, umożliwiający agentowi uwierzytelnienie jako użytkownik przy użyciu jego NTLM hash bez potrzeby znajomości plaintext password
- `mimikatz`: Uruchamia commands Mimikatz w celu wyodrębnienia credentials, hashes i innych poufnych informacji z pamięci lub bazy danych SAM
- `rev2self`: Przywraca token agenta do jego primary token, skutecznie obniżając privileges do pierwotnego poziomu
- `ppid`: Zmienia parent process dla jobs post-exploitation przez podanie nowego parent process ID, umożliwiając lepszą kontrolę nad kontekstem wykonywania job
- `printspoofer`: Wykonuje commands PrintSpoofer w celu obejścia zabezpieczeń print spoolera, umożliwiając privilege escalation lub code execution
- `dcsync`: Synchronizuje Kerberos keys użytkownika z maszyną lokalną, umożliwiając offline password cracking lub dalsze attacks
- `ticket_cache_add`: Dodaje Kerberos ticket do bieżącej logon session lub wskazanej sesji, umożliwiając ponowne użycie ticketa lub impersonation

### Process execution

- `assembly_inject`: Umożliwia wstrzyknięcie .NET assembly loadera do zdalnego process
- `blockdlls`: Blokuje ładowanie DLLs niepodpisanych przez Microsoft do jobs post-exploitation
- `execute_assembly`: Wykonuje .NET assembly w kontekście agenta
- `execute_coff`: Wykonuje plik COFF w pamięci, umożliwiając in-memory execution skompilowanego kodu
- `execute_pe`: Wykonuje unmanaged executable (PE)
- `keylog_inject`: Wstrzykuje keylogger do innego process i przesyła keystrokes z powrotem do widoku keylog w Mythic
- `screenshot` / `screenshot_inject`: Wykonuje capture bieżącego desktopu bezpośrednio lub
przez wstrzyknięcie screenshot assembly do docelowego process/session
- `get_injection_techniques`: Wyświetla dostępne injection techniques oraz aktualnie wybraną technikę
- `inline_assembly`: Wykonuje .NET assembly w disposable AppDomain, umożliwiając tymczasowe wykonanie kodu bez wpływu na główny process agenta
- `register_assembly`: Rejestruje .NET assembly do późniejszego execution
- `register_file`: Rejestruje plik w agent cache do późniejszego użycia przez `execute_*` lub PowerShell tasking
- `run`: Wykonuje binary w systemie docelowym, używając systemowego `PATH` do znalezienia executable
- `set_injection_technique`: Zmienia injection primitive używany przez jobs post-exploitation
- `shinject`: Wstrzykuje shellcode do zdalnego process, umożliwiając in-memory execution dowolnego kodu
- `inject`: Wstrzykuje shellcode agenta do zdalnego process, umożliwiając in-memory execution kodu agenta
- `spawn`: Uruchamia nową agent session we wskazanym executable, umożliwiając execution shellcode w nowym process
- `spawnto_x64` i `spawnto_x86`: Zmieniają domyślny binary używany w jobs post-exploitation na wskazaną ścieżkę zamiast używania `rundll32.exe` bez parametrów, co jest bardzo noisy.

### Mythic Forge

Umożliwia to **ładowanie plików COFF/BOF** z Mythic Forge, który jest repozytorium pre-compiled payloads i tools, które można wykonywać w systemie docelowym. Dzięki wszystkim commands, które można załadować, możliwe będzie wykonywanie common actions w bieżącym agent process jako BOFs (zwykle z lepszym OPSEC niż podczas uruchamiania osobnego process).

Rozpocznij ich instalację za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Następnie użyj `forge_collections`, aby wyświetlić moduły COFF/BOF z Mythic Forge i móc wybrać je oraz załadować do pamięci agenta w celu wykonania. Domyślnie w Apollo dodawane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu modułu pojawi się on na liście jako kolejne polecenie, np. `forge_bof_sa-whoami` lub `forge_bof_sa-netuser`.

W przypadku BOF pamiętaj, że Forge **nie** przekazuje do Apollo pojedynczego, płaskiego ciągu argumentów. Mapuje parametry BOF na format typed-array Mythic, a następnie przekazuje je do przepływu `execute_coff` w Apollo. Jeśli BOF załadowany przez Forge zachowuje się nieprawidłowo, sprawdź oczekiwane typy argumentów BOF oraz entrypoint, zamiast analizować wyłącznie wpisany wiersz poleceń. Należy również pamiętać, że nowszy loader BOF w Apollo zmienił obsługę argumentów w porównaniu ze znacznie starszymi buildami z okresu 2.3.1, dlatego nieaktualne BOF-y lub stare kolekcje mogą kończyć się niepowodzeniem wyłącznie z powodu zmiany oczekiwań dotyczących marshalingu.

### Wykonywanie PowerShell i skryptów

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do cache agenta w celu późniejszego wykonania
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skryptowanie i automatyzację
- `powerpick`: Wstrzykuje assembly loadera PowerShell do procesu ofiarnego i wykonuje polecenie PowerShell (bez logowania PowerShell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając ukierunkowane wykonywanie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie shell w kontekście agenta, podobnie jak uruchomienie polecenia w cmd.exe

### Ruch boczny

- `jump_psexec`: Wykorzystuje technikę PsExec do wykonania ruchu bocznego na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go wykonując.
- `jump_wmi`: Wykorzystuje technikę WMI do wykonania ruchu bocznego na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe), a następnie go wykonując.
- `link` i `unlink`: Tworzą i zrywają linki P2P (np. przez SMB/TCP) między callbackami.
- `wmiexecute`: Wykonuje polecenie w systemie lokalnym lub określonym systemie zdalnym przy użyciu WMI, opcjonalnie z użyciem poświadczeń do impersonacji.
- `net_dclist`: Pobiera listę kontrolerów domeny dla określonej domeny, co pomaga w identyfikowaniu potencjalnych celów ruchu bocznego.
- `net_localgroup`: Wyświetla grupy lokalne na określonym komputerze; jeśli nie podano komputera, domyślnie używa localhost.
- `net_localgroup_member`: Pobiera członkostwo w grupie lokalnej dla określonej grupy na komputerze lokalnym lub zdalnym, umożliwiając enumerację użytkowników należących do konkretnych grup.
- `net_shares`: Wyświetla udziały zdalne i informacje o możliwości uzyskania do nich dostępu na określonym komputerze, co pomaga w identyfikowaniu potencjalnych celów ruchu bocznego.
- `socks`: Włącza zgodny z SOCKS 5 proxy w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Jest kompatybilny z narzędziami takimi jak proxychains.
- `rpfwd`: Rozpoczyna nasłuchiwanie na określonym porcie na hoście docelowym i przekazuje ruch przez Mythic do zdalnego adresu IP i portu, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `listpipes`: Wyświetla wszystkie nazwane potoki w systemie lokalnym, co może być przydatne podczas ruchu bocznego lub eskalacji uprawnień poprzez interakcję z mechanizmami IPC.

Informacje o niskopoziomowych prymitywach wykonywania WMI używanych przez `jump_wmi` lub `wmiexecute` znajdziesz w sekcji [WmiExec](lateral-movement/wmiexec.md). Szersze informacje o wzorcach pivotingu znajdziesz w sekcji [Tunelowanie i przekierowywanie portów](../generic-hacking/tunneling-and-port-forwarding.md).

### Różne polecenia
- `help`: Wyświetla szczegółowe informacje o określonych poleceniach lub ogólne informacje o wszystkich dostępnych poleceniach agenta.
- `clear`: Oznacza zadania jako „wyczyszczone”, aby agenci nie mogli ich pobrać. Możesz określić `all`, aby wyczyścić wszystkie zadania, lub `task Num`, aby wyczyścić konkretne zadanie.


## [Agent Poseidon](https://github.com/MythicAgents/poseidon)

Poseidon to agent napisany w Golang, który kompiluje się do plików wykonywalnych dla **Linux i macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Bieżące uwagi dotyczące buildów/profili

- Bieżące buildy Poseidon są przeznaczone dla systemów Linux i macOS na platformach `x86_64` oraz `arm64`.
- Obsługiwane formaty wyjściowe obejmują natywne pliki wykonywalne oraz formaty w stylu shared library, takie jak `dylib` i `so`.
- Poseidon obsługuje `http`, `websocket`, `tcp` oraz `dynamichttp`, a bieżące buildery udostępniają ustawienia multi-egress, takie jak `egress_order` i progi failover.
- Bieżące metadane możliwości Poseidona obejmują również browser scripts, integrację z przeglądarką plików/procesów, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd oraz P2P, dzięki czemu może on działać jako pełnoprawny Linux/macOS pivot node, a nie tylko prosty remote shell.
- Opcje build-time, takie jak `proxy_bypass` i `garble`, warto sprawdzić, gdy potrzebujesz lepszego zachowania sieciowego lub dodatkowego obfuskowania binarki Go.
- `pty` to jedna z najbardziej użytecznych nowszych funkcji poprawiających komfort pracy podczas operacji na Linux/macOS, ponieważ otwiera interaktywny PTY i może udostępnić port po stronie Mythic zapewniający pełniejszą interakcję z terminalem bez uciekania się do starszego obejścia `sleep 0` + SOCKS.
- Bieżąca dokumentacja Poseidona jest szczególnie interesująca w kontekście macOS-heavy tradecraft: `jxa` wykonuje JavaScript for Automation w pamięci, `screencapture` przechwytuje pulpit zalogowanego użytkownika, `clipboard_monitor` przesyła zmiany pasteboard, `execute_library` ładuje lokalny dylib i wywołuje znajdującą się w nim funkcję, a `libinject` wymusza załadowanie znajdującego się na dysku dylib przez zdalny proces.
- W przypadku długotrwałych zadań pamiętaj, że Poseidon wykonuje działania post-exploitation w goroutines/threads, które są kooperatywne, a nie możliwe do wymuszenia natychmiastowego zakończenia. Dokumentacja wyraźnie zaznacza również, że obecnie nie ma wbudowanego obfuskowania agenta, dlatego tradecraft na poziomie build/profile ma większe znaczenie niż w przypadku silnie obfuskowanych komercyjnych implantów.

W przypadku macOS-specific tradecraft dotyczącego operacji opartych na Mythic, nadużywania JAMF lub pomysłów typu MDM-as-C2 sprawdź [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Używany w systemach Linux lub macOS oferuje kilka interesujących poleceń:

### Typowe działania

- `cat`: Wyświetla zawartość pliku
- `cd`: Zmienia bieżący katalog roboczy
- `chmod`: Zmienia uprawnienia pliku
- `config`: Wyświetla bieżącą konfigurację i informacje o hoście
- `cp`: Kopiuje plik z jednej lokalizacji do innej
- `curl`: Wykonuje pojedyncze żądanie webowe z opcjonalnymi nagłówkami i metodą
- `upload`: Przesyła plik na cel
- `download`: Pobiera plik z systemu celu na lokalną maszynę
- I wiele innych

### Wyszukiwanie poufnych informacji

- `triagedirectory`: Znajduje interesujące pliki w katalogu na hoście, takie jak poufne pliki lub dane uwierzytelniające.
- `getenv`: Pobiera wszystkie bieżące zmienne środowiskowe.

### Tradecraft specyficzny dla macOS

- `jxa`: Wykonuje JavaScript for Automation w pamięci za pośrednictwem `OSAScript`, co jest przydatne podczas natywnego macOS post-exploitation bez zapisywania oddzielnych plików skryptów.
- `clipboard_monitor`: Odczytuje pasteboard i zgłasza zmiany z powrotem do Mythic, co jest przydatne w workflows kradzieży danych uwierzytelniających/tokenów opartych na kopiowaniu i wklejaniu.
- `screencapture`: Przechwytuje pulpit użytkownika w systemie macOS.
- `execute_library`: Ładuje dylib z dysku i wywołuje określoną wyeksportowaną funkcję.
- `libinject`: Wstrzykuje stub shellcode, który wymusza załadowanie dylib z dysku przez inny proces macOS.
- `persist_launchd`: Tworzy persistence LaunchAgent / LaunchDaemon bezpośrednio z poziomu agenta.

### Ruch lateralny

- `ssh`: Łączy się przez SSH z hostem przy użyciu wyznaczonych danych uwierzytelniających i otwiera PTY bez uruchamiania ssh.
- `sshauth`: Łączy się przez SSH z określonymi hostami przy użyciu wyznaczonych danych uwierzytelniających. Możesz również użyć tego polecenia do wykonania określonego polecenia na zdalnych hostach przez SSH lub do kopiowania plików za pomocą SCP.
- `link_tcp`: Łączy się z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Łączy się z agentem przy użyciu profilu webshell P2P, umożliwiając zdalny dostęp do web interface agenta.
- `rpfwd`: Uruchamia lub zatrzymuje Reverse Port Forward, umożliwiając zdalny dostęp do usług w sieci celu.
- `socks`: Uruchamia lub zatrzymuje proxy SOCKS5 w sieci celu, umożliwiając tunelowanie ruchu przez skompromitowany host. Kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuje hosty pod kątem otwartych portów, co pomaga identyfikować potencjalne cele do ruchu lateralnego lub dalszych ataków.

### Wykonywanie procesów

- `shell`: Wykonuje pojedyncze polecenie shell za pośrednictwem /bin/sh, umożliwiając bezpośrednie wykonywanie poleceń w systemie celu.
- `run`: Wykonuje polecenie z dysku wraz z argumentami, umożliwiając uruchamianie binariów lub skryptów w systemie celu.
- `pty`: Otwiera interaktywny PTY, umożliwiając bezpośrednią interakcję z shellem w systemie celu.






## Odnośniki

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
