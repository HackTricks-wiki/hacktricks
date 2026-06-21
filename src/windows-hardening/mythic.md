# Mythic

{{#include ../banners/hacktricks-training.md}}

## Czym jest Mythic?

Mythic to open-source’owy, modularny, współpracujący framework command and control (C2) zaprojektowany do red teaming. Umożliwia operatorom zarządzanie i wdrażanie agentów (payloads) na różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic udostępnia interfejs w przeglądarce do tasking z wieloma operatorami, obsługi plików, zarządzania SOCKS/rpfwd oraz generowania payloads.

W przeciwieństwie do monolitycznych frameworków, samo repozytorium Mythic **nie** zawiera typów payloads ani profili C2. Agents, wrappers i profile C2 są zwykle instalowane jako zewnętrzne komponenty i mogą być aktualizowane niezależnie od core Mythic.

### Installation

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami na oficjalnym **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Typowy bootstrap z katalogu Mythic to:
```bash
sudo make
sudo ./mythic-cli start
```
Jeśli Mythic już działa, zwykle możesz dodać nowego agenta lub profil za pomocą `./mythic-cli install github ...`, a następnie albo zrestartować Mythic, albo po prostu uruchomić nowy komponent bezpośrednio.

### Agents

Mythic wspiera wiele agentów, które są **payloads wykonującymi zadania na skompromitowanych systemach**. Każdy agent można dostosować do konkretnych potrzeb i może działać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agentów. Agenci open-source społeczności są dostępni w [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) jest przydatna do szybkiego sprawdzenia obsługiwanych systemów operacyjnych, formatów payloads, wrappers i profili C2.

Aby zainstalować agenta z tej organizacji, możesz uruchomić:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` jest przydatna, gdy instalujesz z środowiska nie-root. Możesz dodawać nowe agenty poprzednim poleceniem, nawet jeśli Mythic już działa.

### C2 Profiles

C2 profiles w Mythic definiują **jak agenty komunikują się z serwerem Mythic**. Określają protokół komunikacji, metody szyfrowania i inne ustawienia. Możesz tworzyć i zarządzać C2 profiles przez interfejs webowy Mythic.

Domyślnie Mythic jest instalowany bez żadnych profili, jednak możliwe jest pobranie niektórych profili z repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles), uruchamiając:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo może obecnie emitować payloady `WinExe`, `Shellcode`, `Service` i `Source`.
- Najczęściej używane profile Apollo to `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` jest zwykle bardziej elastyczną opcją, gdy potrzebujesz rotacji domen, wsparcia proxy, niestandardowego rozmieszczania wiadomości i transformacji wiadomości zamiast starszego statycznego profilu `http`.
- Apollo obsługuje wrapper payloads takie jak `service_wrapper` i `scarecrow_wrapper`.
- `register_file` i `register_assembly` to staging primitives dla `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. W aktualnych buildach Apollo te staged artefakty są cache’owane po stronie klienta jako obiekty AES256 chronione przez DPAPI.
- Wyniki `ls` i `ps` szczególnie dobrze integrują się z browser scripts i file/process browser w Mythic, co zauważalnie przyspiesza triage operatora w operacjach zespołowych.
- Zadania fork-and-run Apollo dziedziczą ustawienia sacrificial process z
`spawnto_x86` / `spawnto_x64`, dziedziczą wybór parent process z `ppid`, a
następnie używają aktualnie wybranej injection primitive. W praktyce oznacza to,
że dostrajanie OPSEC dla jednej komendy często wpływa jednocześnie na
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` i `spawn`.
- Aktualnie udokumentowane backends injection Apollo obejmują
`CreateRemoteThread`, `QueueUserAPC` (w stylu early-bird) oraz `NtCreateThreadEx`
przez syscalls. Użyj `get_injection_techniques` przed głośnym
post-exploitation i `set_injection_technique`, jeśli musisz przełączyć się
z primitive, która koliduje z celem lub z komendą, którą chcesz uruchomić.
- `blockdlls` wpływa tylko na sacrificial processes tworzone dla zadań
post-exploitation. W połączeniu z mniej podejrzanym celem `spawnto_x64`
niż domyślny goły `rundll32.exe` jest to jedna z najprostszych zmian po stronie
Apollo przed uruchamianiem taskingów mocno opartych na assembly/PowerShell.

Ten agent ma wiele komend, przez co jest bardzo podobny do Beacon z Cobalt Strike, z kilkoma dodatkami. Wśród nich obsługuje:

### Common actions

- `cat`: Wypisz zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `cp`: Skopiuj plik z jednej lokalizacji do innej
- `ls`: Wyświetl pliki i katalogi w bieżącym katalogu lub podanej ścieżce
- `ifconfig`: Pobierz informacje o adapterach i interfejsach sieciowych
- `netstat`: Pobierz informacje o połączeniach TCP i UDP
- `pwd`: Wypisz bieżący katalog roboczy
- `ps`: Wyświetl uruchomione procesy w systemie docelowym (z dodatkowymi informacjami)
- `jobs`: Wyświetl wszystkie uruchomione zadania powiązane z długotrwałym taskingiem
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- `upload`: Wyślij plik z lokalnej maszyny do systemu docelowego
- `reg_query`: Zapytaj o klucze i wartości rejestru w systemie docelowym
- `reg_write_value`: Zapisz nową wartość do określonego klucza rejestru
- `sleep`: Zmień interval uśpienia agenta, który określa, jak często zgłasza się do serwera Mythic
- I wiele innych, użyj `help`, aby zobaczyć pełną listę dostępnych komend.

### Privilege escalation

- `getprivs`: Włącz jak najwięcej uprawnień na bieżącym tokenie wątku
- `getsystem`: Otwórz uchwyt do winlogon i zduplikuj token, skutecznie podnosząc uprawnienia do poziomu SYSTEM
- `make_token`: Utwórz nową sesję logowania i zastosuj ją do agenta, umożliwiając impersonation innego użytkownika
- `steal_token`: Ukraść primary token z innego procesu, umożliwiając agentowi impersonation użytkownika tego procesu
- `pth`: Atak Pass-the-Hash, umożliwiający agentowi uwierzytelnienie się jako użytkownik przy użyciu jego hasha NTLM bez potrzeby znajomości jawnego hasła
- `mimikatz`: Uruchom komendy Mimikatz, aby wyciągnąć poświadczenia, hashe i inne wrażliwe informacje z pamięci lub bazy SAM
- `rev2self`: Przywróć token agenta do jego primary token, skutecznie obniżając uprawnienia z powrotem do pierwotnego poziomu
- `ppid`: Zmień parent process dla zadań post-exploitation, podając nowy parent process ID, co pozwala lepiej kontrolować context wykonania zadania
- `printspoofer`: Wykonaj komendy PrintSpoofer, aby obejść zabezpieczenia print spooler, umożliwiając privilege escalation lub code execution
- `dcsync`: Zsynchronizuj Kerberos keys użytkownika z lokalną maszyną, umożliwiając offline password cracking lub dalsze ataki
- `ticket_cache_add`: Dodaj ticket Kerberos do bieżącej sesji logowania lub wskazanej, umożliwiając ponowne użycie ticketów lub impersonation

### Process execution

- `assembly_inject`: Pozwala wstrzyknąć loader .NET assembly do zdalnego procesu
- `blockdlls`: Blokuje ładowanie bibliotek DLL podpisanych przez Microsoft do zadań post-exploitation
- `execute_assembly`: Wykonuje .NET assembly w kontekście agenta
- `execute_coff`: Wykonuje plik COFF w pamięci, umożliwiając in-memory execution skompilowanego kodu
- `execute_pe`: Wykonuje niezarządzany plik wykonywalny (PE)
- `keylog_inject`: Wstrzykuje keylogger do innego procesu i przesyła naciśnięcia klawiszy z powrotem do widoku keylog w Mythic
- `screenshot` / `screenshot_inject`: Zrób zrzut bieżącego pulpitu bezpośrednio albo
przez wstrzyknięcie assembly do zrzutu ekranu w docelowy proces/sesję
- `get_injection_techniques`: Pokaż dostępne techniki injection i aktualnie wybraną
- `inline_assembly`: Wykonuje .NET assembly w jednorazowym AppDomain, umożliwiając tymczasowe wykonanie kodu bez wpływu na główny proces agenta
- `register_assembly`: Zarejestruj .NET assembly do późniejszego wykonania
- `register_file`: Zarejestruj plik w cache agenta do późniejszego `execute_*` lub taskingu PowerShell
- `run`: Wykonuje binary w systemie docelowym, używając systemowego PATH do znalezienia pliku wykonywalnego
- `set_injection_technique`: Zmień injection primitive używaną przez zadania post-exploitation
- `shinject`: Wstrzykuje shellcode do zdalnego procesu, umożliwiając in-memory execution dowolnego kodu
- `inject`: Wstrzykuje shellcode agenta do zdalnego procesu, umożliwiając in-memory execution kodu agenta
- `spawn`: Tworzy nową sesję agenta w podanym pliku wykonywalnym, umożliwiając wykonanie shellcode w nowym procesie
- `spawnto_x64` and `spawnto_x86`: Zmień domyślny binary używany w zadaniach post-exploitation na podaną ścieżkę zamiast używania `rundll32.exe` bez parametrów, co jest bardzo głośne.

### Mythic Forge

To pozwala **load COFF/BOF** files z Mythic Forge, czyli repozytorium prekompilowanych payloadów i narzędzi, które mogą być uruchamiane w systemie docelowym. Dzięki wszystkim komendom, które można załadować, będzie można wykonywać typowe akcje, uruchamiając je w bieżącym procesie agenta jako BOFs (zwykle z lepszym OPSEC niż tworzenie osobnego procesu).

Zacznij je instalować za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, użyj `forge_collections`, aby pokazać moduły COFF/BOF z Mythic Forge, tak aby móc je wybrać i załadować do pamięci agenta do wykonania. Domyślnie w Apollo dodawane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu jednego modułu pojawi się on na liście jako kolejna komenda, np. `forge_bof_sa-whoami` albo `forge_bof_sa-netuser`.

W przypadku BOF pamiętaj, że Forge **nie** przekazuje do Apollo po prostu jednego płaskiego ciągu argumentów. Mapuje parametry BOF do sformatowanej tablicy typów Mythic, a następnie przekazuje je do przepływu `execute_coff` w Apollo. Jeśli BOF załadowany przez Forge zachowuje się dziwnie, sprawdź oczekiwane typy argumentów BOF / entrypoint, a nie tylko wpisaną linię poleceń.

### PowerShell & scripting execution

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do cache agenta do późniejszego wykonania
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skryptowanie i automatyzację
- `powerpick`: Wstrzykuje assembly loader PowerShell do procesu ofiarnego i wykonuje polecenie PowerShell (bez logowania powershell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając ukierunkowane uruchamianie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie shell w kontekście agenta, podobnie jak uruchomienie polecenia w cmd.exe

### Lateral Movement

- `jump_psexec`: Używa techniki PsExec, aby przemieszczać się lateralnie na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i uruchamiając go.
- `jump_wmi`: Używa techniki WMI, aby przemieszczać się lateralnie na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i uruchamiając go.
- `link` i `unlink`: Tworzą i usuwają połączenia P2P (na przykład przez SMB/TCP) między callbackami.
- `wmiexecute`: Wykonuje polecenie na lokalnym lub wskazanym zdalnym systemie z użyciem WMI, z opcjonalnymi poświadczeniami do impersonation.
- `net_dclist`: Pobiera listę domain controllers dla wskazanej domeny, przydatne do identyfikacji potencjalnych celów lateral movement.
- `net_localgroup`: Wyświetla lokalne grupy na wskazanym komputerze, domyślnie localhost, jeśli nie podano komputera.
- `net_localgroup_member`: Pobiera członkostwo lokalnej grupy dla wskazanej grupy na lokalnym lub zdalnym komputerze, umożliwiając enumerację użytkowników w określonych grupach.
- `net_shares`: Wyświetla zdalne udziały i ich dostępność na wskazanym komputerze, przydatne do identyfikacji potencjalnych celów lateral movement.
- `socks`: Włącza proxy zgodne z SOCKS 5 na docelowej sieci, umożliwiając tunelowanie ruchu przez skompromitowany host. Kompatybilne z narzędziami takimi jak proxychains.
- `rpfwd`: Uruchamia nasłuchiwanie na wskazanym porcie na hoście docelowym i przekazuje ruch przez Mythic do zdalnego IP i portu, umożliwiając zdalny dostęp do usług w docelowej sieci.
- `listpipes`: Wyświetla wszystkie named pipes w lokalnym systemie, co może być przydatne do lateral movement lub privilege escalation poprzez interakcję z mechanizmami IPC.

Dla niższopoziomowych prymitywów wykonywania WMI używanych pod spodem przez `jump_wmi` lub `wmiexecute`, sprawdź [WmiExec](lateral-movement/wmiexec.md). Dla szerszych wzorców pivoting sprawdź [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Wyświetla szczegółowe informacje o konkretnych komendach lub ogólne informacje o wszystkich dostępnych komendach w agencie.
- `clear`: Oznacza zadania jako 'cleared', dzięki czemu nie mogą zostać podjęte przez agenty. Możesz użyć `all`, aby wyczyścić wszystkie zadania, albo `task Num`, aby wyczyścić konkretne zadanie.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon to agent w Golang, który kompiluje się do plików wykonywalnych dla **Linux i macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Obecne buildy Poseidon targetują Linux i macOS na `x86_64` oraz `arm64`.
- Obsługiwane formaty wyjściowe obejmują natywne executables oraz wyjścia w stylu shared-library, takie jak `dylib` i `so`.
- Poseidon obsługuje `http`, `websocket`, `tcp` i `dynamichttp`, a obecne buildery udostępniają ustawienia multi-egress, takie jak `egress_order` i progi failover.
- Opcje build-time, takie jak `proxy_bypass` i `garble`, warto sprawdzić, gdy potrzebujesz albo czystszego zachowania sieciowego, albo dodatkowej obfuskacji binarki Go.
- `pty` to jedno z najbardziej użytecznych nowszych poleceń ułatwiających pracę w Linux/macOS
operations, ponieważ otwiera interaktywny PTY i może wystawić port po stronie Mythic dla pełniejszej interakcji z terminalem bez uciekania się do starszego obejścia `sleep 0`
+ SOCKS.
- Obecna dokumentacja Poseidon jest szczególnie interesująca dla macOS-heavy
tradecraft: `jxa` wykonuje JavaScript for Automation w pamięci,
`screencapture` przechwytuje zalogowany pulpit, `clipboard_monitor` strumieniuje
zmiany pasteboard, `execute_library` ładuje lokalny dylib i wywołuje
z niego funkcję, a `libinject` wymusza na zdalnym procesie załadowanie
dylib z dysku.
- W przypadku długotrwałych zadań pamiętaj, że Poseidon wykonuje pracę
post-exploitation w goroutines/wątkach, które są kooperacyjne, a nie dające się twardo zabić. Dokumentacja wyraźnie też wskazuje, że obecnie nie ma wbudowanej obfuskacji agenta, więc tradecraft na poziomie build/profile ma większe znaczenie niż w przypadku mocno obfuskowanych komercyjnych implantów.

Dla tradecraft specyficznego dla macOS wokół operacji opartych na Mythic, nadużyć JAMF lub pomysłów MDM-as-C2, sprawdź [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

When used on Linux or macOS it has some interesting commands:

### Common actions

- `cat`: Wyświetl zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `chmod`: Zmień uprawnienia pliku
- `config`: Pokaż bieżącą konfigurację i informacje o hoście
- `cp`: Skopiuj plik z jednego miejsca do drugiego
- `curl`: Wykonaj pojedyncze żądanie web z opcjonalnymi nagłówkami i metodą
- `upload`: Wyślij plik na cel
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- I wiele więcej

### Search Sensitive Information

- `triagedirectory`: Znajdź interesujące pliki w katalogu na hoście, takie jak wrażliwe pliki lub credentials.
- `getenv`: Pobierz wszystkie bieżące variables środowiskowe.

### macOS-specific tradecraft

- `jxa`: Wykonaj JavaScript for Automation w pamięci przez `OSAScript`, co jest
przydatne do natywnego post-exploitation na macOS bez wrzucania osobnych plików
skryptów.
- `clipboard_monitor`: Odczytuj pasteboard i raportuj zmiany z powrotem do Mythic,
co jest przydatne w workflow theft credentials/token, które opierają się na copy/paste.
- `screencapture`: Przechwyć pulpit użytkownika na macOS.
- `execute_library`: Załaduj dylib z dysku i wywołaj określoną eksportowaną funkcję.
- `libinject`: Wstrzyknij shellcode stub, który wymusza na innym procesie macOS załadowanie dylib z dysku.
- `persist_launchd`: Utwórz persistence LaunchAgent / LaunchDaemon bezpośrednio z agenta.

### Move laterally

- `ssh`: SSH do hosta przy użyciu wskazanych credentials i otwórz PTY bez uruchamiania ssh.
- `sshauth`: SSH do wskazanego hosta/hostów przy użyciu wskazanych credentials. Możesz też użyć tego do wykonania konkretnego polecenia na zdalnych hostach przez SSH albo do kopiowania plików przez SCP.
- `link_tcp`: Połącz się z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Połącz się z agentem, używając profilu P2P webshell, umożliwiając zdalny dostęp do web interface agenta.
- `rpfwd`: Uruchom lub zatrzymaj Reverse Port Forward, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `socks`: Uruchom lub zatrzymaj proxy SOCKS5 w sieci docelowej, umożliwiając tunelowanie ruchu przez skompromitowany host. Kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuj host(a/y) pod kątem otwartych portów, co jest przydatne do identyfikacji potencjalnych celów do lateral movement lub dalszych attacks.

### Process execution

- `shell`: Wykonaj pojedyncze polecenie shell przez /bin/sh, umożliwiając bezpośrednie wykonanie commands na systemie docelowym.
- `run`: Wykonaj polecenie z dysku z argumentami, umożliwiając uruchamianie binarek lub skryptów na systemie docelowym.
- `pty`: Otwórz interaktywny PTY, umożliwiając bezpośrednią interakcję z shellem na systemie docelowym.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
