# Mythic

{{#include ../banners/hacktricks-training.md}}

## Czym jest Mythic?

Mythic to open-source, modularny, współpracujący framework command and control (C2) zaprojektowany do red teaming. Umożliwia operatorom zarządzanie i wdrażanie agentów (payloads) w różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic zapewnia interfejs UI w przeglądarce do tasking dla wielu operatorów, obsługi plików, zarządzania SOCKS/rpfwd oraz generowania payloads.

W przeciwieństwie do monolitycznych frameworków, sam repozytorium Mythic **nie** dostarcza typów payloads ani profili C2. Agenci, wrappery i profile C2 są zwykle instalowane jako zewnętrzne komponenty i mogą być aktualizowane niezależnie od core Mythic.

### Instalacja

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami w oficjalnym **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Typowy bootstrap z katalogu Mythic to:
```bash
sudo make
sudo ./mythic-cli start
```
Jeśli Mythic jest już uruchomiony, zwykle możesz dodać nowy agent lub profile za pomocą `./mythic-cli install github ...`, a następnie albo zrestartować Mythic, albo po prostu uruchomić nowy komponent bezpośrednio.

### Agents

Mythic obsługuje wiele agents, które są **payloads wykonującymi zadania na skompromitowanych systemach**. Każdy agent można dostosować do konkretnych potrzeb i może działać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agents. Open-source community agents znajdują się w [**https://github.com/MythicAgents**](https://github.com/MythicAgents), a [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) jest przydatna do szybkiego sprawdzenia obsługiwanych systemów operacyjnych, formatów payloads, wrappers i profili C2.

Aby zainstalować agenta z tej organizacji, możesz uruchomić:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Forma `sudo -E` jest przydatna, gdy instalujesz z środowiska nie-root. Możesz dodawać nowe agenty za pomocą poprzedniego polecenia, nawet jeśli Mythic jest już uruchomiony.

### C2 Profiles

C2 profiles w Mythic definiują **jak agenty komunikują się z serwerem Mythic**. Określają protokół komunikacji, metody szyfrowania i inne ustawienia. Możesz tworzyć i zarządzać C2 profiles przez interfejs webowy Mythic.

Domyślnie Mythic jest instalowany bez żadnych profili, jednak możliwe jest pobranie niektórych profili z repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) uruchamiając:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): podstawowy asynchroniczny ruch GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): bardziej elastyczny ruch HTTP z wieloma domenami callback, rotacją fail-over/round-robin, niestandardowymi nagłówkami/parametrami query oraz transformacjami wiadomości (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) umieszczanymi w cookies, nagłówkach, parametrach query lub body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): kształtowanie wiadomości HTTP sterowane przez JSON/TOML, gdy statyczny profil `http` jest zbyt rozpoznawalny.

### Wrapper payloads

Wrapper payloads pozwalają zachować tę samą logikę agenta, jednocześnie zmieniając reprezentację on-disk, która jest dostarczana lub utrwalana.

- `service_wrapper`: zamienia inny payload w Windows service executable, co jest przydatne, gdy ścieżka wykonania wymaga poprawnego binarium usługi.
- `scarecrow_wrapper`: opakowuje zgodny shellcode przy użyciu loadera ScareCrow, aby generować outputy oparte na loaderze, takie jak EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo może obecnie emitować payloady `WinExe`, `Shellcode`, `Service` i `Source`.
- Najczęściej używane profile Apollo to `http`, `httpx`, `smb`, `tcp` i `websocket`.
- `httpx` jest zwykle bardziej elastyczną opcją, gdy potrzebujesz rotacji domen, obsługi proxy, niestandardowego rozmieszczania wiadomości i transformacji wiadomości zamiast starszego statycznego profilu `http`.
- Apollo obsługuje wrapper payloads, takie jak `service_wrapper` i `scarecrow_wrapper`.
- `register_file` i `register_assembly` to staging primitives dla `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` i `powerpick`. W obecnych buildach Apollo te staged artifacts są cache'owane po stronie klienta jako blob-y AES256 chronione przez DPAPI.
- Wyniki `ls` i `ps` integrują się szczególnie dobrze z browser scripts i file/process browser Mythic, co zauważalnie przyspiesza triage operatora podczas operacji zespołowych.

Ten agent ma wiele komend, przez co jest bardzo podobny do Beacon z Cobalt Strike, ale z kilkoma dodatkami. Wśród nich obsługuje:

### Common actions

- `cat`: Wyświetl zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `cp`: Skopiuj plik z jednej lokalizacji do innej
- `ls`: Wyświetl pliki i katalogi w bieżącym katalogu lub podanej ścieżce
- `ifconfig`: Pobierz informacje o adapterach i interfejsach sieciowych
- `netstat`: Pobierz informacje o połączeniach TCP i UDP
- `pwd`: Wyświetl bieżący katalog roboczy
- `ps`: Wyświetl uruchomione procesy w systemie docelowym (z dodatkowymi informacjami)
- `jobs`: Wyświetl wszystkie uruchomione zadania powiązane z długotrwałym tasking
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- `upload`: Wyślij plik z lokalnej maszyny do systemu docelowego
- `reg_query`: Zapytaj o klucze i wartości rejestru na systemie docelowym
- `reg_write_value`: Zapisz nową wartość do określonego klucza rejestru
- `sleep`: Zmień interval sleep agenta, który określa, jak często łączy się z serwerem Mythic
- I wiele innych, użyj `help`, aby zobaczyć pełną listę dostępnych komend.

### Privilege escalation

- `getprivs`: Włącz jak najwięcej uprawnień w bieżącym tokenie wątku
- `getsystem`: Otwórz uchwyt do winlogon i zduplikuj token, skutecznie eskalując uprawnienia do poziomu SYSTEM
- `make_token`: Utwórz nową sesję logowania i zastosuj ją do agenta, umożliwiając impersonation innego użytkownika
- `steal_token`: Ukradnij primary token z innego procesu, umożliwiając agentowi impersonation użytkownika tego procesu
- `pth`: Atak Pass-the-Hash, pozwalający agentowi uwierzytelnić się jako użytkownik przy użyciu jego hasha NTLM bez potrzeby znajomości hasła w postaci jawnej
- `mimikatz`: Uruchom komendy Mimikatz, aby wyekstrahować poświadczenia, hashe i inne wrażliwe informacje z pamięci lub bazy danych SAM
- `rev2self`: Przywróć token agenta do jego primary token, skutecznie obniżając uprawnienia z powrotem do poziomu początkowego
- `ppid`: Zmień proces nadrzędny dla zadań post-exploitation, podając nowy parent process ID, co pozwala lepiej kontrolować context wykonania zadania
- `printspoofer`: Wykonaj komendy PrintSpoofer, aby obejść zabezpieczenia print spooler, umożliwiając privilege escalation lub code execution
- `dcsync`: Zsynchronizuj klucze Kerberos użytkownika z lokalną maszyną, umożliwiając offline password cracking lub dalsze ataki
- `ticket_cache_add`: Dodaj ticket Kerberos do bieżącej sesji logowania lub określonej, umożliwiając ponowne użycie ticketu lub impersonation

### Process execution

- `assembly_inject`: Pozwala wstrzyknąć loader .NET assembly do zdalnego procesu
- `blockdlls`: Blokuj ładowanie bibliotek DLL podpisanych przez Microsoft do zadań post-exploitation
- `execute_assembly`: Uruchamia .NET assembly w kontekście agenta
- `execute_coff`: Uruchamia plik COFF w pamięci, umożliwiając in-memory execution skompilowanego kodu
- `execute_pe`: Uruchamia niezarządzalny plik wykonywalny (PE)
- `get_injection_techniques`: Pokaż dostępne techniki injection i aktualnie wybraną
- `inline_assembly`: Uruchamia .NET assembly w jednorazowym AppDomain, umożliwiając tymczasowe wykonanie kodu bez wpływu na główny proces agenta
- `register_assembly`: Zarejestruj .NET assembly do późniejszego uruchomienia
- `register_file`: Zarejestruj plik w cache agenta do późniejszego `execute_*` lub taskingu PowerShell
- `run`: Uruchamia binarkę na systemie docelowym, używając PATH systemu do znalezienia pliku wykonywalnego
- `set_injection_technique`: Zmień primitive injection używany przez zadania post-exploitation
- `shinject`: Wstrzykuje shellcode do zdalnego procesu, umożliwiając in-memory execution dowolnego kodu
- `inject`: Wstrzykuje shellcode agenta do zdalnego procesu, umożliwiając in-memory execution kodu agenta
- `spawn`: Tworzy nową sesję agenta w określonym pliku wykonywalnym, umożliwiając wykonanie shellcode w nowym procesie
- `spawnto_x64` i `spawnto_x86`: Zmień domyślną binarkę używaną w zadaniach post-exploitation na podaną ścieżkę zamiast używać `rundll32.exe` bez parametrów, co jest bardzo noisy.

### Mythic Forge

To pozwala **załadować pliki COFF/BOF** z Mythic Forge, czyli repozytorium prekompilowanych payloadów i narzędzi, które można uruchomić na systemie docelowym. Dzięki wszystkim komendom, które można załadować, będzie możliwe wykonywanie typowych działań przez uruchamianie ich w bieżącym procesie agenta jako BOF-y (zwykle z lepszym OPSEC niż uruchamianie osobnego procesu).

Zacznij instalować je za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, użyj `forge_collections`, aby pokazać moduły COFF/BOF z Mythic Forge, tak by można je było wybrać i załadować do pamięci agenta do wykonania. Domyślnie w Apollo dodawane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu modułu pojawi się on na liście jako kolejna komenda, np. `forge_bof_sa-whoami` lub `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do cache agenta do późniejszego wykonania
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skryptowanie i automatyzację
- `powerpick`: Wstrzykuje assembly ładujące PowerShell do procesu ofiarnego i wykonuje polecenie PowerShell (bez logowania powershell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając ukierunkowane wykonywanie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie shell w kontekście agenta, podobnie jak uruchomienie polecenia w cmd.exe

### Lateral Movement

- `jump_psexec`: Używa techniki PsExec do lateral movement na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i uruchamiając go.
- `jump_wmi`: Używa techniki WMI do lateral movement na nowy host, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i uruchamiając go.
- `link` i `unlink`: Tworzą i usuwają połączenia P2P (na przykład przez SMB/TCP) między callbacks.
- `wmiexecute`: Wykonuje polecenie na lokalnym lub wskazanym zdalnym systemie za pomocą WMI, z opcjonalnymi poświadczeniami do impersonation.
- `net_dclist`: Pobiera listę domain controllers dla określonej domeny, przydatne do identyfikowania potencjalnych celów lateral movement.
- `net_localgroup`: Wyświetla lokalne grupy na wskazanym komputerze, domyślnie localhost, jeśli nie podano komputera.
- `net_localgroup_member`: Pobiera członkostwo lokalnej grupy dla wskazanej grupy na lokalnym lub zdalnym komputerze, umożliwiając enumerację użytkowników w określonych grupach.
- `net_shares`: Wyświetla zdalne shares i ich dostępność na wskazanym komputerze, przydatne do identyfikowania potencjalnych celów lateral movement.
- `socks`: Włącza proxy zgodne z SOCKS 5 na sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Kompatybilne z narzędziami takimi jak proxychains.
- `rpfwd`: Rozpoczyna nasłuchiwanie na wskazanym porcie na hoście docelowym i przekazuje ruch przez Mythic do zdalnego IP i portu, umożliwiając zdalny dostęp do usług na sieci docelowej.
- `listpipes`: Wyświetla wszystkie named pipes w lokalnym systemie, co może być przydatne do lateral movement lub privilege escalation poprzez interakcję z mechanizmami IPC.

Dla niższopoziomowych primitive WMI używanych pod spodem przez `jump_wmi` lub `wmiexecute`, sprawdź [WmiExec](lateral-movement/wmiexec.md). Dla szerszych wzorców pivoting sprawdź [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Wyświetla szczegółowe informacje o konkretnych komendach lub ogólne informacje o wszystkich dostępnych komendach w agencie.
- `clear`: Oznacza zadania jako 'cleared', aby agenci nie mogli ich podjąć. Możesz podać `all`, aby wyczyścić wszystkie zadania, albo `task Num`, aby wyczyścić konkretne zadanie.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon to agent Golang, który kompiluje się do plików wykonywalnych **Linux i macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Aktualne notatki dotyczące build/profile

- Obecne buildy Poseidon celują w Linux i macOS na obu `x86_64` i `arm64`.
- Obsługiwane formaty wyjściowe obejmują natywne pliki wykonywalne oraz wyjścia w stylu shared-library, takie jak `dylib` i `so`.
- Poseidon obsługuje `http`, `websocket`, `tcp` i `dynamichttp`, a obecne buildery udostępniają ustawienia multi-egress, takie jak `egress_order` i progi failover.
- Opcje build-time, takie jak `proxy_bypass` i `garble`, warto sprawdzić, gdy potrzebujesz albo czystszego zachowania sieciowego, albo dodatkowej obfuskacji binarki Go.

W przypadku macOS-specific tradecraft związanych z operacjami opartymi na Mythic, nadużyciami JAMF lub pomysłami na MDM-as-C2, sprawdź [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Gdy używany na Linux lub macOS, ma kilka interesujących komend:

### Common actions

- `cat`: Wyświetl zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `chmod`: Zmień uprawnienia pliku
- `config`: Wyświetl bieżącą konfigurację i informacje o hoście
- `cp`: Skopiuj plik z jednej lokalizacji do innej
- `curl`: Wykonaj pojedyncze żądanie web z opcjonalnymi nagłówkami i metodą
- `upload`: Wyślij plik do celu
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- I wiele więcej

### Search Sensitive Information

- `triagedirectory`: Znajdź interesujące pliki w katalogu na hoście, takie jak pliki wrażliwe lub poświadczenia.
- `getenv`: Pobierz wszystkie bieżące zmienne środowiskowe.

### Move laterally

- `ssh`: SSH do hosta używając wskazanych poświadczeń i otwórz PTY bez uruchamiania ssh.
- `sshauth`: SSH do określonego hosta(-ów) używając wskazanych poświadczeń. Możesz też użyć tego do wykonania konkretnej komendy na zdalnych hostach przez SSH albo do kopiowania plików przez SCP.
- `link_tcp`: Połącz z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Połącz z agentem używając profilu webshell P2P, umożliwiając zdalny dostęp do interfejsu web agenta.
- `rpfwd`: Uruchom lub zatrzymaj Reverse Port Forward, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `socks`: Uruchom lub zatrzymaj proxy SOCKS5 w sieci docelowej, umożliwiając tunelowanie ruchu przez przejęty host. Kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuj host(y) pod kątem otwartych portów, przydatne do identyfikacji potencjalnych celów do lateral movement lub dalszych ataków.

### Process execution

- `shell`: Wykonaj pojedynczą komendę shell przez /bin/sh, umożliwiając bezpośrednie wykonanie komend na systemie docelowym.
- `run`: Wykonaj komendę z dysku z argumentami, umożliwiając uruchamianie binarek lub skryptów na systemie docelowym.
- `pty`: Otwórz interaktywny PTY, umożliwiając bezpośrednią interakcję z shellem na systemie docelowym.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
