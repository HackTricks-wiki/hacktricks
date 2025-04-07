# Mythic

## Czym jest Mythic?

Mythic to otwartoźródłowy, modułowy framework dowodzenia i kontroli (C2) zaprojektowany do red teaming. Umożliwia specjalistom ds. bezpieczeństwa zarządzanie i wdrażanie różnych agentów (ładunków) na różnych systemach operacyjnych, w tym Windows, Linux i macOS. Mythic oferuje przyjazny interfejs webowy do zarządzania agentami, wykonywania poleceń i zbierania wyników, co czyni go potężnym narzędziem do symulowania rzeczywistych ataków w kontrolowanym środowisku.

### Instalacja

Aby zainstalować Mythic, postępuj zgodnie z instrukcjami na oficjalnym **[Mythic repo](https://github.com/its-a-feature/Mythic)**.

### Agenci

Mythic obsługuje wiele agentów, które są **ładunkami wykonującymi zadania na skompromitowanych systemach**. Każdy agent może być dostosowany do specyficznych potrzeb i może działać na różnych systemach operacyjnych.

Domyślnie Mythic nie ma zainstalowanych żadnych agentów. Oferuje jednak kilka otwartoźródłowych agentów w [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Aby zainstalować agenta z tego repo, wystarczy uruchomić:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Możesz dodać nowe agenty za pomocą poprzedniego polecenia, nawet jeśli Mythic już działa.

### Profile C2

Profile C2 w Mythic definiują **jak agenty komunikują się z serwerem Mythic**. Określają protokół komunikacji, metody szyfrowania i inne ustawienia. Możesz tworzyć i zarządzać profilami C2 za pomocą interfejsu webowego Mythic.

Domyślnie Mythic jest zainstalowany bez profili, jednak możliwe jest pobranie niektórych profili z repozytorium [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) uruchamiając:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo to agent Windows napisany w C# z użyciem .NET Framework 4.0, zaprojektowany do wykorzystania w szkoleniach SpecterOps.

Zainstaluj go za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Ten agent ma wiele poleceń, które czynią go bardzo podobnym do Beacona Cobalt Strike z dodatkowymi funkcjami. Wśród nich obsługuje:

### Common actions

- `cat`: Wyświetl zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `cp`: Skopiuj plik z jednego miejsca do drugiego
- `ls`: Wyświetl pliki i katalogi w bieżącym katalogu lub określonej ścieżce
- `pwd`: Wyświetl bieżący katalog roboczy
- `ps`: Wyświetl uruchomione procesy na systemie docelowym (z dodatkowymi informacjami)
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- `upload`: Prześlij plik z lokalnej maszyny do systemu docelowego
- `reg_query`: Zapytaj o klucze i wartości rejestru w systemie docelowym
- `reg_write_value`: Zapisz nową wartość do określonego klucza rejestru
- `sleep`: Zmień interwał snu agenta, który określa, jak często sprawdza połączenie z serwerem Mythic
- I wiele innych, użyj `help`, aby zobaczyć pełną listę dostępnych poleceń.

### Privilege escalation

- `getprivs`: Włącz jak najwięcej uprawnień na bieżącym tokenie wątku
- `getsystem`: Otwórz uchwyt do winlogon i zdubluj token, skutecznie eskalując uprawnienia do poziomu SYSTEM
- `make_token`: Utwórz nową sesję logowania i zastosuj ją do agenta, umożliwiając podszywanie się pod innego użytkownika
- `steal_token`: Ukradnij główny token z innego procesu, umożliwiając agentowi podszywanie się pod użytkownika tego procesu
- `pth`: Atak Pass-the-Hash, umożliwiający agentowi uwierzytelnienie się jako użytkownik przy użyciu ich hasha NTLM bez potrzeby posiadania hasła w postaci tekstowej
- `mimikatz`: Uruchom polecenia Mimikatz, aby wyodrębnić dane uwierzytelniające, hashe i inne wrażliwe informacje z pamięci lub bazy danych SAM
- `rev2self`: Przywróć token agenta do jego głównego tokena, skutecznie obniżając uprawnienia do pierwotnego poziomu
- `ppid`: Zmień proces nadrzędny dla zadań poeksploatacyjnych, określając nowy identyfikator procesu nadrzędnego, co pozwala na lepszą kontrolę nad kontekstem wykonania zadań
- `printspoofer`: Wykonaj polecenia PrintSpoofer, aby obejść środki bezpieczeństwa spooling drukarki, umożliwiając eskalację uprawnień lub wykonanie kodu
- `dcsync`: Synchronizuj klucze Kerberos użytkownika z lokalną maszyną, umożliwiając łamanie haseł offline lub dalsze ataki
- `ticket_cache_add`: Dodaj bilet Kerberos do bieżącej sesji logowania lub określonej, umożliwiając ponowne użycie biletu lub podszywanie się

### Process execution

- `assembly_inject`: Umożliwia wstrzyknięcie loadera zestawu .NET do zdalnego procesu
- `execute_assembly`: Wykonuje zestaw .NET w kontekście agenta
- `execute_coff`: Wykonuje plik COFF w pamięci, umożliwiając wykonanie skompilowanego kodu w pamięci
- `execute_pe`: Wykonuje niezarządzalny plik wykonywalny (PE)
- `inline_assembly`: Wykonuje zestaw .NET w jednorazowym AppDomain, umożliwiając tymczasowe wykonanie kodu bez wpływu na główny proces agenta
- `run`: Wykonuje binarny plik na systemie docelowym, używając PATH systemu do znalezienia pliku wykonywalnego
- `shinject`: Wstrzykuje shellcode do zdalnego procesu, umożliwiając wykonanie dowolnego kodu w pamięci
- `inject`: Wstrzykuje shellcode agenta do zdalnego procesu, umożliwiając wykonanie kodu agenta w pamięci
- `spawn`: Uruchamia nową sesję agenta w określonym pliku wykonywalnym, umożliwiając wykonanie shellcode w nowym procesie
- `spawnto_x64` i `spawnto_x86`: Zmień domyślny plik binarny używany w zadaniach poeksploatacyjnych na określoną ścieżkę zamiast używać `rundll32.exe` bez parametrów, co jest bardzo hałaśliwe.

### Mithic Forge

To pozwala na **ładowanie plików COFF/BOF** z Mythic Forge, który jest repozytorium wstępnie skompilowanych ładunków i narzędzi, które mogą być wykonywane na systemie docelowym. Dzięki wszystkim poleceniom, które można załadować, będzie możliwe wykonywanie typowych działań, uruchamiając je w bieżącym procesie agenta jako BOF (zwykle bardziej dyskretnie).

Zacznij je instalować za pomocą:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Następnie użyj `forge_collections`, aby pokazać moduły COFF/BOF z Mythic Forge, aby móc je wybrać i załadować do pamięci agenta w celu wykonania. Domyślnie w Apollo dodawane są następujące 2 kolekcje:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Po załadowaniu jednego modułu, pojawi się on na liście jako inna komenda, jak `forge_bof_sa-whoami` lub `forge_bof_sa-netuser`.

### Wykonanie Powershell i skryptów

- `powershell_import`: Importuje nowy skrypt PowerShell (.ps1) do pamięci podręcznej agenta do późniejszego wykonania
- `powershell`: Wykonuje polecenie PowerShell w kontekście agenta, umożliwiając zaawansowane skrypty i automatyzację
- `powerpick`: Wstrzykuje zestaw ładujący PowerShell do procesu ofiary i wykonuje polecenie PowerShell (bez logowania PowerShell).
- `psinject`: Wykonuje PowerShell w określonym procesie, umożliwiając celowe wykonanie skryptów w kontekście innego procesu
- `shell`: Wykonuje polecenie powłoki w kontekście agenta, podobnie jak uruchamianie polecenia w cmd.exe

### Ruch Lateralny

- `jump_psexec`: Używa techniki PsExec do ruchu lateralnego do nowego hosta, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i wykonując go.
- `jump_wmi`: Używa techniki WMI do ruchu lateralnego do nowego hosta, najpierw kopiując plik wykonywalny agenta Apollo (apollo.exe) i wykonując go.
- `wmiexecute`: Wykonuje polecenie na lokalnym lub określonym zdalnym systemie za pomocą WMI, z opcjonalnymi poświadczeniami do impersonacji.
- `net_dclist`: Pobiera listę kontrolerów domeny dla określonej domeny, przydatne do identyfikacji potencjalnych celów do ruchu lateralnego.
- `net_localgroup`: Wyświetla lokalne grupy na określonym komputerze, domyślnie na localhost, jeśli nie określono komputera.
- `net_localgroup_member`: Pobiera członkostwo lokalnej grupy dla określonej grupy na lokalnym lub zdalnym komputerze, umożliwiając enumerację użytkowników w określonych grupach.
- `net_shares`: Wyświetla zdalne udostępnienia i ich dostępność na określonym komputerze, przydatne do identyfikacji potencjalnych celów do ruchu lateralnego.
- `socks`: Włącza proxy zgodne z SOCKS 5 w sieci docelowej, umożliwiając tunelowanie ruchu przez skompromitowany host. Kompatybilne z narzędziami takimi jak proxychains.
- `rpfwd`: Rozpoczyna nasłuchiwanie na określonym porcie na docelowym hoście i przekazuje ruch przez Mythic do zdalnego adresu IP i portu, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `listpipes`: Wyświetla wszystkie nazwane potoki w lokalnym systemie, co może być przydatne do ruchu lateralnego lub eskalacji uprawnień poprzez interakcję z mechanizmami IPC.

### Różne polecenia
- `help`: Wyświetla szczegółowe informacje o konkretnych poleceniach lub ogólne informacje o wszystkich dostępnych poleceniach w agencie.
- `clear`: Oznacza zadania jako 'wyczyszczone', aby nie mogły być przejęte przez agentów. Możesz określić `all`, aby wyczyścić wszystkie zadania lub `task Num`, aby wyczyścić konkretne zadanie.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon to agent Golang, który kompiluje się do **Linux i macOS** wykonywalnych.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Kiedy użytkownik korzysta z systemu Linux, ma do dyspozycji kilka interesujących poleceń:

### Common actions

- `cat`: Wyświetl zawartość pliku
- `cd`: Zmień bieżący katalog roboczy
- `chmod`: Zmień uprawnienia pliku
- `config`: Wyświetl bieżącą konfigurację i informacje o hoście
- `cp`: Skopiuj plik z jednego miejsca do drugiego
- `curl`: Wykonaj pojedyncze żądanie webowe z opcjonalnymi nagłówkami i metodą
- `upload`: Prześlij plik do celu
- `download`: Pobierz plik z systemu docelowego na lokalną maszynę
- I wiele więcej

### Search Sensitive Information

- `triagedirectory`: Znajdź interesujące pliki w katalogu na hoście, takie jak pliki wrażliwe lub poświadczenia.
- `getenv`: Pobierz wszystkie bieżące zmienne środowiskowe.

### Move laterally

- `ssh`: SSH do hosta przy użyciu wyznaczonych poświadczeń i otwórz PTY bez uruchamiania ssh.
- `sshauth`: SSH do określonego hosta(y) przy użyciu wyznaczonych poświadczeń. Możesz również użyć tego do wykonania konkretnego polecenia na zdalnych hostach za pomocą SSH lub użyć go do SCP plików.
- `link_tcp`: Połącz się z innym agentem przez TCP, umożliwiając bezpośrednią komunikację między agentami.
- `link_webshell`: Połącz się z agentem używając profilu P2P webshell, umożliwiając zdalny dostęp do interfejsu webowego agenta.
- `rpfwd`: Rozpocznij lub zatrzymaj odwrócone przekierowanie portów, umożliwiając zdalny dostęp do usług w sieci docelowej.
- `socks`: Rozpocznij lub zatrzymaj proxy SOCKS5 w sieci docelowej, umożliwiając tunelowanie ruchu przez skompromitowany host. Kompatybilne z narzędziami takimi jak proxychains.
- `portscan`: Skanuj hosty w poszukiwaniu otwartych portów, przydatne do identyfikacji potencjalnych celów do ruchu lateralnego lub dalszych ataków.

### Process execution

- `shell`: Wykonaj pojedyncze polecenie powłoki za pomocą /bin/sh, umożliwiając bezpośrednie wykonanie poleceń na systemie docelowym.
- `run`: Wykonaj polecenie z dysku z argumentami, umożliwiając wykonanie binariów lub skryptów na systemie docelowym.
- `pty`: Otwórz interaktywny PTY, umożliwiając bezpośrednią interakcję z powłoką na systemie docelowym.
