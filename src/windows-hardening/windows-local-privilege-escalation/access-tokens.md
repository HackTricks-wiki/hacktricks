# Токени доступу

{{#include ../../banners/hacktricks-training.md}}

## Токени доступу

Кожен **користувач, який увійшов** у систему, **має токен доступу з інформацією безпеки** для цього сеансу входу. Система створює токен доступу, коли користувач входить у систему. **Кожен процес, виконаний** від імені користувача, **має копію токена доступу**. Токен ідентифікує користувача, групи користувача та привілеї користувача. Токен також містить SID входу (ідентифікатор безпеки), який ідентифікує поточний сеанс входу.

Цю інформацію можна переглянути, виконавши `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
або використовуючи _Process Explorer_ від Sysinternals (виберіть процес і відкрийте вкладку "Security"):

![Access Tokens - Access Tokens: або використовуючи Process Explorer від Sysinternals (виберіть процес і відкрийте вкладку "Security")](<../../images/image (772).png>)

### Локальний адміністратор

Коли локальний адміністратор входить у систему, створюються **два access tokens**: один із правами адміністратора, а інший — зі звичайними правами. **За замовчуванням**, коли цей користувач запускає процес, використовується токен зі **звичайними** (не адміністративними) **правами**. Коли цей користувач намагається **запустити** щось **як адміністратор** (наприклад, "Run as Administrator"), для запиту дозволу використовується **UAC**.\
Якщо ви хочете [**дізнатися більше про UAC, прочитайте цю сторінку**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

На практиці це означає, що **непідвищена оболонка адміністратора зазвичай працює з відфільтрованим токеном**. Саме тому `whoami /groups` часто показує **`BUILTIN\Administrators` як `Deny only`**, доки процес не буде підвищено. Усередині Windows зберігає **пов’язаний підвищений токен** (`TokenLinkedToken`) і відстежує цей стан за допомогою таких полів, як `TokenElevationType`.

### Імперсонація користувача за обліковими даними

Якщо у вас є **дійсні облікові дані будь-якого іншого користувача**, ви можете **створити** **новий сеанс входу** з цими обліковими даними:
```
runas /user:domain\username cmd.exe
```
**Токен доступу** також містить **посилання** на сеанси входу в **LSASS**; це корисно, якщо процесу потрібно отримати доступ до деяких об'єктів мережі.\
Ви можете запустити процес, який **використовує інші облікові дані для доступу до мережевих служб**, за допомогою:
```
runas /user:domain\username /netonly cmd.exe
```
Це корисно, якщо у вас є дійсні облікові дані для доступу до об'єктів у мережі, але ці облікові дані недійсні всередині поточного хоста, оскільки вони використовуватимуться лише в мережі (на поточному хості використовуватимуться привілеї вашого поточного користувача).

#### Деталі `runas /netonly`

`runas /netonly` (а також помічники C2, такі як `make_token`) створює токен **`LOGON32_LOGON_NEW_CREDENTIALS`**. Це дуже важливо розуміти під час lateral movement, оскільки:<sup>[[3]](#references)</sup>

- **Локально** новий процес зберігає **ту саму локальну ідентичність**, групи, рівень цілісності та більшість тих самих рішень щодо доступу, що й поточний токен.
- **Віддалено** для вихідної автентифікації можна використовувати **надані облікові дані** для SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Тому `whoami` може й надалі показувати **початкового локального користувача**, тоді як доступ до мережі здійснюватиметься як **альтернативний обліковий запис**.

Це чудовий варіант, коли облікові дані дійсні в домені або на іншому хості, але користувач **не може або не повинен входити локально** на поточну машину.

### Типи токенів

Доступні два типи токенів:

- **Primary Token**: Використовується як представлення облікових даних безпеки процесу. Створення первинних токенів і їхнє призначення процесам потребують підвищених привілеїв, що підкреслює принцип розділення привілеїв. Зазвичай за створення токена відповідає служба автентифікації, а служба входу виконує його прив'язку до оболонки операційної системи користувача. Варто зазначити, що під час створення процеси успадковують первинний токен батьківського процесу.
- **Impersonation Token**: Дозволяє серверному застосунку тимчасово прийняти ідентичність клієнта для доступу до захищених об'єктів. Цей механізм поділяється на чотири рівні роботи:
- **Anonymous**: Надає серверу доступ на рівні невідомого користувача.
- **Identification**: Дозволяє серверу перевірити ідентичність клієнта, не використовуючи її для доступу до об'єктів.
- **Impersonation**: Дозволяє серверу працювати від імені клієнта.
- **Delegation**: Подібний до Impersonation, але також дозволяє поширювати цю ідентичність на віддалені системи, з якими взаємодіє сервер, забезпечуючи збереження облікових даних.

#### Імітація токенів

Використовуючи модуль _**incognito**_ у metasploit, за наявності достатніх привілеїв можна легко **перерахувати** й **імітувати** інші **токени**. Це може бути корисним для виконання **дій так, ніби ви є іншим користувачем**. За допомогою цієї техніки також можна **підвищити привілеї**.

Деякі практичні моменти, про які легко забути під час роботи:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** вимагає **`SeImpersonatePrivilege`** у викликаючого процесу, а новий процес запускатиметься в **сеансі викликаючого процесу**.
- **`CreateProcessAsUserW`** є стандартним запасним варіантом, коли **`CreateProcessWithTokenW`** завершується помилкою `1314` або коли потрібно запустити процес у **сеансі, на який посилається токен**.
- Якщо токен отримано через **`LogonUser(LOGON32_LOGON_NETWORK)`**, зазвичай це **токен імітації**, тому перед спробою запустити з нього процес потрібно виконати **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Не кожен токен імітації однаково корисний: **`SecurityIdentification`** дає змогу перевірити користувача, але **не дозволяє діяти від його імені**. Якщо primitive примусової автентифікації або клієнт pipe/RPC надає вам лише токен рівня identification, перевірте **`TokenImpersonationLevel`** і використайте primitive, який повертає **`SecurityImpersonation`** або вищий рівень.

#### Викрадення токенів без взаємодії з LSASS

Якщо ви вже маєте контекст **служби** або **SYSTEM**, а **привілейований користувач увійшов у систему**, викрадення або дублювання токена цього користувача часто є менш помітним, ніж дамп **LSASS**. У багатьох реальних вторгненнях цього достатньо, щоб:<sup>[[2]](#references)</sup>

- виконувати локальні дії від імені цього користувача
- отримувати доступ до віддалених ресурсів від імені цього користувача
- виконувати операції в AD без попереднього вилучення облікових даних, придатних для повторного використання

Приклади **перехоплення токенів сеансу/користувача** з привілейованого контексту наведено на сторінці [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Пам'ятайте, що API, такі як **`WTSQueryUserToken`**, призначені для **сервісів із високим рівнем довіри** та зазвичай потребують **`LocalSystem` + `SeTcbPrivilege`**, тому вони переважно корисні після отримання контролю над контекстом рівня служби. Способи отримання **SYSTEM** із використанням конкретних привілеїв спочатку наведено на сторінках нижче.

### Привілеї токенів

Дізнайтеся, які **привілеї токенів можна зловживати для підвищення привілеїв:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Перегляньте [**all the possible token privileges and some definitions on this external page**](https://github.com/gtworek/Priv2Admin).

## Посилання

- [1] [Understanding and Abusing Access Tokens — Part II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Abusing Windows' tokens to compromise Active Directory without touching LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Demystifying Cobalt Strike's "make_token" Command](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
