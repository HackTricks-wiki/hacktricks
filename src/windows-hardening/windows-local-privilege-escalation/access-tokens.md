# Токени доступу

{{#include ../../banners/hacktricks-training.md}}

## Токени доступу

Кожен процес має **основний токен доступу**, який визначає його контекст безпеки. Потік зазвичай використовує цей токен, але також може тимчасово мати **токен імперсоналізації**. Токени містять SID користувача, SID груп, привілеї, інформацію про рівень цілісності та SID входу для сеансу входу. Зазвичай процеси успадковують посилання на основний токен батьківського процесу; вони не отримують незалежну копію його вмісту.<sup>[[4]](#references)</sup>

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

або за допомогою _Process Explorer_ від Sysinternals (виберіть процес і відкрийте вкладку «Безпека»):

![Access Tokens - Access Tokens: або за допомогою Process Explorer від Sysinternals (виберіть процес і відкрийте вкладку «Безпека»)](<../../images/image (772).png>)

### Локальний адміністратор

Коли до адміністратора застосовується **UAC Admin Approval Mode**, інтерактивний вхід створює повний токен адміністратора та відфільтрований токен. Провідник і звичайні дочірні процеси за замовчуванням використовують відфільтрований токен. Запит на підвищення прав, наприклад **Run as administrator**, просить UAC запустити програму з повним токеном. Точна поведінка відрізняється для вбудованого облікового запису Administrator і коли Admin Approval Mode вимкнено.<sup>[[5]](#references)</sup>

Докладніше про методи обходу та параметри політик читайте на окремій [**сторінці UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md).

На практиці це означає, що **оболонка адміністратора без підвищених прав зазвичай працює з відфільтрованим токеном**. Саме тому `whoami /groups` часто показує **`BUILTIN\Administrators` як `Deny only`**, доки процес не отримає підвищені права. Усередині Windows зберігає **пов’язаний токен із підвищеними правами** (`TokenLinkedToken`) і відстежує стан за допомогою таких полів, як `TokenElevationType`.

### Імперсонізація користувача за обліковими даними

Якщо у вас є **дійсні облікові дані будь-якого іншого користувача**, ви можете **створити** **новий сеанс входу** з цими обліковими даними:

```
runas /user:domain\username cmd.exe
```

**Маркер доступу** також містить **посилання** на сеанси входу в **LSASS**. Це корисно, якщо процесу потрібно отримати доступ до певних мережевих об’єктів.\
Ви можете запустити процес, який **використовує інші облікові дані для доступу до мережевих служб**, за допомогою:

```
runas /user:domain\username /netonly cmd.exe
```

Це корисно, якщо у вас є облікові дані для доступу до об’єктів у мережі, але вони не дійсні на поточному хості, оскільки використовуватимуться лише в мережі (на поточному хості використовуватимуться привілеї поточного користувача).

#### Деталі `runas /netonly`

`runas /netonly` (а також допоміжні засоби C2, як-от `make_token`) створює токен **`LOGON32_LOGON_NEW_CREDENTIALS`**. Це корисно розуміти під час lateral movement, оскільки:<sup>[[3]](#references)</sup>

- **Локально** новий процес зберігає **ту саму локальну ідентичність**, групи, рівень цілісності та більшість тих самих рішень щодо доступу, що й поточний токен.
- **Віддалено** для вихідної автентифікації можуть використовуватися **надані облікові дані** для SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Тому `whoami` може й далі показувати **початкового локального користувача**, тоді як мережевий доступ здійснюється від імені **альтернативного облікового запису**.

Це чудовий варіант, якщо облікові дані дійсні в домені або на іншому хості, але користувач **не може або не повинен входити локально** на поточну машину.

### Типи токенів

Є два типи токенів:<sup>[[4]](#references)[[6]](#references)</sup>

- **Основний токен**: представляє контекст безпеки процесу. Дочірній процес зазвичай успадковує основний токен батьківського процесу, тоді як API створення процесу з явним токеном мають власні вимоги до доступу до токена та привілеїв викликача.
- **Токен імперсонації**: дає змогу потоку сервера тимчасово використовувати контекст безпеки клієнта для перевірок доступу. Є чотири рівні:
  - **Анонімний**: надає серверу доступ, подібний до доступу невідомого користувача.
  - **Ідентифікація**: дає серверу змогу перевірити особу клієнта, не використовуючи її для доступу до об’єктів.
  - **Імперсонація**: дає змогу серверу діяти від імені клієнта.
  - **Делегування**: дає серверу змогу імперсонувати клієнта у віддалених системах, якщо механізм автентифікації та конфігурація облікового запису підтримують делегування.

#### Перевірте перехоплений токен перед використанням

Не вибирайте токен лише за іменем користувача. Один обліковий запис може мати кілька токенів із різними сеансами входу, SID служб, привілеями, рівнями цілісності, обмеженнями та мережевими обліковими даними.<sup>[[9]](#references)</sup> За допомогою `GetTokenInformation` отримайте щонайменше **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** і **`TokenStatistics.AuthenticationId`**.<sup>[[7]](#references)</sup>

Обмежений токен може містити SID лише для заборони, вилучені привілеї та обмежувальні SID. Якщо наявні обмежувальні SID, Windows виконує одну перевірку доступу з увімкненими SID, а іншу — з обмежувальними SID; **обидві перевірки мають дозволяти доступ**. Тому привабливий SID користувача чи ввімкнена група у виводі самі по собі не доводять, що токен може отримати доступ до цільового об’єкта.<sup>[[8]](#references)</sup>

Дотримуйтеся цього алгоритму з урахуванням задокументованих вимог до токенів і створення процесів:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. **Основний токен** потребує дескриптора з правами `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, перш ніж його можна буде передати до `CreateProcessWithTokenW` або `CreateProcessAsUserW`.
2. Перетворіть **токен імперсонації** за допомогою `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Токени рівня Identification можуть надавати дані про особу, але не можуть виконувати перевірки доступу від імені цього клієнта.
3. `CreateProcessWithTokenW` потребує `SeImpersonatePrivilege` і запускає дочірній процес у сеансі викликача. Натомість `CreateProcessAsUserW` використовує сеанс токена, але зазвичай потребує `SeIncreaseQuotaPrivilege`, а іноді — `SeAssignPrimaryTokenPrivilege`. Якщо облікові дані доступні, але цих привілеїв немає, задокументованою альтернативою є `CreateProcessWithLogonW`.

#### Шукайте дескриптори токенів, а не лише власників процесів

Відкриття основного токена кожного процесу може не виявити **токени імперсонації, збережені як звичайні дескриптори** в службах і процесах-брокерах. Повторно використовуваний алгоритм роботи з таблицею дескрипторів: перелічити системні дескриптори, відфільтрувати об’єкти токенів, відкрити власника кожного дескриптора з правом `PROCESS_DUP_HANDLE`, продублювати кандидатний дескриптор у поточний процес, а потім запитати наведені вище поля. Переконайтеся, що продубльований дескриптор має права `TOKEN_QUERY` і `TOKEN_DUPLICATE`; наявність дескриптора токена не означає, що його можна продублювати в придатний основний токен. Захищені процеси та DACL процесу все одно можуть блокувати дескриптор процесу-власника.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` автоматизує перелік основних токенів процесів і збережених дескрипторів токенів. `list_token` залишає одного пріоритетного кандидата для кожного імені користувача, тоді як `list_all_token` виводить усіх кандидатів. PID обмежує перелік одним процесом-власником.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Для ручної перевірки та контролю доступу **TokenUniverse** може відкривати токени процесів/потоків, шукати наявні дескриптори токенів, перевіряти обмеження та сеанси входу, дублювати токени й тестувати кілька способів створення процесів.<sup>[[13]](#references)</sup> Щоб дізнатися про базовий механізм роботи з дескрипторами між процесами, див.:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

#### Імперсонація токенів

За допомогою модуля _**incognito**_ у metasploit, якщо у вас достатньо привілеїв, можна легко **переглядати** й **імперсонувати** інші **токени**. Це може бути корисно, щоб **виконувати дії від імені іншого користувача**. За допомогою цієї техніки також можна **підвищити привілеї**.

Кілька практичних зауважень, про які легко забути під час роботи:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** вимагає наявності **`SeImpersonatePrivilege`** у викликача, а новий процес запускатиметься в **сеансі викликача**.
- **`CreateProcessAsUserW`** може бути запасним варіантом, якщо `CreateProcessWithTokenW` повертає помилку `1314`, але лише якщо викликач відповідає вимогам щодо привілеїв. Також це правильний вибір, якщо дочірній процес має запускатися в **сеансі, на який посилається токен**.<sup>[[9]](#references)[[10]](#references)</sup>
- Якщо токен отримано через **`LogonUser(LOGON32_LOGON_NETWORK)`**, зазвичай це **токен імперсонації**, тому перед спробою запустити з ним процес потрібно виконати **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Не всі токени імперсонації однаково корисні: **`SecurityIdentification`** дає змогу перевірити користувача, але **не діяти від його імені**. Якщо примітив coercion або клієнт pipe/RPC надає вам лише токен рівня identification, перевірте **`TokenImpersonationLevel`** і перейдіть до примітива, що надає рівень **`SecurityImpersonation`** або вище.

#### Крадіжка токенів без взаємодії з LSASS

Якщо у вас уже є контекст **служби** або **SYSTEM**, а **привілейований користувач увійшов у систему**, викрадення чи дублювання його токена часто менш помітне, ніж дамп **LSASS**. У багатьох реальних вторгненнях цього достатньо, щоб:<sup>[[2]](#references)</sup>

- виконувати локальні дії від імені цього користувача
- отримувати доступ до віддалених ресурсів від імені цього користувача
- виконувати операції AD, не вилучаючи спершу облікові дані, придатні для повторного використання

Приклади **перехоплення токена сеансу/користувача** з привілейованого контексту див. у [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Пам’ятайте, що API на кшталт **`WTSQueryUserToken`** призначені для **служб із високим рівнем довіри** й зазвичай вимагають **`LocalSystem` + `SeTcbPrivilege`**, тому переважно корисні, якщо ви вже контролюєте контекст рівня служби. Щоб дізнатися про способи спершу отримати **SYSTEM** за допомогою конкретних привілеїв, перегляньте сторінки нижче.

### Привілеї токенів

Дізнайтеся, **які привілеї токенів можна зловживати для підвищення привілеїв:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Перегляньте [**усі можливі привілеї токенів і деякі визначення на цій зовнішній сторінці**](https://github.com/gtworek/Priv2Admin).

## References

- [1] [Розуміння токенів доступу та зловживання ними — частина II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Зловживання токенами Windows для компрометації Active Directory без взаємодії з LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Розвінчання міфів про команду "make_token" у Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Токени доступу - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Як працює контроль облікових записів користувачів - Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Рівні імперсонації - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Перелік TOKEN_INFORMATION_CLASS - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Обмежені токени - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Функція CreateProcessWithTokenW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Функція CreateProcessAsUserW - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Функція DuplicateHandle - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
{{#include ../../banners/hacktricks-training.md}}
