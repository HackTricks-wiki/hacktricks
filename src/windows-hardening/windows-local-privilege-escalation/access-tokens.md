# Токени доступу

{{#include ../../banners/hacktricks-training.md}}

## Токени доступу

Кожен процес має **основний токен доступу**, який визначає його контекст безпеки. Потік зазвичай використовує цей токен, але тимчасово може мати також **токен імперсоналізації**. Токени містять SID користувача, SID груп, привілеї, дані про рівень цілісності та SID входу для сеансу входу. Процеси зазвичай успадковують посилання на основний токен батьківського процесу; вони не отримують незалежну копію його вмісту.<sup>[[4]](#references)</sup>

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

or using _Process Explorer_ від Sysinternals (виберіть процес і відкрийте вкладку "Security"):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Локальний адміністратор

Коли до адміністратора застосовується **UAC Admin Approval Mode**, під час інтерактивного входу створюються повний токен адміністратора та відфільтрований токен. Explorer і звичайні дочірні процеси за замовчуванням використовують відфільтрований токен. Запит на підвищення прав, наприклад **Run as administrator**, просить UAC запустити програму з повним токеном. Точна поведінка відрізняється для вбудованого облікового запису Administrator і коли Admin Approval Mode вимкнено.<sup>[[5]](#references)</sup>

Перегляньте окрему [**сторінку UAC**](../authentication-credentials-uac-and-efs/uac-user-account-control.md), щоб дізнатися про методи обходу та параметри політики.

На практиці це означає, що **непідвищена оболонка адміністратора зазвичай працює з відфільтрованим токеном**. Саме тому `whoami /groups` часто показує **`BUILTIN\Administrators` як `Deny only`**, доки процес не буде підвищено. Усередині Windows зберігається **пов’язаний токен із підвищеними правами** (`TokenLinkedToken`), а стан відстежується за допомогою таких полів, як `TokenElevationType`.

### Імперсонація користувача за обліковими даними

Якщо у вас є **дійсні облікові дані іншого користувача**, ви можете **створити** **новий сеанс входу** з цими обліковими даними:

```
runas /user:domain\username cmd.exe
```

**Маркер доступу** також містить **посилання** на сеанси входу в систему в **LSASS**. Це корисно, якщо процесу потрібно отримати доступ до певних мережевих об’єктів.\
Ви можете запустити процес, який **використовує інші облікові дані для доступу до мережевих служб**, за допомогою:

```
runas /user:domain\username /netonly cmd.exe
```

Це корисно, якщо у вас є облікові дані для доступу до об’єктів у мережі, але вони не дійсні на поточному хості, оскільки їх використовуватимуть лише в мережі (на поточному хості застосовуватимуться привілеї поточного користувача).

#### Подробиці `runas /netonly`

`runas /netonly` (і помічники C2, як-от `make_token`) створює токен **`LOGON32_LOGON_NEW_CREDENTIALS`**. Це важливо розуміти під час lateral movement, оскільки:<sup>[[3]](#references)</sup>

- **Локально** новий процес зберігає **ту саму локальну ідентичність**, групи, рівень цілісності та більшість тих самих рішень щодо доступу, що й поточний токен.
- **Віддалено** для вихідної автентифікації можна використовувати **надані облікові дані** для SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Тому `whoami` може й надалі показувати **початкового локального користувача**, тоді як мережевий доступ відбуватиметься від імені **іншого облікового запису**.

Це чудовий варіант, коли облікові дані дійсні в домені або на іншому хості, але користувач **не може або не повинен входити локально** на поточну машину.

### Типи токенів

Існує два типи токенів:<sup>[[4]](#references)[[6]](#references)</sup>

- **Первинний токен**: представляє контекст безпеки процесу. Дочірній процес зазвичай успадковує первинний токен батьківського процесу, тоді як API створення процесів із явним токеном накладають власні вимоги до доступу до токена та привілеїв викликача.
- **Токен імперсонації**: дає змогу потоку сервера тимчасово використовувати контекст безпеки клієнта для перевірок доступу. Існує чотири рівні:
  - **Anonymous**: надає серверу доступ, подібний до доступу невідомого користувача.
  - **Identification**: дає серверу змогу перевірити ідентичність клієнта, не використовуючи її для доступу до об’єктів.
  - **Impersonation**: дає серверу змогу діяти від імені клієнта.
  - **Delegation**: дає серверу змогу імперсонувати клієнта у віддалених системах, якщо механізм автентифікації та конфігурація облікового запису підтримують делегування.

#### Перевірте перехоплений токен перед використанням

Не вибирайте токен лише за іменем користувача. Для одного облікового запису може існувати кілька токенів із різними сеансами входу, SID служб, привілеями, рівнями цілісності, обмеженнями та мережевими обліковими даними.<sup>[[9]](#references)</sup> Запитуйте щонайменше **`TokenType`**, **`TokenImpersonationLevel`**, **`TokenElevationType`**, **`TokenLinkedToken`**, **`TokenIntegrityLevel`**, **`TokenSessionId`**, **`TokenIsRestricted`** / **`TokenHasRestrictions`** і **`TokenStatistics.AuthenticationId`** за допомогою `GetTokenInformation`.<sup>[[7]](#references)</sup>

Обмежений токен може містити SID лише для заборони, вилучені привілеї та SID обмеження. Якщо присутні SID обмеження, Windows виконує одну перевірку доступу з увімкненими SID і ще одну — із SID обмеження; **обидві перевірки мають дозволити доступ**. Тому наявність SID користувача, що здається привабливим, або увімкненої групи у виводі сама по собі не доводить, що токен може отримати доступ до цільового об’єкта.<sup>[[8]](#references)</sup>

Користуйтеся цим алгоритмом для документованих вимог до токенів і створення процесів:<sup>[[6]](#references)[[9]](#references)[[10]](#references)</sup>

1. Для **первинного токена** потрібен дескриптор із правами `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, перш ніж його можна буде передати до `CreateProcessWithTokenW` або `CreateProcessAsUserW`.
2. Перетворіть **токен імперсонації** за допомогою `DuplicateTokenEx(..., SecurityImpersonation, TokenPrimary, ...)`. Токени рівня Identification можуть надавати дані про ідентичність, але не можуть виконувати перевірки доступу від імені цього клієнта.
3. `CreateProcessWithTokenW` потребує `SeImpersonatePrivilege` і запускає дочірній процес у сеансі викликача. Натомість `CreateProcessAsUserW` використовує сеанс токена, але зазвичай потребує `SeIncreaseQuotaPrivilege` і може потребувати `SeAssignPrimaryTokenPrivilege`. Якщо облікові дані доступні, а цих привілеїв бракує, документованою альтернативою є `CreateProcessWithLogonW`.

#### Шукайте дескриптори токенів, а не лише власників процесів

Відкриття первинного токена кожного процесу може не виявити **токени імперсонації, збережені як звичайні дескриптори** у службах і брокерних процесах. Універсальний процес роботи з таблицею дескрипторів: перелічити системні дескриптори, відфільтрувати об’єкти токенів, відкрити кожен процес-власник із `PROCESS_DUP_HANDLE`, дублювати кандидатний дескриптор у поточний процес, а потім опитати наведені вище поля. Переконайтеся, що дубльований дескриптор містить права `TOKEN_QUERY` і `TOKEN_DUPLICATE`; наявність дескриптора токена не означає, що його можна дублювати в придатний для використання первинний токен. Захищені процеси та DACL процесу все ще можуть блокувати дескриптор процесу-власника.<sup>[[11]](#references)[[12]](#references)</sup>

`SharpToken` автоматизує перелік первинних токенів процесів і збережених дескрипторів токенів. `list_token` залишає одного пріоритетного кандидата для кожного імені користувача, а `list_all_token` виводить усіх кандидатів. PID обмежує перелік одним процесом-власником.<sup>[[12]](#references)</sup>

```cmd
SharpToken.exe list_token
SharpToken.exe list_all_token
SharpToken.exe list_all_token 1234
SharpToken.exe execute "DOMAIN\User" "cmd /c whoami /all"
```

Для ручної перевірки та контролю доступу **TokenUniverse** може відкривати токени процесів/потоків, шукати наявні дескриптори токенів, перевіряти обмеження та сеанси входу, дублювати токени й тестувати кілька методів створення процесів.<sup>[[13]](#references)</sup> Про базовий механізм роботи з дескрипторами між процесами дивіться:

{{#ref}}
leaked-handle-exploitation.md
{{#endref}}

### Пошук активних токенів імперсонації потоків

Потік служби може тимчасово імперсонувати клієнта, навіть якщо **основний токен процесу** належить обліковому запису служби, тому сканування власників процесів може не виявити контекст клієнта.<sup>[[4]](#references)</sup> TokenUniverse може показувати доступні токени процесів/потоків; у System Informer перегляньте вкладку **Threads** процесу та стовпець **Impersonation**, щоб знайти потенційні потоки.<sup>[[13]](#references)[[14]](#references)</sup>

Для цільової перевірки через API створіть знімок `TH32CS_SNAPTHREAD`, відфільтруйте `THREADENTRY32.th32OwnerProcessID` за PID служби, а потім для кожного доступного потоку викличте `OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid)` і `OpenThreadToken(thread, TOKEN_QUERY | TOKEN_DUPLICATE, TRUE, &token)`.<sup>[[15]](#references)[[16]](#references)</sup> Значення `TRUE` змушує перевірку доступу під час відкриття токена використовувати контекст **процесу** викликувача; це важливо, якщо сам сканер імперсонує на рівні identification.<sup>[[17]](#references)</sup> Перш ніж виконувати описаний вище процес дублювання/створення процесу, перевірте користувача токена, тип, рівень імперсонації та ID входу.<sup>[[7]](#references)</sup> Потік може припинити імперсонацію між переліком і відкриттям; збирання можуть унеможливити відсутність токена, анонімні токени, захищені потоки, DACL потоків і DACL токенів.<sup>[[16]](#references)[[17]](#references)</sup> На відміну від сканування збережених дескрипторів токенів служби, цей метод перевіряє **токен, призначений потоку зараз**.

Про шлях атаки, який отримує токен потоку, змушуючи привілейованого клієнта під’єднатися до вашого каналу, а не скануючи наявні потоки, дивіться [імперсонацію клієнта named pipe](named-pipe-client-impersonation.md).

#### Імперсонація токенів

Якщо у вас достатньо привілеїв, за допомогою модуля _**incognito**_ metasploit можна легко **перелічувати** й **імперсонувати** інші **токени**. Це може стати в пригоді для виконання **дій від імені іншого користувача**. Цей метод також можна використати для **підвищення привілеїв**.

Кілька практичних зауважень, про які легко забути під час роботи:<sup>[[1]](#references)</sup>

- **`CreateProcessWithTokenW`** вимагає наявності **`SeImpersonatePrivilege`** у викликувача, а новий процес запускатиметься в **сеансі викликувача**.
- **`CreateProcessAsUserW`** може бути запасним варіантом, якщо `CreateProcessWithTokenW` завершується помилкою `1314`, але лише за умови, що викликувач має необхідні привілеї. Це також правильний вибір, якщо дочірній процес має запускатися в **сеансі, на який посилається токен**.<sup>[[9]](#references)[[10]](#references)</sup>
- **`LogonUser(LOGON32_LOGON_NETWORK)`** повертає **токен імперсонації**. Перш ніж створювати процес, перетворіть його за допомогою **`DuplicateTokenEx(..., TokenPrimary, ...)`**. Навіть після перетворення отриманий процес не зможе використовувати цей мережевий вхід для доступу до віддалених спільних ресурсів або принтерів, що вимагають автентифікації: цей тип входу не кешує облікові дані. Якщо у вас є облікові дані й потрібен подальший доступ до мережі, використовуйте інтерактивний вхід або вхід із мережевим відкритим текстом; не плутайте їх із `LOGON32_LOGON_NEW_CREDENTIALS` (`runas /netonly`), який зберігає локальну ідентичність, але надає вихідні облікові дані.<sup>[[18]](#references)</sup>
- Не всі токени імперсонації однаково корисні: **`SecurityIdentification`** дає змогу перевірити користувача, але **не діяти від його імені**. Якщо примітив примусу або клієнт pipe/RPC надає вам лише токен рівня identification, перевірте **`TokenImpersonationLevel`** і скористайтеся примітивом, який дає **`SecurityImpersonation`** або вищий рівень.

#### Крадіжка токена без взаємодії з LSASS

Якщо ви вже маєте контекст **служби** або **SYSTEM**, а **привілейований користувач увійшов у систему**, крадіжка або дублювання токена цього користувача часто менш помітні, ніж дамп **LSASS**. У багатьох реальних вторгненнях цього достатньо, щоб:<sup>[[2]](#references)</sup>

- виконувати локальні дії від імені цього користувача
- отримувати доступ до віддалених ресурсів від імені цього користувача
- виконувати операції AD, не витягуючи спершу облікові дані, придатні для повторного використання

Приклади **перехоплення токена сеансу/користувача** з привілейованого контексту дивіться в [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Пам’ятайте, що API на кшталт **`WTSQueryUserToken`** призначені для **служб із високим рівнем довіри** й зазвичай вимагають **`LocalSystem` + `SeTcbPrivilege`**, тому вони переважно корисні, якщо ви вже контролюєте контекст рівня служби. Способи отримати **SYSTEM** із використанням певних привілеїв описано на сторінках нижче.

### Привілеї токенів

Дізнайтеся, **які привілеї токенів можна використати для підвищення привілеїв:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Перегляньте [**всі можливі привілеї токенів і деякі визначення на цій зовнішній сторінці**](https://github.com/gtworek/Priv2Admin).



## References

- [1] [Розуміння токенів доступу та зловживання ними — Частина II](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [2] [Зловживання токенами Windows для компрометації Active Directory без взаємодії з LSASS](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [3] [Розвінчання міфів про команду "make_token" у Cobalt Strike](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)
- [4] [Токени доступу — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [5] [Як працює User Account Control — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [6] [Рівні імперсонації — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [7] [Перелік TOKEN_INFORMATION_CLASS — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class)
- [8] [Обмежені токени — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)
- [9] [Функція CreateProcessWithTokenW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
- [10] [Функція CreateProcessAsUserW — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
- [11] [Функція DuplicateHandle — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [12] [BeichenDream/SharpToken](https://github.com/BeichenDream/SharpToken)
- [13] [diversenok/TokenUniverse](https://github.com/diversenok/TokenUniverse)
- [14] [Запит на додавання функції токенів потоків у System Informer](https://github.com/winsiderss/systeminformer/issues/1275)
- [15] [Перегляд списку потоків — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list)
- [16] [NtOpenThreadToken — Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenthreadtoken)
- [17] [OpenThreadToken — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken)
- [18] [LogonUserA — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
{{#include ../../banners/hacktricks-training.md}}
