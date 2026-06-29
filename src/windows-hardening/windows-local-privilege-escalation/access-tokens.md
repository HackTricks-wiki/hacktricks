# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

Кожен **користувач, що увійшов** у систему, **має access token із security information** для цієї logon session. Система створює access token, коли користувач виконує logon. **Кожен process, запущений** від імені користувача, **має копію access token**. Token ідентифікує користувача, groups користувача та privileges користувача. Token також містить logon SID (Security Identifier), який ідентифікує поточну logon session.

Ви можете побачити цю інформацію, виконавши `whoami /all`
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
or using _Process Explorer_ from Sysinternals (select process and access"Security" tab):

![Access Tokens - Access Tokens: or using Process Explorer from Sysinternals (select process and access"Security" tab)](<../../images/image (772).png>)

### Local administrator

When a local administrator logins, **two access tokens are created**: One with admin rights and other one with normal rights. **By default**, when this user executes a process the one with **regular** (non-administrator) **rights is used**. When this user tries to **execute** anything **as administrator** ("Run as Administrator" for example) the **UAC** will be used to ask for permission.\
If you want to [**learn more about the UAC read this page**](../authentication-credentials-uac-and-efs/index.html#uac)**.**

In practice, this means a **non-elevated admin shell usually runs with a filtered token**. That is why `whoami /groups` often shows **`BUILTIN\Administrators` as `Deny only`** until the process is elevated. Internally, Windows keeps a **linked elevated token** (`TokenLinkedToken`) and tracks the state with fields such as `TokenElevationType`.

### Імперсонація користувача з обліковими даними

If you have **valid credentials of any other user**, you can **create** a **new logon session** with those credentials :
```
runas /user:domain\username cmd.exe
```
**access token** також має **reference** на logon sessions всередині **LSASS**, це корисно, якщо процесу потрібно отримати доступ до деяких об’єктів мережі.\
Ви можете запустити процес, який **uses different credentials for accessing network services** за допомогою:
```
runas /user:domain\username /netonly cmd.exe
```
Це корисно, якщо у вас є корисні credentials для доступу до об’єктів у мережі, але ці credentials не є дійсними всередині поточного хоста, оскільки вони будуть використовуватися лише в мережі (на поточному хості будуть використовуватися ваші поточні привілеї користувача).

#### `runas /netonly` details

`runas /netonly` (і C2 helpers на кшталт `make_token`) створює token **`LOGON32_LOGON_NEW_CREDENTIALS`**. Це дуже корисно розуміти під час lateral movement, тому що:

- **Локально**, новий процес зберігає **ту саму локальну identity**, групи, integrity level і більшість тих самих рішень щодо доступу, що й поточний token.
- **Віддалено**, outbound authentication може використовувати **надані credentials** для SMB / WinRM / LDAP / HTTP / Kerberos / NTLM.
- Отже, `whoami` може все ще показувати **оригінального локального користувача**, тоді як мережевий доступ відбувається як **альтернативний account**.

Це чудовий варіант, коли credentials дійсні в domain або на іншому хості, але користувач **не може або не повинен входити локально** на поточну машину.

### Types of tokens

Доступні два типи tokens:

- **Primary Token**: Він слугує представленням security credentials process. Створення та прив’язка primary tokens до processes — це дії, що потребують підвищених привілеїв, підкреслюючи принцип separation of privileges. Зазвичай authentication service відповідає за створення token, тоді як logon service обробляє його прив’язку до shell операційної системи користувача. Варто зазначити, що processes успадковують primary token свого parent process під час створення.
- **Impersonation Token**: Дозволяє server application тимчасово прийняти identity client для доступу до secure objects. Цей механізм поділяється на чотири рівні operation:
- **Anonymous**: Надає server access, подібний до доступу невідомого користувача.
- **Identification**: Дозволяє server перевірити identity client без використання її для object access.
- **Impersonation**: Дозволяє server працювати під identity client.
- **Delegation**: Подібно до Impersonation, але включає можливість поширювати це прийняття identity на remote systems, з якими взаємодіє server, забезпечуючи збереження credentials.

#### Impersonate Tokens

Використовуючи модуль _**incognito**_ у metasploit, якщо у вас достатньо привілеїв, ви можете легко **перелічити** та **impersonate** інші **tokens**. Це може бути корисно для виконання **actions as if you where the other user**. Також цим technique можна **escalate privileges**.

Кілька практичних приміток, які легко забути під час роботи:

- **`CreateProcessWithTokenW`** вимагає **`SeImpersonatePrivilege`** у викликача, і новий process працюватиме в **session викликача**.
- **`CreateProcessAsUserW`** — це звичайний fallback, коли `CreateProcessWithTokenW` завершується помилкою `1314`, або коли вам потрібно запустити процес у **session, на яку посилається token**.
- Якщо token походить з **`LogonUser(LOGON32_LOGON_NETWORK)`**, то це зазвичай **impersonation token**, тому перед спробою створити з ним process потрібно **`DuplicateTokenEx(..., TokenPrimary, ...)`**.
- Не кожен impersonation token однаково корисний: **`SecurityIdentification`** дає змогу інспектувати user, але **не діяти від його імені**. Якщо coercion primitive або pipe/RPC client дає лише token рівня identification, перевірте **`TokenImpersonationLevel`** і перейдіть на primitive, який дає **`SecurityImpersonation`** або краще.

#### Token theft without touching LSASS

Якщо у вас уже є контекст **service** або **SYSTEM** і **privileged user is logged on**, викрадення або дублювання token цього користувача часто є тихішим, ніж дамп **LSASS**. У багатьох реальних intrusions цього достатньо, щоб:

- виконувати локальні дії як цей user
- отримувати доступ до remote resources як цей user
- виконувати AD operations без попереднього вилучення reusable credentials

Для прикладів **session/user token hijacking** із привілейованого контексту дивіться [**WTS Impersonator**](../stealing-credentials/wts-impersonator.md). Пам’ятайте, що APIs на кшталт **`WTSQueryUserToken`** призначені для **highly trusted services** і зазвичай вимагають **`LocalSystem` + `SeTcbPrivilege`**, тому вони переважно корисні вже після того, як ви контролюєте service-level context. Для способів, специфічних до привілеїв, отримати спочатку **SYSTEM**, дивіться сторінки нижче.

### Token Privileges

Дізнайтеся, які **token privileges can be abused to escalate privileges:**


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

Подивіться [**усі можливі token privileges та деякі визначення на цій зовнішній сторінці**](https://github.com/gtworek/Priv2Admin).

## References

- [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa)
- [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)
- [https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/)
- [https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/](https://www.fox-it.com/nl-en/demystifying-cobalt-strike-s-make_token-command/)

{{#include ../../banners/hacktricks-training.md}}
