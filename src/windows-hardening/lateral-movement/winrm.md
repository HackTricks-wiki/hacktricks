# WinRM

{{#include ../../banners/hacktricks-training.md}}

WinRM to jeden z najwygodniejszych mechanizmów **lateral movement** w środowiskach Windows, ponieważ zapewnia zdalną powłokę przez **WS-Man/HTTP(S)** i nie wymaga sztuczek z tworzeniem usług SMB. Jeśli cel udostępnia port **5985/5986**, a Twoje konto ma uprawnienia do korzystania ze zdalnego zarządzania, często możesz bardzo szybko przejść od „valid creds” do „interactive shell”.

Informacje o **enumeracji protokołu/usługi**, listenerach, włączaniu WinRM, `Invoke-Command` i ogólnym użyciu klientów znajdziesz tutaj:

{{#ref}}
../../network-services-pentesting/5985-5986-pentesting-winrm.md
{{#endref}}

## Dlaczego operatorzy lubią WinRM

- Używa **HTTP/HTTPS** zamiast SMB/RPC, więc często działa tam, gdzie blokowane jest uruchamianie kodu w stylu PsExec.
- Przy użyciu **Kerberos** nie trzeba przesyłać na cel poświadczeń, których można użyć ponownie.
- Działa bezproblemowo z narzędziami dla **Windows**, **Linux** i **Pythona** (`winrs`, `evil-winrm`, `pypsrp`, `netexec`).
- Interaktywna ścieżka PowerShell remoting uruchamia na celu **`wsmprovhost.exe`** w kontekście uwierzytelnionego użytkownika, co operacyjnie różni się od uruchamiania kodu za pomocą usług.

## Model dostępu i wymagania wstępne

W praktyce powodzenie lateral movement przez WinRM zależy od **trzech** rzeczy:

1. Cel ma **listener WinRM** (`5985`/`5986`) i reguły zapory zezwalające na dostęp.
2. Konto może **uwierzytelnić się** do endpointu.
3. Konto ma uprawnienia do **otwarcia sesji remoting**.

Typowe sposoby uzyskania takiego dostępu:

- Uprawnienia **Local Administrator** na celu.
- Członkostwo w grupie **Remote Management Users** w nowszych systemach albo **WinRMRemoteWMIUsers__** w systemach/komponentach, które nadal respektują tę grupę.
- Jawnie przyznane uprawnienia do remoting, delegowane przez lokalne deskryptory zabezpieczeń / zmiany ACL PowerShell remoting.

Jeśli masz już kontrolę nad komputerem z uprawnieniami administratora, pamiętaj, że możesz też **przyznać dostęp WinRM bez członkostwa w grupie administratorów** za pomocą technik opisanych tutaj:

{{#ref}}
../active-directory-methodology/security-descriptors.md
{{#endref}}

### Pułapki związane z uwierzytelnianiem, istotne podczas lateral movement

- **Kerberos wymaga nazwy hosta/FQDN**. Jeśli łączysz się przez IP, klient zwykle przechodzi na **NTLM/Negotiate**.
- W **workgroup** lub przypadkach związanych z zaufaniem między domenami NTLM często wymaga użycia **HTTPS** albo dodania celu do **TrustedHosts** na kliencie.
- Przy użyciu lokalnych kont przez Negotiate w workgroup ograniczenia zdalnego UAC mogą uniemożliwić dostęp, chyba że użyto wbudowanego konta Administrator albo ustawiono `LocalAccountTokenFilterPolicy=1`.
- Domyślnie PowerShell remoting używa **`HTTP/<host>` SPN**. W środowiskach, w których **`HTTP/<host>`** jest już zarejestrowany na innym koncie usługi, Kerberos WinRM może zakończyć się błędem `0x80090322`; użyj SPN z określonym portem albo przełącz się na **`WSMAN/<host>`**, jeśli ten SPN istnieje.<sup>[[3]](#references)</sup>

Jeśli podczas password spraying uzyskasz prawidłowe poświadczenia, sprawdzenie ich przez WinRM to często najszybszy sposób, by ustalić, czy pozwalają uzyskać powłokę:

{{#ref}}
../active-directory-methodology/password-spraying.md
{{#endref}}

## Lateral movement z Linux do Windows

### NetExec / CrackMapExec do weryfikacji i jednorazowego wykonania команды

```bash
# Validate creds and execute a simple command
netexec winrm <HOST_FQDN> -u <USER> -p '<PASSWORD>' -x "whoami /all"

# Pass-the-Hash
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -x "hostname"

# PowerShell command instead of cmd.exe
netexec winrm <HOST_FQDN> -u <USER> -H <NTHASH> -X '$PSVersionTable'
```

### Evil-WinRM do interaktywnych shelli

`evil-winrm` pozostaje najwygodniejszą opcją do interaktywnej pracy z Linuksa, ponieważ obsługuje **hasła**, **hashe NT**, **bilety Kerberos**, **certyfikaty klienta**, transfer plików oraz ładowanie PowerShell/.NET do pamięci.

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

Gdy domyślny SPN **`HTTP/<host>`** powoduje problemy z Kerberos, spróbuj zamiast niego zażądać biletu **`WSMAN/<host>`** lub użyć go. Zdarza się to w utwardzonych lub nietypowych środowiskach enterprise, gdzie **`HTTP/<host>`** jest już przypisany do innego konta usługi.<sup>[[3]](#references)</sup>

```bash
# Example: use a WSMAN ticket instead of the default HTTP SPN
export KRB5CCNAME=administrator@WSMAN_srv01.domain.local@DOMAIN.LOCAL.ccache
evil-winrm -i srv01.domain.local -r DOMAIN.LOCAL --spn WSMAN
```

To przydaje się również po nadużyciu **RBCD / S4U**, gdy celowo sfałszowano lub zażądano biletu usługi **WSMAN**, a nie ogólnego biletu `HTTP`.

### Uwierzytelnianie oparte na certyfikatach

WinRM obsługuje również **uwierzytelnianie za pomocą certyfikatu klienta**, ale certyfikat musi być mapowany na hoście docelowym na **konto lokalne**. Z perspektywy ofensywnej ma to znaczenie, gdy:

- skradziono lub wyeksportowano prawidłowy certyfikat klienta i klucz prywatny, które są już mapowane na potrzeby WinRM;
- nadużyto **AD CS / Pass-the-Certificate**, aby uzyskać certyfikat dla podmiotu, a następnie przejść do innej ścieżki uwierzytelniania;
- działa się w środowiskach, które celowo unikają zdalnego dostępu opartego na hasłach.

```bash
evil-winrm -i <HOST_FQDN> -S -c user.crt -k user.key
```

Client-certificate WinRM jest znacznie rzadsze niż uwierzytelnianie hasłem, hashem lub Kerberosem, ale gdy jest dostępne, może zapewnić ścieżkę **ruchu bocznego bez hasła**, która działa nawet po rotacji haseł.

### Python / automatyzacja z `pypsrp`

Jeśli potrzebujesz automatyzacji zamiast operatorskiego shell, `pypsrp` udostępnia WinRM/PSRP z poziomu Pythona i obsługuje **NTLM**, **uwierzytelnianie certyfikatem**, **Kerberos** oraz **CredSSP**.<sup>[[2]](#references)</sup>

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


Jeśli potrzebujesz dokładniejszej kontroli niż zapewnia wysokopoziomowy wrapper `Client`, przydatne są niższopoziomowe API `WSMan` + `RunspacePool` w dwóch typowych sytuacjach:

- wymuszenie **`WSMAN`** jako usługi/SPN Kerberos zamiast domyślnego `HTTP`, którego oczekuje wiele klientów PowerShell;
- łączenie się z **niestandardowym endpointem PSRP**, takim jak **JEA** / niestandardowa konfiguracja sesji, zamiast `Microsoft.PowerShell`.

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

Pomyślne uwierzytelnienie WinRM **nie** zawsze oznacza uzyskanie dostępu do domyślnego, nieograniczonego endpointu `Microsoft.PowerShell`. Dojrzałe środowiska mogą udostępniać **niestandardowe konfiguracje sesji** lub endpointy **JEA** z własnymi listami ACL i ustawieniami uruchamiania.<sup>[[1]](#references)</sup>

Jeśli masz już możliwość wykonywania kodu na hoście Windows i chcesz sprawdzić dostępne powierzchnie zdalnego zarządzania, wylicz zarejestrowane endpointy:

```powershell
Get-PSSessionConfiguration | Select-Object Name, Permission
```

Gdy istnieje użyteczny endpoint, wskaż go jawnie zamiast domyślnego shell:

```powershell
Enter-PSSession -ComputerName srv01.domain.local -ConfigurationName MyJEAEndpoint
```

Praktyczne konsekwencje ofensywne:

- **Ograniczony** endpoint może wystarczyć do lateral movement, jeśli udostępnia odpowiednie cmdlety/funkcje do zarządzania usługami, dostępu do plików, tworzenia procesów lub wykonywania dowolnego kodu .NET / poleceń zewnętrznych.
- **Błędnie skonfigurowana JEA** jest szczególnie cenna, jeśli udostępnia niebezpieczne polecenia, takie jak `Start-Process`, szerokie symbole wieloznaczne, zapisywalne providery lub niestandardowe funkcje proxy pozwalające ominąć założone ograniczenia.
- Endpointy korzystające z **wirtualnych kont RunAs** lub **gMSA** zmieniają efektywny kontekst zabezpieczeń poleceń, które uruchamiasz. W szczególności endpoint oparty na gMSA może zapewnić **tożsamość sieciową przy drugim przeskoku**, nawet gdy zwykła sesja WinRM napotka klasyczny problem delegowania.

W przypadku niestandardowego, ograniczonego endpointu sprawdź osobno efektywne uprawnienia do poleceń i skryptów: krótka lista `Get-Command` sama w sobie nie dowodzi, że nie można uruchomić istniejącego pliku `.ps1`. [Możliwości ról JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) jawnie określają, które ścieżki skryptów można wywołać; inne niestandardowe endpointy mogą stosować odmienne reguły sesji. Jeśli dozwolony skrypt używa zapisanej wartości `SecureString` do utworzenia poświadczeń dla innego hosta, blob utworzony bez jawnie podanego klucza korzysta z [Windows DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) i do odszyfrowania zazwyczaj wymaga kontekstu użytkownika i komputera, które go chroniły. Zanim uznasz zapisywalny kod źródłowy lub skopiowany blob za ścieżkę eskalacji między hostami, sprawdź ACL skryptu, dozwolone sposoby jego wywoływania, tożsamość RunAs i uprawnienia do poświadczeń w dalszych etapach. Podczas pasywnego rozpoznania nie wyświetlaj chronionej wartości.

W przypadku niestandardowej funkcji JEA przyjmującej ścieżkę pliku sprawdź łącznie ACL zarejestrowanego endpointu, przypisaną funkcję roli i efektywną tożsamość RunAs. Wywołujący może mieć `NoLanguage`, podczas gdy treść funkcji działa w domyślnym trybie języka systemu; konto wirtualne może też mieć lokalne uprawnienia administratora. Jeśli funkcja sprawdza dozwolony katalog za pomocą surowego prefiksu tekstowego, a później odczytuje podaną ścieżkę, składniki `..` mogą wskazać lokalizację poza tym katalogiem. Granicę wyznacza rozstrzygnięta ścieżka w kontekście tożsamości funkcji, a nie tryb języka wywołującego ani pozorny prefiks. Zanim uznasz dostępny do odczytu plik `.psrc` lub `.pssc` za podatność pozwalającą na uprzywilejowany odczyt plików, potwierdź, że funkcja jest osiągalna i że waliduje końcową ścieżkę. Zobacz wytyczne Microsoft dotyczące [możliwości ról JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/role-capabilities) i [zagadnień bezpieczeństwa](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations).

## lateral movement w WinRM z użyciem natywnych mechanizmów Windows

### `winrs.exe`

`winrs.exe` jest wbudowanym narzędziem, przydatnym, gdy chcesz **wykonywać polecenia przez natywny WinRM** bez otwierania interaktywnej sesji zdalnej PowerShell:

```cmd
winrs -r:srv01.domain.local cmd /c whoami
winrs -r:https://srv01.domain.local:5986 -u:DOMAIN\\user -p:Password123! hostname
```

Dwie flagi łatwo przeoczyć, a w praktyce mają znaczenie:

- `/noprofile` jest często wymagane, gdy zdalny podmiot **nie** jest lokalnym administratorem.
- `/allowdelegate` umożliwia zdalnej powłoce używanie Twoich poświadczeń w komunikacji z **trzecim hostem** (na przykład gdy polecenie wymaga dostępu do `\\fileserver\share`).

```cmd
winrs -r:srv01.domain.local /noprofile cmd /c set
winrs -r:srv01.domain.local /allowdelegate cmd /c dir \\fileserver.domain.local\share
```

W praktyce `winrs.exe` często tworzy zdalny łańcuch procesów podobny do:

```text
svchost.exe (DcomLaunch) -> winrshost.exe -> cmd.exe /c <command>
```

Warto o tym pamiętać, ponieważ różni się to od service-based exec i interaktywnych sesji PSRP.

### `winrm.cmd` / WS-Man COM zamiast PowerShell remoting

Możesz też wykonywać polecenia przez **transport WinRM** bez użycia `Enter-PSSession`, wywołując klasy WMI przez WS-Man. Transport nadal odbywa się przez WinRM, ale zdalnym mechanizmem wykonywania staje się **WMI `Win32_Process.Create`**:

```cmd
winrm invoke Create wmicimv2/Win32_Process @{CommandLine="cmd.exe /c whoami > C:\\Windows\\Temp\\who.txt"} -r:srv01.domain.local
```

To podejście jest przydatne, gdy:

- Monitorowanie logów PowerShell jest intensywne.
- Chcesz używać **transportu WinRM**, ale nie klasycznego workflow PS remoting.
- Tworzysz własne narzędzia korzystające z obiektu COM **`WSMan.Automation`** lub z nich korzystasz.

## Przekaźnik NTLM do WinRM (WS-Man)

Gdy relay SMB jest blokowany przez wymóg podpisywania, a relay LDAP podlega ograniczeniom, **WS-Man/WinRM** może nadal być atrakcyjnym celem relay. Nowoczesny `ntlmrelayx.py` obsługuje serwery WinRM relay i może przekazywać uwierzytelnianie do celów **`wsman://`** lub **`winrms://`**.

```bash
# Relay to HTTP WinRM
ntlmrelayx.py -t wsman://srv01.domain.local --no-smb-server -smb2support

# Relay to HTTPS WinRM
ntlmrelayx.py -t winrms://srv01.domain.local --no-smb-server -smb2support
```

Dwie praktyczne uwagi:

- Relay jest najbardziej przydatny, gdy cel akceptuje **NTLM**, a przekazywany principal może korzystać z WinRM.
- Nowszy kod Impacket obsługuje żądania **`WSMANIDENTIFY: unauthenticated`**, dzięki czemu sondy w stylu `Test-WSMan` nie przerywają działania Relay.

Informacje o ograniczeniach multi-hop po uzyskaniu pierwszej sesji WinRM znajdziesz tutaj:

{{#ref}}
../active-directory-methodology/kerberos-double-hop-problem.md
{{#endref}}

## Uwagi dotyczące OPSEC i wykrywania

- **Interaktywne zdalne sesje PowerShell** zwykle tworzą na celu proces **`wsmprovhost.exe`**.
- **`winrs.exe`** często tworzy proces **`winrshost.exe`**, a następnie żądany proces potomny.
- Niestandardowe endpointy **JEA** mogą wykonywać działania jako konta wirtualne **`WinRM_VA_*`** lub skonfigurowane **gMSA**, co zmienia zarówno telemetrię, jak i zachowanie przy drugim przeskoku w porównaniu ze zwykłą powłoką działającą w kontekście użytkownika.<sup>[[1]](#references)</sup>
- Jeśli używasz PSRP zamiast surowego `cmd.exe`, spodziewaj się telemetrii logowania sieciowego, zdarzeń usługi WinRM oraz rejestrowania operacyjnego i bloków skryptu PowerShell.
- Jeśli potrzebujesz tylko pojedynczego polecenia, `winrs.exe` lub jednorazowe wykonanie przez WinRM może być mniej widoczne niż długotrwała interaktywna sesja zdalna.
- Jeśli dostępny jest Kerberos, wybierz **FQDN + Kerberos** zamiast IP + NTLM, aby ograniczyć problemy z zaufaniem i kłopotliwe zmiany po stronie klienta w `TrustedHosts`.

## References

- [1] [Microsoft: Zagadnienia bezpieczeństwa JEA](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/security-considerations?view=powershell-7.6)
- [2] [README pypsrp](https://github.com/jborean93/pypsrp)
- [3] [Microsoft: Błąd `0x80090322` podczas łączenia PowerShell ze zdalnym serwerem przez WinRM](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/error-0x80090322-when-connecting-powershell-to-remote-server-via-winrm)
{{#include ../../banners/hacktricks-training.md}}
