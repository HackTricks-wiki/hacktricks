# Golden gMSA/dMSA Attack (dérivation hors ligne des mots de passe des Managed Service Accounts)

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les Managed Service Accounts Windows sont des principaux de domaine destinés à exécuter des services sans qu’un administrateur ait à gérer un mot de passe à longue durée de vie :

1. **gMSA** (group Managed Service Account) peut être utilisé par les ordinateurs autorisés via `msDS-GroupMSAMembership` / `PrincipalsAllowedToRetrieveManagedPassword`.
2. **dMSA** (delegated Managed Service Account) a été introduit dans **Windows Server 2025**. Il lie l’authentification normale aux identités des machines autorisées et peut remplacer un compte de service legacy via un workflow de migration.

Ne confondez pas **Golden dMSA** avec **BadSuccessor**. Golden dMSA nécessite la compromission du matériel de la KDS root key et dérive les clés des managed accounts ; [BadSuccessor](badsuccessor-dmsa-migration-abuse.md) abuse au contraire du contrôle d’un objet dMSA et de ses attributs de migration.

Un DC ne stocke pas un mot de passe en clair généré indépendamment pour chaque gMSA. Il dérive le mot de passe du compte à partir d’une **KDS root key**, d’une clé Group Key Distribution Protocol (GKDI) indexée dans le temps et du SID du compte. Les objets root-key sont des objets `msKds-ProvRootKey` situés sous `CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,...` ; la valeur sensible est `msKds-RootKeyData`. `msDS-ManagedPasswordId` **n’est pas un GUID** : il s’agit d’un identifiant de clé binaire contenant le GUID de la KDS root-key, les index `L0`/`L1`/`L2` de la GKDI, ainsi que les métadonnées du domaine/de la forêt. Le DC applique la KDF avec le label `GMSA PASSWORD` et le SID binaire comme contexte, puis n’expose un `MSDS-MANAGEDPASSWORD_BLOB` qu’aux principaux autorisés à récupérer le mot de passe d’un gMSA.<sup>[[2]](#references)</sup>

Un dMSA diffère normalement sur le plan opérationnel : son secret est censé rester sur le DC et le KDC délivre des credentials à une machine autorisée. Cependant, les dMSA réutilisent le mécanisme sous-jacent de dérivation de mot de passe KDS/GKDI. Golden dMSA reconstruit directement ce secret et contourne ainsi le flux prévu lié à la machine et Credential Guard sur l’hôte de service.<sup>[[1]](#references)</sup>

## Golden gMSA / Golden dMSA Attack

Après avoir extrait une KDS root key, un attaquant peut dériver les mots de passe des comptes associés à cette clé sans lire `msDS-ManagedPassword`. Cela contourne l’ACL de récupération des mots de passe propre à chaque compte et résiste aux rotations ordinaires des managed passwords tant que la root key compromise reste utilisée. Pour les gMSA, `msDS-ManagedPasswordId`, qui est lisible, fournit normalement l’identifiant exact de la clé. Pour les dMSA dont l’ACL est restreinte, Golden dMSA réduit l’identifiant manquant à seulement **1 024 candidats**.<sup>[[1]](#references)[[2]](#references)</sup>

### Prérequis

* L’objet KDS root-key concerné, généralement obtenu avec des droits Enterprise Admin / Domain Admin de la forest-root, `SYSTEM` sur un DC, ou depuis une base de données de DC exposée ou une sauvegarde.<sup>[[1]](#references)[[2]](#references)</sup>
* Le SID du compte cible, le domaine DNS, le nom de la forêt et le `sAMAccountName`.<sup>[[1]](#references)[[2]](#references)</sup>
* Pour le calcul direct d’un gMSA, son `msDS-ManagedPasswordId` encodé en base64 ; pour Golden dMSA, celui-ci peut être deviné.<sup>[[1]](#references)[[2]](#references)</sup>
* Un hôte Windows x64 avec .NET Framework 4.7.2 pour [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA).<sup>[[3]](#references)</sup>

### Phase 1 - Extraire la KDS root key

`GoldenDMSA` et [`GoldenGMSA`](https://github.com/Semperis/GoldenGMSA) exportent les champs de l’objet root-key sous forme de blob base64. Sans argument de domaine, les outils interrogent la forest-root et nécessitent un accès privilégié approprié à l’annuaire. Avec l’argument domaine/forêt, `SYSTEM` sur un DC peut interroger la réplique locale du naming-context Configuration de ce DC.<sup>[[1]](#references)[[2]](#references)</sup>
```cmd
:: GoldenDMSA: Enterprise Admin, or SYSTEM on a DC with --domain
GoldendMSA.exe kds
GoldendMSA.exe kds -g KDS_ROOT_KEY_GUID
GoldendMSA.exe kds --domain child.example.local

:: GoldenGMSA equivalents
GoldenGMSA.exe kdsinfo
GoldenGMSA.exe kdsinfo --guid KDS_ROOT_KEY_GUID
```
Enregistrez à la fois le GUID de la root key et le blob root-key en base64. Un export de ruche de registre `SECURITY`/`SYSTEM` ne constitue pas à lui seul la KDS root key : les données faisant autorité se trouvent dans la partition Configuration d’AD.<sup>[[1]](#references)[[2]](#references)</sup>

### Phase 2 - Énumérer les objets gMSA / dMSA

Pour les gMSA, récupérez `sAMAccountName`, `objectSid` et la valeur binaire `msDS-ManagedPasswordId`. Cette dernière est normalement lisible même lorsque le caller n’est pas autorisé à récupérer `msDS-ManagedPassword`.<sup>[[2]](#references)</sup>
```powershell
Get-ADServiceAccount -Filter * -Properties objectSid,msDS-ManagedPasswordId |
Select-Object sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo --domain example.local
```
L’ACL par défaut d’un dMSA peut empêcher l’énumération LDAP par des utilisateurs peu privilégiés. `GoldenDMSA info` peut soit interroger LDAP, soit énumérer les RIDs candidats et résoudre les SIDs via `LsaLookupSids` sur `\PIPE\lsarpc`, puis distinguer les dMSAs des comptes d’ordinateur et des gMSAs.<sup>[[1]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe info -d example.local -m ldap
GoldendMSA.exe info -d example.local -m brute -u alice -p PASSWORD -o EXAMPLE -r 5000
```
### Phase 3 - Reconstruire ou deviner `msDS-ManagedPasswordId`

L’identifiant de clé inclut `L0Index`, `L1Index` et `L2Index`, et non un horodatage de création de compte suivi de bits aléatoires. Semperis a découvert que le chemin de génération du mot de passe ne consomme pas le `L0Index` candidat, tandis que `L1Index` et `L2Index` sont chacun limités aux valeurs `0..31`. Par conséquent, un attaquant qui connaît le GUID de la root key, le domaine, la forêt et le SID peut construire les `32 * 32 = 1,024` identifiants candidats.<sup>[[1]](#references)</sup>
```cmd
:: Write 1,024 base64 ManagedPasswordId candidates to KDS_ROOT_KEY_GUID.txt
GoldendMSA.exe wordlist -s DMSA_SID -d example.local -f example.local -k KDS_ROOT_KEY_GUID

:: Derive and validate candidates; -t caches the successful TGT
GoldendMSA.exe bruteforce -s DMSA_SID -i KDS_ROOT_KEY_GUID -k KDS_ROOT_KEY_BASE64 -d example.local -u svc_dmsa$ -t
```
Les dérivations sont effectuées hors ligne, mais l’identification du candidat actif nécessite généralement des tentatives d’authentification. Cela peut produire une série d’échecs de pré-authentification Kerberos ou de validation NTLM avant de trouver la clé valide. Pour les clés Kerberos AES, le salt du compte géré utilisé par l’outil est `UPPERCASE.DNS.DOMAIN` + `host` + l’UPN du compte en minuscules, sans le `$` final (par exemple, `EXAMPLE.LOCALhostsvc_dmsa.example.local`).<sup>[[1]](#references)</sup>

### Phase 4 - Calculer et utiliser le mot de passe

Si l’identifiant exact est connu, calculez le buffer de mot de passe de 256 octets et convertissez-le en éléments cryptographiques NTLM/AES. La valeur base64 affichée par ces outils est le buffer de mot de passe encodé, **et non** le `MSDS-MANAGEDPASSWORD_BLOB` LDAP lui-même.<sup>[[2]](#references)[[3]](#references)</sup>
```cmd
GoldendMSA.exe compute -s ACCOUNT_SID -k KDS_ROOT_KEY_BASE64 -d example.local -m MANAGED_PASSWORD_ID_BASE64
GoldendMSA.exe convert -d example.local -u svc_account$ -p BASE64_PASSWORD

GoldenGMSA.exe compute --sid ACCOUNT_SID --kdskey KDS_ROOT_KEY_BASE64 --pwdid MANAGED_PASSWORD_ID_BASE64
```
Le résultat NTLM peut être utilisé là où NTLM est accepté ; la clé AES peut être utilisée pour l’overpass-the-hash / les requêtes TGT lorsque le compte managé est limité à AES. Cela donne les privilèges, les SPN, la configuration de la délégation et l’accès aux ressources du managed service account compromis, sans ajouter la machine de l’attaquant à `PrincipalsAllowedToRetrieveManagedPassword`.<sup>[[1]](#references)[[2]](#references)</sup>

### Abuse de la partition Configuration inter-domaines

Les objets de clé racine KDS résident dans le contexte d’affectation de noms Configuration de la forêt, qui est répliqué vers les DC des domaines enfants. Par conséquent, `SYSTEM` sur un DC d’un domaine enfant peut lire le matériel KDS de la racine de la forêt depuis la réplique locale du DC enfant, même si les Domain Admins du domaine enfant ne peuvent pas lire directement l’objet depuis un DC de la racine de la forêt. Si l’attaquant peut également lire le `msDS-ManagedPasswordId` d’un gMSA du domaine parent, GoldenGMSA peut calculer le mot de passe de ce compte parent ; le filtrage SID n’empêche pas cette attaque cryptographique.<sup>[[5]](#references)</sup>
```cmd
:: Run as SYSTEM on a child.example.local DC
GoldenGMSA.exe kdsinfo --forest child.example.local

:: Query target metadata in the parent, then combine both inputs
GoldenGMSA.exe gmsainfo --domain example.local
GoldenGMSA.exe compute --sid PARENT_GMSA_SID --domain example.local --forest child.example.local
```
## Détection, confinement et récupération

* Configurez une SACL sur le conteneur **Master Root Keys**, héritée par les objets `msKds-ProvRootKey`, pour les lectures réussies de `msKds-RootKeyData`. Avec l'audit Directory Service Access activé, une extraction en ligne produit l'événement de sécurité **4662** ; examinez les sujets qui ne sont pas des DC ou des opérateurs Tier-0 attendus. Auditez également les modifications apportées à ces SACL et aux ACL des objets de clé racine.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>
* Une attaque child-to-parent lit l'objet KDS depuis la réplique locale du DC enfant compromis ; le domaine forest-root peut donc ne pas observer cette lecture. Dans le domaine parent, auditez les lectures réussies de `msDS-ManagedPasswordId` (GUID de schéma `0e78295a-c6d3-0a40-b491-d62251ffa0a6`) sur les objets `msDS-GroupManagedServiceAccount` et examinez les lectures effectuées par des principals provenant d'un autre domaine.<sup>[[5]](#references)</sup>
* Corrélez l'accès aux objets KDS avec les logons inhabituels de comptes managed et les rafales d'échecs Kerberos/NTLM pour les comptes de service suffixés par `$`. Un calcul offline effectué après le vol préalable d'une base de données ou d'une sauvegarde n'est pas visible par un DC actif.<sup>[[1]](#references)[[3]](#references)</sup>
* Une rotation ordinaire des mots de passe ne suffit pas après l'exposition d'une clé racine. La procédure actuelle de récupération de Microsoft crée une nouvelle clé racine KDS, redémarre KDS sur tous les DC concernés et déplace les comptes affectés vers cette clé. Si l'étendue ou la durée de l'exposition est inconnue et qu'attendre un roll sûr est inacceptable, remplacez chaque gMSA ayant utilisé la clé compromise ; si l'étendue est connue, Microsoft documente un workflow d'authoritative-restore pour forcer un rolling sûr. Validez le nouveau GUID de clé dans `msDS-ManagedPasswordId` avant de supprimer l'ancienne clé.<sup>[[4]](#references)</sup>
* Considérez l'accès aux bases de données et aux sauvegardes des DC, la réplication de la partition Configuration et l'administration des clés racines KDS comme Tier-0. Réduire `ManagedPasswordIntervalInDays` limite certaines fenêtres de récupération, mais ne révoque pas une clé racine déjà compromise.<sup>[[4]](#references)</sup>

## Outils

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) - énumération dMSA/gMSA, génération d'identifiants, validation de 1 024 candidats, calcul de mot de passe et conversion NTLM/AES.<sup>[[3]](#references)</sup>
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) - énumération gMSA/KDS et calcul de mots de passe online, offline et cross-domain.<sup>[[2]](#references)</sup>
* [`Rubeus`](https://github.com/GhostPack/Rubeus) et [`Impacket`](https://github.com/fortra/impacket) - utilisez ou validez les clés NTLM/AES dérivées lors de tests autorisés.



## References

- [1] [Golden dMSA - contournement de l'authentification pour les Managed Service Accounts délégués](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [2] [Attaques Active Directory contre les gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)
- [3] [Dépôt GitHub Semperis/GoldenDMSA](https://github.com/Semperis/GoldenDMSA)
- [4] [Microsoft - Comment récupérer après une attaque Golden gMSA](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/recover-from-golden-gmsa-attack)
- [5] [Le filtre SID comme frontière de sécurité entre domaines ? Partie 5 - Attaque de confiance Golden gMSA](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
{{#include ../../banners/hacktricks-training.md}}
