# Artefacts Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts Windows génériques

### Notifications Windows 10

Dans le chemin `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant Windows anniversary) ou `wpndatabase.db` (après Windows Anniversary).

Dans cette base de données SQLite, vous pouvez trouver la table `Notification` contenant toutes les notifications (au format XML), qui peuvent contenir des données intéressantes.

### Timeline

Timeline est une fonctionnalité de Windows qui fournit un **historique chronologique** des pages web visitées, des documents modifiés et des applications exécutées.

La base de données se trouve dans le chemin `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Les fichiers téléchargés peuvent contenir l'**ADS Zone.Identifier**, indiquant **comment** ils ont été **téléchargés** depuis l'intranet, Internet, etc. Certains logiciels (comme les navigateurs) ajoutent généralement **encore plus** d'**informations**, comme l'**URL** depuis laquelle le fichier a été téléchargé.

## **Sauvegardes de fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** se trouve dans le dossier **`$Recycle.bin`**, à la racine du lecteur (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

- `$I{id}` : Informations sur le fichier (date à laquelle il a été supprimé}
- `$R{id}` : Contenu du fichier

![Sauvegardes de fichiers - Corbeille : $R{id} : Contenu du fichier](<../../../images/image (1029).png>)

Avec ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'emplacement d'origine des fichiers supprimés ainsi que la date à laquelle ils ont été supprimés (utilisez `rifiuti-vista.exe` pour Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Sauvegardes de fichiers - Corbeille : rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Copies fantômes de volume

Shadow Copy est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers ou de volumes informatiques, même lorsqu’ils sont utilisés.

Ces sauvegardes se trouvent généralement dans `\System Volume Information`, à la racine du système de fichiers, et leur nom est composé d’**UIDs**, comme illustré dans l’image suivante :

![Corbeille - Copies fantômes de volume : ces sauvegardes se trouvent généralement dans System Volume Information, à la racine du système de fichiers, et leur nom est composé d’UIDs, comme illustré dans l...](<../../../images/image (94).png>)

Après avoir monté l’image forensics avec **ArsenalImageMounter**, l’outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) peut être utilisé pour inspecter une copie fantôme et même **extraire les fichiers** des sauvegardes de copies fantômes.

![Corbeille - Copies fantômes de volume : après avoir monté l’image forensics avec ArsenalImageMounter, l’outil ShadowCopyView peut être utilisé pour inspecter une copie fantôme et même extraire les fichiers...](<../../../images/image (576).png>)

L’entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et les clés **à ne pas sauvegarder** :

![Corbeille - Copies fantômes de volume : l’entrée de registre HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contient les fichiers et les clés à ne pas sauvegarder](<../../../images/image (254).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Volume Shadow Copies`.

### Fichiers AutoSaved d’Office

Vous pouvez trouver les fichiers autosaved d’Office dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments Shell

Un élément Shell est un élément qui contient des informations sur la manière d’accéder à un autre fichier.

### Documents récents (LNK)

Windows **crée** **automatiquement** ces **raccourcis** lorsque l’utilisateur **ouvre, utilise ou crée un fichier** dans :

- Win7-Win10 : `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office : `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu’un dossier est créé, un lien vers le dossier, vers le dossier parent et vers le dossier grand-parent est également créé.

Ces fichiers de liens créés automatiquement **contiennent des informations sur l’origine**, notamment s’il s’agit d’un **fichier** **ou** d’un **dossier**, les **dates** **MAC** de ce fichier, les **informations de volume** indiquant où le fichier est stocké et le **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers au cas où ils auraient été supprimés.

De plus, la **date de création du fichier de lien** correspond à la première **fois** où le fichier d’origine a été **utilisé** et la **date** de **modification** du fichier de lien correspond à la dernière **fois** où le fichier d’origine a été utilisé.

Pour inspecter ces fichiers, vous pouvez utiliser [**LinkParser**](http://4discovery.com/our-tools/).

Dans cet outil, vous trouverez **2 ensembles** d’horodatages :

- **Premier ensemble :**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Deuxième ensemble :**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Le premier ensemble d’horodatages fait référence aux **horodatages du fichier lui-même**. Le deuxième ensemble fait référence aux **horodatages du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l’outil CLI Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Dans ce cas, les informations vont être enregistrées dans un fichier CSV.

### Jumplists

Il s'agit des fichiers récents indiqués pour chaque application. C'est la liste des **fichiers récemment utilisés par une application** à laquelle vous pouvez accéder depuis chaque application. Ils peuvent être créés **automatiquement ou être personnalisés**.

Les **jumplists** créées automatiquement sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommées selon le format `{id}.autmaticDestinations-ms`, où l'ID initial est l'ID de l'application.

Les jumplists personnalisées sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont généralement créées par l'application parce que quelque chose d'**important** s'est produit avec le fichier (peut-être qu'il a été marqué comme favori).

La **date de création** d'une jumplist indique **la première fois où le fichier a été consulté**, et la **date de modification, la dernière fois**.

Vous pouvez inspecter les jumplists à l'aide de [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Documents récents (LNK) - Jumplists : vous pouvez inspecter les jumplists à l'aide de JumplistExplorer](<../../../images/image (168).png>)

(_Notez que les timestamps fournis par JumplistExplorer concernent le fichier de jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour découvrir ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation de périphériques USB sous Windows

Il est possible d'identifier qu'un périphérique USB a été utilisé grâce à la création de :

- Dossier Windows Recent
- Dossier Microsoft Office Recent
- Jumplists

Notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE :

![Shellbags - Utilisation de périphériques USB sous Windows : notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE](<../../../images/image (218).png>)

Les fichiers du dossier WPDNSE sont des copies des fichiers originaux. Ils ne survivront donc pas à un redémarrage du PC et le GUID est extrait d'un shellbag.

### Informations du registre

[Consultez cette page](interesting-windows-registry-keys.md#usb-information) pour découvrir quelles clés de registre contiennent des informations intéressantes sur les périphériques USB connectés.

### setupapi

Consultez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les timestamps indiquant quand la connexion USB a été établie (recherchez `Section start`).

![Informations du registre - setupapi : consultez le fichier C: Windows inf setupapi.dev.log pour obtenir les timestamps indiquant quand la connexion USB a été établie (recherchez Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![setupapi - USB Detective : USBDetective peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image](<../../../images/image (452).png>)

### Nettoyage Plug and Play

La tâche planifiée appelée « Plug and Play Cleanup » est principalement conçue pour supprimer les versions obsolètes des drivers. Contrairement à son objectif déclaré, qui est de conserver la dernière version du package de drivers, des sources en ligne indiquent qu'elle cible également les drivers inactifs depuis 30 jours. Par conséquent, les drivers de périphériques amovibles qui n'ont pas été connectés au cours des 30 derniers jours peuvent être supprimés.<sup>[[1]](#references)</sup>

La tâche se trouve dans le chemin suivant : `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Une capture d'écran présentant le contenu de la tâche est fournie : ![USB Detective - Nettoyage Plug and Play : la tâche se trouve dans le chemin suivant : C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants et paramètres principaux de la tâche :**

- **pnpclean.dll** : cette DLL est responsable du processus de nettoyage réel.
- **UseUnifiedSchedulingEngine** : défini sur `TRUE`, indiquant l'utilisation du moteur générique de planification des tâches.
- **MaintenanceSettings** :
- **Period ('P1M')** : demande au Task Scheduler de lancer la tâche de nettoyage chaque mois pendant la maintenance automatique normale.
- **Deadline ('P2M')** : indique au Task Scheduler, si la tâche échoue pendant deux mois consécutifs, d'exécuter la tâche pendant la maintenance automatique d'urgence.

Cette configuration garantit une maintenance et un nettoyage réguliers des drivers, avec la possibilité de réessayer la tâche en cas d'échecs consécutifs.

**Pour plus d'informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## Emails

Les emails contiennent **2 parties intéressantes : les en-têtes et le contenu** de l'email. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

- **Qui** a envoyé les emails (adresse email, IP, serveurs de messagerie qui ont redirigé l'email)
- **Quand** l'email a été envoyé

De plus, les en-têtes `References` et `In-Reply-To` contiennent l'ID des messages :

![Nettoyage Plug and Play - Emails : quand l'email a-t-il été envoyé](<../../../images/image (593).png>)

### Application Windows Mail

Cette application enregistre les emails au format HTML ou texte. Vous pouvez trouver les emails dans des sous-dossiers de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Les emails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des emails et les **contacts** se trouvent dans la **base de données EDB** : `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Modifiez l'extension** du fichier de `.vol` vers `.edb` afin de pouvoir utiliser l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) pour l'ouvrir. Dans la table `Message`, vous pouvez voir les emails.

### Microsoft Outlook

Lorsque des serveurs Exchange ou des clients Outlook sont utilisés, certains en-têtes MAPI sont présents :

- `Mapi-Client-Submit-Time` : heure système à laquelle l'email a été envoyé
- `Mapi-Conversation-Index` : nombre de messages enfants du thread et timestamp de chaque message du thread
- `Mapi-Entry-ID` : identifiant du message.
- `Mappi-Message-Flags` et `Pr_last_Verb-Executed` : informations sur le client MAPI (message lu ? non lu ? réponse envoyée ? redirigé ? absence du bureau ?)

Dans le client Microsoft Outlook, tous les messages envoyés/reçus, les données des contacts et les données du calendrier sont stockés dans un fichier PST situé dans :

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin de registre `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indique le fichier utilisé.

Vous pouvez ouvrir le fichier PST à l'aide de l'outil [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Application Windows Mail - Microsoft Outlook : vous pouvez ouvrir le fichier PST à l'aide de l'outil Kernel PST Viewer](<../../../images/image (498).png>)

### Fichiers OST de Microsoft Outlook

Un **fichier OST** est généré par Microsoft Outlook lorsqu'il est configuré avec **IMAP** ou un serveur **Exchange**, et stocke des informations similaires à celles d'un fichier PST. Ce fichier est synchronisé avec le serveur et conserve les données des **12 derniers mois**, jusqu'à une **taille maximale de 50 Go**. Il se trouve dans le même répertoire que le fichier PST. Pour consulter un fichier OST, vous pouvez utiliser [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Récupération des pièces jointes

Les pièces jointes perdues peuvent être récupérables depuis :

- Pour **IE10** : `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Pour **IE11 et versions ultérieures** : `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Fichiers MBOX de Thunderbird

**Thunderbird** utilise des **fichiers MBOX** pour stocker les données, situés dans `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatures d'images

- **Windows XP et 8-8.1** : l'accès à un dossier contenant des miniatures génère un fichier `thumbs.db` stockant les aperçus des images, même après leur suppression.
- **Windows 7/10** : `thumbs.db` est créé lorsque le dossier est consulté via un réseau à l'aide d'un chemin UNC.
- **Windows Vista et versions ultérieures** : les aperçus des miniatures sont centralisés dans `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, avec des fichiers nommés **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) et [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sont des outils permettant de consulter ces fichiers.

### Informations du registre Windows

Le registre Windows, qui stocke de nombreuses données relatives au système et à l'activité des utilisateurs, se trouve dans des fichiers situés dans :

- `%windir%\System32\Config` pour différentes sous-clés de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` pour `HKEY_CURRENT_USER`.
- Windows Vista et les versions ultérieures sauvegardent les fichiers du registre `HKEY_LOCAL_MACHINE` dans `%Windir%\System32\Config\RegBack\`.
- De plus, les informations relatives à l'exécution des programmes sont stockées dans `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` à partir de Windows Vista et Windows 2008 Server.

### Outils

Certains outils sont utiles pour analyser les fichiers du registre :

- **Registry Editor** : il est installé dans Windows. Il s'agit d'une interface graphique permettant de parcourir le registre Windows de la session actuelle.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md) : il permet de charger le fichier du registre et de le parcourir à l'aide d'une interface graphique. Il contient également des signets mettant en évidence les clés contenant des informations intéressantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : il dispose également d'une interface graphique permettant de parcourir le registre chargé et contient des plugins mettant en évidence les informations intéressantes qu'il contient.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : une autre application graphique capable d'extraire les informations importantes du registre chargé.

### Récupération d'un élément supprimé

Lorsqu'une clé est supprimée, elle est marquée comme telle, mais elle n'est pas supprimée tant que l'espace qu'elle occupe n'est pas nécessaire. Par conséquent, à l'aide d'outils tels que **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Last Write Time

Chaque paire clé-valeur contient un **timestamp** indiquant la dernière fois où elle a été modifiée.

### SAM

Le fichier/la ruche **SAM** contient les hashes des **utilisateurs, groupes et mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, la dernière tentative de connexion échouée, le compteur de connexions, la stratégie de mot de passe et la date de création du compte. Pour obtenir les **hashes**, vous avez également **besoin** du fichier/de la ruche **SYSTEM**.

### Entrées intéressantes du registre Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmes exécutés

### Processus Windows de base

Dans [cet article](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), vous pouvez découvrir les processus Windows courants permettant de détecter les comportements suspects.<sup>[[2]](#references)</sup>

### Applications récentes de Windows

Dans le registre `NTUSER.DAT`, à l'emplacement `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés contenant des informations sur **l'application exécutée**, la **dernière fois** où elle a été exécutée et le **nombre de fois** où elle a été lancée.

### BAM (Background Activity Moderator)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de registre et, dans le chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, trouver les informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) ainsi que **l'heure** à laquelle elles ont été exécutées (l'heure se trouve dans la valeur Data du registre).

### Windows Prefetch

Le Prefetch est une technique qui permet à un ordinateur de **récupérer discrètement les ressources nécessaires à l'affichage d'un contenu** auquel un utilisateur **pourrait accéder prochainement**, afin que les ressources soient accessibles plus rapidement.

Le Prefetch de Windows consiste à créer des **caches des programmes exécutés** afin de pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin `C:\Windows\Prefetch`. La limite est de 128 fichiers sous XP/VISTA/WIN7 et de 1024 fichiers sous Win8/Win10.

Le nom du fichier est créé selon le format `{program_name}-{hash}.pf` (le hash est basé sur le chemin et les arguments de l'exécutable). Sous W10, ces fichiers sont compressés. Notez que la simple présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers contenant les fichiers faisant l'objet du Prefetch**. Ce fichier contient des **informations sur le nombre d'exécutions**, les **dates** d'exécution et les **fichiers** **ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) :
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** a le même objectif que prefetch, **charger les programmes plus rapidement** en prédisant ce qui va être chargé ensuite. Cependant, il ne remplace pas le service prefetch.\
Ce service génère des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d’**exécutions**, les **fichiers** **ouverts**, le **volume** **consulté**, le **chemin** **complet**, les **périodes** et les **horodatages**.

Vous pouvez accéder à ces informations à l’aide de l’outil [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **surveille** les **ressources** **consommées** **par un processus**. Il est apparu dans W8 et stocke les données dans une base de données ESE située dans `C:\Windows\System32\sru\SRUDB.dat`.

Il fournit les informations suivantes :

- AppID et chemin
- Utilisateur ayant exécuté le processus
- Octets envoyés
- Octets reçus
- Interface réseau
- Durée de la connexion
- Durée du processus

Ces informations sont mises à jour toutes les 60 minutes.

Vous pouvez obtenir la date à partir de ce fichier à l’aide de l’outil [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

L’**AppCompatCache**, également connu sous le nom de **ShimCache**, fait partie de l’**Application Compatibility Database** développée par **Microsoft** pour résoudre les problèmes de compatibilité des applications. Ce composant système enregistre diverses informations de métadonnées sur les fichiers, notamment :

- Chemin complet du fichier
- Taille du fichier
- Heure de dernière modification sous **$Standard_Information** (SI)
- Heure de dernière mise à jour du ShimCache
- Indicateur d’exécution du processus

Ces données sont stockées dans le registre à des emplacements spécifiques selon la version du système d’exploitation :

- Pour XP, les données sont stockées sous `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, avec une capacité de 96 entrées.
- Pour Server 2003, ainsi que pour les versions Windows 2008, 2012, 2016, 7, 8 et 10, le chemin de stockage est `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, avec une capacité respective de 512 et 1024 entrées.

Pour analyser les informations stockées, il est recommandé d’utiliser l’outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache) : pour analyser les informations stockées, il est recommandé d’utiliser l’outil AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Le fichier **Amcache.hve** est essentiellement une ruche de registre qui consigne les informations relatives aux applications exécutées sur un système. Il se trouve généralement à l’emplacement `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ce fichier est notamment connu pour stocker les enregistrements des processus récemment exécutés, y compris les chemins vers les fichiers exécutables et leurs hachages SHA1. Ces informations sont très utiles pour suivre l’activité des applications sur un système.

Pour extraire et analyser les données du fichier **Amcache.hve**, l’outil [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) peut être utilisé. La commande suivante fournit un exemple d’utilisation d’AmcacheParser pour analyser le contenu du fichier **Amcache.hve** et exporter les résultats au format CSV :
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Parmi les fichiers CSV générés, `Amcache_Unassociated file entries` est particulièrement remarquable en raison des nombreuses informations qu'il fournit sur les entrées de fichiers non associées.

Le fichier CVS généré le plus intéressant est `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artifact peut uniquement être trouvé dans W7 à l'emplacement `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour parser le fichier.

### Scheduled tasks

Vous pouvez les extraire de `C:\Windows\Tasks` ou de `C:\Windows\System32\Tasks` et les lire au format XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui sera exécuté et à quel moment.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository\`\
Ce repository contient un **log** avec **chaque application installée** sur le système, dans la base de données **`StateRepository-Machine.srd`**.

Dans la table Application de cette base de données, il est possible de trouver les colonnes « Application ID », « PackageNumber » et « Display Name ». Ces colonnes contiennent des informations sur les applications préinstallées et installées, et il est possible de déterminer si certaines applications ont été désinstallées, car les IDs des applications installées devraient être séquentiels.

Il est également possible de **trouver les applications installées** dans le chemin du registre : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Et les **applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont :

- Ce qui s'est produit
- Timestamp (UTC + 0)
- Utilisateurs impliqués
- Hosts impliqués (hostname, IP)
- Assets consultés (fichiers, dossiers, imprimantes, services)

Les logs se trouvent dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` après Windows Vista. Avant Windows Vista, les logs d'événements étaient au format binaire ; après cette version, ils sont au **format XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM, à l'emplacement **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés depuis Windows Event Viewer (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendre la journalisation des événements de sécurité Windows

Les événements d'accès sont enregistrés dans le fichier de configuration de sécurité situé à `C:\Windows\System32\winevt\Security.evtx`. La taille de ce fichier est configurable et, lorsque sa capacité est atteinte, les événements les plus anciens sont écrasés. Les événements enregistrés incluent les authentifications et déconnexions des utilisateurs, les actions des utilisateurs et les modifications des paramètres de sécurité, ainsi que les accès aux fichiers, dossiers et assets partagés.

### Principaux Event IDs pour l'authentification des utilisateurs :

- **EventID 4624** : indique qu'un utilisateur s'est authentifié avec succès.
- **EventID 4625** : signale un échec d'authentification.
- **EventIDs 4634/4647** : représentent les événements de déconnexion d'un utilisateur.
- **EventID 4672** : indique une connexion avec des privilèges administratifs.

#### Sous-types dans EventID 4634/4647 :

- **Interactive (2)** : connexion directe d'un utilisateur.
- **Network (3)** : accès à des dossiers partagés.
- **Batch (4)** : exécution de processus batch.
- **Service (5)** : lancement de services.
- **Proxy (6)** : authentification proxy.
- **Unlock (7)** : écran déverrouillé avec un mot de passe.
- **Network Cleartext (8)** : transmission d'un mot de passe en clair, souvent depuis IIS.
- **New Credentials (9)** : utilisation d'autres credentials pour l'accès.
- **Remote Interactive (10)** : connexion via Remote Desktop ou Terminal Services.
- **Cache Interactive (11)** : connexion avec des credentials mis en cache sans contacter le contrôleur de domaine.
- **Cache Remote Interactive (12)** : connexion distante avec des credentials mis en cache.
- **Cached Unlock (13)** : déverrouillage avec des credentials mis en cache.

#### Codes Status et Sub Status pour EventID 4625 :

- **0xC0000064** : le nom d'utilisateur n'existe pas - peut indiquer une attaque d'énumération de noms d'utilisateur.
- **0xC000006A** : nom d'utilisateur correct mais mot de passe incorrect - possible tentative de password guessing ou de brute-force.
- **0xC0000234** : compte utilisateur verrouillé - peut survenir après une attaque brute-force ayant entraîné plusieurs échecs de connexion.
- **0xC0000072** : compte désactivé - tentatives non autorisées d'accès à des comptes désactivés.
- **0xC000006F** : connexion en dehors des horaires autorisés - indique des tentatives d'accès en dehors des horaires définis, ce qui peut signaler un accès non autorisé.
- **0xC0000070** : violation des restrictions du poste de travail - peut être une tentative de connexion depuis un emplacement non autorisé.
- **0xC0000193** : expiration du compte - tentatives d'accès avec des comptes utilisateur expirés.
- **0xC0000071** : mot de passe expiré - tentatives de connexion avec des mots de passe obsolètes.
- **0xC0000133** : problèmes de synchronisation de l'heure - des écarts importants entre le client et le serveur peuvent indiquer des attaques plus sophistiquées comme pass-the-ticket.
- **0xC0000224** : changement obligatoire du mot de passe requis - des changements obligatoires fréquents peuvent suggérer une tentative de déstabilisation de la sécurité du compte.
- **0xC0000225** : indique un bug système plutôt qu'un problème de sécurité.
- **0xC000015b** : type de connexion refusé - tentative d'accès avec un type de connexion non autorisé, comme un utilisateur essayant d'exécuter une connexion de service.

#### EventID 4616 :

- **Time Change** : modification de l'heure système, ce qui peut masquer la timeline des événements.

#### EventID 6005 et 6006 :

- **System Startup and Shutdown** : EventID 6005 indique le démarrage du système, tandis que EventID 6006 indique son arrêt.

#### EventID 1102 :

- **Log Deletion** : effacement des logs de sécurité, souvent un signal d'alerte indiquant une tentative de dissimulation d'activités illicites.

#### EventIDs pour le suivi des périphériques USB :

- **20001 / 20003 / 10000** : première connexion d'un périphérique USB.
- **10100** : mise à jour du driver USB.
- **EventID 112** : moment de l'insertion du périphérique USB.

Pour des exemples pratiques de simulation de ces types de connexion et des opportunités de credential dumping, consultez [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Les détails des événements, y compris les codes status et sub-status, fournissent davantage d'informations sur les causes des événements, en particulier pour l'Event ID 4625.

### Récupération des événements Windows

Pour augmenter les chances de récupérer des événements Windows supprimés, il est conseillé d'éteindre l'ordinateur suspect en le débranchant directement. **Bulk_extractor**, un outil de récupération configuré pour l'extension `.evtx`, est recommandé pour tenter de récupérer ces événements.

### Identification des attaques courantes via les événements Windows

Pour un guide complet sur l'utilisation des Windows Event IDs afin d'identifier les cyberattaques courantes, consultez [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identifiables par plusieurs enregistrements EventID 4625, suivis d'un EventID 4624 si l'attaque réussit.

#### Time Change

Enregistrées par EventID 4616, les modifications de l'heure système peuvent compliquer l'analyse forensic.

#### USB Device Tracking

Les System EventIDs utiles au suivi des périphériques USB incluent 20001/20003/10000 pour la première utilisation, 10100 pour les mises à jour de driver et EventID 112 de DeviceSetupManager pour les timestamps d'insertion.

#### System Power Events

EventID 6005 indique le démarrage du système, tandis que EventID 6006 indique son arrêt.

#### Log Deletion

Security EventID 1102 signale la suppression des logs, un événement critique pour l'analyse forensic.

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
