# Artefacts Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts Windows génériques

### Notifications Windows 10

Dans le chemin `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant Windows anniversary) ou `wpndatabase.db` (après Windows Anniversary).

Dans cette base de données SQLite, vous pouvez trouver la table `Notification` contenant toutes les notifications (au format XML), qui peuvent contenir des données intéressantes.

### Timeline

Timeline est une fonctionnalité de Windows qui fournit un **historique chronologique des pages web visitées, des documents modifiés et des applications exécutées**.

La base de données se trouve dans le chemin `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Les fichiers téléchargés peuvent contenir l'**ADS Zone.Identifier**, indiquant **comment** ils ont été **téléchargés** depuis l'intranet, Internet, etc. Certains logiciels (comme les browsers) ajoutent généralement **davantage** **d'informations**, comme l'**URL** depuis laquelle le fichier a été téléchargé.

## **Sauvegardes de fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** se trouve dans le dossier **`$Recycle.bin`** à la racine du lecteur (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

- `$I{id}` : Informations sur le fichier (date à laquelle il a été supprimé}
- `$R{id}` : Contenu du fichier

![Sauvegardes de fichiers - Corbeille : $R{id} : Contenu du fichier](<../../../images/image (1029).png>)

Avec ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'emplacement d'origine des fichiers supprimés et la date à laquelle ils ont été supprimés (utilisez `rifiuti-vista.exe` pour Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers ou de volumes de l'ordinateur, même lorsqu'ils sont utilisés.

Ces sauvegardes se trouvent généralement dans `\System Volume Information`, à la racine du système de fichiers, et leur nom est composé d'**UID** comme indiqué dans l'image suivante :

![Corbeille - Volume Shadow Copies : Ces sauvegardes se trouvent généralement dans System Volume Information, à la racine du système de fichiers, et leur nom est composé d'UID comme indiqué dans l'image suivante...](<../../../images/image (94).png>)

En montant l'image forensique avec **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) peut être utilisé pour inspecter une shadow copy et même **extraire les fichiers** des sauvegardes de shadow copy.

![Corbeille - Volume Shadow Copies : En montant l'image forensique avec ArsenalImageMounter, l'outil ShadowCopyView peut être utilisé pour inspecter une shadow copy et même extraire les fichiers...](<../../../images/image (576).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et les clés **à ne pas sauvegarder** :

![Corbeille - Volume Shadow Copies : L'entrée de registre HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contient les fichiers et les clés à ne pas sauvegarder](<../../../images/image (254).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Volume Shadow Copies`.

### Fichiers enregistrés automatiquement par Office

Vous pouvez trouver les fichiers enregistrés automatiquement par Office dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments Shell

Un élément Shell est un élément qui contient des informations sur la manière d'accéder à un autre fichier.

### Documents récents (LNK)

Windows **crée** **automatiquement** ces **raccourcis** lorsque l'utilisateur **ouvre, utilise ou crée un fichier** dans :

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu'un dossier est créé, un lien vers le dossier, vers le dossier parent et vers le grand-parent est également créé.

Ces fichiers de lien créés automatiquement **contiennent des informations sur l'origine**, notamment s'il s'agit d'un **fichier** **ou** d'un **dossier**, les **horodatages** **MAC** de ce fichier, les **informations du volume** où le fichier est stocké et le **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers s'ils ont été supprimés.

De plus, la **date de création du lien** est la première **date** à laquelle le fichier d'origine a été **utilisé** et la **date de modification** du fichier de lien correspond à la dernière **date** à laquelle le fichier d'origine a été utilisé.

Pour inspecter ces fichiers, vous pouvez utiliser [**LinkParser**](http://4discovery.com/our-tools/).

Dans cet outil, vous trouverez **2 ensembles** d'horodatages :

- **Premier ensemble :**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Deuxième ensemble :**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Le premier ensemble d'horodatages fait référence aux **horodatages du fichier lui-même**. Le deuxième ensemble fait référence aux **horodatages du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l'outil CLI Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Dans ce cas, les informations vont être enregistrées dans un fichier CSV.

### Jumplists

Il s'agit des fichiers récents indiqués pour chaque application. C'est la liste des **fichiers récemment utilisés par une application**, à laquelle vous pouvez accéder depuis chaque application. Ils peuvent être créés **automatiquement ou manuellement**.

Les **jumplists** créés automatiquement sont enregistrés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommés selon le format `{id}.autmaticDestinations-ms`, où l'ID initial est celui de l'application.

Les jumplists personnalisés sont enregistrés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et sont généralement créés par l'application lorsqu'un événement **important** s'est produit avec le fichier (par exemple, lorsqu'il a été marqué comme favori).

La **date de création** d'une jumplist indique la **première fois où le fichier a été consulté**, tandis que la **date de modification indique la dernière fois**.

Vous pouvez inspecter les jumplists avec [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Recent Documents (LNK) - Jumplists : vous pouvez inspecter les jumplists avec JumplistExplorer](<../../../images/image (168).png>)

(_Notez que les horodatages fournis par JumplistExplorer concernent le fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour découvrir ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation de périphériques USB sous Windows

Il est possible d'identifier qu'un périphérique USB a été utilisé grâce à la création de :

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE :

![Shellbags - Utilisation de périphériques USB sous Windows : notez que certains fichiers LNK, au lieu de pointer vers le chemin d'origine, pointent vers le dossier WPDNSE](<../../../images/image (218).png>)

Les fichiers du dossier WPDNSE sont des copies des fichiers d'origine. Ils ne survivront donc pas au redémarrage du PC et le GUID provient d'un shellbag.

### Informations du Registry

[Consultez cette page pour découvrir](interesting-windows-registry-keys.md#usb-information) quelles clés du Registry contiennent des informations intéressantes sur les périphériques USB connectés.

### setupapi

Consultez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les horodatages indiquant quand la connexion USB a été établie (recherchez `Section start`).

![Informations du Registry - setupapi : consultez le fichier C: Windows inf setupapi.dev.log pour obtenir les horodatages indiquant quand la connexion USB a été établie (recherchez Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image.

![setupapi - USB Detective : USBDetective peut être utilisé pour obtenir des informations sur les périphériques USB qui ont été connectés à une image](<../../../images/image (452).png>)

### Plug and Play Cleanup

La tâche planifiée appelée « Plug and Play Cleanup » est principalement conçue pour supprimer les versions obsolètes des drivers. Contrairement à son objectif déclaré, qui consiste à conserver la dernière version du package de drivers, des sources en ligne indiquent qu'elle cible également les drivers qui sont restés inactifs pendant 30 jours. Par conséquent, les drivers des périphériques amovibles qui n'ont pas été connectés au cours des 30 derniers jours peuvent être supprimés.<sup>[[1]](#references)</sup>

La tâche se trouve à l'emplacement suivant : `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Une capture d'écran présentant le contenu de la tâche est fournie : ![USB Detective - Plug and Play Cleanup : la tâche se trouve à l'emplacement suivant : C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants et paramètres principaux de la tâche :**

- **pnpclean.dll** : cette DLL est responsable du processus de nettoyage proprement dit.
- **UseUnifiedSchedulingEngine** : défini sur `TRUE`, ce qui indique l'utilisation du moteur générique de planification des tâches.
- **MaintenanceSettings** :
- **Period ('P1M')** : demande au Task Scheduler de lancer la tâche de nettoyage chaque mois lors de la maintenance automatique normale.
- **Deadline ('P2M')** : demande au Task Scheduler, si la tâche échoue pendant deux mois consécutifs, d'exécuter la tâche lors de la maintenance automatique d'urgence.

Cette configuration garantit une maintenance et un nettoyage réguliers des drivers, tout en prévoyant une nouvelle tentative d'exécution de la tâche en cas d'échecs consécutifs.

**Pour plus d'informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-mails

Les e-mails contiennent **2 parties intéressantes : les en-têtes et le contenu** de l'e-mail. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

- **Qui** a envoyé les e-mails (adresse e-mail, adresse IP, mail servers ayant redirigé l'e-mail)
- **Quand** l'e-mail a été envoyé

De plus, les en-têtes `References` et `In-Reply-To` contiennent l'ID des messages :

![Plug and Play Cleanup - E-mails : quand l'e-mail a-t-il été envoyé ?](<../../../images/image (593).png>)

### Windows Mail App

Cette application enregistre les e-mails au format HTML ou texte. Vous pouvez trouver les e-mails dans des sous-dossiers de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Les e-mails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des e-mails et les **contacts** se trouvent dans la **base de données EDB** : `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Modifiez l'extension** du fichier de `.vol` à `.edb`, puis utilisez l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) pour l'ouvrir. Dans la table `Message`, vous pouvez voir les e-mails.

### Microsoft Outlook

Lorsque des serveurs Exchange ou des clients Outlook sont utilisés, certains en-têtes MAPI sont présents :

- `Mapi-Client-Submit-Time` : heure système à laquelle l'e-mail a été envoyé
- `Mapi-Conversation-Index` : nombre de messages enfants du thread et horodatage de chaque message du thread
- `Mapi-Entry-ID` : identifiant du message.
- `Mappi-Message-Flags` et `Pr_last_Verb-Executed` : informations sur le client MAPI (message lu ? non lu ? réponse envoyée ? redirigé ? absence du bureau ?)

Dans le client Microsoft Outlook, tous les messages envoyés/reçus, les données des contacts et les données du calendrier sont enregistrés dans un fichier PST situé dans :

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin du Registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indique le fichier utilisé.

Vous pouvez ouvrir le fichier PST avec l'outil [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook : vous pouvez ouvrir le fichier PST avec l'outil Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Un **fichier OST** est généré par Microsoft Outlook lorsqu'il est configuré avec **IMAP** ou un serveur **Exchange**. Il stocke des informations similaires à celles d'un fichier PST. Ce fichier est synchronisé avec le serveur et conserve les données des **12 derniers mois**, jusqu'à une **taille maximale de 50 Go**. Il se trouve dans le même répertoire que le fichier PST. Pour afficher un fichier OST, vous pouvez utiliser [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Récupération des pièces jointes

Les pièces jointes perdues peuvent être récupérables depuis :

- Pour **IE10** : `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Pour **IE11 et versions ultérieures** : `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Fichiers MBOX de Thunderbird

**Thunderbird** utilise des **fichiers MBOX** pour stocker les données, situés dans `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniatures d'images

- **Windows XP et 8-8.1** : l'accès à un dossier contenant des miniatures génère un fichier `thumbs.db` stockant les aperçus des images, même après leur suppression.
- **Windows 7/10** : `thumbs.db` est créé lorsqu'un dossier est consulté sur un réseau via un chemin UNC.
- **Windows Vista et versions ultérieures** : les aperçus des miniatures sont centralisés dans `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, dans des fichiers nommés **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) et [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sont des outils permettant d'afficher ces fichiers.

### Informations du Windows Registry

Le Windows Registry, qui stocke de nombreuses données relatives au système et à l'activité des utilisateurs, se trouve dans les fichiers suivants :

- `%windir%\System32\Config` pour différentes sous-clés de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` pour `HKEY_CURRENT_USER`.
- Windows Vista et les versions ultérieures sauvegardent les fichiers du Registry de `HKEY_LOCAL_MACHINE` dans `%Windir%\System32\Config\RegBack\`.
- De plus, les informations relatives à l'exécution des programmes sont stockées dans `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` depuis Windows Vista et Windows 2008 Server.

### Outils

Certains outils sont utiles pour analyser les fichiers du Registry :

- **Registry Editor** : il est installé dans Windows. Il s'agit d'une interface graphique permettant de naviguer dans le Registry de la session actuelle.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md) : il permet de charger le fichier du Registry et d'y naviguer avec une interface graphique. Il contient également des Bookmarks mettant en évidence les clés contenant des informations intéressantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : il dispose également d'une interface graphique permettant de naviguer dans le Registry chargé et contient des plugins qui mettent en évidence les informations intéressantes qu'il contient.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : une autre application avec interface graphique capable d'extraire les informations importantes du Registry chargé.

### Récupération d'éléments supprimés

Lorsqu'une clé est supprimée, elle est marquée comme telle. Toutefois, elle n'est pas supprimée tant que l'espace qu'elle occupe n'est pas nécessaire. Ainsi, à l'aide d'outils tels que **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Last Write Time

Chaque paire clé-valeur contient un **horodatage** indiquant la dernière fois où elle a été modifiée.

### SAM

Le fichier/hive **SAM** contient les hashes des **utilisateurs, groupes et mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, la dernière tentative de connexion échouée, le compteur de connexions, la password policy et la date de création du compte. Pour obtenir les **hashes**, vous avez également **besoin** du fichier/hive **SYSTEM**.

### Entrées intéressantes dans le Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmes exécutés

### Processus Windows de base

Dans [cet article](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), vous pouvez découvrir les processus Windows courants afin de détecter les comportements suspects.

### Applications récentes de Windows

Dans le Registry `NTUSER.DAT`, à l'emplacement `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés contenant des informations sur **l'application exécutée**, la **dernière fois** où elle a été exécutée et le **nombre de fois** où elle a été lancée.

### BAM (Background Activity Moderator)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de Registry. Dans le chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, vous trouverez des informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) ainsi que l'heure à laquelle elles ont été exécutées (l'heure se trouve dans la valeur Data du Registry).

### Windows Prefetch

Le Prefetch est une technique qui permet à un ordinateur de **récupérer discrètement les ressources nécessaires à l'affichage d'un contenu** auquel un utilisateur **pourrait accéder dans un avenir proche**, afin que les ressources soient accessibles plus rapidement.

Le Windows Prefetch consiste à créer des **caches des programmes exécutés** afin de pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin `C:\Windows\Prefetch`. La limite est de 128 fichiers sous XP/VISTA/WIN7 et de 1024 fichiers sous Win8/Win10.

Le nom du fichier est créé sous la forme `{program_name}-{hash}.pf` (le hash est basé sur le chemin et les arguments de l'exécutable). Sous W10, ces fichiers sont compressés. Notez que la simple présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers des fichiers qui sont préchargés**. Ce fichier contient des **informations sur le nombre d'exécutions**, les **dates** d'exécution et les **fichiers** **ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** a le même objectif que prefetch : **charger les programmes plus rapidement** en prédisant ce qui sera chargé ensuite. Cependant, il ne remplace pas le service prefetch.\
Ce service génère des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin** **complet**, les **périodes** et les **horodatages**.

Vous pouvez accéder à ces informations à l'aide de l'outil [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

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

Vous pouvez obtenir les données de ce fichier à l'aide de l'outil [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

L’**AppCompatCache**, également connu sous le nom de **ShimCache**, fait partie de l’**Application Compatibility Database** développée par **Microsoft** pour résoudre les problèmes de compatibilité des applications. Ce composant du système enregistre différents éléments de métadonnées des fichiers, notamment :

- Chemin complet du fichier
- Taille du fichier
- Heure de dernière modification sous **$Standard_Information** (SI)
- Heure de dernière mise à jour du ShimCache
- Indicateur d’exécution du processus

Ces données sont stockées dans le registre à des emplacements spécifiques selon la version du système d’exploitation :

- Pour XP, les données sont stockées sous `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, avec une capacité de 96 entrées.
- Pour Server 2003, ainsi que pour les versions Windows 2008, 2012, 2016, 7, 8 et 10, le chemin de stockage est `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`, avec respectivement 512 et 1024 entrées.

Pour analyser les informations stockées, il est recommandé d’utiliser l’outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache) : pour analyser les informations stockées, il est recommandé d’utiliser l’outil AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

Le fichier **Amcache.hve** est essentiellement une ruche du registre qui enregistre des informations sur les applications exécutées sur un système. Il se trouve généralement à l’emplacement `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ce fichier est particulièrement important, car il stocke les enregistrements des processus récemment exécutés, notamment les chemins vers les fichiers exécutables et leurs hachages SHA1. Ces informations sont très utiles pour suivre l’activité des applications sur un système.

Pour extraire et analyser les données du fichier **Amcache.hve**, l’outil [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) peut être utilisé. La commande suivante montre comment utiliser AmcacheParser pour analyser le contenu du fichier **Amcache.hve** et exporter les résultats au format CSV :
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Parmi les fichiers CSV générés, `Amcache_Unassociated file entries` est particulièrement remarquable en raison des nombreuses informations qu'il fournit sur les entrées de fichiers non associées.

Le fichier CSV généré le plus intéressant est `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artefact peut uniquement être trouvé dans W7, à l'emplacement `C:\Windows\AppCompat\Programs\RecentFileCache.bcf`, et contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire depuis `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire au format XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui sera exécuté et à quel moment.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository`\
Ce référentiel contient un **journal** de **chaque application installée** sur le système dans la base de données **`StateRepository-Machine.srd`**.

Dans la table Application de cette base de données, il est possible de trouver les colonnes suivantes : « Application ID », « PackageNumber » et « Display Name ». Ces colonnes contiennent des informations sur les applications préinstallées et installées. Il est également possible de déterminer si certaines applications ont été désinstallées, car les ID des applications installées devraient être séquentiels.

Il est également possible de **trouver les applications installées** dans le chemin de registre suivant : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\
Et les **applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont les suivantes :

- Ce qui s'est passé
- Horodatage (UTC + 0)
- Utilisateurs impliqués
- Hôtes impliqués (nom d'hôte, IP)
- Ressources consultées (fichiers, dossiers, imprimantes, services)

Les journaux se trouvent dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` à partir de Windows Vista. Avant Windows Vista, les journaux d'événements étaient au format binaire. Ensuite, ils sont au **format XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM, sous **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés depuis l'Observateur d'événements Windows (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendre la journalisation des événements de sécurité Windows

Les événements d'accès sont enregistrés dans le fichier de configuration de sécurité situé à `C:\Windows\System32\winevt\Security.evtx`. La taille de ce fichier est configurable et, lorsque sa capacité est atteinte, les événements les plus anciens sont écrasés. Les événements enregistrés incluent les connexions et déconnexions des utilisateurs, les actions des utilisateurs et les modifications des paramètres de sécurité, ainsi que l'accès aux fichiers, dossiers et ressources partagées.

### ID d'événements clés pour l'authentification des utilisateurs :

- **EventID 4624** : indique qu'un utilisateur s'est authentifié avec succès.
- **EventID 4625** : signale un échec d'authentification.
- **EventIDs 4634/4647** : représentent les événements de déconnexion d'un utilisateur.
- **EventID 4672** : indique une connexion avec des privilèges administratifs.

#### Sous-types de EventID 4634/4647 :

- **Interactive (2)** : connexion directe d'un utilisateur.
- **Network (3)** : accès à des dossiers partagés.
- **Batch (4)** : exécution de processus batch.
- **Service (5)** : lancement de services.
- **Proxy (6)** : authentification proxy.
- **Unlock (7)** : écran déverrouillé avec un mot de passe.
- **Network Cleartext (8)** : transmission d'un mot de passe en clair, souvent depuis IIS.
- **New Credentials (9)** : utilisation d'identifiants différents pour l'accès.
- **Remote Interactive (10)** : connexion via Remote Desktop ou terminal services.
- **Cache Interactive (11)** : connexion avec des identifiants mis en cache, sans contact avec le contrôleur de domaine.
- **Cache Remote Interactive (12)** : connexion distante avec des identifiants mis en cache.
- **Cached Unlock (13)** : déverrouillage avec des identifiants mis en cache.

#### Codes Status et Sub Status pour EventID 4625 :

- **0xC0000064** : le nom d'utilisateur n'existe pas - peut indiquer une attaque d'énumération de noms d'utilisateur.
- **0xC000006A** : nom d'utilisateur correct, mais mot de passe incorrect - possible tentative de deviner le mot de passe ou de brute force.
- **0xC0000234** : compte utilisateur verrouillé - peut suivre une attaque de brute force ayant entraîné plusieurs échecs de connexion.
- **0xC0000072** : compte désactivé - tentatives non autorisées d'accès à des comptes désactivés.
- **0xC000006F** : connexion en dehors des horaires autorisés - indique des tentatives d'accès en dehors des heures de connexion définies, ce qui peut signaler un accès non autorisé.
- **0xC0000070** : violation des restrictions de station de travail - peut correspondre à une tentative de connexion depuis un emplacement non autorisé.
- **0xC0000193** : expiration du compte - tentatives d'accès avec des comptes utilisateur expirés.
- **0xC0000071** : mot de passe expiré - tentatives de connexion avec des mots de passe obsolètes.
- **0xC0000133** : problèmes de synchronisation de l'heure - des écarts importants entre le client et le serveur peuvent indiquer des attaques plus sophistiquées telles que pass-the-ticket.
- **0xC0000224** : changement de mot de passe obligatoire - des changements obligatoires fréquents peuvent suggérer une tentative de déstabilisation de la sécurité du compte.
- **0xC0000225** : indique un bug système plutôt qu'un problème de sécurité.
- **0xC000015b** : type de connexion refusé - tentative d'accès avec un type de connexion non autorisé, par exemple lorsqu'un utilisateur tente d'exécuter une connexion de service.

#### EventID 4616 :

- **Time Change** : modification de l'heure système, pouvant masquer la chronologie des événements.

#### EventID 6005 et 6006 :

- **Démarrage et arrêt du système** : EventID 6005 indique le démarrage du système, tandis que EventID 6006 indique son arrêt.

#### EventID 1102 :

- **Suppression des journaux** : effacement des journaux de sécurité, ce qui constitue souvent un signal d'alerte indiquant une tentative de dissimulation d'activités illicites.

#### EventIDs pour le suivi des périphériques USB :

- **20001 / 20003 / 10000** : première connexion d'un périphérique USB.
- **10100** : mise à jour du pilote USB.
- **EventID 112** : heure d'insertion du périphérique USB.

Pour des exemples pratiques de simulation de ces types de connexion et des possibilités de credential dumping, consultez le guide détaillé d'[Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Les détails des événements, notamment les codes Status et Sub Status, fournissent davantage d'informations sur les causes des événements, en particulier pour Event ID 4625.

### Récupération des événements Windows

Pour augmenter les chances de récupérer des événements Windows supprimés, il est conseillé d'éteindre l'ordinateur suspect en le débranchant directement. **Bulk_extractor**, un outil de récupération configuré avec l'extension `.evtx`, est recommandé pour tenter de récupérer ces événements.

### Identification des attaques courantes grâce aux événements Windows

Pour obtenir un guide complet sur l'utilisation des Windows Event IDs afin d'identifier les cyberattaques courantes, consultez [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Attaques par brute force

Elles sont identifiables par plusieurs enregistrements EventID 4625, suivis d'un EventID 4624 si l'attaque réussit.

#### Changement d'heure

Enregistrées par EventID 4616, les modifications de l'heure système peuvent compliquer l'analyse forensic.

#### Suivi des périphériques USB

Les System EventIDs utiles pour le suivi des périphériques USB incluent 20001/20003/10000 pour la première utilisation, 10100 pour les mises à jour de pilotes et EventID 112 de DeviceSetupManager pour les horodatages d'insertion.

#### Événements d'alimentation du système

EventID 6005 indique le démarrage du système, tandis que EventID 6006 indique son arrêt.

#### Suppression des journaux

Security EventID 1102 signale la suppression des journaux, un événement critique pour l'analyse forensic.

## Références

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
