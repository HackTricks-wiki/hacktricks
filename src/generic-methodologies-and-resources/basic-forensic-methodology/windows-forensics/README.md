# Artefacts Windows

## Artefacts Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts Windows Généraux

### Notifications Windows 10

Dans le chemin `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, vous pouvez trouver la base de données `appdb.dat` (avant l'anniversaire de Windows) ou `wpndatabase.db` (après l'anniversaire de Windows).

À l'intérieur de cette base de données SQLite, vous pouvez trouver la table `Notification` avec toutes les notifications (au format XML) qui peuvent contenir des données intéressantes.

### Chronologie

La chronologie est une caractéristique de Windows qui fournit un **historique chronologique** des pages web visitées, des documents modifiés et des applications exécutées.

La base de données se trouve dans le chemin `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Cette base de données peut être ouverte avec un outil SQLite ou avec l'outil [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **qui génère 2 fichiers pouvant être ouverts avec l'outil** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Flux de Données Alternatifs)

Les fichiers téléchargés peuvent contenir l'**ADS Zone.Identifier** indiquant **comment** il a été **téléchargé** depuis l'intranet, internet, etc. Certains logiciels (comme les navigateurs) ajoutent généralement même **plus** **d'informations** comme l'**URL** d'où le fichier a été téléchargé.

## **Sauvegardes de Fichiers**

### Corbeille

Dans Vista/Win7/Win8/Win10, la **Corbeille** se trouve dans le dossier **`$Recycle.bin`** à la racine du lecteur (`C:\$Recycle.bin`).\
Lorsqu'un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

- `$I{id}` : Informations sur le fichier (date de sa suppression)
- `$R{id}` : Contenu du fichier

![](<../../../images/image (1029).png>)

Avec ces fichiers, vous pouvez utiliser l'outil [**Rifiuti**](https://github.com/abelcheung/rifiuti2) pour obtenir l'adresse originale des fichiers supprimés et la date à laquelle ils ont été supprimés (utilisez `rifiuti-vista.exe` pour Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Copies de Volume Shadow

La copie Shadow est une technologie incluse dans Microsoft Windows qui peut créer des **copies de sauvegarde** ou des instantanés de fichiers ou de volumes d'ordinateur, même lorsqu'ils sont en cours d'utilisation.

Ces sauvegardes se trouvent généralement dans le `\System Volume Information` à la racine du système de fichiers et le nom est composé de **UIDs** montrés dans l'image suivante :

![](<../../../images/image (94).png>)

En montant l'image d'analyse avec **ArsenalImageMounter**, l'outil [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) peut être utilisé pour inspecter une copie shadow et même **extraire les fichiers** des sauvegardes de copies shadow.

![](<../../../images/image (576).png>)

L'entrée de registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contient les fichiers et clés **à ne pas sauvegarder** :

![](<../../../images/image (254).png>)

Le registre `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également des informations de configuration sur les `Copies de Volume Shadow`.

### Fichiers AutoEnregistrés d'Office

Vous pouvez trouver les fichiers autoenregistrés d'Office dans : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Éléments Shell

Un élément shell est un élément qui contient des informations sur la façon d'accéder à un autre fichier.

### Documents Récents (LNK)

Windows **crée automatiquement** ces **raccourcis** lorsque l'utilisateur **ouvre, utilise ou crée un fichier** dans :

- Win7-Win10 : `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office : `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Lorsqu'un dossier est créé, un lien vers le dossier, vers le dossier parent et le dossier grand-parent est également créé.

Ces fichiers de lien créés automatiquement **contiennent des informations sur l'origine** comme s'il s'agit d'un **fichier** **ou** d'un **dossier**, les **temps MAC** de ce fichier, les **informations de volume** où le fichier est stocké et le **dossier du fichier cible**. Ces informations peuvent être utiles pour récupérer ces fichiers en cas de suppression.

De plus, la **date de création du lien** est le premier **moment** où le fichier original a été **utilisé pour la première fois** et la **date** **modifiée** du fichier de lien est le **dernier** **moment** où le fichier d'origine a été utilisé.

Pour inspecter ces fichiers, vous pouvez utiliser [**LinkParser**](http://4discovery.com/our-tools/).

Dans cet outil, vous trouverez **2 ensembles** de timestamps :

- **Premier Ensemble :**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Deuxième Ensemble :**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Le premier ensemble de timestamps fait référence aux **timestamps du fichier lui-même**. Le deuxième ensemble fait référence aux **timestamps du fichier lié**.

Vous pouvez obtenir les mêmes informations en exécutant l'outil CLI Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Dans ce cas, les informations vont être enregistrées dans un fichier CSV.

### Jumplists

Ce sont les fichiers récents qui sont indiqués par application. C'est la liste des **fichiers récents utilisés par une application** auxquels vous pouvez accéder sur chaque application. Ils peuvent être créés **automatiquement ou être personnalisés**.

Les **jumplists** créés automatiquement sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. Les jumplists sont nommés selon le format `{id}.autmaticDestinations-ms` où l'ID initial est l'ID de l'application.

Les jumplists personnalisés sont stockés dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` et ils sont généralement créés par l'application parce que quelque chose **d'important** s'est produit avec le fichier (peut-être marqué comme favori).

Le **temps de création** de tout jumplist indique **la première fois que le fichier a été accédé** et le **temps modifié la dernière fois**.

Vous pouvez inspecter les jumplists en utilisant [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../images/image (168).png>)

(_Notez que les horodatages fournis par JumplistExplorer sont liés au fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour apprendre ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation des USB Windows

Il est possible d'identifier qu'un appareil USB a été utilisé grâce à la création de :

- Dossier Récents de Windows
- Dossier Récents de Microsoft Office
- Jumplists

Notez que certains fichiers LNK au lieu de pointer vers le chemin original, pointent vers le dossier WPDNSE :

![](<../../../images/image (218).png>)

Les fichiers dans le dossier WPDNSE sont une copie des originaux, donc ne survivront pas à un redémarrage du PC et le GUID est pris d'un shellbag.

### Informations sur le Registre

[Consultez cette page pour apprendre](interesting-windows-registry-keys.md#usb-information) quels clés de registre contiennent des informations intéressantes sur les appareils USB connectés.

### setupapi

Vérifiez le fichier `C:\Windows\inf\setupapi.dev.log` pour obtenir les horodatages concernant le moment où la connexion USB a été produite (recherchez `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) peut être utilisé pour obtenir des informations sur les appareils USB qui ont été connectés à une image.

![](<../../../images/image (452).png>)

### Nettoyage Plug and Play

La tâche planifiée connue sous le nom de 'Nettoyage Plug and Play' est principalement conçue pour la suppression des versions de pilotes obsolètes. Contrairement à son objectif spécifié de conserver la dernière version du package de pilotes, des sources en ligne suggèrent qu'elle cible également les pilotes qui ont été inactifs pendant 30 jours. Par conséquent, les pilotes pour les appareils amovibles non connectés au cours des 30 derniers jours peuvent être sujets à suppression.

La tâche est située au chemin suivant : `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Une capture d'écran montrant le contenu de la tâche est fournie : ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants clés et paramètres de la tâche :**

- **pnpclean.dll** : Ce DLL est responsable du processus de nettoyage réel.
- **UseUnifiedSchedulingEngine** : Défini sur `TRUE`, indiquant l'utilisation du moteur de planification de tâches générique.
- **MaintenanceSettings** :
- **Period ('P1M')** : Indique au Planificateur de tâches de lancer la tâche de nettoyage mensuellement lors de la maintenance automatique régulière.
- **Deadline ('P2M')** : Instruits le Planificateur de tâches, si la tâche échoue pendant deux mois consécutifs, d'exécuter la tâche lors de la maintenance automatique d'urgence.

Cette configuration garantit un entretien régulier et un nettoyage des pilotes, avec des dispositions pour réessayer la tâche en cas d'échecs consécutifs.

**Pour plus d'informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## Emails

Les emails contiennent **2 parties intéressantes : Les en-têtes et le contenu** de l'email. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

- **Qui** a envoyé les emails (adresse email, IP, serveurs de messagerie qui ont redirigé l'email)
- **Quand** l'email a été envoyé

De plus, à l'intérieur des en-têtes `References` et `In-Reply-To`, vous pouvez trouver l'ID des messages :

![](<../../../images/image (593).png>)

### Application Mail Windows

Cette application enregistre les emails en HTML ou en texte. Vous pouvez trouver les emails dans des sous-dossiers à l'intérieur de `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Les emails sont enregistrés avec l'extension `.dat`.

Les **métadonnées** des emails et les **contacts** peuvent être trouvés à l'intérieur de la **base de données EDB** : `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Changez l'extension** du fichier de `.vol` à `.edb` et vous pouvez utiliser l'outil [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) pour l'ouvrir. À l'intérieur de la table `Message`, vous pouvez voir les emails.

### Microsoft Outlook

Lorsque des serveurs Exchange ou des clients Outlook sont utilisés, il y aura quelques en-têtes MAPI :

- `Mapi-Client-Submit-Time` : Heure du système lorsque l'email a été envoyé
- `Mapi-Conversation-Index` : Nombre de messages enfants du fil et horodatage de chaque message du fil
- `Mapi-Entry-ID` : Identifiant du message.
- `Mappi-Message-Flags` et `Pr_last_Verb-Executed` : Informations sur le client MAPI (message lu ? non lu ? répondu ? redirigé ? hors du bureau ?)

Dans le client Microsoft Outlook, tous les messages envoyés/reçus, les données de contacts et les données de calendrier sont stockés dans un fichier PST dans :

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin du registre `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indique le fichier qui est utilisé.

Vous pouvez ouvrir le fichier PST en utilisant l'outil [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../images/image (498).png>)

### Fichiers OST de Microsoft Outlook

Un **fichier OST** est généré par Microsoft Outlook lorsqu'il est configuré avec **IMAP** ou un serveur **Exchange**, stockant des informations similaires à un fichier PST. Ce fichier est synchronisé avec le serveur, conservant des données pour **les 12 derniers mois** jusqu'à une **taille maximale de 50 Go**, et est situé dans le même répertoire que le fichier PST. Pour visualiser un fichier OST, le [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) peut être utilisé.

### Récupération des Pièces Jointes

Les pièces jointes perdues pourraient être récupérables à partir de :

- Pour **IE10** : `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Pour **IE11 et supérieur** : `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Fichiers MBOX de Thunderbird

**Thunderbird** utilise des **fichiers MBOX** pour stocker des données, situés à `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Vignettes d'Image

- **Windows XP et 8-8.1** : Accéder à un dossier avec des vignettes génère un fichier `thumbs.db` stockant des aperçus d'images, même après suppression.
- **Windows 7/10** : `thumbs.db` est créé lorsqu'il est accédé via un réseau par un chemin UNC.
- **Windows Vista et versions ultérieures** : Les aperçus de vignettes sont centralisés dans `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` avec des fichiers nommés **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) et [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sont des outils pour visualiser ces fichiers.

### Informations sur le Registre Windows

Le Registre Windows, stockant d'importantes données sur le système et l'activité des utilisateurs, est contenu dans des fichiers dans :

- `%windir%\System32\Config` pour divers sous-clés `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` pour `HKEY_CURRENT_USER`.
- Windows Vista et les versions ultérieures sauvegardent les fichiers de registre `HKEY_LOCAL_MACHINE` dans `%Windir%\System32\Config\RegBack\`.
- De plus, les informations sur l'exécution des programmes sont stockées dans `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` à partir de Windows Vista et Windows 2008 Server.

### Outils

Certains outils sont utiles pour analyser les fichiers de registre :

- **Éditeur de Registre** : Il est installé dans Windows. C'est une interface graphique pour naviguer à travers le registre Windows de la session actuelle.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md) : Il vous permet de charger le fichier de registre et de naviguer à travers eux avec une interface graphique. Il contient également des signets mettant en évidence des clés avec des informations intéressantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : Encore une fois, il a une interface graphique qui permet de naviguer à travers le registre chargé et contient également des plugins qui mettent en évidence des informations intéressantes à l'intérieur du registre chargé.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : Une autre application GUI capable d'extraire les informations importantes du registre chargé.

### Récupération d'Éléments Supprimés

Lorsqu'une clé est supprimée, elle est marquée comme telle, mais tant que l'espace qu'elle occupe n'est pas nécessaire, elle ne sera pas supprimée. Par conséquent, en utilisant des outils comme **Registry Explorer**, il est possible de récupérer ces clés supprimées.

### Dernière Heure d'Écriture

Chaque clé-valeur contient un **horodatage** indiquant la dernière fois qu'elle a été modifiée.

### SAM

Le fichier/hive **SAM** contient les **utilisateurs, groupes et hachages de mots de passe des utilisateurs** du système.

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir le nom d'utilisateur, le RID, la dernière connexion, la dernière tentative de connexion échouée, le compteur de connexion, la politique de mot de passe et quand le compte a été créé. Pour obtenir les **hachages**, vous avez également **besoin** du fichier/hive **SYSTEM**.

### Entrées Intéressantes dans le Registre Windows

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmes Exécutés

### Processus Windows de Base

Dans [ce post](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), vous pouvez apprendre sur les processus Windows communs pour détecter des comportements suspects.

### Applications Récentes Windows

À l'intérieur du registre `NTUSER.DAT` dans le chemin `Software\Microsoft\Current Version\Search\RecentApps`, vous pouvez trouver des sous-clés avec des informations sur l'**application exécutée**, **la dernière fois** qu'elle a été exécutée, et **le nombre de fois** qu'elle a été lancée.

### BAM (Modérateur d'Activité en Arrière-plan)

Vous pouvez ouvrir le fichier `SYSTEM` avec un éditeur de registre et à l'intérieur du chemin `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, vous pouvez trouver des informations sur les **applications exécutées par chaque utilisateur** (notez le `{SID}` dans le chemin) et à **quelle heure** elles ont été exécutées (l'heure est à l'intérieur de la valeur de données du registre).

### Préchargement Windows

Le préchargement est une technique qui permet à un ordinateur de **récupérer silencieusement les ressources nécessaires pour afficher le contenu** auquel un utilisateur **pourrait accéder dans un avenir proche** afin que les ressources puissent être accessibles plus rapidement.

Le préchargement Windows consiste à créer des **caches des programmes exécutés** pour pouvoir les charger plus rapidement. Ces caches sont créés sous forme de fichiers `.pf` dans le chemin : `C:\Windows\Prefetch`. Il y a une limite de 128 fichiers dans XP/VISTA/WIN7 et 1024 fichiers dans Win8/Win10.

Le nom du fichier est créé sous la forme `{program_name}-{hash}.pf` (le hachage est basé sur le chemin et les arguments de l'exécutable). Dans W10, ces fichiers sont compressés. Notez que la seule présence du fichier indique que **le programme a été exécuté** à un moment donné.

Le fichier `C:\Windows\Prefetch\Layout.ini` contient les **noms des dossiers des fichiers qui sont préchargés**. Ce fichier contient **des informations sur le nombre d'exécutions**, **les dates** d'exécution et **les fichiers** **ouverts** par le programme.

Pour inspecter ces fichiers, vous pouvez utiliser l'outil [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) :
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** a le même objectif que le prefetch, **charger les programmes plus rapidement** en prédisant ce qui va être chargé ensuite. Cependant, il ne remplace pas le service de prefetch.\
Ce service générera des fichiers de base de données dans `C:\Windows\Prefetch\Ag*.db`.

Dans ces bases de données, vous pouvez trouver le **nom** du **programme**, le **nombre** d'**exécutions**, les **fichiers** **ouverts**, le **volume** **accédé**, le **chemin** **complet**, les **plages horaires** et les **horodatages**.

Vous pouvez accéder à ces informations en utilisant l'outil [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **surveille** les **ressources** **consommées** **par un processus**. Il est apparu dans W8 et stocke les données dans une base de données ESE située dans `C:\Windows\System32\sru\SRUDB.dat`.

Il fournit les informations suivantes :

- AppID et Chemin
- Utilisateur ayant exécuté le processus
- Octets envoyés
- Octets reçus
- Interface réseau
- Durée de la connexion
- Durée du processus

Ces informations sont mises à jour toutes les 60 minutes.

Vous pouvez obtenir la date de ce fichier en utilisant l'outil [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Le **AppCompatCache**, également connu sous le nom de **ShimCache**, fait partie de la **Base de données de compatibilité des applications** développée par **Microsoft** pour résoudre les problèmes de compatibilité des applications. Ce composant système enregistre divers éléments de métadonnées de fichiers, qui incluent :

- Chemin complet du fichier
- Taille du fichier
- Heure de dernière modification sous **$Standard_Information** (SI)
- Heure de dernière mise à jour du ShimCache
- Drapeau d'exécution du processus

Ces données sont stockées dans le registre à des emplacements spécifiques en fonction de la version du système d'exploitation :

- Pour XP, les données sont stockées sous `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` avec une capacité de 96 entrées.
- Pour Server 2003, ainsi que pour les versions de Windows 2008, 2012, 2016, 7, 8 et 10, le chemin de stockage est `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, accueillant respectivement 512 et 1024 entrées.

Pour analyser les informations stockées, l'outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) est recommandé.

![](<../../../images/image (75).png>)

### Amcache

Le fichier **Amcache.hve** est essentiellement une ruche de registre qui enregistre des détails sur les applications qui ont été exécutées sur un système. Il se trouve généralement à `C:\Windows\AppCompat\Programas\Amcache.hve`.

Ce fichier est notable pour stocker des enregistrements de processus récemment exécutés, y compris les chemins vers les fichiers exécutables et leurs hachages SHA1. Ces informations sont inestimables pour suivre l'activité des applications sur un système.

Pour extraire et analyser les données de **Amcache.hve**, l'outil [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) peut être utilisé. La commande suivante est un exemple de la façon d'utiliser AmcacheParser pour analyser le contenu du fichier **Amcache.hve** et afficher les résultats au format CSV :
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Parmi les fichiers CSV générés, le `Amcache_Unassociated file entries` est particulièrement remarquable en raison des informations riches qu'il fournit sur les entrées de fichiers non associées.

Le fichier CVS le plus intéressant généré est le `Amcache_Unassociated file entries`.

### RecentFileCache

Cet artefact ne peut être trouvé que dans W7 dans `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` et il contient des informations sur l'exécution récente de certains binaires.

Vous pouvez utiliser l'outil [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.

### Tâches planifiées

Vous pouvez les extraire de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` et les lire au format XML.

### Services

Vous pouvez les trouver dans le registre sous `SYSTEM\ControlSet001\Services`. Vous pouvez voir ce qui va être exécuté et quand.

### **Windows Store**

Les applications installées peuvent être trouvées dans `\ProgramData\Microsoft\Windows\AppRepository\`\
Ce dépôt a un **journal** avec **chaque application installée** dans le système à l'intérieur de la base de données **`StateRepository-Machine.srd`**.

À l'intérieur de la table Application de cette base de données, il est possible de trouver les colonnes : "Application ID", "PackageNumber" et "Display Name". Ces colonnes contiennent des informations sur les applications préinstallées et installées et il peut être vérifié si certaines applications ont été désinstallées car les ID des applications installées devraient être séquentiels.

Il est également possible de **trouver des applications installées** à l'intérieur du chemin du registre : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Et **des applications désinstallées** dans : `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Événements Windows

Les informations qui apparaissent dans les événements Windows sont :

- Ce qui s'est passé
- Horodatage (UTC + 0)
- Utilisateurs impliqués
- Hôtes impliqués (nom d'hôte, IP)
- Actifs accédés (fichiers, dossiers, imprimante, services)

Les journaux sont situés dans `C:\Windows\System32\config` avant Windows Vista et dans `C:\Windows\System32\winevt\Logs` après Windows Vista. Avant Windows Vista, les journaux d'événements étaient au format binaire et après, ils sont au **format XML** et utilisent l'extension **.evtx**.

L'emplacement des fichiers d'événements peut être trouvé dans le registre SYSTEM dans **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Ils peuvent être visualisés depuis le Visualiseur d'événements Windows (**`eventvwr.msc`**) ou avec d'autres outils comme [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Comprendre la journalisation des événements de sécurité Windows

Les événements d'accès sont enregistrés dans le fichier de configuration de sécurité situé à `C:\Windows\System32\winevt\Security.evtx`. La taille de ce fichier est ajustable, et lorsque sa capacité est atteinte, les événements plus anciens sont écrasés. Les événements enregistrés incluent les connexions et déconnexions des utilisateurs, les actions des utilisateurs et les modifications des paramètres de sécurité, ainsi que l'accès aux fichiers, dossiers et actifs partagés.

### Identifiants d'événements clés pour l'authentification des utilisateurs :

- **EventID 4624** : Indique qu'un utilisateur s'est authentifié avec succès.
- **EventID 4625** : Signale un échec d'authentification.
- **EventIDs 4634/4647** : Représentent les événements de déconnexion des utilisateurs.
- **EventID 4672** : Indique une connexion avec des privilèges administratifs.

#### Sous-types dans EventID 4634/4647 :

- **Interactive (2)** : Connexion directe de l'utilisateur.
- **Network (3)** : Accès aux dossiers partagés.
- **Batch (4)** : Exécution de processus par lots.
- **Service (5)** : Lancements de services.
- **Proxy (6)** : Authentification par proxy.
- **Unlock (7)** : Écran déverrouillé avec un mot de passe.
- **Network Cleartext (8)** : Transmission de mot de passe en texte clair, souvent depuis IIS.
- **New Credentials (9)** : Utilisation de différentes informations d'identification pour l'accès.
- **Remote Interactive (10)** : Connexion à distance ou services de terminal.
- **Cache Interactive (11)** : Connexion avec des informations d'identification mises en cache sans contact avec le contrôleur de domaine.
- **Cache Remote Interactive (12)** : Connexion à distance avec des informations d'identification mises en cache.
- **Cached Unlock (13)** : Déverrouillage avec des informations d'identification mises en cache.

#### Codes d'état et sous-état pour EventID 4625 :

- **0xC0000064** : Le nom d'utilisateur n'existe pas - Pourrait indiquer une attaque d'énumération de noms d'utilisateur.
- **0xC000006A** : Nom d'utilisateur correct mais mot de passe incorrect - Tentative de devinette de mot de passe ou de force brute possible.
- **0xC0000234** : Compte utilisateur verrouillé - Peut suivre une attaque par force brute entraînant plusieurs échecs de connexion.
- **0xC0000072** : Compte désactivé - Tentatives non autorisées d'accès à des comptes désactivés.
- **0xC000006F** : Connexion en dehors des heures autorisées - Indique des tentatives d'accès en dehors des heures de connexion définies, un signe possible d'accès non autorisé.
- **0xC0000070** : Violation des restrictions de station de travail - Pourrait être une tentative de connexion depuis un emplacement non autorisé.
- **0xC0000193** : Expiration du compte - Tentatives d'accès avec des comptes utilisateurs expirés.
- **0xC0000071** : Mot de passe expiré - Tentatives de connexion avec des mots de passe obsolètes.
- **0xC0000133** : Problèmes de synchronisation horaire - Grandes divergences de temps entre le client et le serveur peuvent indiquer des attaques plus sophistiquées comme le pass-the-ticket.
- **0xC0000224** : Changement de mot de passe obligatoire requis - Changements obligatoires fréquents pourraient suggérer une tentative de déstabiliser la sécurité du compte.
- **0xC0000225** : Indique un bug système plutôt qu'un problème de sécurité.
- **0xC000015b** : Type de connexion refusé - Tentative d'accès avec un type de connexion non autorisé, comme un utilisateur essayant d'exécuter une connexion de service.

#### EventID 4616 :

- **Changement d'heure** : Modification de l'heure système, pourrait obscurcir la chronologie des événements.

#### EventID 6005 et 6006 :

- **Démarrage et arrêt du système** : L'EventID 6005 indique le démarrage du système, tandis que l'EventID 6006 marque son arrêt.

#### EventID 1102 :

- **Suppression de journal** : Les journaux de sécurité étant effacés, ce qui est souvent un signal d'alarme pour couvrir des activités illicites.

#### EventIDs pour le suivi des appareils USB :

- **20001 / 20003 / 10000** : Première connexion de l'appareil USB.
- **10100** : Mise à jour du pilote USB.
- **EventID 112** : Heure de l'insertion de l'appareil USB.

Pour des exemples pratiques sur la simulation de ces types de connexion et d'opportunités de dumping d'informations d'identification, consultez [le guide détaillé d'Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Les détails des événements, y compris les codes d'état et de sous-état, fournissent des informations supplémentaires sur les causes des événements, particulièrement notables dans l'Event ID 4625.

### Récupération des événements Windows

Pour améliorer les chances de récupérer des événements Windows supprimés, il est conseillé d'éteindre l'ordinateur suspect en le débranchant directement. **Bulk_extractor**, un outil de récupération spécifiant l'extension `.evtx`, est recommandé pour tenter de récupérer de tels événements.

### Identification des attaques courantes via les événements Windows

Pour un guide complet sur l'utilisation des identifiants d'événements Windows pour identifier des cyberattaques courantes, visitez [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Attaques par force brute

Identifiables par plusieurs enregistrements EventID 4625, suivis d'un EventID 4624 si l'attaque réussit.

#### Changement d'heure

Enregistré par l'EventID 4616, les changements d'heure système peuvent compliquer l'analyse judiciaire.

#### Suivi des appareils USB

Les EventIDs système utiles pour le suivi des appareils USB incluent 20001/20003/10000 pour l'utilisation initiale, 10100 pour les mises à jour de pilotes, et l'EventID 112 de DeviceSetupManager pour les horodatages d'insertion.

#### Événements d'alimentation système

L'EventID 6005 indique le démarrage du système, tandis que l'EventID 6006 marque l'arrêt.

#### Suppression de journal

L'EventID de sécurité 1102 signale la suppression de journaux, un événement critique pour l'analyse judiciaire.

{{#include ../../../banners/hacktricks-training.md}}
