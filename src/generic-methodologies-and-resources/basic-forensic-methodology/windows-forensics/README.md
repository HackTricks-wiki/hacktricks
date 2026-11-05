# Artefacts Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts Windows génériques

### Notifications Windows 10

La base de données des notifications par utilisateur se trouve sous `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (par exemple, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Les premières versions de Windows 10 utilisaient `appdb.dat` ; la mise à jour Anniversary Update (1607) a introduit `wpndatabase.db`. La base de données SQLite contient une table `Notification` avec les charges utiles des notifications et des champs temporels, bien que la durée de conservation et les données disponibles varient selon la version et la politique de nettoyage.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline est une fonctionnalité d’historique des activités qui peut contenir des enregistrements pour les applications prises en charge, les documents et d’autres activités utilisateur ; sa couverture dépend de l’application et de la version de Windows.<sup>[[4]](#references)</sup>

La base de données se trouve à `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Elle peut être ouverte avec SQLite ou analysée avec [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), dont la sortie peut être examinée avec [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### Instantanés Windows Recall (PC Copilot+)

Recall est activé par l’utilisateur sur les PC Copilot+ pris en charge sous Windows 11. Les versions actuelles chiffrent les instantanés et leur index à l’aide de clés liées à Windows Hello et à une enclave VBS. Ne considérez pas une copie hors ligne du stockage comme une base de données SQLite en clair ; l’aperçu de 2024 et la version publiée présentent des propriétés d’accès différentes.<sup>[[77]](#references)</sup>

Dans une **session Recall active et activée**, le processus de rendu `AIXHost.exe` du même utilisateur constitue une autre surface d’accès. La preuve de concept TotalRecall Reloaded injecte une DLL dans ce processus et appelle ses interfaces COM Recall. L’extraction de l’historique complet nécessite toujours que l’utilisateur s’authentifie avec Windows Hello ; il ne s’agit ni d’un déchiffrement hors ligne ni d’un contournement de Hello. Le chercheur a documenté l’outil sous Windows 11 ARM64 ; vérifiez donc sa compatibilité avec la version cible avant de vous y fier.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` utilise `GetRecentCaptureThumbnail` pour demander une version haute résolution de la dernière capture sans Hello. Après autorisation, `--wait` peut extraire des captures d’écran, du texte OCR et des métadonnées par capture, notamment le contexte de l’application et de la fenêtre. Les résultats sont écrits dans un répertoire `extraction_*` horodaté. Ces observations dépendent de la build et proviennent de la preuve de concept ; elles ne garantissent ni que Recall est activé, ni que chaque écran a été capturé.<sup>[[78]](#references)</sup>

### ADS (flux de données alternatifs)

Les fichiers téléchargés depuis l’extérieur de la zone de confiance locale peuvent contenir le **flux de données alternatif `Zone.Identifier`**, qui enregistre des informations de zone et peut inclure des métadonnées d’origine telles qu’une URL. Sa présence et ses champs dépendent du producteur et de la stratégie système.<sup>[[6]](#references)</sup>

## **Sauvegardes de fichiers**

### Corbeille

Sous Vista et les versions ultérieures, la **Corbeille** se trouve dans le dossier **`$Recycle.bin`** à la racine du lecteur (par exemple, `C:\$Recycle.bin`).\
Lorsqu’un fichier est supprimé dans ce dossier, 2 fichiers spécifiques sont créés :

- `$I{id}` : informations sur le fichier, notamment l’heure de suppression et le chemin d’origine
- `$R{id}` : contenu du fichier

![Sauvegardes de fichiers - Corbeille : $R{id} : contenu du fichier](<../../../images/image (1029).png>)

Une fois ces fichiers récupérés, vous pouvez utiliser [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) pour extraire le chemin d’origine et l’heure de suppression (utilisez la version adaptée à la version de Windows cible).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Sauvegardes de fichiers - Corbeille : rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Clichés instantanés de volume

Le service Volume Shadow Copy (VSS) peut créer des clichés instantanés de volumes à un instant donné, même lorsque des fichiers sont en cours d’utilisation ; un cliché instantané ne remplace pas une image forensique.<sup>[[8]](#references)</sup>

Les métadonnées des copies sont généralement associées à `\System Volume Information`, à la racine du volume, avec des identifiants qui varient selon le système :

![Corbeille - Clichés instantanés de volume : ces sauvegardes se trouvent généralement dans System Volume Information, à la racine du système de fichiers, et leur nom est composé d’UID affichés dans le...](<../../../images/image (94).png>)

Après avoir monté une image à l’aide d’un outil de montage forensique adapté, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) peut énumérer les clichés VSS disponibles et permettre de parcourir ou de copier des fichiers depuis ceux-ci.<sup>[[9]](#references)</sup>

![Corbeille - Clichés instantanés de volume : après avoir monté l’image forensique avec ArsenalImageMounter, l’outil ShadowCopyView permet d’inspecter un cliché instantané et même d’en extraire les fichiers...](<../../../images/image (576).png>)

La configuration du rédacteur de registre VSS inclut `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, qui peut spécifier les fichiers et les clés exclus de la sauvegarde :<sup>[[10]](#references)[[11]](#references)</sup>

![Corbeille - Clichés instantanés de volume : l’entrée de registre HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contient les fichiers et les clés à ne pas sauvegarder](<../../../images/image (254).png>)

La clé `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` contient également la configuration du service VSS.<sup>[[8]](#references)</sup>

### Fichiers enregistrés automatiquement par Office

Les emplacements AutoRecover varient selon l’application Office, la version et la configuration. Pour Word, Microsoft indique `%APPDATA%\Microsoft\Word` comme emplacement par défaut ; vérifiez les paramètres de l’application pour connaître le chemin actif.<sup>[[12]](#references)</sup>

## Éléments Shell

Un élément Shell contient des informations sur la manière d’accéder à un autre fichier.

### Documents récents (LNK)

Windows crée généralement des raccourcis vers les éléments récents lorsqu’un utilisateur ouvre un élément ou y accède d’une autre manière :

- Win7-Win10 : `%APPDATA%\Microsoft\Windows\Recent\`
- Office : `%APPDATA%\Microsoft\Office\Recent\`

L’accès à un dossier peut également créer des liens vers ce dossier et les dossiers parents associés.

Ces fichiers de liens peuvent contenir le type de cible, ses horodatages MAC, des informations sur le volume et le chemin de la cible. Ces métadonnées peuvent aider à identifier une cible supprimée, mais cet artefact ne prouve pas à lui seul qu’un utilisateur particulier a ouvert la cible.<sup>[[13]](#references)[[14]](#references)</sup>

Les horodatages du système de fichiers propres au LNK et les horodatages de la cible qu’il contient sont distincts. Ne considérez pas la création du lien comme la première utilisation, ni la modification du lien comme la dernière utilisation, sans artefacts corroborants ; le format stocke les horodatages de la cible séparément de ceux du fichier de lien.<sup>[[13]](#references)[[14]](#references)</sup>

Le lien existant vers [**LinkParser**](http://4discovery.com/our-tools/) est conservé comme option historique, mais sa documentation n’était pas disponible lors de la révision. Pour un analyseur en ligne de commande documenté, utilisez [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Ces outils exposent généralement deux ensembles d’horodatages :

- **Horodatages de la cible :**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Horodatages du fichier de lien :**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Le premier ensemble concerne la cible ; le second concerne le fichier LNK lui-même. Interprétez les deux en vous référant à la documentation de l’analyseur et au contexte du système de fichiers.<sup>[[14]](#references)[[15]](#references)</sup>

Vous pouvez obtenir les mêmes informations en exécutant l’outil CLI Windows : [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

Dans ce cas, les informations seront enregistrées dans un fichier CSV.

### Jumplists

Les Jump Lists sont des listes, propres à chaque application, d’éléments récents ou associés à des tâches spécifiques. Elles peuvent être automatiques ou personnalisées.<sup>[[13]](#references)</sup>

Les Jump Lists automatiques sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` et utilisent des noms tels que `{id}.automaticDestinations-ms`, où l’ID identifie l’application.

Les Jump Lists personnalisées sont stockées dans `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` ; l’application détermine les tâches ou les éléments qu’elles contiennent.

Les dates de création et de modification du système de fichiers décrivent le fichier Jump List, et non automatiquement le premier et le dernier accès à chacune des cibles répertoriées. Recoupez les entrées analysées avec les horodatages du fichier et d’autres artefacts.<sup>[[13]](#references)</sup>

Vous pouvez examiner les Jump Lists avec [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documents récents (LNK) - Jumplists : vous pouvez examiner les jumplists avec JumplistExplorer](<../../../images/image (168).png>)

(_Notez que les horodatages fournis par JumplistExplorer concernent le fichier jumplist lui-même_)

### Shellbags

[**Suivez ce lien pour découvrir ce que sont les shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Utilisation de clés USB sous Windows

L’utilisation d’une clé USB peut parfois être corroborée par les artefacts créés lors de l’accès à des fichiers sur un support amovible, notamment :

- Dossier Windows Recent
- Dossier Microsoft Office Recent
- Jumplists

Des outils comme [**USBDetective**](https://usbdetective.com) recoupent ces artefacts avec les enregistrements des périphériques USB. Leur disponibilité dépend toutefois de la version de Windows et de l’application.<sup>[[18]](#references)</sup>

Lors de tests documentés avec les flux de travail MTP sous Windows XP et Windows 7, certains LNK pointaient vers un dossier `WPDNSE` plutôt que vers le chemin d’origine.<sup>[[16]](#references)</sup>

![Shellbags - Utilisation de clés USB sous Windows : notez que certains fichiers LNK pointent vers le dossier WPDNSE plutôt que vers le chemin d’origine](<../../../images/image (218).png>)

Cette étude a observé des copies dans `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` ; lors des tests, le contenu temporaire ne persistait pas après un redémarrage, et le GUID pouvait être recoupé avec les données des shellbags. Considérez ce comportement comme dépendant du système d’exploitation, du périphérique et de l’application, et non comme une règle universelle.<sup>[[16]](#references)</sup>

### Informations du registre

[Consultez cette page pour découvrir](interesting-windows-registry-keys.md#usb-information) quelles clés de registre contiennent des informations intéressantes sur les périphériques USB connectés.

### setupapi

Sous Vista et les versions ultérieures, examinez `C:\Windows\inf\setupapi.dev.log` pour repérer l’activité d’installation des périphériques. Les en-têtes de section comprennent des horodatages `Section start` ; ils documentent le traitement de l’installation et doivent être recoupés avec d’autres éléments attestant d’une connexion, plutôt que considérés comme l’heure exacte de branchement physique.<sup>[[17]](#references)</sup>

![Informations du registre - setupapi : consultez le fichier C: Windows inf setupapi.dev.log pour obtenir les horodatages de connexion de la clé USB (recherchez Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) permet d’obtenir des informations sur les périphériques USB qui ont été connectés à une image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective : USBDetective permet d’obtenir des informations sur les périphériques USB qui ont été connectés à une image](<../../../images/image (452).png>)

### Nettoyage Plug and Play

La tâche planifiée appelée `Plug and Play Cleanup` supprime les anciennes versions des pilotes. Une définition de tâche Windows 10 documentée par Adam Harrison cible également les pilotes inactifs depuis 30 jours ; les preuves liées aux pilotes de périphériques amovibles peuvent donc être supprimées. Vérifiez la définition locale de la tâche et la version de Windows avant de généraliser ce comportement.<sup>[[1]](#references)</sup>

La tâche se trouve au chemin suivant : `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Définition XML de la tâche planifiée Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Composants clés et paramètres de la tâche :**

- **pnpclean.dll** : cette DLL est responsable du processus de nettoyage proprement dit.
- **UseUnifiedSchedulingEngine** : défini sur `TRUE`, indique l’utilisation du moteur générique de planification des tâches.
- **MaintenanceSettings** :
  - **Period ('P1M')** : demande au Task Scheduler de lancer la tâche de nettoyage tous les mois pendant la maintenance automatique régulière.
  - **Deadline ('P2M')** : demande au Task Scheduler, si la tâche échoue pendant deux mois consécutifs, de l’exécuter pendant la maintenance automatique d’urgence.

Cette configuration planifie une maintenance régulière et des tentatives après des échecs consécutifs ; le XML exact et le comportement dépendent de la version.<sup>[[1]](#references)</sup>

**Pour plus d’informations, consultez :** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-mails

Les e-mails contiennent **2 parties intéressantes : les en-têtes et le contenu** du message. Dans les **en-têtes**, vous pouvez trouver des informations telles que :

- **Qui** a envoyé les e-mails (adresse e-mail, IP, serveurs de messagerie ayant redirigé l’e-mail)
- **Quand** l’e-mail a été envoyé

Les en-têtes `References` et `In-Reply-To` peuvent également contenir des identifiants de message permettant d’associer les réponses à une conversation.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-mails : quand l’e-mail a-t-il été envoyé](<../../../images/image (593).png>)

### Application Windows Mail

Cette application enregistre le contenu des e-mails dans des fichiers texte ou HTML auxiliaires sous des chemins tels que `\Users\<username>\AppData\Local\Comms\Unistore\data\3\` ; le dossier numéroté et l’organisation des fichiers peuvent varier selon l’artefact.<sup>[[75]](#references)</sup>

Les **métadonnées** des e-mails et les **contacts** se trouvent dans la **base de données ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` utilise le format Extensible Storage Engine (ESE). Travaillez sur une copie et utilisez un analyseur ESE tel que [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) ; si un outil exige l’extension `.edb`, renommez uniquement la copie et vérifiez le schéma des tables avant de vous fier à une table `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Lors de l’examen des propriétés MAPI d’Outlook, les propriétés canoniques comprennent :

- `PidTagClientSubmitTime` : heure UTC à laquelle le client a envoyé le message.
- `PidTagConversationIndex` : position relative du message dans un fil de conversation.
- `PidTagEntryId` : identifiant de l’objet message.
- `PidTagMessageFlags` : indicateurs d’état, tels que envoyé, lu, non lu ou avec pièces jointes.
- `PidTagLastVerbExecuted` : dernière opération enregistrée pour le message, comme l’ouverture, la réponse ou le transfert.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

L’emplacement des fichiers de données Outlook varie selon la version et le type de compte. Microsoft documente ces emplacements courants pour les fichiers PST/OST :

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Le chemin de registre `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` peut indiquer le profil Outlook et la configuration des fichiers de données associés.

Les fichiers PST peuvent contenir des messages, des contacts, des données de calendrier et d’autres éléments Outlook. Vous pouvez examiner une copie avec [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Application Windows Mail - Microsoft Outlook : vous pouvez ouvrir le fichier PST avec l’outil Kernel PST Viewer](<../../../images/image (498).png>)

### Fichiers OST de Microsoft Outlook

Un **fichier OST** est un cache local pour les comptes Exchange ou Microsoft 365 ; le mode Exchange mis en cache ne s’applique pas aux comptes POP ou IMAP. La période de disponibilité hors ligne est configurable et est souvent définie par défaut sur 12 mois, tandis que les limites de taille des fichiers PST/OST sont des paramètres distincts et configurables. Pour afficher un fichier OST, vous pouvez utiliser [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Récupération des pièces jointes

Les pièces jointes perdues peuvent parfois être récupérées dans :

- Pour les anciennes configurations Outlook/IE : `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Pour les configurations plus récentes Outlook/IE11 : `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Fichiers MBOX de Thunderbird

**Thunderbird** stocke les données de profil dans `%APPDATA%\Thunderbird\Profiles` ; les dossiers de courrier utilisent généralement des fichiers mbox sans extension dans les répertoires `Mail` ou `ImapMail` propres à chaque compte.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniatures d’images

- **Windows XP** : les aperçus de miniatures étaient généralement stockés dans des fichiers `thumbs.db` propres à chaque dossier.
- **Dossiers réseau** : un fichier `thumbs.db` peut encore être créé pour un dossier UNC lorsque le comportement correspondant des miniatures est activé ; ne partez pas du principe que toutes les versions ou stratégies Windows en créent un.
- **Windows Vista et versions ultérieures** : le cache de miniatures du système est centralisé dans `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, dans des fichiers tels que **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) peut analyser les anciens fichiers `Thumbs.db`, tandis que [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) peut analyser les bases de données modernes du cache de miniatures.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informations du registre Windows

Le registre Windows, qui stocke les données de configuration du système et des utilisateurs, se trouve dans des fichiers de ruches situés dans :

- `%WINDIR%\System32\Config` pour les ruches de la machine correspondant à diverses sous-clés `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` pour la ruche `HKEY_CURRENT_USER` d’un utilisateur.
- Certaines anciennes installations de Windows contiennent des copies dans `%WINDIR%\System32\Config\RegBack\` ; Windows 10 version 1803 et ultérieure ne remplit pas automatiquement ce répertoire, sauf si la sauvegarde périodique est activée.<sup>[[34]](#references)[[35]](#references)</sup>
- Sous Windows moderne, les données de shell et d’enregistrement de classes propres à chaque utilisateur sont également généralement stockées dans `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat`.<sup>[[34]](#references)[[66]](#references)</sup>

### Outils

Certains outils sont utiles pour analyser les ruches du registre ; vérifiez les formats de ruches et les versions pris en charge par chaque outil avant de vous fier à ses résultats :

- **Registry Editor** : il est installé sous Windows. C’est une interface graphique permettant de parcourir le registre Windows de la session en cours.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md) : il permet de charger un fichier de registre et de le parcourir à l’aide d’une interface graphique. Il comprend également des signets qui mettent en évidence les clés contenant des informations intéressantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0) : il comprend également une interface graphique permettant de parcourir le registre chargé, ainsi que des plugins mettant en évidence les informations intéressantes qu’il contient.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html) : une autre application graphique capable d’extraire des informations d’une ruche de registre chargée.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Récupération d’éléments supprimés

Les cellules supprimées d’une ruche peuvent subsister jusqu’à ce que leur espace soit réutilisé, mais la récupération dépend de l’état de la ruche et de l’analyseur. Considérez les clés supprimées récupérées comme des éléments de preuve à valider, et non comme des enregistrements garantis.

### Heure de dernière écriture

Les clés de registre comportent un horodatage de dernière écriture ; Windows l’expose pour la clé ou pour l’une de ses entrées de valeur. Une valeur ne possède donc pas nécessairement son propre horodatage de modification indépendant.<sup>[[69]](#references)</sup>

### SAM

La ruche **SAM** contient les données des comptes d’utilisateurs et de groupes locaux, notamment les hachages de mots de passe protégés par les données de clé de démarrage du système.<sup>[[38]](#references)[[39]](#references)</sup>

Dans `SAM\Domains\Account\Users`, vous pouvez obtenir les identifiants des comptes ainsi que certains champs de connexion et de stratégie. L’extraction hors ligne des hachages nécessite également la ruche `SYSTEM` pour récupérer les données de clé de démarrage correspondantes.<sup>[[38]](#references)[[39]](#references)</sup>

### Entrées intéressantes du registre Windows


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programmes exécutés

### Processus Windows de base

Un [article sur les processus Windows courants](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) est conservé comme lecture complémentaire ; recoupez toute affirmation concernant le comportement des processus avec la documentation Windows à jour et les éléments observés localement.<sup>[[2]](#references)</sup>

### Applications récentes de Windows

Sur les versions de Windows 10 où il est disponible, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contient des sous-clés propres à chaque application, avec des champs tels que l’heure de dernière utilisation et le nombre de lancements. Cet artefact a été supprimé des versions ultérieures ; vérifiez donc la version ciblée.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Sur les systèmes où le Background Activity Moderator est disponible, examinez `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ou le chemin plus récent `...\bam\State\UserSettings\{SID}`. Les valeurs sont indexées par SID utilisateur et peuvent contenir des chemins d’exécutables suivis et des données d’exécution de type FILETIME ; cet artefact dépend de la version et doit être corroboré par d’autres éléments.<sup>[[63]](#references)</sup>

### Windows Prefetch

Le Prefetch met en cache les ressources et les métadonnées de lancement afin d’accélérer le démarrage des programmes.

Les fichiers Prefetch sont stockés sous forme de fichiers `.pf` dans `C:\Windows\Prefetch` ; le format, la durée de conservation et le nombre maximal de fichiers varient selon la version de Windows. Microsoft indique que Windows 8 et les versions ultérieures conservent les huit dernières heures d’exécution et jusqu’à 1024 fichiers ; les anciennes descriptions faisant état de limites fixes ne doivent donc pas être généralisées.<sup>[[13]](#references)</sup>

Le nom de fichier suit généralement le format `{program_name}-{hash}.pf`, le hachage étant dérivé du contexte d’exécution, comme le chemin et les arguments ; Windows 10 et les versions ultérieures peuvent compresser le fichier. La présence d’un fichier constitue un indice utile d’exécution, mais ne prouve pas à elle seule qu’un utilisateur a exécuté le programme ; elle doit être recoupée avec d’autres artefacts.<sup>[[13]](#references)</sup>

Pour examiner ces fichiers, vous pouvez utiliser [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), qui documente l’analyse de répertoires, la sortie CSV/HTML et la prise en charge de la décompression pour les fichiers Prefetch concernés de Windows 10.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** complète Prefetch en s’appuyant sur les habitudes d’utilisation historiques pour améliorer le chargement. Sur les systèmes qui les génèrent, ses fichiers de base de données se trouvent généralement dans `C:\Windows\Prefetch\Ag*.db` ; leur format et leur présence dépendent de la version.<sup>[[41]](#references)</sup>

Ces bases de données peuvent contenir des noms d’applications, des compteurs d’utilisation, des fichiers ou volumes consultés, des chemins et des plages horaires, mais elles ne doivent pas être considérées comme un journal exact des exécutions.<sup>[[41]](#references)</sup>

Le lien existant vers [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) est conservé comme outil d’analyse possible ; avant de l’utiliser, vérifiez sa disponibilité actuelle et les formats de sortie pris en charge dans la documentation de l’outil.

### SRUM

**System Resource Usage Monitor** (SRUM) enregistre l’utilisation des ressources par les applications et les utilisateurs. Introduit dans Windows 8, il stocke les données dans la base de données ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Il fournit les informations suivantes :

- AppID et chemin
- Utilisateur/SID associé à l’enregistrement
- Octets envoyés
- Octets reçus
- Interface réseau
- Durée de connexion
- Durée du processus

La fréquence de collecte et la durée de conservation dépendent de l’implémentation ; ne supposez pas que chaque enregistrement correspond à un intervalle d’exécution exact de 60 minutes.<sup>[[13]](#references)</sup>

Vous pouvez extraire et examiner les données avec [**srum_dump**](https://github.com/MarkBaggett/srum-dump), en utilisant les options documentées pour la version actuelle de l’outil.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

L’**AppCompatCache**, également appelé **ShimCache**, fait partie de l’infrastructure de compatibilité des applications de Windows et enregistre les métadonnées des fichiers utilisées pour les décisions de compatibilité. Le chemin de la ruche, le format des enregistrements, la capacité de conservation et les champs varient selon la version de Windows ; sur les versions modernes de Windows, ShimCache seul ne permet pas de prouver qu’un utilisateur a exécuté un fichier. Analysez la ruche `SYSTEM` concernée avec l’outil [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser), puis recoupez ses résultats avec les artefacts d’exécution.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache) : pour analyser les informations stockées, l’utilisation de l’outil AppCompatCacheParser est recommandée](<../../../images/image (75).png>)

### Amcache

Le fichier **Amcache.hve** est une ruche de registre qui répertorie les applications et les fichiers observés par Windows. Il se trouve généralement à l’emplacement `C:\Windows\AppCompat\Programs\Amcache.hve`.

Il peut contenir des entrées de fichiers associées ou non, des chemins et des valeurs SHA1, mais sa présence constitue une preuve d’inventaire et ne prouve pas, à elle seule, qu’un processus a été exécuté.<sup>[[13]](#references)[[44]](#references)</sup>

Pour extraire et analyser **Amcache.hve**, utilisez l’outil [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Cette commande analyse la ruche et écrit les résultats au format CSV.<sup>[[44]](#references)</sup>

Par exemple :

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Parmi les fichiers CSV générés, `Amcache_Unassociated file entries` peut être utile pour examiner les fichiers qui ne sont associés à aucun programme reconnu.<sup>[[44]](#references)</sup>

### RecentFileCache

Sur les systèmes Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` peut contenir des informations sur les binaires récemment observés ; sa disponibilité et sa signification varient selon la version.

Vous pouvez utiliser [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) pour analyser le fichier.<sup>[[45]](#references)</sup>

### Tâches planifiées

Les éléments liés aux tâches planifiées peuvent se trouver dans `C:\Windows\System32\Tasks` pour les tâches modernes et dans `C:\Windows\Tasks` sous forme de fichiers `.job` pour les tâches héritées ; examinez le format de définition de tâche correspondant au système d’exploitation.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

La base de données du Service Control Manager se trouve sous `SYSTEM\CurrentControlSet\Services` (pour une ruche SYSTEM hors ligne, examinez la clé de l’ensemble de contrôle correspondant) ; elle contient la configuration des services et des pilotes, comme les chemins des exécutables et les types de démarrage.<sup>[[72]](#references)</sup>

### **Windows Store**

Les applications Windows Store installées peuvent être représentées sous `\ProgramData\Microsoft\Windows\AppRepository\`, notamment dans la base de données **`StateRepository-Machine.srd`**. Le schéma et les chemins varient selon la version de Windows.<sup>[[71]](#references)</sup>

La base de données peut contenir des identifiants d’application, des numéros de package et des noms d’affichage. Des lacunes dans les identifiants ne prouvent pas, à elles seules, qu’une application a été désinstallée ; recoupez avec l’état des packages et du registre.

Les enregistrements de packages peuvent également se trouver sous `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documente une sous-clé `Deprovisioned`, spécifique à certaines versions, pour les applications provisionnées supprimées ; ne supposez pas qu’une sous-clé `Deleted` existe sur toutes les versions.<sup>[[70]](#references)</sup>

## Événements Windows

Selon le fournisseur, les événements Windows peuvent contenir :

- La nature de l’événement
- Un horodatage `TimeCreated` à interpréter selon le schéma d’événement et le contexte temporel de l’hôte
- Les utilisateurs concernés
- Les hôtes concernés (nom d’hôte, IP)
- Les ressources consultées (fichiers, dossiers, imprimantes ou services).<sup>[[49]](#references)</sup>

Avant Windows Vista, les journaux d’événements utilisaient généralement l’ancien format binaire, sous `C:\Windows\System32\config` ; Vista et les versions ultérieures utilisent le format Windows Event Log, généralement sous `C:\Windows\System32\winevt\Logs`, où les fichiers `.evtx` contiennent les données d’événement rendues en XML.<sup>[[46]](#references)[[47]](#references)</sup>

Le registre SYSTEM stocke la configuration des canaux sous **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, notamment le chemin d’accès configuré et les paramètres de rétention.<sup>[[47]](#references)</sup>

Ils peuvent être consultés avec Windows Event Viewer (**`eventvwr.msc`**) ou des outils tels que [**Event Log Explorer**](https://eventlogxp.com) et [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Comprendre la journalisation des événements de sécurité Windows

Sous Vista et les versions ultérieures, le canal Security est généralement stocké dans `C:\Windows\System32\winevt\Logs\Security.evtx`. Sa taille maximale et sa stratégie de rétention sont configurables ; avec la journalisation circulaire, les enregistrements les plus anciens peuvent être écrasés lorsque le fichier atteint sa limite. Le canal peut enregistrer les événements d’authentification, de fermeture de session, de privilège, de stratégie d’audit et d’accès aux objets lorsque l’audit correspondant est activé.<sup>[[46]](#references)[[47]](#references)</sup>

### ID d’événement clés pour l’authentification des utilisateurs :

- **Event ID 4624** : ouverture de session réussie sur un compte.<sup>[[50]](#references)</sup>
- **Event ID 4625** : échec d’ouverture de session sur un compte.<sup>[[51]](#references)</sup>
- **Event ID 4634** : une session d’ouverture de session a été terminée.<sup>[[52]](#references)</sup>
- **Event ID 4647** : un utilisateur a lancé une fermeture de session.<sup>[[53]](#references)</sup>
- **Event ID 4672** : des privilèges spéciaux ont été attribués à une nouvelle ouverture de session ; cela est courant pour les comptes système et administrateur et ne prouve donc pas, à lui seul, une activité malveillante.<sup>[[54]](#references)</sup>

#### Types d’ouverture de session couramment consignés dans les événements 4624, 4625, 4634 et 4647 :

- **Interactive (2)** : ouverture de session locale interactive.
- **Network (3)** : accès à une ressource partagée.
- **Batch (4)** : ouverture de session d’un processus batch.
- **Service (5)** : ouverture de session d’un service.
- **Unlock (7)** : déverrouillage d’une station de travail.
- **NetworkCleartext (8)** : ouverture de session réseau fournissant les identifiants en texte clair au package d’authentification.
- **NewCredentials (9)** : ouverture de session utilisant des identifiants alternatifs fournis pour les connexions sortantes.
- **RemoteInteractive (10)** : ouverture de session via Remote Desktop ou Terminal Services.
- **CachedInteractive (11)** : ouverture de session interactive utilisant des identifiants de domaine mis en cache.
- **CachedRemoteInteractive (12)** : ouverture de session distante interactive mise en cache.
- **CachedUnlock (13)** : déverrouillage utilisant des identifiants mis en cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Codes Status et Sub Status de l’événement 4625 :

- **0xC0000064** : utilisateur inexistant.
- **0xC000006A** : nom d’utilisateur correct, mais mot de passe incorrect.
- **0xC0000234** : compte verrouillé.
- **0xC0000072** : compte désactivé.
- **0xC000006F** : ouverture de session en dehors des heures autorisées.
- **0xC0000070** : violation d’une restriction de station de travail.
- **0xC0000193** : compte expiré.
- **0xC0000071** : mot de passe expiré.
- **0xC0000133** : l’écart horaire entre le client et le serveur est trop important.
- **0xC0000224** : le compte doit changer de mot de passe.
- **0xC0000225** : `STATUS_NOT_FOUND` ; ce code seul ne permet pas d’identifier un bogue système ou une attaque.
- **0xC000015B** : le type d’ouverture de session demandé n’est pas accordé au compte.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616 :

- **Changement d’heure** : l’heure système a été modifiée. De nombreux événements reflètent une correction normale par le service de temps ; vérifiez l’acteur et la source horaire avant de conclure à une falsification.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 et 6009 :

- **Contexte d’alimentation et de service** : l’événement 12 consigne le démarrage du système d’exploitation, le 13 son arrêt, le 1074 un arrêt ou redémarrage planifié, le 6008 un arrêt inattendu et le 6009 la version de Windows au démarrage. Les événements 6005 et 6006 indiquent respectivement le démarrage et l’arrêt du service Event Log ; ils ne prouvent pas, à eux seuls, le démarrage et l’arrêt du système d’exploitation.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102 :

- **Suppression du journal** : l’événement 1102 indique que le journal d’audit Security a été effacé ; examinez l’acteur et les événements environnants plutôt que de déduire une intention de cet événement seul.<sup>[[62]](#references)</sup>

#### EventIDs pour le suivi des périphériques USB :

- **20001 / 20003** : événements d’installation de périphérique `UserPnp` pouvant aider à établir une première utilisation ou une activité d’installation.
- **10000 / 10100** : événements `DriverFrameworks-UserMode` pouvant accompagner l’activité d’un périphérique.
- **Event ID 112** : activité `DeviceSetupManager/Admin` pouvant fournir des horodatages liés à l’insertion.
- Le fournisseur, le canal et la signification des événements varient selon la version de Windows ; examinez le nom du fournisseur et la charge utile de l’événement avant de lui attribuer une signification.<sup>[[59]](#references)</sup>

Pour des exemples pratiques sur les types d’ouverture de session et les identifiants associés, consultez le [guide détaillé d’Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Les détails des événements, notamment le type d’ouverture de session, le statut, le sous-statut, l’adresse source et les champs de processus, apportent du contexte à l’événement 4625 ; un code de statut ou des échecs répétés constituent une piste d’enquête, pas une conclusion.<sup>[[51]](#references)[[55]](#references)</sup>

### Récupération des événements Windows

Comme les journaux d’événements sont généralement circulaires, les enregistrements écrasés par le système de journalisation peuvent être irrécupérables. Préservez une image forensique ou une copie de travail avant toute interaction avec un système en fonctionnement ; utilisez un parseur ou un outil de carving validé, tel que **Bulk_extractor**, uniquement après avoir confirmé que sa version prend en charge les données `.evtx` visées, et ne débranchez pas un système en fonctionnement dans le seul but de tenter de récupérer des événements.<sup>[[46]](#references)</sup>

### Identifier les attaques courantes à l’aide des événements Windows

Pour consulter une référence pratique des ID d’événements, voir le lien [Red Team Recipe](https://redteamrecipe.com/event-codes/) et vérifier ses exemples à l’aide de la documentation des fournisseurs ci-dessus.

#### Attaques par force brute

Recoupez les échecs répétés de l’événement 4625 avec une réussite ultérieure de l’événement 4624, le type d’ouverture de session, le statut, la source et le contexte du compte ; cette séquence est un indice à examiner, pas une preuve d’attaque.<sup>[[50]](#references)[[51]](#references)</sup>

#### Changement d’heure

L’événement 4616 consigne les changements de l’heure système, ce qui peut compliquer l’analyse de la chronologie ; comparez-le aux éléments liés au service de temps et à l’hôte.<sup>[[56]](#references)</sup>

#### Suivi des périphériques USB

Les ID d’événements USB dépendent du fournisseur ; recoupez `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 et `DeviceSetupManager/Admin` 112 avec les éléments de SetupAPI et du registre.<sup>[[17]](#references)[[59]](#references)</sup>

#### Événements d’alimentation du système

Utilisez les événements 12/13/1074/6008/6009 pour établir le contexte du démarrage, de l’arrêt, du redémarrage et des coupures d’alimentation inattendues du système d’exploitation ; les événements 6005/6006 marquent le démarrage et l’arrêt du service Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Suppression du journal

L’événement Security 1102 indique que le journal d’audit Security a été effacé ; recoupez-le avec le compte et le processus responsables.<sup>[[62]](#references)</sup>



## References

- [1] [Nettoyage de Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Enquête sur les processus Windows courants](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Un regard de criminalistique numérique sur les notifications de Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Outils de criminalistique numérique d’Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier et flux de données alternatifs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Service Volume Shadow Copy](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Opérations de sauvegarde et de restauration du registre sous VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Clés de registre pour la sauvegarde et la restauration](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problème de performances de Word lié à l’emplacement de récupération automatique](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Guide de réponse aux incidents](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK : format binaire Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Criminalistique USB MTP : identifier les traces d’exfiltration de données](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Entrées du journal d’installation des périphériques SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID et types associés](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Rechercher et transférer des fichiers de données Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Activer le mode Exchange mis en cache](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Seul un sous-ensemble des éléments est synchronisé](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurer les limites de taille des fichiers de données Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profils - Emplacement de stockage des données utilisateur de Thunderbird](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Paramètres de compte Thunderbird et répertoires mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interface IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Ruches du registre](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Le registre système n’est pas sauvegardé dans RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Récupération du registre Windows](https://www.mitec.cz/wrr.html)
- [38] [Modifier le registre à distance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Présentation technique des mots de passe](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Éléments de preuve liés à Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Format des fichiers de journal des événements](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Clé de registre Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Propriété d’événement TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Événement 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Événement 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Événement 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Événement 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Événement 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF : valeurs NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Événement 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Résoudre les redémarrages inattendus à l’aide des journaux d’événements système](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Résoudre les problèmes d’arrêt en cours](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Criminalistique des périphériques de stockage USB sous Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Les types d’ouverture de session Windows expliqués](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Événement 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Gestionnaire d’activité en arrière-plan](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registre - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print cesse d’imprimer les pièces jointes PDF dans Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Fichiers du registre Windows](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Empêcher le retour des applications supprimées lors d’une mise à jour](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT : résultats des tests de FTK et Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Base de données des services installés](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tâches](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Échec des tâches planifiées avec l’erreur « Le service Planificateur de tâches n’est pas disponible »](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Explorer la base de données Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322 : format des messages Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Gérer Recall pour les clients Windows](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
