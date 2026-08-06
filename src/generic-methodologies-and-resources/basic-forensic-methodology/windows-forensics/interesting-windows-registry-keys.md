# Clés de registre Windows intéressantes

{{#include ../../../banners/hacktricks-training.md}}

Les ruches du registre Windows sont l’un des moyens les plus rapides de passer de _que s’est-il passé ?_ à _quel utilisateur, quand et depuis où ?_. Pour l’analyse en direct, préférez `CurrentControlSet` ; pour l’analyse d’une ruche hors ligne, commencez par déterminer quel `ControlSet00x` était actif au lieu de coder en dur `ControlSet001`.

### Informations sur la version de Windows et le propriétaire

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion` : édition/version de build de Windows, heure d’installation, propriétaire enregistré, nom du produit et autres métadonnées de build.
- `SYSTEM\Select` : associe `Current`, `Default` et `LastKnownGood` aux valeurs `ControlSet00x` réelles utilisées par le système.

### Nom de l’ordinateur

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` : nom d’hôte actuel.

### Configuration du fuseau horaire

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` : fuseau horaire configuré et valeurs liées à l’heure d’été.

### Suivi des heures d’accès

- `SYSTEM\CurrentControlSet\Control\FileSystem` : `NtfsDisableLastAccessUpdate` indique si les horodatages du dernier accès NTFS sont mis à jour.
- Pour l’activer, utilisez : `fsutil behavior set disablelastaccess 0`

### Détails de l’arrêt

- `SYSTEM\CurrentControlSet\Control\Windows` : heure du dernier arrêt.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display` : les systèmes plus anciens peuvent également exposer des compteurs d’arrêt.

### Configuration réseau

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}` : adresses IP des interfaces, baux DHCP, données de passerelle et DNS.<sup>[[1]](#references)</sup>
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` : nom du profil réseau/SSID ainsi que les heures de première et de dernière connexion.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` et `...\Unmanaged\{GUID}` : données de corrélation du profil, telles que l’adresse MAC de la passerelle et le suffixe DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares` : dossiers partagés locaux publiés par l’hôte.

### Historique des accès distants et des partages réseau

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default` : liste MRU RDP sortante (`MRU0`..`MRU9`).<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>` : historique RDP sortant par hôte. Les sous-clés contiennent généralement `UsernameHint`, et l’heure `LastWrite` de la clé constitue un pivot utile.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` : lecteurs réseau mappés, partages UNC et points de montage de supports amovibles associés à un utilisateur donné.

### Programmes démarrés automatiquement et persistance planifiée

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` et `...\Tasks\{GUID}` : métadonnées des tâches planifiées. Si une tâche existe ici mais que la valeur `SD` est absente de `Tree\<TaskName>`, suspectez une falsification de tâche de type Tarrask et mettez-la en corrélation avec `C:\Windows\System32\Tasks\<TaskName>`.

### Recherches, chemins saisis et MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` : termes de recherche de File Explorer.<sup>[[1]](#references)</sup>
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` : chemins Explorer saisis manuellement.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` : les 26 dernières commandes `Win + R`. `MRUList` en conserve l’ordre.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` : documents et dossiers récemment ouverts.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU` : fichiers Office récents.

### Suivi de l’activité utilisateur

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` : historique des exécutions déclenchées par l’interface graphique. Les noms des valeurs sont encodés en ROT13 et les données binaires incluent les compteurs d’exécution ainsi que l’heure de la dernière exécution.<sup>[[1]](#references)</sup>
- Considérez `UserAssist` comme un élément de preuve important, mais pas comme une conclusion autonome : il suit principalement les applications ou fichiers `.lnk` lancés via Explorer et peut manquer les exécutions en ligne de commande ou par un service. À partir de Windows 10, certaines entrées ne signifient pas nécessairement que le processus s’est exécuté complètement.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` et `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}` : traces d’exécution modernes de Windows 10/11 avec attribution au SID et heure de la dernière exécution. Elles sont particulièrement utiles pour les binaires exécutés localement, mais les anciennes entrées peuvent rapidement être supprimées et les exécutions depuis des partages réseau ou des supports amovibles sont moins fiables.
- Pour des artefacts d’exécution plus larges tels que Prefetch, Amcache, ShimCache et SRUM, consultez la [vue d’ensemble de la forensic Windows](README.md#programs-executed).

### Shellbags

- Les Shellbags sont stockés à la fois dans `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` et dans `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.<sup>[[1]](#references)</sup>
- Les entrées `NTUSER.DAT` sont particulièrement utiles pour la navigation UNC/réseau, tandis que `UsrClass.dat` est l’emplacement où Windows Vista+ stocke généralement les Shellbags des dossiers locaux/amovibles.
- Elles peuvent révéler l’existence et la navigation dans des dossiers ainsi que les préférences d’affichage des dossiers, même après la suppression du dossier. Un accès de type Explorer à des fichiers d’archive peut également laisser des traces de Shellbag.<sup>[[1]](#references)</sup>
- Tous les Shellbags ne prouvent pas un accès réussi au dossier ; effectuez donc une corrélation avec les LNK, les Jump Lists, les horodatages ou les mappages de volumes.
- Utilisez **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ou **SBECmd** pour les analyser.

### Informations USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` : inventaire principal des périphériques de stockage de masse USB (fabricant, produit, révision, instance de périphérique/numéro de série).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB` : inventaire USB plus large, incluant les périphériques qui ne sont pas des supports de stockage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}` : dans les builds récentes de Windows 10/11, cet emplacement est particulièrement utile pour les horodatages du cycle de vie par périphérique, tels que l’installation, la première installation, la dernière connexion et la dernière déconnexion.<sup>[[2]](#references)</sup>
- `HKLM\SYSTEM\MountedDevices` : associe les volumes et les identifiants de périphériques aux lettres de lecteur / GUID de volume. Seul le dernier mappage d’une lettre de lecteur donnée peut subsister.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` : pivot utile pour les numéros de série de volumes et les métadonnées des supports précédemment utilisés.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` : historique, propre à l’utilisateur, des interactions avec les lettres de lecteur et les partages.<sup>[[2]](#references)</sup>
- Les téléphones et tablettes modernes connectés via MTP/PTP peuvent **ne pas** apparaître sous `USBSTOR`. Vérifiez également `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` et `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.<sup>[[2]](#references)</sup>
- Pour associer un périphérique à un utilisateur, partez des identifiants du périphérique ou du volume et examinez les artefacts propres à l’utilisateur, tels que les Shellbags, les LNK, les Jump Lists, `RecentDocs` et `MountPoints2`.<sup>[[2]](#references)</sup>

## Références

- [1] [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [2] [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)

{{#include ../../../banners/hacktricks-training.md}}
