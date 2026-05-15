# Clés de registre Windows intéressantes

{{#include ../../../banners/hacktricks-training.md}}

Les hives du Windows Registry sont l’un des moyens les plus rapides pour passer de _que s’est-il passé ?_ à _quel utilisateur, quand et d’où ?_. Pour l’analyse en direct, privilégiez `CurrentControlSet`; pour l’analyse hors ligne, commencez par résoudre quel `ControlSet00x` était actif au lieu de coder en dur `ControlSet001`.

### Version de Windows et informations sur le propriétaire

- `SOFTWARE\Microsoft\Windows NT\CurrentVersion`: édition/build de Windows, heure d’installation, propriétaire enregistré, nom du produit et autres métadonnées de build.
- `SYSTEM\Select`: mappe `Current`, `Default` et `LastKnownGood` vers les vraies valeurs `ControlSet00x` utilisées par le système.

### Nom de l’ordinateur

- `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`: nom d’hôte actuel.

### Paramètre de fuseau horaire

- `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`: fuseau horaire configuré et valeurs liées au DST.

### Suivi du temps d’accès

- `SYSTEM\CurrentControlSet\Control\FileSystem`: `NtfsDisableLastAccessUpdate` indique si les horodatages du dernier accès NTFS sont mis à jour.
- Pour l’activer, utilisez : `fsutil behavior set disablelastaccess 0`

### Détails de l’arrêt

- `SYSTEM\CurrentControlSet\Control\Windows`: heure du dernier arrêt.
- `SYSTEM\CurrentControlSet\Control\Watchdog\Display`: les anciens systèmes peuvent aussi exposer des compteurs d’arrêt.

### Configuration réseau

- `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`: adresses IP des interfaces, baux DHCP, passerelle et données DNS.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}`: nom du profil réseau/SSID ainsi que les heures de première et dernière connexion.
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\{GUID}` et `...\Unmanaged\{GUID}`: données de corrélation du profil comme l’adresse MAC de la passerelle et le suffixe DNS.
- `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`: dossiers partagés locaux publiés par l’hôte.

### Accès distant et historique des partages réseau

- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default`: liste MRU RDP sortante (`MRU0`..`MRU9`).
- `NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<target>`: historique RDP sortant par hôte. Les sous-clés stockent souvent `UsernameHint`, et l’heure `LastWrite` de la clé est un pivot utile.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: lecteurs réseau mappés, partages UNC et points de montage de supports amovibles liés à un utilisateur spécifique.

### Programmes qui se lancent automatiquement et persistance planifiée

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` et `...\Tasks\{GUID}`: métadonnées des tâches planifiées. Si une tâche existe ici mais que la valeur `SD` manque dans `Tree\<TaskName>`, suspectez une altération cachée de type Tarrask et corrélez avec `C:\Windows\System32\Tasks\<TaskName>`.

### Recherches, chemins saisis et MRU

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`: termes de recherche de File Explorer.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`: chemins Explorer saisis manuellement.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`: les 26 dernières commandes `Win + R`. `MRUList` conserve leur ordre.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`: documents et dossiers ouverts récemment.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`
- `NTUSER.DAT\Software\Microsoft\Office\<VERSION>\UserMRU\*\FileMRU`: fichiers Office récents.

### Suivi de l’activité utilisateur

- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`: historique d’exécution piloté par l’interface graphique. Les noms des valeurs sont encodés en ROT13, et les données binaires incluent les compteurs d’exécution et l’heure du dernier lancement.
- Traitez `UserAssist` comme une preuve de soutien solide, pas comme un verdict autonome : il suit surtout les applications ou les fichiers `.lnk` lancés via Explorer et peut manquer les exécutions en ligne de commande ou via service. Sur Windows 10+, certaines entrées ne signifient pas nécessairement que le processus s’est entièrement exécuté.
- `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}` et `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}`: traces d’exécution modernes de Windows 10/11 avec attribution par SID et heure de dernière exécution. Elles sont particulièrement utiles pour les binaires exécutés localement, mais les anciennes entrées peuvent expirer rapidement et les exécutions depuis des partages réseau ou des supports amovibles sont moins fiables.
- Pour des artefacts d’exécution plus larges comme Prefetch, Amcache, ShimCache et SRUM, voir le [Windows forensics overview](README.md#programs-executed) principal.

### Shellbags

- Les Shellbags sont stockés à la fois dans `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` / `Bags` et `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` / `Bags`.
- Les entrées `NTUSER.DAT` sont particulièrement utiles pour la navigation UNC/réseau, tandis que `UsrClass.dat` est l’endroit où Windows Vista+ stocke généralement les shellbags de dossiers locaux/amovibles.
- Elles peuvent montrer l’existence d’un dossier, sa traversée et les préférences d’affichage du dossier même après suppression du dossier. Un accès de type Explorer à des fichiers d’archive peut aussi laisser des traces de shellbag.
- Toutes les shellbags ne prouvent pas un accès réussi au dossier, alors corroborez avec des LNKs, Jump Lists, des timestamps ou des mappings de volume.
- Utilisez **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** ou **SBECmd** pour les parser.

### Informations USB

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`: inventaire principal des périphériques de stockage de masse USB (vendor, produit, révision, serial/device instance).
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB`: inventaire USB plus large, y compris les périphériques non-storage.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_*\PID_*\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: sur les versions récentes de Windows 10/11, c’est un emplacement très important pour des timestamps du cycle de vie par périphérique, comme install, first install, last arrival et last removal.
- `HKLM\SYSTEM\MountedDevices`: mappe les volumes et identifiants de périphérique vers les lettres de lecteur / GUID de volume. Seul le dernier mapping pour une lettre de lecteur donnée peut subsister.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`: pivot utile pour les numéros de série de volume et les métadonnées de media précédentes.
- `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: historique d’interaction avec les lettres de lecteur et les partages, spécifique à l’utilisateur.
- Les téléphones et tablettes modernes connectés via MTP/PTP peuvent **ne pas** apparaître sous `USBSTOR`. Vérifiez aussi `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` et `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
- Pour relier un périphérique à un utilisateur, partez des identifiants de périphérique ou de volume vers des artefacts par utilisateur tels que les shellbags, LNKs, Jump Lists, `RecentDocs` et `MountPoints2`.



## Références

- [Windows Registry Forensics Cheat Sheet 2026 - Cyber Triage](https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/)
- [USB Device Forensics on Windows 10 and 11 - ElcomSoft](https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/)
{{#include ../../../banners/hacktricks-training.md}}
