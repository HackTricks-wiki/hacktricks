{{#include ../../banners/hacktricks-training.md}}

# Horodatages

Un attaquant peut être intéressé par **le changement des horodatages des fichiers** pour éviter d'être détecté.\
Il est possible de trouver les horodatages à l'intérieur du MFT dans les attributs `$STANDARD_INFORMATION` ** et ** `$FILE_NAME`.

Les deux attributs ont 4 horodatages : **Modification**, **accès**, **création**, et **modification du registre MFT** (MACE ou MACB).

**L'explorateur Windows** et d'autres outils affichent les informations de **`$STANDARD_INFORMATION`**.

## TimeStomp - Outil anti-forensique

Cet outil **modifie** les informations d'horodatage à l'intérieur de **`$STANDARD_INFORMATION`** **mais** **pas** les informations à l'intérieur de **`$FILE_NAME`**. Par conséquent, il est possible d'**identifier** **une activité** **suspecte**.

## Usnjrnl

Le **Journal USN** (Journal de Numéro de Séquence de Mise à Jour) est une fonctionnalité du NTFS (système de fichiers Windows NT) qui suit les changements de volume. L'outil [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) permet d'examiner ces changements.

![](<../../images/image (449).png>)

L'image précédente est la **sortie** affichée par l'**outil** où l'on peut observer que certains **changements ont été effectués** sur le fichier.

## $LogFile

**Tous les changements de métadonnées d'un système de fichiers sont enregistrés** dans un processus connu sous le nom de [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Les métadonnées enregistrées sont conservées dans un fichier nommé `**$LogFile**`, situé dans le répertoire racine d'un système de fichiers NTFS. Des outils comme [LogFileParser](https://github.com/jschicht/LogFileParser) peuvent être utilisés pour analyser ce fichier et identifier les changements.

![](<../../images/image (450).png>)

Encore une fois, dans la sortie de l'outil, il est possible de voir que **certains changements ont été effectués**.

En utilisant le même outil, il est possible d'identifier **à quel moment les horodatages ont été modifiés** :

![](<../../images/image (451).png>)

- CTIME : Heure de création du fichier
- ATIME : Heure de modification du fichier
- MTIME : Modification du registre MFT du fichier
- RTIME : Heure d'accès du fichier

## Comparaison de `$STANDARD_INFORMATION` et `$FILE_NAME`

Une autre façon d'identifier des fichiers modifiés suspects serait de comparer le temps sur les deux attributs à la recherche de **disparités**.

## Nanosecondes

Les horodatages **NTFS** ont une **précision** de **100 nanosecondes**. Ainsi, trouver des fichiers avec des horodatages comme 2010-10-10 10:10:**00.000:0000 est très suspect**.

## SetMace - Outil anti-forensique

Cet outil peut modifier les deux attributs `$STARNDAR_INFORMATION` et `$FILE_NAME`. Cependant, depuis Windows Vista, il est nécessaire qu'un OS en direct modifie ces informations.

# Masquage de données

NFTS utilise un cluster et la taille minimale d'information. Cela signifie que si un fichier occupe un et demi cluster, la **moitié restante ne sera jamais utilisée** jusqu'à ce que le fichier soit supprimé. Il est donc possible de **cacher des données dans cet espace de réserve**.

Il existe des outils comme slacker qui permettent de cacher des données dans cet espace "caché". Cependant, une analyse du `$logfile` et du `$usnjrnl` peut montrer que certaines données ont été ajoutées :

![](<../../images/image (452).png>)

Il est alors possible de récupérer l'espace de réserve en utilisant des outils comme FTK Imager. Notez que ce type d'outil peut sauvegarder le contenu obfusqué ou même chiffré.

# UsbKill

C'est un outil qui **éteindra l'ordinateur si un changement dans les ports USB** est détecté.\
Une façon de découvrir cela serait d'inspecter les processus en cours et de **réviser chaque script python en cours d'exécution**.

# Distributions Linux Live

Ces distributions sont **exécutées dans la mémoire RAM**. La seule façon de les détecter est **si le système de fichiers NTFS est monté avec des permissions d'écriture**. S'il est monté uniquement avec des permissions de lecture, il ne sera pas possible de détecter l'intrusion.

# Suppression sécurisée

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Configuration Windows

Il est possible de désactiver plusieurs méthodes de journalisation Windows pour rendre l'enquête forensique beaucoup plus difficile.

## Désactiver les horodatages - UserAssist

C'est une clé de registre qui maintient les dates et heures auxquelles chaque exécutable a été exécuté par l'utilisateur.

Désactiver UserAssist nécessite deux étapes :

1. Définir deux clés de registre, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` et `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, toutes deux à zéro pour signaler que nous voulons désactiver UserAssist.
2. Effacer vos sous-arbres de registre qui ressemblent à `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Désactiver les horodatages - Prefetch

Cela enregistrera des informations sur les applications exécutées dans le but d'améliorer les performances du système Windows. Cependant, cela peut également être utile pour les pratiques forensiques.

- Exécutez `regedit`
- Sélectionnez le chemin de fichier `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Cliquez avec le bouton droit sur `EnablePrefetcher` et `EnableSuperfetch`
- Sélectionnez Modifier sur chacun d'eux pour changer la valeur de 1 (ou 3) à 0
- Redémarrez

## Désactiver les horodatages - Dernière heure d'accès

Chaque fois qu'un dossier est ouvert à partir d'un volume NTFS sur un serveur Windows NT, le système prend le temps de **mettre à jour un champ d'horodatage sur chaque dossier répertorié**, appelé l'heure de dernier accès. Sur un volume NTFS très utilisé, cela peut affecter les performances.

1. Ouvrez l'Éditeur de Registre (Regedit.exe).
2. Parcourez `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Recherchez `NtfsDisableLastAccessUpdate`. S'il n'existe pas, ajoutez ce DWORD et définissez sa valeur à 1, ce qui désactivera le processus.
4. Fermez l'Éditeur de Registre et redémarrez le serveur.

## Supprimer l'historique USB

Tous les **entrées de périphériques USB** sont stockées dans le Registre Windows sous la clé de registre **USBSTOR** qui contient des sous-clés créées chaque fois que vous branchez un périphérique USB sur votre PC ou ordinateur portable. Vous pouvez trouver cette clé ici `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **En supprimant cela**, vous supprimerez l'historique USB.\
Vous pouvez également utiliser l'outil [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) pour vous assurer que vous les avez supprimés (et pour les supprimer).

Un autre fichier qui sauvegarde des informations sur les USB est le fichier `setupapi.dev.log` à l'intérieur de `C:\Windows\INF`. Cela devrait également être supprimé.

## Désactiver les copies de sauvegarde

**Lister** les copies de sauvegarde avec `vssadmin list shadowstorage`\
**Les supprimer** en exécutant `vssadmin delete shadow`

Vous pouvez également les supprimer via l'interface graphique en suivant les étapes proposées dans [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Pour désactiver les copies de sauvegarde [étapes à partir d'ici](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Ouvrez le programme Services en tapant "services" dans la zone de recherche après avoir cliqué sur le bouton de démarrage Windows.
2. Dans la liste, trouvez "Volume Shadow Copy", sélectionnez-le, puis accédez aux Propriétés en cliquant avec le bouton droit.
3. Choisissez Désactivé dans le menu déroulant "Type de démarrage", puis confirmez le changement en cliquant sur Appliquer et OK.

Il est également possible de modifier la configuration des fichiers qui vont être copiés dans la copie de sauvegarde dans le registre `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Écraser les fichiers supprimés

- Vous pouvez utiliser un **outil Windows** : `cipher /w:C` Cela indiquera à cipher de supprimer toutes les données de l'espace disque inutilisé disponible à l'intérieur du lecteur C.
- Vous pouvez également utiliser des outils comme [**Eraser**](https://eraser.heidi.ie)

## Supprimer les journaux d'événements Windows

- Windows + R --> eventvwr.msc --> Développez "Journaux Windows" --> Cliquez avec le bouton droit sur chaque catégorie et sélectionnez "Effacer le journal"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Désactiver les journaux d'événements Windows

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Dans la section des services, désactivez le service "Windows Event Log"
- `WEvtUtil.exec clear-log` ou `WEvtUtil.exe cl`

## Désactiver $UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}
