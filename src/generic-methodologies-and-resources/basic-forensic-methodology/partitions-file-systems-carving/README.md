# Partitions/Systèmes de fichiers/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Un disque peut contenir plusieurs **partitions** : des plages logiques de blocs, et non des espaces de stockage physiquement distincts. Le début et la longueur des partitions sont exprimés en **secteurs logiques** ; ne supposez pas que chaque image utilise des secteurs de 512 octets, car il existe aussi des secteurs logiques de 4096 octets.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

Le MBR occupe le premier secteur logique (LBA 0) ; ses quatre entrées de partition de 16 octets commencent à l’octet 446. La zone qui les précède comprend le code d’amorçage et peut inclure une signature de disque.<sup>[[4]](#references)</sup>\
Il permet jusqu’à **4 partitions** (au maximum **1 seule** peut être active/**bootable**). Cependant, si vous avez besoin de plus de partitions, vous pouvez utiliser des **partitions étendues**. Les **deux derniers octets** du MBR de 512 octets sont la signature d’amorçage **0x55 0xAA**. Une seule partition peut être marquée comme active.\
Avec des secteurs logiques de 512 octets, les champs de secteur 32 bits du MBR limitent l’adressage à environ **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Partitions - MBR (master Boot Record) : le MBR permet au maximum 2,2 TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record) : le MBR permet au maximum 2,2 TB](<../../../images/image (304).png>)

Dans les **octets 440 à 443** du MBR se trouve la **signature de disque Windows** (si Windows est utilisé). La lettre de lecteur logique du disque dur dépend de la signature de disque Windows. Modifier cette signature peut empêcher Windows de démarrer (outil : [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record) : dans les octets 440 à 443 du MBR se trouve la signature de disque Windows (si Windows est utilisé). La lettre de lecteur logique du disque dur...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                      |
| ----------- | ---------- | ------------------------- |
| 0 (0x00)    | 446(0x1BE) | Code d’amorçage           |
| 446 (0x1BE) | 16 (0x10)  | Première partition        |
| 462 (0x1CE) | 16 (0x10)  | Deuxième partition        |
| 478 (0x1DE) | 16 (0x10)  | Troisième partition       |
| 494 (0x1EE) | 16 (0x10)  | Quatrième partition       |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA        |

**Format de l’enregistrement de partition**

| Offset    | Length   | Item                                                                  |
| --------- | -------- | --------------------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Indicateur actif (0x80 = bootable)                                    |
| 1 (0x01)  | 1 (0x01) | Tête de départ                                                        |
| 2 (0x02)  | 1 (0x01) | Secteur de départ (bits 0-5) ; bits de poids fort du cylindre (6-7)   |
| 3 (0x03)  | 1 (0x01) | 8 bits de poids faible du cylindre de départ                          |
| 4 (0x04)  | 1 (0x01) | Code du type de partition (0x83 = Linux)                              |
| 5 (0x05)  | 1 (0x01) | Tête de fin                                                           |
| 6 (0x06)  | 1 (0x01) | Secteur de fin (bits 0-5) ; bits de poids fort du cylindre (6-7)      |
| 7 (0x07)  | 1 (0x01) | 8 bits de poids faible du cylindre de fin                             |
| 8 (0x08)  | 4 (0x04) | Secteurs précédant la partition (little endian)                       |
| 12 (0x0C) | 4 (0x04) | Secteurs de la partition                                              |

Pour examiner une partition dans une image MBR de disque entier, commencez par obtenir son LBA de départ et la taille du secteur logique. `mount` prend un **décalage en octets**, et non un LBA ; l’exemple ci-dessous ne convient qu’à une image avec des secteurs de 512 octets dont la partition commence au LBA 63. Pour les images non fiables ou les systèmes de fichiers journalisés, utilisez plutôt la procédure isolée en lecture seule décrite dans [Acquisition et montage d’image](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partitions - MBR (master Boot Record) : pour monter un MBR sous Linux, vous devez d’abord obtenir le décalage de départ (vous pouvez utiliser fdisk et la commande p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (adressage par blocs logiques)**

**L’adressage par blocs logiques** (**LBA**) est un schéma courant utilisé pour **spécifier l’emplacement des blocs** de données stockés sur des périphériques de stockage informatique, généralement des systèmes de stockage secondaires tels que les disques durs. LBA est un schéma d’adressage linéaire particulièrement simple ; **les blocs sont repérés par un index entier**, le premier bloc étant LBA 0, le deuxième LBA 1, et ainsi de suite.

### GPT (GUID Partition Table)

La GUID Partition Table (GPT) stocke un GUID unique pour chaque partition et utilise des métadonnées principales et de sauvegarde. Sa disposition diffère de celle du MBR comme suit :<sup>[[4]](#references)</sup>

- **Emplacement et taille** : LBA 0 contient un **MBR protecteur**. L’en-tête GPT principal se trouve à LBA 1 ; le tableau des entrées de partition le suit, tandis qu’un tableau et un en-tête de sauvegarde se trouvent à la fin du disque. GPT utilise des champs LBA de 64 bits, tandis que les entrées de partition MBR utilisent des champs LBA de 32 bits.
- **Limites des partitions** : Un tableau d’entrées courant de 16 Kio contient **128 entrées de 128 octets**, mais le nombre d’entrées est indiqué dans l’en-tête plutôt que fixé par GPT. La taille adressable dépend également de la taille du secteur logique (environ **9,4 Zio** avec des secteurs de 512 octets).<sup>[[4]](#references)</sup>
- **Noms des partitions** : Permet de nommer les partitions avec jusqu’à 36 caractères Unicode.

**Résilience et récupération des données** :

- **Redondance** : Contrairement au MBR, GPT ne limite pas les données de partitionnement et de démarrage à un seul emplacement. Ces données sont répliquées sur le disque, ce qui améliore leur intégrité et leur résilience.
- **Contrôle de redondance cyclique (CRC)** : L’en-tête et le tableau des entrées de partition possèdent chacun un CRC32. Un CRC détecte les incohérences ; il ne surveille pas continuellement le disque et ne le répare pas lui-même. Si la copie principale est invalide, validez la sauvegarde située au dernier LBA avant toute récupération sur une copie de travail.<sup>[[4]](#references)</sup>

**MBR protecteur (LBA0)** :

- GPT assure la compatibilité ascendante au moyen d’un MBR protecteur. Cette fonctionnalité se trouve dans l’espace MBR traditionnel, mais elle est conçue pour empêcher les anciens utilitaires basés sur MBR d’écraser par erreur les disques GPT, protégeant ainsi l’intégrité des données sur les disques formatés en GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**MBR hybride (LBA 0 + GPT)**

[Depuis Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Dans les systèmes d’exploitation qui prennent en charge le **démarrage basé sur GPT via les services BIOS**, plutôt que via EFI, le premier secteur peut encore être utilisé pour stocker le code de première étape du **chargeur d’amorçage**, mais il est **modifié** pour reconnaître les **partitions** **GPT**. Le chargeur d’amorçage dans le MBR ne doit pas supposer une taille de secteur de 512 octets.

**En-tête de la table de partitions (LBA 1)**

[Depuis Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

L’en-tête de la table de partitions définit les blocs utilisables sur le disque. Il définit également le nombre et la taille des entrées de partition qui composent la table de partitions (décalages 80 et 84 dans la table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature (« EFI PART », 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)sur les machines little-endian) |
| 8 (0x08)  | 4 bytes  | Révision 1.0 (00h 00h 01h 00h) pour UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Taille de l’en-tête en little-endian (en octets, généralement 5Ch 00h 00h 00h, soit 92 octets)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) de l’en-tête (du décalage +0 jusqu’à la taille de l’en-tête) en little-endian, ce champ étant mis à zéro pendant le calcul                             |
| 20 (0x14) | 4 bytes  | Réservé ; doit être égal à zéro                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | LBA actuel (emplacement de cette copie de l’en-tête)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | LBA de sauvegarde (emplacement de l’autre copie de l’en-tête)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Premier LBA utilisable pour les partitions (dernier LBA de la table de partitions principale + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Dernier LBA utilisable (premier LBA de la table de partitions secondaire − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | GUID du disque en endianness mixte                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | LBA de départ d’un tableau d’entrées de partition (toujours 2 dans la copie principale)                                                                                                     |
| 80 (0x50) | 4 bytes  | Nombre d’entrées de partition dans le tableau                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Taille d’une entrée de partition (généralement 80h, soit 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 du tableau des entrées de partition en little-endian                                                                                                                            |
| 92 (0x5C) | \*       | Réservé ; doit être égal à zéro pour le reste du bloc (420 octets pour une taille de secteur de 512 octets, mais peut être supérieur avec des tailles de secteur plus grandes)                                      |

**Entrées de partition (LBA 2–33)**

| Format des entrées de partition GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Décalage                      | Longueur   | Contenu                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID du type de partition](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (endianness mixte) |
| 16 (0x10)                   | 16 bytes | GUID unique de la partition (endianness mixte)                                                                          |
| 32 (0x20)                   | 8 bytes  | Premier LBA ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Dernier LBA (inclus, généralement impair)                                                                             |
| 48 (0x30)                   | 8 bytes  | Indicateurs d’attribut (par exemple, le bit 60 indique un accès en lecture seule)                                                               |
| 56 (0x38)                   | 72 bytes | Nom de la partition (36 unités de code [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                               |

**Types de partitions**

![MBR (Master Boot Record) - GPT (GUID Partition Table) : 56 (0x38) | 72 bytes | Nom de la partition (36 unités de code UTF-16LE)](<../../../images/image (83).png>)

D’autres types de partitions sont répertoriés sur [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspection

Après avoir monté l’image forensique avec [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), vous pouvez inspecter le premier secteur à l’aide de l’outil Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** L’image suivante montre un **MBR** détecté et interprété sur le **secteur 0** :

![GPT (GUID Partition Table) - Inspection : après avoir monté l’image forensique avec ArsenalImageMounter, vous pouvez inspecter le premier secteur à l’aide de l’outil Windows Active Disk Editor. Dans l’image...](<../../../images/image (354).png>)

Pour GPT, recherchez la signature _EFI PART_ dans l’en-tête principal à **LBA 1** ; LBA 0 contient toujours le MBR protecteur.<sup>[[4]](#references)</sup>

### Recherche de données en dehors des partitions répertoriées

Une entrée de partition supprimée ou une zone volontairement inutilisée peut laisser un système de fichiers en dehors de la carte actuelle des partitions. Sur une **copie de travail brute vérifiée**, répertoriez les plages non allouées, puis testez le LBA de départ candidat comme système de fichiers. `mmls` et `fsstat` utilisent des **décalages en secteurs** ; indiquez à chacun la taille réelle du secteur logique. Ne confondez pas les secteurs de métadonnées GPT avec un volume caché.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Si `fsstat` ne peut pas identifier de système de fichiers au début de la zone vide, utilisez **Analyse → Quick Search** dans TestDisk, puis **Deeper Search** si nécessaire. Appuyez sur `P` sur une partition candidate pour examiner les fichiers ; ne sélectionnez pas **Write** sur une preuve. Sur les images GPT, `sgdisk --verify disk.img` vérifie les CRC et la cohérence entre les tables principale et de sauvegarde, mais un en-tête de sauvegarde peut être obsolète après un repartitionnement. Vérifiez donc les limites candidates à l’aide des structures du système de fichiers avant toute récupération.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Systèmes de fichiers

### Liste des systèmes de fichiers Windows

- **FAT12/16** : MSDOS, WIN95/98/NT/200
- **FAT32** : 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT** : 2008/2012/2016/VISTA/7/8/10
- **NTFS** : XP/2003/2008/2012/VISTA/7/8/10
- **ReFS** : 2012/2016

### FAT

Le système de fichiers **FAT (File Allocation Table)** est conçu autour de son composant principal, la table d’allocation des fichiers, située au début du volume. Un volume comporte généralement **deux copies de la FAT**, bien que le BPB en autorise une seule. FAT12/16 placent le répertoire racine dans une région fixe ; FAT32 stocke le répertoire racine dans la zone de données, au cluster indiqué par `BPB_RootClus`.<sup>[[7]](#references)</sup>

L’unité d’allocation est un **cluster** : `BPB_BytsPerSec × BPB_SecPerClus`, et elle ne fait pas nécessairement 512 octets. Le type FAT est déterminé par le nombre de clusters de données, et non par une chaîne de version dans le secteur d’amorçage. Les limites du nombre de clusters sont les suivantes :<sup>[[7]](#references)</sup>

- **FAT12** : moins de 4 085 clusters de données.
- **FAT16** : de 4 085 à 65 524 clusters de données.
- **FAT32** : au moins 65 525 clusters de données ; seuls 28 bits de chaque entrée FAT de 32 bits sont utilisés pour le numéro de cluster.

Le champ de taille de fichier de 32 bits limite la taille d’un fichier ordinaire à **2³²−1 octets** (un peu moins de 4 Gio).<sup>[[7]](#references)</sup>

Les principaux composants du répertoire racine, notamment pour FAT12 et FAT16, comprennent :

- **Nom du fichier/dossier** (jusqu’à 8 caractères)
- **Attributs**
- **Dates de création, de modification et de dernier accès**
- **Adresse de la table FAT** (indiquant le cluster de départ du fichier)
- **Taille du fichier**

### EXT

**Ext2** est le système de fichiers le plus courant pour les partitions **sans journalisation** (**les partitions qui changent peu**), comme la partition d’amorçage. **Ext3/4** utilisent la **journalisation** et sont généralement utilisés pour les **autres partitions**.

## **Métadonnées**

Certains fichiers contiennent des métadonnées. Ces informations concernent le contenu du fichier et peuvent parfois intéresser un analyste. Selon le type de fichier, elles peuvent notamment indiquer :

- Le titre
- La version de MS Office utilisée
- L’auteur
- Les dates de création et de dernière modification
- Le modèle de l’appareil photo
- Les coordonnées GPS
- Des informations sur l’image

Vous pouvez utiliser des outils comme [**exiftool**](https://exiftool.org) et [**Metadiver**](https://www.easymetadata.com/metadiver-2/) pour extraire les métadonnées d’un fichier.

## **Récupération des fichiers supprimés**

### Fichiers supprimés enregistrés

Comme vu précédemment, plusieurs endroits peuvent encore contenir le fichier après sa « suppression ». En effet, la suppression d’un fichier dans un système de fichiers consiste généralement à le marquer comme supprimé, sans toucher aux données. Il est alors possible d’examiner les registres des fichiers (comme la MFT) pour retrouver les fichiers supprimés.<sup>[[2]](#references)</sup>

De plus, le système d’exploitation conserve généralement de nombreuses informations sur les modifications du système de fichiers et les sauvegardes. Il est donc possible d’essayer de les utiliser pour récupérer le fichier ou autant d’informations que possible.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

Le **File Carving** est une technique qui cherche à **retrouver des fichiers dans un ensemble de données brutes**. Les outils de ce type fonctionnent principalement de trois façons : **à partir des en-têtes et des fins de fichiers**, à partir des **structures** propres aux types de fichiers, ou à partir du **contenu** lui-même.

Le carving simple à partir des en-têtes et des fins de fichiers suppose que les blocs sont contigus ; il peut donc ne renvoyer qu’un fragment si un fichier est fragmenté. Cette limite n’est pas absolue : PhotoRec propose une option **Paranoid → bruteforce**, gourmande en CPU, pour certains JPEG fragmentés, tandis que la réassemblage de fragments tenant compte du format peut récupérer d’autres types pris en charge. Consultez [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) pour connaître un processus actuel de réassemblage des fragments.<sup>[[8]](#references)</sup>

Il existe plusieurs outils de File Carving auxquels vous pouvez indiquer les types de fichiers à rechercher.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Data Stream Carving**

Le Data Stream Carving ressemble au File Carving, mais **au lieu de rechercher des fichiers complets, il recherche des fragments d’information intéressants**.\
Par exemple, au lieu de rechercher un fichier complet contenant des URL enregistrées, cette technique recherchera des URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Suppression sécurisée

Il existe évidemment des moyens de supprimer des fichiers et une partie des journaux les concernant de manière **« sécurisée »**. Par exemple, il est possible de **remplacer le contenu** d’un fichier plusieurs fois par des données inutiles, puis de **supprimer** les **journaux** concernant le fichier dans **$MFT** et **$LOGFILE**, ainsi que les **Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Vous remarquerez peut-être que même après cette opération, **d’autres endroits peuvent encore enregistrer l’existence du fichier**. C’est exact, et le travail des professionnels de la criminalistique numérique consiste notamment à les retrouver.



## References

- [1] [Table de partition GUID - Wikipédia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Comment analyser les entrées NTFS $I30 (répertoire) pour rechercher des preuves de fichiers supprimés](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Service Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Spécification UEFI : disposition des disques GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Manuel de mmls de The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Manuel de fsstat de The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Spécification FAT de Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Options de récupération de PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Récupération de partitions supprimées avec TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Manuel de sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Manuel de mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
