# Partitions/Systèmes de fichiers/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Un disque dur ou un **disque SSD peut contenir différentes partitions** afin de séparer physiquement les données.\
L'unité **minimale** d'un disque est le **secteur** (normalement composé de 512B). Ainsi, la taille de chaque partition doit être un multiple de cette taille.

### MBR (master Boot Record)

Il est alloué dans le **premier secteur du disque, après les 446B du boot code**. Ce secteur est essentiel pour indiquer au PC quelle partition doit être montée et depuis où.\
Il autorise jusqu'à **4 partitions** (au maximum **1 seule** peut être active/**bootable**). Cependant, si vous avez besoin de davantage de partitions, vous pouvez utiliser des **partitions étendues**. L'**octet final** de ce premier secteur est la signature du boot record **0x55AA**. Une seule partition peut être marquée comme active.\
MBR autorise **au maximum 2,2 To**.

![Partitions - MBR (master Boot Record): MBR autorise au maximum 2,2 To](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR autorise au maximum 2,2 To](<../../../images/image (304).png>)

Dans les **octets 440 à 443** du MBR, vous pouvez trouver la **Windows Disk Signature** (si Windows est utilisé). La lettre du lecteur logique du disque dur dépend de la Windows Disk Signature. Modifier cette signature peut empêcher Windows de démarrer (outil : [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Dans les octets 440 à 443 du MBR, vous pouvez trouver la Windows Disk Signature (si Windows est utilisé). La lettre du lecteur logique du disque dur...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | Première partition  |
| 462 (0x1CE) | 16 (0x10)  | Deuxième partition  |
| 478 (0x1DE) | 16 (0x10)  | Troisième partition |
| 494 (0x1EE) | 16 (0x10)  | Quatrième partition |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record Format**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Indicateur actif (0x80 = bootable)                     |
| 1 (0x01)  | 1 (0x01) | Tête de début                                          |
| 2 (0x02)  | 1 (0x01) | Secteur de début (bits 0-5) ; bits supérieurs du cylindre (6- 7) |
| 3 (0x03)  | 1 (0x01) | 8 bits de poids faible du cylindre de début            |
| 4 (0x04)  | 1 (0x01) | Code du type de partition (0x83 = Linux)               |
| 5 (0x05)  | 1 (0x01) | Tête de fin                                             |
| 6 (0x06)  | 1 (0x01) | Secteur de fin (bits 0-5) ; bits supérieurs du cylindre (6- 7) |
| 7 (0x07)  | 1 (0x01) | 8 bits de poids faible du cylindre de fin              |
| 8 (0x08)  | 4 (0x04) | Secteurs précédant la partition (little endian)         |
| 12 (0x0C) | 4 (0x04) | Secteurs dans la partition                              |

Pour monter un MBR sous Linux, vous devez d'abord obtenir l'offset de début (vous pouvez utiliser `fdisk` et la commande `p`).

![Partitions - MBR (master Boot Record): Pour monter un MBR sous Linux, vous devez d'abord obtenir l'offset de début (vous pouvez utiliser fdisk et la commande p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Utilisez ensuite le code suivant
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) est un schéma courant utilisé pour **spécifier l'emplacement des blocs** de données stockés sur des périphériques de stockage informatique, généralement des systèmes de stockage secondaires tels que les disques durs. LBA est un schéma d'adressage linéaire particulièrement simple ; **les blocs sont localisés par un index entier**, le premier bloc étant LBA 0, le deuxième LBA 1, et ainsi de suite.

### GPT (GUID Partition Table)

La GUID Partition Table, connue sous le nom de GPT, est privilégiée pour ses capacités améliorées par rapport au MBR (Master Boot Record). Se distinguant par son **identifiant globalement unique** pour les partitions, GPT présente plusieurs caractéristiques :

- **Emplacement et taille** : GPT et MBR commencent tous deux au **secteur 0**. Cependant, GPT fonctionne sur **64 bits**, contrairement aux 32 bits du MBR.
- **Limites des partitions** : GPT prend en charge jusqu'à **128 partitions** sur les systèmes Windows et peut gérer jusqu'à **9,4 Zo** de données.
- **Noms des partitions** : permet de nommer les partitions avec jusqu'à 36 caractères Unicode.

**Résilience et récupération des données** :

- **Redondance** : contrairement au MBR, GPT ne confine pas les données de partitionnement et de boot à un seul emplacement. Elle réplique ces données sur l'ensemble du disque, améliorant ainsi l'intégrité et la résilience des données.
- **Cyclic Redundancy Check (CRC)** : GPT utilise le CRC pour garantir l'intégrité des données. Il surveille activement les corruptions de données et, lorsqu'il en détecte une, GPT tente de récupérer les données corrompues depuis un autre emplacement du disque.

**Protective MBR (LBA0)** :

- GPT maintient la compatibilité ascendante grâce à un protective MBR. Cette fonctionnalité réside dans l'espace MBR legacy, mais est conçue pour empêcher les anciens utilitaires basés sur le MBR d'écraser par erreur les disques GPT, protégeant ainsi l'intégrité des données sur les disques formatés en GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Depuis Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Dans les systèmes d'exploitation qui prennent en charge le boot basé sur GPT via les services du BIOS plutôt que l'EFI, le premier secteur peut également continuer à être utilisé pour stocker le code de première étape du **bootloader**, mais il est **modifié** pour reconnaître les **partitions** **GPT**. Le bootloader du MBR ne doit pas supposer une taille de secteur de 512 octets.

**En-tête de la table de partitions (LBA 1)**

[Depuis Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

L'en-tête de la table de partitions définit les blocs utilisables sur le disque. Il définit également le nombre et la taille des entrées de partition qui constituent la table de partitions (offsets 80 et 84 dans la table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**Entrées de partition (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Types de partitions**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Nom de la partition (36 unités de code UTF-16LE)](<../../../images/image (83).png>)

Davantage de types de partitions sur [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspection

Après avoir monté l'image forensics avec [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), vous pouvez inspecter le premier secteur à l'aide de l'outil Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Dans l'image suivante, un **MBR** a été détecté sur le **secteur 0** et interprété :

![GPT (GUID Partition Table) - Inspection : après avoir monté l'image forensics avec ArsenalImageMounter, vous pouvez inspecter le premier secteur à l'aide de l'outil Windows Active Disk Editor. Dans l'image...](<../../../images/image (354).png>)

S'il s'agissait d'une **table GPT au lieu d'un MBR**, la signature _EFI PART_ devrait apparaître dans le **secteur 1** (qui est vide dans l'image précédente).

## File-Systems

### Liste des file-systems Windows

- **FAT12/16** : MSDOS, WIN95/98/NT/200
- **FAT32** : 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT** : 2008/2012/2016/VISTA/7/8/10
- **NTFS** : XP/2003/2008/2012/VISTA/7/8/10
- **ReFS** : 2012/2016

### FAT

Le file system **FAT (File Allocation Table)** est conçu autour de son composant principal, la file allocation table, située au début du volume. Ce système protège les données en conservant **deux copies** de la table, garantissant ainsi l'intégrité des données même si l'une d'elles est corrompue. La table, ainsi que le dossier racine, doivent se trouver à un **emplacement fixe**, ce qui est essentiel au processus de démarrage du système.

L'unité de stockage de base du file system est un **cluster, généralement de 512 octets**, composé de plusieurs secteurs. FAT a évolué au travers de plusieurs versions :

- **FAT12**, prenant en charge des adresses de cluster de 12 bits et gérant jusqu'à 4078 clusters (4084 avec UNIX).
- **FAT16**, passant à des adresses de 16 bits et pouvant ainsi gérer jusqu'à 65 517 clusters.
- **FAT32**, progressant encore avec des adresses de 32 bits et permettant jusqu'à 268 435 456 clusters par volume.

Une limitation importante commune à toutes les versions de FAT est la **taille maximale de fichier de 4 Go**, imposée par le champ de 32 bits utilisé pour stocker la taille des fichiers.

Les composants clés du répertoire racine, notamment pour FAT12 et FAT16, comprennent :

- **Nom du fichier/dossier** (jusqu'à 8 caractères)
- **Attributs**
- **Dates de création, de modification et de dernier accès**
- **Adresse de la table FAT** (indiquant le cluster de début du fichier)
- **Taille du fichier**

### EXT

**Ext2** est le file system le plus courant pour les partitions **sans journaling** (**partitions qui changent peu**), comme la partition boot. **Ext3/4** utilisent le **journaling** et sont généralement employés pour les **autres partitions**.

## **Metadata**

Certains fichiers contiennent des metadata. Ces informations concernent le contenu du fichier et peuvent parfois être intéressantes pour un analyste car, selon le type de fichier, elles peuvent fournir des informations telles que :

- Titre
- Version de MS Office utilisée
- Auteur
- Dates de création et de dernière modification
- Modèle de l'appareil photo
- Coordonnées GPS
- Informations sur l'image

Vous pouvez utiliser des outils comme [**exiftool**](https://exiftool.org) et [**Metadiver**](https://www.easymetadata.com/metadiver-2/) pour obtenir les metadata d'un fichier.

## **Récupération de fichiers supprimés**

### Fichiers supprimés journalisés

Comme indiqué précédemment, il existe plusieurs endroits où le fichier est encore sauvegardé après avoir été "supprimé". Cela s'explique généralement par le fait que la suppression d'un fichier d'un file system le marque simplement comme supprimé, sans toucher aux données. Il est alors possible d'inspecter les registres des fichiers (comme la MFT) et de trouver les fichiers supprimés.<sup>[[2]](#references)</sup>

De plus, l'OS sauvegarde généralement de nombreuses informations sur les modifications et les backups du file system. Il est donc possible d'essayer de les utiliser pour récupérer le fichier ou autant d'informations que possible.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

Le **File Carving** est une technique qui tente de **trouver des fichiers dans la masse de données**. Il existe 3 principales façons dont les outils de ce type fonctionnent : **à partir des headers et footers des types de fichiers**, à partir des **structures** des types de fichiers et à partir du **contenu** lui-même.

Notez que cette technique **ne permet pas de récupérer les fichiers fragmentés**. Si un fichier **n'est pas stocké dans des secteurs contigus**, cette technique ne pourra pas le trouver, ou du moins pas dans son intégralité.

Il existe plusieurs outils que vous pouvez utiliser pour le File Carving en indiquant les types de fichiers que vous souhaitez rechercher.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Le Data Stream Carving est similaire au File Carving, mais **au lieu de rechercher des fichiers complets, il recherche des fragments d'informations intéressants**.\
Par exemple, au lieu de rechercher un fichier complet contenant des URLs journalisées, cette technique recherchera des URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Évidemment, il existe des moyens de **supprimer des fichiers et une partie des logs les concernant de manière "sécurisée"**. Par exemple, il est possible de **réécrire le contenu** d'un fichier plusieurs fois avec des données incohérentes, puis de **supprimer** les **logs** du fichier dans **$MFT** et **$LOGFILE**, et de **supprimer les Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Vous remarquerez que, même après avoir effectué cette action, il peut y avoir **d'autres emplacements où l'existence du fichier est toujours journalisée**. Cela est exact, et le travail du professionnel de la forensics consiste notamment à les trouver.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Comment analyser les entrées NTFS $I30 (répertoire) pour trouver des preuves de fichiers supprimés](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
