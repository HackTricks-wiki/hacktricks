# Système de fichiers propriétaire d’Apple (APFS)

{{#include ../../banners/hacktricks-training.md}}

## Système de fichiers propriétaire d’Apple (APFS)

**Apple File System (APFS)** est un système de fichiers moderne conçu pour remplacer le Hierarchical File System Plus (HFS+). Son développement a été motivé par le besoin d’améliorer les **performances, la sécurité et l’efficacité**.

Voici quelques fonctionnalités notables d’APFS :<sup>[[1]](#references)</sup>

1. **Partage de l’espace** : APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul appareil physique. Cela permet une utilisation plus efficace de l’espace, car les volumes peuvent s’agrandir et rétrécir dynamiquement sans nécessiter de redimensionnement manuel ou de repartitionnement.
1. Cela signifie que, par rapport aux partitions traditionnelles des disques, **les différentes partitions (volumes) d’APFS partagent tout l’espace du disque**, tandis qu’une partition classique avait généralement une taille fixe.
2. **Snapshots** : APFS prend en charge la **création de snapshots**, qui sont des instances du système de fichiers **en lecture seule** à un instant donné. Les snapshots permettent d’effectuer des sauvegardes efficaces et de restaurer facilement le système, car ils consomment très peu d’espace de stockage supplémentaire et peuvent être créés ou restaurés rapidement.
3. **Clones** : APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même espace de stockage** que l’original jusqu’à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l’espace de stockage.
4. **Chiffrement** : APFS **prend nativement en charge le chiffrement intégral du disque**, ainsi que le chiffrement par fichier et par répertoire, ce qui renforce la sécurité des données dans différents cas d’utilisation.
5. **Protection contre les plantages** : APFS utilise un **schéma de métadonnées copy-on-write qui garantit la cohérence du système de fichiers** même en cas de coupure soudaine de courant ou de plantage du système, réduisant ainsi le risque de corruption des données.

Dans l’ensemble, APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, en mettant l’accent sur l’amélioration des performances, de la fiabilité et de la sécurité.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Le volume `Data` est monté dans **`/System/Volumes/Data`** (vous pouvez le vérifier avec `diskutil apfs list`).

La liste des firmlinks se trouve dans le fichier **`/usr/share/firmlinks`**.
```bash

```
## Références

- [1] [Guide APFS - Fonctionnalités - Documentation Apple pour les développeurs](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
