# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Proprietary File System (APFS)

**Apple File System (APFS)** est un système de fichiers moderne conçu pour remplacer le Hierarchical File System Plus (HFS+). Son développement a été motivé par le besoin d'**améliorer les performances, la sécurité et l'efficacité**.

Certaines caractéristiques notables d'APFS incluent :

1. **Partage d'espace** : APFS permet à plusieurs volumes de **partager le même espace de stockage libre sous-jacent** sur un seul appareil physique. Cela permet une utilisation plus efficace de l'espace, car les volumes peuvent croître et rétrécir dynamiquement sans avoir besoin de redimensionnement ou de repartitionnement manuel.
1. Cela signifie, par rapport aux partitions traditionnelles dans les disques de fichiers, **qu'en APFS, différentes partitions (volumes) partagent tout l'espace disque**, tandis qu'une partition classique avait généralement une taille fixe.
2. **Snapshots** : APFS prend en charge **la création de snapshots**, qui sont des instances **en lecture seule** et à un moment donné du système de fichiers. Les snapshots permettent des sauvegardes efficaces et des retours en arrière faciles, car ils consomment un espace de stockage supplémentaire minimal et peuvent être rapidement créés ou annulés.
3. **Clones** : APFS peut **créer des clones de fichiers ou de répertoires qui partagent le même stockage** que l'original jusqu'à ce que le clone ou le fichier original soit modifié. Cette fonctionnalité offre un moyen efficace de créer des copies de fichiers ou de répertoires sans dupliquer l'espace de stockage.
4. **Chiffrement** : APFS **prend en charge nativement le chiffrement de disque complet** ainsi que le chiffrement par fichier et par répertoire, renforçant la sécurité des données dans différents cas d'utilisation.
5. **Protection contre les pannes** : APFS utilise un **schéma de métadonnées en copie sur écriture qui garantit la cohérence du système de fichiers** même en cas de perte soudaine de puissance ou de crash système, réduisant le risque de corruption des données.

Dans l'ensemble, APFS offre un système de fichiers plus moderne, flexible et efficace pour les appareils Apple, avec un accent sur l'amélioration des performances, de la fiabilité et de la sécurité.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Le volume `Data` est monté dans **`/System/Volumes/Data`** (vous pouvez vérifier cela avec `diskutil apfs list`).

La liste des firmlinks peut être trouvée dans le fichier **`/usr/share/firmlinks`**.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
