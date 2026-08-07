# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Appareil verrouillé

Pour commencer à extraire des données d'un appareil Android, celui-ci doit être déverrouillé. S'il est verrouillé, vous pouvez :

- Vérifier si le debugging via USB est activé.
- Vérifier la possibilité d'une [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Essayer le [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Acquisition de données

Créez une [sauvegarde Android à l'aide d'adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) et extrayez-la avec [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) : `java -jar abe.jar unpack file.backup file.tar`

### En cas d'accès root ou de connexion physique à l'interface JTAG

- `cat /proc/partitions` (recherchez le chemin vers la mémoire flash ; généralement, la première entrée est _mmcblk0_ et correspond à l'ensemble de la mémoire flash).
- `df /data` (déterminez la taille des blocs du système).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (exécutez cette commande avec les informations obtenues concernant la taille des blocs).

### Mémoire

Utilisez Linux Memory Extractor (LiME) pour extraire les informations de la RAM. Il s'agit d'une extension du kernel qui doit être chargée via adb.

## Références

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
