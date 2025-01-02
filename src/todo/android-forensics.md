# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Gelslote Toestel

Om data van 'n Android-toestel te begin onttrek, moet dit ontgrendel wees. As dit gesluit is, kan jy:

- Kontroleer of die toestel debugging via USB geaktiveer is.
- Soek na 'n moontlike [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Probeer met [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Data Verkryging

Skep 'n [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) en onttrek dit met behulp van [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### As root-toegang of fisiese verbinding met JTAG-koppelvlak

- `cat /proc/partitions` (soek die pad na die flitsgeheue, gewoonlik is die eerste inskrywing _mmcblk0_ en kom ooreen met die hele flitsgeheue).
- `df /data` (ontdek die blokgrootte van die stelsel).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (voer dit uit met die inligting wat van die blokgrootte versamel is).

### Geheue

Gebruik Linux Memory Extractor (LiME) om die RAM-inligting te onttrek. Dit is 'n kernuitbreiding wat via adb gelaai moet word.

{{#include ../banners/hacktricks-training.md}}
