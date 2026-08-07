# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Gesluite Toestel

Om data uit 'n Android-toestel te begin onttrek, moet dit ontsluit wees. As dit gesluit is, kan jy:

- Kontroleer of debugging via USB geaktiveer is.
- Kontroleer vir 'n moontlike [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Probeer met [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Data-insameling

Skep 'n [Android-rugsteun met adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) en onttrek dit met [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Indien root-toegang of fisiese verbinding met JTAG-koppelvlak

- `cat /proc/partitions` (soek die pad na die flash-geheue; gewoonlik is die eerste inskrywing _mmcblk0_ en stem dit met die volledige flash-geheue ooreen).
- `df /data` (Bepaal die blokgrootte van die stelsel).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (voer dit uit met die inligting wat oor die blokgrootte ingewin is).

### Geheue

Gebruik Linux Memory Extractor (LiME) om die RAM-inligting te onttrek. Dit is 'n kernel-uitbreiding wat via adb gelaai moet word.

## Verwysings

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
