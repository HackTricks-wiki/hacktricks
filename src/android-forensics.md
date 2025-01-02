# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Locked Device

Ili kuanza kutoa data kutoka kwa kifaa cha Android, lazima kifaa kiwe wazi. Ikiwa kimefungwa unaweza:

- Kuangalia ikiwa kifaa kina ufuatiliaji kupitia USB umewezeshwa.
- Kuangalia kwa shambulio la [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Jaribu na [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Data Adquisition

Unda [android backup using adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) na uitoe kwa kutumia [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

- `cat /proc/partitions` (tafuta njia ya kumbukumbu ya flash, kwa kawaida ingizo la kwanza ni _mmcblk0_ na linahusiana na kumbukumbu yote ya flash).
- `df /data` (Gundua ukubwa wa block wa mfumo).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (itekeleze kwa kutumia taarifa zilizokusanywa kutoka kwa ukubwa wa block).

### Memory

Tumia Linux Memory Extractor (LiME) kutoa taarifa za RAM. Ni nyongeza ya kernel ambayo inapaswa kupakiwa kupitia adb.

{{#include ./banners/hacktricks-training.md}}
