# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Kifaa Kilichofungwa

Ili kuanza kutoa data kutoka kwenye kifaa cha Android, lazima kifunguliwe. Ikiwa kimefungwa, unaweza:

- Kukagua ikiwa kifaa kina debugging kupitia USB iliyowashwa.
- Kukagua uwezekano wa [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Kujaribu kutumia [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Upatikanaji wa Data

Tengeneza [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) na uitowe kwa kutumia [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Ikiwa kuna root access au muunganisho wa kimwili kwenye interface ya JTAG

- `cat /proc/partitions` (tafuta path ya flash memory; kwa ujumla ingizo la kwanza ni _mmcblk0_ na linalingana na flash memory yote).
- `df /data` (gundua ukubwa wa block wa mfumo).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (itekeleze kwa kutumia maelezo yaliyokusanywa kuhusu ukubwa wa block).

### Memory

Tumia Linux Memory Extractor (LiME) kutoa maelezo ya RAM. Ni kernel extension inayopaswa kupakiwa kupitia adb.

## Marejeo

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
