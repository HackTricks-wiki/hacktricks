# Android Forensics

## Locked Device

To start extracting data from an Android device it has to be unlocked. If it's locked you can:

* Check if the device has debugging via USB activated.
* Check for a possible [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
* Try with [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Data Adquisition

Create an [android backup using adb](mobile-apps-pentesting/android-app-pentesting/adb-commands.md#backup) and extract it using [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

* `cat /proc/partitions` (search the path to the flash memory, generally the first entry is _mmcblk0 _and corresponds to the whole flash memory).
* `df /data` (Discover the block size of the system).
* dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (execute it with the information gathered from the block size).

### Memory

Use Linux Memory Extractor (LiME) to extract the RAM information. It's a kernel extension that should be loaded via adb.
