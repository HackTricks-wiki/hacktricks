# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Android device에서 data를 추출하려면 기기의 잠금을 해제해야 합니다. 잠겨 있다면 다음을 수행할 수 있습니다:

- 기기에서 USB를 통한 debugging이 활성화되어 있는지 확인합니다.
- 가능한 [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>을 확인합니다.
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>를 시도합니다.

## Data Acquisition

[adb를 사용하여 Android backup 생성](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) 후 [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)를 사용하여 추출합니다: `java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

- `cat /proc/partitions` (flash memory의 경로를 검색합니다. 일반적으로 첫 번째 항목은 _mmcblk0_이며 전체 flash memory에 해당합니다.)
- `df /data` (system의 block size를 확인합니다.)
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (block size 정보를 바탕으로 실행합니다.)

### Memory

Linux Memory Extractor (LiME)를 사용하여 RAM 정보를 추출합니다. 이는 adb를 통해 로드해야 하는 kernel extension입니다.

## References

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
