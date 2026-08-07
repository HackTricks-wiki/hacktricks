# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Android device से data extraction शुरू करने के लिए उसका unlocked होना आवश्यक है। यदि यह locked है, तो आप:

- जाँचें कि device में USB के माध्यम से debugging activated है या नहीं।
- संभावित [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup> की जाँच करें।
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup> आज़माएँ।

## Data Adquisition

[adb का उपयोग करके Android backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) बनाएँ और इसे [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) का उपयोग करके extract करें: `java -jar abe.jar unpack file.backup file.tar`

### If root access or physical connection to JTAG interface

- `cat /proc/partitions` (flash memory का path खोजें, सामान्यतः पहली entry _mmcblk0_ होती है और यह पूरी flash memory से संबंधित होती है)।
- `df /data` (system का block size निर्धारित करें)।
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (block size से प्राप्त information का उपयोग करके इसे execute करें)।

### Memory

RAM information extract करने के लिए Linux Memory Extractor (LiME) का उपयोग करें। यह एक kernel extension है, जिसे adb के माध्यम से load किया जाना चाहिए।

## References

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
