# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Android डिवाइस से डेटा निकालने के लिए इसे अनलॉक करना होगा। यदि यह लॉक है, तो आप कर सकते हैं:

- जांचें कि क्या डिवाइस में USB के माध्यम से डिबगिंग सक्रिय है।
- संभावित [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf) के लिए जांचें।
- [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/) के साथ प्रयास करें।

## Data Adquisition

[adb का उपयोग करके android बैकअप बनाएं](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) और इसे [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/) का उपयोग करके निकालें: `java -jar abe.jar unpack file.backup file.tar`

### यदि रूट एक्सेस या JTAG इंटरफेस के लिए भौतिक कनेक्शन है

- `cat /proc/partitions` (फ्लैश मेमोरी के पथ की खोज करें, सामान्यतः पहला प्रविष्टि _mmcblk0_ होती है और यह पूरी फ्लैश मेमोरी से संबंधित होती है)।
- `df /data` (सिस्टम का ब्लॉक आकार खोजें)।
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (इसे ब्लॉक आकार से एकत्रित जानकारी के साथ निष्पादित करें)।

### Memory

RAM जानकारी निकालने के लिए Linux Memory Extractor (LiME) का उपयोग करें। यह एक कर्नेल एक्सटेंशन है जिसे adb के माध्यम से लोड किया जाना चाहिए।

{{#include ../banners/hacktricks-training.md}}
