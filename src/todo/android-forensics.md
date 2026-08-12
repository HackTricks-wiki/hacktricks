# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

ऐसे acquisition methods को प्राथमिकता दें जो device की स्थिति को सुरक्षित रखें और हर कार्रवाई का documentation करें। यदि device locked है, तो उपलब्ध options model, Android version, patch level और seizure से पहले access configure किया गया था या नहीं, इस पर निर्भर करते हैं। NIST examination के लिए device और authority के अनुसार method चुनने की सलाह देता है।<sup>[[1]](#references)</sup>

- जाँचें कि USB debugging enabled था या नहीं और acquisition workstation पहले से authorized है या नहीं। ADB access के लिए सामान्यतः user को device unlock करना और workstation की RSA key की पुष्टि करना आवश्यक होता है।<sup>[[3]](#references)</sup>
- विचार करें कि लागू कानूनी और प्रक्रियात्मक नियमों के अंतर्गत biometric access अभी भी उपलब्ध है या नहीं।
- एक **smudge attack** screen पर बचे residue से graphical unlock pattern प्रकट कर सकता है, हालांकि बाद में किए गए touches और cleaning इसकी reliability कम कर देते हैं।<sup>[[2]](#references)</sup>
- जहाँ authorized tooling exact device और software build को support करती है, वहाँ यह PIN, password या pattern recovery अथवा brute force का प्रयास कर सकती है। Hardware-backed credential verification, retry delays और wipe policies के कारण यह पूरी तरह device-specific होता है, इसलिए Android device के supported होने के evidence के रूप में iPhone technique या result का उपयोग न करें।<sup>[[1]](#references)</sup>

## Data acquisition

पुराने devices पर, एक legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) `.backup` file बना सकता है, जिसे Android Backup Extractor unpack कर सकता है:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Do not assume this captures every application. ADB इस command को deprecated के रूप में label करता है, और Android 12 API level 31 या उसके बाद को target करने वाले apps का data exclude करता है, जब तक कि app debuggable न हो।<sup>[[4]](#references)</sup>

### Root या physical debug access

Live device पर Root access के साथ, पहले partitions और mounts की inventory बनाएं; नीचे दिए गए commands सीधे physical JTAG acquisition पर लागू नहीं होते। सही block device hardware-dependent होता है, इसलिए यह न मानें कि वह हमेशा `mmcblk0` ही होगा। केवल verified source की image अलग storage पर बनाएं:<sup>[[1]](#references)</sup>

JTAG acquisition के लिए device के hardware test-access interface और compatible acquisition equipment का उपयोग करके accessible memory को read किया जाता है। Pinout, chipset support, device state और volatile तथा non-volatile targets के बीच का अंतर device-specific होते हैं; hardware path को document करें और उस model के लिए validated procedure का उपयोग करें।<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
उदाहरण के लिए, यदि partition inventory पुष्टि करता है कि `/dev/block/mmcblk0` पूरा flash device है और destination में पर्याप्त space है, तो original acquisition command बन जाता है:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
यहाँ, `df /data` `/data` को उसके mounted filesystem से संबद्ध करने में मदद करता है; इसे इस बात के प्रमाण के रूप में नहीं माना जाना चाहिए कि `mmcblk0` सही whole-device source है या `4096` ही एकमात्र मान्य `dd` block size है।

परिणाम का Hash निकालें और exact command, device identifiers, समय, तथा acquisition के दौरान किए गए किसी भी बदलाव को रिकॉर्ड करें।<sup>[[1]](#references)</sup>

### Memory

LiME Linux और कुछ Android devices से physical memory acquire कर सकता है, लेकिन इसके kernel module को target kernel के लिए build किया जाना चाहिए और पर्याप्त privileges के साथ load किया जाना चाहिए। Module signing, kernel lockdown और modern Android hardening इसे load होने से रोक सकते हैं।<sup>[[5]](#references)</sup>

Project का Android workflow matching module को ADB के माध्यम से push करता है, TCP port forward करता है, root shell से module load करता है और examination host पर stream capture करता है:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME इसके बजाय `path=/sdcard/ram.lime` के साथ device storage में लिख सकता है, लेकिन इससे device का storage बदल जाता है और पर्याप्त free space की आवश्यकता होती है। इस side effect को रिकॉर्ड करें और प्राप्त image का hash करें।<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobile Device Forensics के दिशानिर्देश](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens पर Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
