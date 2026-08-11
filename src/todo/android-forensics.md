# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

ऐसी acquisition methods को प्राथमिकता दें जो device की स्थिति को सुरक्षित रखें और हर action का documentation करें। यदि device locked है, तो उपलब्ध options model, Android version, patch level और seizure से पहले access configure किया गया था या नहीं, इस पर निर्भर करते हैं। NIST examination के लिए device और authority के अनुसार method चुनने की सलाह देता है।<sup>[[1]](#references)</sup>

- जाँचें कि USB debugging enabled था या नहीं और acquisition workstation पहले से authorized है या नहीं। ADB access के लिए सामान्यतः user को device unlock करके workstation की RSA key की पुष्टि करनी होती है।<sup>[[3]](#references)</sup>
- जाँचें कि लागू legal और procedural rules के अंतर्गत biometric access अभी उपलब्ध है या नहीं।
- एक **smudge attack** screen पर बचे residue से graphical unlock pattern प्रकट कर सकता है, हालांकि बाद के touches और cleaning इसकी reliability कम कर देते हैं।<sup>[[2]](#references)</sup>
- Commercial या research lock-bypass tooling का उपयोग केवल तभी करें जब वह exact device और software build को स्पष्ट रूप से support करता हो।

## Data acquisition

पुराने devices पर, legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) एक `.backup` file बना सकता है, जिसे Android Backup Extractor unpack कर सकता है:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
यह न मानें कि इसमें हर application शामिल है। ADB इस command को deprecated के रूप में चिह्नित करता है, और Android 12 में API level 31 या उसके बाद को target करने वाले apps का data शामिल नहीं होता, जब तक कि app debuggable न हो।<sup>[[4]](#references)</sup>

### Root या physical debug access

किसी live device पर root access के साथ, पहले partitions और mounts की inventory बनाएं; नीचे दिए गए commands सीधे physical JTAG acquisition पर लागू नहीं होते। सही block device hardware पर निर्भर करता है, इसलिए यह न मानें कि वह हमेशा `mmcblk0` ही होगा। केवल verified source की image अलग storage पर बनाएं:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
परिणाम का Hash निकालें और acquisition के दौरान इस्तेमाल की गई exact command, device identifiers, समय और किए गए किसी भी बदलाव को रिकॉर्ड करें।<sup>[[1]](#references)</sup>

### Memory

LiME Linux और कुछ Android devices से physical memory acquire कर सकता है, लेकिन इसके kernel module को target kernel के लिए build करके पर्याप्त privileges के साथ load करना आवश्यक है। Module signing, kernel lockdown और modern Android hardening इसे load होने से रोक सकते हैं।<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobile Device Forensics के लिए दिशानिर्देश](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens पर Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
