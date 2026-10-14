# Android Forensics

{{#include ../../banners/hacktricks-training.md}}

## लॉक किया गया डिवाइस

ऐसी acquisition विधियों को प्राथमिकता दें जो डिवाइस की स्थिति को सुरक्षित रखें, और हर कार्रवाई का दस्तावेज़ीकरण करें। यदि डिवाइस लॉक है, तो उपलब्ध विकल्प मॉडल, Android version, patch level और डिवाइस ज़ब्त करने से पहले access कॉन्फ़िगर किया गया था या नहीं, इस पर निर्भर करते हैं। NIST डिवाइस और जाँच के अधिकार के अनुसार विधि चुनने की सलाह देता है।<sup>[[1]](#references)</sup>

- जाँचें कि USB debugging सक्षम था या नहीं और acquisition workstation पहले से authorized है या नहीं। ADB access के लिए आमतौर पर उपयोगकर्ता को डिवाइस अनलॉक करके workstation की RSA key की पुष्टि करनी पड़ती है।<sup>[[3]](#references)</sup>
- विचार करें कि लागू कानूनी और प्रक्रियात्मक नियमों के तहत biometric access अब भी उपलब्ध है या नहीं।
- **smudge attack** से स्क्रीन पर बचे निशानों के आधार पर graphical unlock pattern का पता चल सकता है, हालाँकि बाद के स्पर्श और सफ़ाई से इसकी विश्वसनीयता कम हो जाती है।<sup>[[2]](#references)</sup>
- जहाँ authorized tooling किसी खास डिवाइस और software build को support करता हो, वहाँ वह PIN, password या pattern को recover करने या brute force करने की कोशिश कर सकता है। Hardware-backed credential verification, retry delays और wipe policies के कारण यह पूरी तरह डिवाइस-विशिष्ट है; इसलिए किसी Android डिवाइस के support होने के सबूत के रूप में iPhone की तकनीक या नतीजे का इस्तेमाल न करें।<sup>[[1]](#references)</sup>

## डेटा अधिग्रहण

पुराने डिवाइसों पर, legacy [ADB backup](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup) से `.backup` फ़ाइल बन सकती है, जिसे Android Backup Extractor unpack कर सकता है:<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

यह न मानें कि इससे हर application का डेटा मिल जाता है। ADB इस command को deprecated बताता है, और Android 12 उन apps का डेटा शामिल नहीं करता जो API level 31 या उसके बाद के लिए target करती हैं—जब तक कि app debuggable न हो।<sup>[[4]](#references)</sup>

### Root या physical debug access

Live device पर root access होने पर, पहले partitions और mounts की inventory बनाएं; नीचे दिए गए commands सीधे physical JTAG acquisition पर लागू नहीं होते। सही block device hardware पर निर्भर करता है, इसलिए यह न मानें कि वह हमेशा `mmcblk0` ही होगा। केवल सत्यापित source की image अलग storage पर बनाएं:<sup>[[1]](#references)</sup>

इसके बजाय, JTAG acquisition में device के hardware test-access interface और संगत acquisition उपकरणों का उपयोग करके सुलभ memory पढ़ी जाती है। Pinout, chipset support, device state और volatile तथा non-volatile targets के बीच का अंतर device के अनुसार अलग-अलग होता है; इस model के लिए hardware path दर्ज करें और validated procedure का उपयोग करें।<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

उदाहरण के लिए, यदि partition inventory यह पुष्टि करता है कि `/dev/block/mmcblk0` पूरी flash डिवाइस है और destination में पर्याप्त जगह है, तो acquisition की मूल command यह बन जाती है:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

यहाँ, `df /data` से `/data` को उसके mounted filesystem से जोड़ने में मदद मिलती है; इसे इस बात का प्रमाण नहीं मानना चाहिए कि `mmcblk0` सही whole-device source है या `4096` ही `dd` block size का एकमात्र मान्य विकल्प है।

परिणाम का hash निकालें और सटीक command, device identifiers, समय और acquisition के दौरान किए गए किसी भी बदलाव को दर्ज करें।<sup>[[1]](#references)</sup>

### मेमोरी

LiME Linux और कुछ Android devices से physical memory acquire कर सकता है, लेकिन इसका kernel module target kernel के लिए बनाया जाना चाहिए और पर्याप्त privileges के साथ load किया जाना चाहिए। Module signing, kernel lockdown और आधुनिक Android hardening इसे load होने से रोक सकते हैं।<sup>[[5]](#references)</sup>

प्रोजेक्ट का Android workflow ADB से matching module को push करता है, TCP port forward करता है, root shell से module load करता है और examination host पर stream capture करता है:<sup>[[5]](#references)</sup>

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

LiME इसके बजाय `path=/sdcard/ram.lime` के साथ device storage में लिख सकता है, लेकिन इससे device की storage बदलती है और पर्याप्त खाली जगह की आवश्यकता होती है। इस दुष्प्रभाव को रिकॉर्ड करें और प्राप्त image का hash निकालें।<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Mobile Device Forensics के लिए दिशानिर्देश](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smartphone Touch Screens पर Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup प्रतिबंध](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
