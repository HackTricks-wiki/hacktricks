# SUSE सत्र और डिस्क-सेवा विशेषाधिकार-वृद्धि के संकेत

{{#include ../../banners/hacktricks-training.md}}

## PAM के माध्यम से SSH सत्र प्राधिकरण

CVE-2025-6018 ने SUSE 15 के उन PAM कॉन्फ़िगरेशन को प्रभावित किया, जिनमें SSH authentication stack ने `pam_env` को तब लोड किया, जब session stack ने `pam_systemd` लोड किया। जब `pam_env` किसी उपयोगकर्ता की `.pam_environment` फ़ाइल पढ़ता था, तो वह उपयोगकर्ता `XDG_SEAT` और `XDG_VTNR` की ऐसी values दे सकता था जिनसे SSH सत्र Polkit को भौतिक रूप से सक्रिय दिखाई देता था। इसके बाद `allow_active=yes` वाली कार्रवाई किसी दूरस्थ उपयोगकर्ता के लिए उपलब्ध हो सकती थी। इससे सत्र प्राधिकरण बदलता है; इससे अपने-आप root access की गारंटी नहीं मिलती। SUSE ने `pam` में डिफ़ॉल्ट user-environment व्यवहार और `pam-config` द्वारा जनरेट किए जाने वाले module placement को ठीक किया।<sup>[[1]](#references)[[2]](#references)</sup>

प्रभावी `/etc/pam.d/sshd` include chain, `pam_env.so` और `pam_systemd.so` का क्रम, और `user_readenv=1` का कोई स्पष्ट विकल्प जाँचें। पैच किया गया `pam` package डिफ़ॉल्ट व्यवहार बदलता है, लेकिन स्पष्ट विकल्प अब भी user-environment पढ़ने का अनुरोध कर सकता है। नया `pam-config` package इस बात का प्रमाण नहीं है कि स्थानीय रूप से बदला गया या पुराना PAM stack फिर से जनरेट किया गया है। विक्रेता के package release और वास्तविक कॉन्फ़िगरेशन—दोनों की जाँच करें।<sup>[[1]](#references)[[2]](#references)</sup>

## सक्रिय-उपयोगकर्ता डिस्क-सेवा पथ

CVE-2025-6019, `udisks2` के माध्यम से उपयोग किए जाने वाले `libblockdev` में विशेषाधिकार-वृद्धि का एक पथ था: XFS का आकार बदलने के दौरान, हमलावर द्वारा दिया गया filesystem अस्थायी रूप से अपेक्षित `nosuid` प्रतिबंध के बिना mount हो सकता था। इस पथ के लिए उपयोग योग्य UDisks D-Bus service, XFS resize support, caller के लिए उपलब्ध संबंधित Polkit action और प्रभावित library package आवश्यक हैं। CVE-2025-6018 सक्रिय-उपयोगकर्ता सत्र पाने का एक तरीका है, लेकिन पहले से सक्रिय उपयोगकर्ता स्वतंत्र रूप से डिस्क-सेवा पथ तक पहुँच सकता है।<sup>[[3]](#references)</sup>

निष्क्रिय समीक्षा के लिए, UDisks service metadata, `org.freedesktop.udisks2.modify-device` policy, `xfs_growfs` और इंस्टॉल किए गए `libbd_fs2` package की जाँच करें। SUSE, openSUSE Leap 15.6 के लिए `libbd_fs2` version `2.26-150400.3.5.1` को ठीक किया गया version बताता है; सटीक fixed release उत्पाद पर निर्भर करता है। केवल policy और package की मौजूदगी इस बात का प्रमाण नहीं है कि caller किसी device को mount या resize कर सकता है। जाँच के दौरान mounts में बदलाव करने या D-Bus methods चलाने से बचें।<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 सलाह](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config सुरक्षा अपडेट](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 सलाह](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
