# SUSE Session और Disk-Service Escalation के संकेत

{{#include ../../banners/hacktricks-training.md}}

## PAM के ज़रिए SSH session authorization

CVE-2025-6018 ने SUSE 15 के उन PAM configurations को प्रभावित किया जिनमें SSH authentication stack ने `pam_env` को उस session stack से पहले लोड किया जिसमें `pam_systemd` लोड होता था। जब `pam_env` ने किसी user की `.pam_environment` फ़ाइल पढ़ी, तो वह user `XDG_SEAT` और `XDG_VTNR` की ऐसी values दे सकता था जिनसे Polkit को SSH session भौतिक रूप से सक्रिय दिखाई देता। इसके बाद remote user के लिए `allow_active=yes` वाली action उपलब्ध हो सकती थी। इससे session authorization बदलता है; अपने-आप root access मिलने की गारंटी नहीं होती। SUSE ने `pam` में user-environment का default behavior और `pam-config` द्वारा जनरेट किए जाने वाले module placement को ठीक किया।<sup>[[1]](#references)[[2]](#references)</sup>

प्रभावी `/etc/pam.d/sshd` include chain, `pam_env.so` और `pam_systemd.so` का क्रम, और किसी भी स्पष्ट `user_readenv=1` option की जाँच करें। Patched `pam` package default बदलता है, लेकिन कोई स्पष्ट option अब भी user-environment पढ़ने का अनुरोध कर सकता है। नया `pam-config` package इस बात का प्रमाण नहीं है कि स्थानीय रूप से संशोधित या पुराना PAM stack फिर से जनरेट किया गया था। Vendor package release और वास्तविक configuration, दोनों की जाँच करें।<sup>[[1]](#references)[[2]](#references)</sup>

## Active-user disk-service path

CVE-2025-6019, `udisks2` के ज़रिए इस्तेमाल होने वाले `libblockdev` में escalation path था: XFS resize के दौरान, हमलावर द्वारा दी गई filesystem को अपेक्षित `nosuid` restriction के बिना अस्थायी रूप से mount किया जा सकता था। इस रास्ते के लिए उपयोग योग्य UDisks D-Bus service, XFS resize support, caller के लिए उपलब्ध संबंधित Polkit action और प्रभावित library package आवश्यक हैं। CVE-2025-6018 active-user session हासिल करने का एक तरीका है, लेकिन पहले से सक्रिय user स्वतंत्र रूप से disk-service path तक पहुँच सकता है।<sup>[[3]](#references)</sup>

Passive review के लिए UDisks service metadata, `org.freedesktop.udisks2.modify-device` policy, `xfs_growfs` और install किए गए `libbd_fs2` package की जाँच करें। SUSE ने openSUSE Leap 15.6 के लिए `libbd_fs2` version `2.26-150400.3.5.1` को fixed बताया है; सटीक fixed release product पर निर्भर करती है। केवल policy और package की मौजूदगी से यह साबित नहीं होता कि caller किसी device को mount या resize कर सकता है। Enumeration के दौरान mounts में बदलाव करने या D-Bus methods invoke करने से बचें।<sup>[[3]](#references)</sup>

## References

- [1] [SUSE CVE-2025-6018 की सलाह](https://www.suse.com/security/cve/CVE-2025-6018.html)
- [2] [SUSE pam-config security update](https://www.suse.com/support/update/announcement/2025/suse-su-202502082-1)
- [3] [SUSE CVE-2025-6019 की सलाह](https://www.suse.com/security/cve/CVE-2025-6019.html)
{{#include ../../banners/hacktricks-training.md}}
