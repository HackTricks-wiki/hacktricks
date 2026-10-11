# उपयोगकर्ता जानकारी

{{#include ../../banners/hacktricks-training.md}}

उपयोगकर्ता की पहचान, समूह सदस्यता और प्रत्यायोजित credentials यह निर्धारित करते हैं कि कोई process किन संसाधनों तक पहुँच सकता है। नीचे दिए गए access paths की जाँच करने से पहले प्रभावी पहचान और supplementary groups जाँचें।

- [उपयोगकर्ता, sessions और credential artifacts](user-and-session-triage.md) में account enumeration, सक्रिय logins, SSH और shell artifacts, तथा credential stores शामिल हैं।
- [वास्तविक, प्रभावी और सहेजी गई user IDs](euid-ruid-suid.md) में SUID programs और process execution के दौरान पहचान में होने वाले बदलाव समझाए गए हैं।
- [Linux privilege escalation के लिए दिलचस्प groups](interesting-groups-linux-pe/README.md) में group-granted access शामिल है, जिसमें LXD/LXC भी शामिल हैं।
- [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) में forwarded SSH credentials से जुड़े जोखिमों की जाँच की गई है।
- [Linux Active Directory](linux-active-directory.md) में AD environment से जुड़े hosts शामिल हैं।
{{#include ../../banners/hacktricks-training.md}}
