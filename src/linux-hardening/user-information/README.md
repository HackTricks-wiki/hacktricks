# उपयोगकर्ता जानकारी

{{#include ../../banners/hacktricks-training.md}}

उपयोगकर्ता की पहचान, समूह सदस्यता और delegated credentials यह निर्धारित करते हैं कि कोई process किन resources तक पहुँच सकता है। नीचे दिए गए access paths की जाँच करने से पहले effective identity और supplementary groups देखें।

- [उपयोगकर्ता, sessions और credential artifacts](user-and-session-triage.md) में account enumeration, active logins, SSH और shell artifacts, तथा credential stores शामिल हैं।
- [Real, effective और saved user IDs](euid-ruid-suid.md) SUID programs और process execution के दौरान identity में होने वाले बदलाव समझाता है।
- [Linux privilege escalation के लिए दिलचस्प समूह](interesting-groups-linux-pe/README.md) में group-granted access शामिल है, जिसमें LXD/LXC भी शामिल हैं।
- [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) forwarded SSH credentials से जुड़े जोखिमों की पड़ताल करता है।
- [Linux Active Directory](linux-active-directory.md) में AD environment से जुड़े hosts शामिल हैं।

{{#include ../../banners/hacktricks-training.md}}
