# उपयोगकर्ता जानकारी

{{#include ../../banners/hacktricks-training.md}}

उपयोगकर्ता की पहचान, समूह सदस्यता और सौंपे गए credentials यह तय करते हैं कि कोई process किन resources तक पहुँच सकता है। नीचे दिए गए access paths की जाँच करने से पहले प्रभावी पहचान और अतिरिक्त समूहों की जाँच करें।

- [उपयोगकर्ता, sessions और credential artifacts](user-and-session-triage.md) में account enumeration, सक्रिय logins, SSH और shell artifacts, और credential stores शामिल हैं।
- [वास्तविक, प्रभावी और सहेजी गई user IDs](euid-ruid-suid.md) बताता है कि SUID programs और process execution के दौरान पहचान में कैसे बदलाव होते हैं।
- [Linux privilege escalation के लिए रुचिकर समूह](interesting-groups-linux-pe/README.md) में समूहों द्वारा दिए गए access, जिसमें LXD/LXC शामिल हैं, की जानकारी है।
- [SSH forwarding agent का exploitation](ssh-forward-agent-exploitation.md) forwarded SSH credentials से जुड़े जोखिमों की जाँच करता है।
- [Linux Active Directory](linux-active-directory.md) में AD environment से जुड़े hosts शामिल हैं।

{{#include ../../banners/hacktricks-training.md}}
