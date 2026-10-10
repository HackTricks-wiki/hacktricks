# उपयोगकर्ता, सेशन और क्रेडेंशियल आर्टिफैक्ट

{{#include ../../banners/hacktricks-training.md}}

सबसे पहले उस पहचान से शुरू करें जिसके पास मौजूदा shell का स्वामित्व है। फिर अन्य उपयोगकर्ताओं, समूहों, सक्रिय सेशन और क्रेडेंशियल स्टोर की सूची बनाएँ। [real, effective, and saved user ID](euid-ruid-suid.md) पेज बताता है कि किसी प्रोसेस के effective privileges उसके login account से अलग क्यों हो सकते हैं।

## पहचान और समूह-आधारित एक्सेस की सूची बनाएँ

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` में directory-backed accounts शामिल होते हैं, जो `/etc/passwd` को सीधे पढ़ने पर छूट सकते हैं। UID 0 वाले accounts, login shells, home directories, supplementary groups और ऐसे accounts की समीक्षा करें जिनकी configuration अप्रत्याशित रूप से interactive login की अनुमति देती है। [interesting groups](interesting-groups-linux-pe/README.md) पेज में `sudo`, `docker`, `disk` और `shadow` जैसी delegated access की जानकारी है। किसी group name को privilege मानने से पहले वास्तविक filesystem ACLs और local policy जाँचें।

अगर [NSS `passwd`, `group` या `shadow` lookups को](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) किसी database पर map करता है, तो database-backed identities का आकलन करने से पहले सक्रिय provider और उसकी configuration path की समीक्षा करें। PostgreSQL NSS deployments के लिए, `/etc/nss-pgsql.conf` और `/etc/nss-pgsql-root.conf` केवल path देखने के सुराग हैं, क्योंकि connection settings में credentials हो सकते हैं। कोई database role तभी मायने रखता है, जब वह उन records को बदल सके जिन्हें सक्रिय NSS provider वास्तव में लौटाता है, और कोई account उनका इस्तेमाल करके authenticate कर सके। Primary GID 0 होने से root-group membership मिलती है, UID 0 नहीं; sudo-group mapping के लिए प्रभावी [sudoers group rule](https://man7.org/linux/man-pages/man5/sudoers.5.html) और आवश्यक authentication चाहिए। UID 0 mapping एक अलग identity boundary है। Passive enumeration के दौरान connection strings प्रिंट न करें या account records न बदलें।

Local account names के बीच numeric UIDs की भी तुलना करें। [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) में दो नाम एक ही Unix file identity को दर्शा सकते हैं, जबकि उनके login authentication records अलग हो सकते हैं। इसलिए, सफल authentication के बाद साझा nonzero UID वाला नया alias किसी अन्य user की files या processes तक पहुँच दे सकता है; इससे root access नहीं मिलता, जब तक कि वह UID या कोई अलग privilege path ऐसा न दे। साझा UIDs जानबूझकर भी रखे जा सकते हैं। Account source (`/etc/passwd` बनाम NSS), creation history, shell और home, वास्तविक authentication policy, और यह जाँचें कि accounts को identity साझा करने की अनुमति है या नहीं। केवल local accounts की जाँच करने से directory-backed alias होने की संभावना खारिज नहीं होती।

## सक्रिय और हाल के sessions खोजें

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` या `tmux` socket किसी मौजूदा shell तक पहुँच दे सकता है, यदि उसकी permissions मौजूदा user को attach होने की अनुमति देती हैं। पहुँच का प्रयास करने से पहले owner और socket mode जाँचें; किसी अन्य user के session से अपने-आप attach नहीं किया जा सकता। सक्रिय sudo timestamp या SSH agent socket भी मायने रख सकता है, लेकिन उनका पुनः उपयोग user की पहचान, permissions और policy पर निर्भर करता है। Agent forwarding abuse के लिए, [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) देखें।

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK` से अलग होता है: `ControlMaster` और `ControlPath` बाद के SSH clients को मौजूदा authenticated connection साझा करने देते हैं, जबकि `ControlPersist` पहला session समाप्त होने के बाद भी master को उपलब्ध रख सकता है। मौजूदा user की `.ssh/config` और `.ssh` में मौजूद socket paths की जाँच करें; owner और permissions भी देखें। केवल socket filename से यह साबित नहीं होता कि master सक्रिय है, मौजूदा user उससे connect कर सकता है, या वह किस remote account का उपयोग करता है।

## User artifacts की समीक्षा करें

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, startup files, SSH keys, application configuration, GPG keyrings और Kerberos caches से credentials या writable persistence points का पता चल सकता है। अधिक privileged account की `authorized_keys` या shell startup file में लिखने की अनुमति की जाँच की जानी चाहिए। [post-exploitation page](../post-exploitation/README.md) में GPG homedir relocation और credential hunting शामिल हैं; [Linux Active Directory](linux-active-directory.md) में Kerberos cache और keytab reuse शामिल हैं। [PAM page](../software-information/pam-pluggable-authentication-modules.md) में authentication-policy risks समझाए गए हैं।
{{#include ../../banners/hacktricks-training.md}}
