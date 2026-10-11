# उपयोगकर्ता, सत्र और क्रेडेंशियल आर्टिफैक्ट

{{#include ../../banners/hacktricks-training.md}}

उस पहचान से शुरुआत करें जिसके पास वर्तमान shell है, फिर अन्य उपयोगकर्ताओं, समूहों, सक्रिय सत्रों और क्रेडेंशियल स्टोर की सूची बनाएँ। [real, effective, and saved user ID](euid-ruid-suid.md) पेज बताता है कि किसी प्रक्रिया के effective privileges उसके login account से अलग क्यों हो सकते हैं।

## पहचान और समूह-आधारित पहुँच की सूची बनाएँ

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` में डायरेक्टरी-आधारित खाते भी शामिल होते हैं, जो `/etc/passwd` को सीधे पढ़ने पर छूट सकते हैं। UID 0 वाले खातों, login shells, home directories, supplementary groups और उन खातों की समीक्षा करें जिनकी configuration अप्रत्याशित रूप से interactive login की अनुमति देती है। [interesting groups](interesting-groups-linux-pe/README.md) पेज `sudo`, `docker`, `disk` और `shadow` जैसी delegated access के बारे में बताता है। किसी group name को privilege मानने से पहले वास्तविक filesystem ACLs और local policy जाँचें।

अगर [NSS `passwd`, `group` या `shadow` lookups को](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) किसी database पर map करता है, तो database-backed identities का आकलन करने से पहले सक्रिय provider और उसकी configuration path की समीक्षा करें। PostgreSQL NSS deployments के लिए `/etc/nss-pgsql.conf` और `/etc/nss-pgsql-root.conf` केवल path तक सीमित सुराग हैं, क्योंकि connection settings में credentials हो सकते हैं। कोई database role तभी मायने रखता है जब वह उन records को बदल सके जिन्हें सक्रिय NSS provider वास्तव में लौटाता है और कोई account उनका उपयोग करके authenticate कर सके। Primary GID 0 से root-group membership मिलती है, UID 0 नहीं; sudo-group mapping के लिए प्रभावी [sudoers group rule](https://man7.org/linux/man-pages/man5/sudoers.5.html) और ज़रूरी authentication आवश्यक है। UID 0 mapping एक अलग identity boundary है। Passive enumeration के दौरान connection strings प्रिंट न करें और account records न बदलें।

Local account names के बीच numeric UIDs की भी तुलना करें। [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) में दो नाम एक ही Unix file identity को संदर्भित कर सकते हैं, जबकि उनके login authentication records अलग हो सकते हैं। इसलिए, सफल authentication के बाद साझा nonzero UID वाला नया alias किसी अन्य user की files या processes तक पहुँच दे सकता है; जब तक वह UID या privilege का कोई अलग रास्ता न हो, इससे root access नहीं मिलता। साझा UIDs जानबूझकर भी रखे जा सकते हैं। Account source (`/etc/passwd` बनाम NSS), creation history, shell और home, वास्तविक authentication policy, और यह जाँचें कि क्या खातों को identity साझा करने की अनुमति है। केवल local खातों की duplicate जाँच से directory-backed alias का पता न चलने की संभावना बनी रहती है।

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

`screen` या `tmux` socket मौजूदा shell को उजागर कर सकता है, यदि उसकी permissions मौजूदा user को attach करने देती हैं। पहुँचने का प्रयास करने से पहले owner और socket mode जाँचें; किसी दूसरे user का session अपने-आप attach नहीं किया जा सकता। सक्रिय sudo timestamp या SSH agent socket भी मायने रख सकता है, लेकिन उनका पुनः उपयोग user identity, permissions और policy पर निर्भर करता है। agent forwarding abuse के लिए, देखें [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md)।

एक [OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK` से अलग होता है: `ControlMaster` और `ControlPath` बाद के SSH clients को मौजूदा authenticated connection साझा करने देते हैं, जबकि `ControlPersist` पहली session समाप्त होने के बाद भी master को उपलब्ध रख सकता है। मौजूदा user का `.ssh/config` और ऊपरी स्तर के `.ssh` socket paths जाँचें, साथ ही owner और permissions भी। केवल socket filename से यह साबित नहीं होता कि master सक्रिय है, मौजूदा user उससे connect कर सकता है, या वह किस remote account का उपयोग करता है।

## उपयोगकर्ता artifacts की समीक्षा

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, startup files, SSH keys, application configuration, GPG keyrings और Kerberos caches से credentials या writable persistence points का पता चल सकता है। किसी अधिक privileged account की writable `authorized_keys` फ़ाइल या shell startup file की समीक्षा करना ज़रूरी है। [post-exploitation page](../post-exploitation/README.md) में GPG homedir relocation और credential hunting शामिल हैं; [Linux Active Directory](linux-active-directory.md) में Kerberos cache और keytab reuse शामिल हैं। [PAM page](../software-information/pam-pluggable-authentication-modules.md) में authentication-policy के जोखिम समझाए गए हैं।
{{#include ../../banners/hacktricks-training.md}}
