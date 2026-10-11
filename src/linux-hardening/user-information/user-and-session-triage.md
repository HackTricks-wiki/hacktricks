# उपयोगकर्ता, सत्र और क्रेडेंशियल आर्टिफैक्ट

{{#include ../../banners/hacktricks-training.md}}

शुरुआत उस पहचान से करें जिसके पास मौजूदा shell है, फिर अन्य उपयोगकर्ताओं, समूहों, सक्रिय सत्रों और क्रेडेंशियल स्टोर की सूची बनाएं। [real, effective, and saved user ID](euid-ruid-suid.md) पेज बताता है कि किसी process के effective privileges उसके login account से अलग क्यों हो सकते हैं।

## पहचान और समूह-आधारित पहुंच की सूची बनाएं

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` में directory-backed accounts भी शामिल होते हैं, जिन्हें केवल `/etc/passwd` पढ़ने पर नज़रअंदाज़ किया जा सकता है। UID 0 accounts, login shells, home directories, supplementary groups और उन accounts की समीक्षा करें जिनकी configuration अप्रत्याशित रूप से interactive login की अनुमति देती है। [interesting groups](interesting-groups-linux-pe/README.md) पेज `sudo`, `docker`, `disk` और `shadow` जैसी delegated access को कवर करता है। किसी group name को privilege मानने से पहले वास्तविक filesystem ACLs और local policy जाँचें।

अगर [NSS `passwd`, `group` या `shadow` lookups को](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) किसी database पर map करता है, तो database-backed identities का आकलन करने से पहले सक्रिय provider और उसकी configuration path की समीक्षा करें। PostgreSQL NSS deployments के लिए, `/etc/nss-pgsql.conf` और `/etc/nss-pgsql-root.conf` केवल path-only leads हैं, क्योंकि connection settings में credentials हो सकते हैं। Database role तभी मायने रखता है, जब वह उन records को बदल सकता हो जिन्हें सक्रिय NSS provider वास्तव में लौटाता है और कोई account उनका उपयोग करके authenticate कर सकता हो। Primary GID 0 से root-group membership मिलती है, UID 0 नहीं; sudo-group mapping के लिए प्रभावी [sudoers group rule](https://man7.org/linux/man-pages/man5/sudoers.5.html) और आवश्यक authentication चाहिए। UID 0 mapping एक अलग identity boundary है। Passive enumeration के दौरान connection strings प्रिंट न करें या account records न बदलें।

Local account names में numeric UIDs की भी तुलना करें। [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) में दो names एक ही Unix file identity को संदर्भित कर सकते हैं, जबकि उनके login authentication records अलग हो सकते हैं। इसलिए, सफल authentication के बाद साझा nonzero UID वाला नया जोड़ा गया alias किसी अन्य user की files या processes तक पहुँच दे सकता है; यह root access नहीं देता, जब तक वह UID या कोई अलग privilege path ऐसा न करे। Shared UIDs जानबूझकर भी रखे जा सकते हैं। Account source (`/etc/passwd` बनाम NSS), creation history, shell और home, वास्तविक authentication policy, और यह जाँचें कि क्या accounts को identity साझा करने की अनुमति है। केवल local accounts की जाँच से directory-backed alias की संभावना खारिज नहीं होती।

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

एक `screen` या `tmux` socket, यदि उसकी permissions वर्तमान user को attach करने देती हैं, तो मौजूदा shell तक पहुँच दे सकता है। पहुँचने की कोशिश करने से पहले owner और socket mode जाँचें; किसी अन्य user का session अपने-आप attach नहीं किया जा सकता। सक्रिय sudo timestamp या SSH agent socket भी मायने रख सकता है, लेकिन उनका पुनः उपयोग user identity, permissions और policy पर निर्भर करता है। Agent forwarding के दुरुपयोग के लिए, [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) देखें।

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster), `SSH_AUTH_SOCK` से अलग होता है: `ControlMaster` और `ControlPath` बाद के SSH clients को मौजूदा authenticated connection साझा करने देते हैं, जबकि `ControlPersist` पहला session समाप्त होने के बाद भी master को उपलब्ध रख सकता है। वर्तमान user की `.ssh/config` और `.ssh` में मौजूद socket paths की जाँच करें, जिसमें owner और permissions भी शामिल हों। केवल socket filename से यह साबित नहीं होता कि master सक्रिय है, वर्तमान user उससे connect कर सकता है, या वह किस remote account का उपयोग करता है।

## उपयोगकर्ता के artifacts की समीक्षा करें

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history, startup files, SSH keys, application configuration, GPG keyrings और Kerberos caches से credentials या writable persistence points का पता चल सकता है। अधिक privileged account की writable `authorized_keys` फ़ाइल या shell startup file की समीक्षा की जानी चाहिए। [post-exploitation page](../post-exploitation/README.md) में GPG homedir relocation और credential hunting शामिल हैं; [Linux Active Directory](linux-active-directory.md) में Kerberos cache और keytab reuse शामिल हैं। [PAM page](../software-information/pam-pluggable-authentication-modules.md) authentication-policy risks समझाता है।
{{#include ../../banners/hacktricks-training.md}}
