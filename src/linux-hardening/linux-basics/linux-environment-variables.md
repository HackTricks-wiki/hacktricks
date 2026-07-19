# Linux Environment Variables

{{#include ../../banners/hacktricks-training.md}}

## Global variables

Global variables को **child processes** द्वारा inherit **किया जाएगा**।

आप यह करके अपने current session के लिए एक global variable बना सकते हैं:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
यह variable आपके वर्तमान sessions और उनकी child processes के लिए accessible होगा।

आप इस प्रकार variable को **remove** कर सकते हैं:
```bash
unset MYGLOBAL
```
## Local variables

**local variables** को केवल **current shell/script** द्वारा **accessed** किया जा सकता है।
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## वर्तमान variables की सूची
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` की सामग्री **NUL-separated** होती है, इसलिए ये variants आमतौर पर पढ़ने में आसान होते हैं:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
यदि आप inherited environments के अंदर **credentials** या **interesting service configuration** ढूंढ रहे हैं, तो [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) भी जांचें।

## सामान्य variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** द्वारा उपयोग किया जाने वाला display। यह variable आमतौर पर **:0.0** पर set होता है, जिसका अर्थ current computer पर पहला display है।
- **EDITOR** – user का पसंदीदा text editor।
- **HISTFILESIZE** – history file में मौजूद lines की maximum संख्या।
- **HISTSIZE** – user के session समाप्त करने पर history file में जोड़ी जाने वाली lines की संख्या।
- **HOME** – आपकी home directory।
- **HOSTNAME** – computer का hostname।
- **LANG** – आपकी current language।
- **MAIL** – user के mail spool का location। आमतौर पर **/var/spool/mail/USER**।
- **MANPATH** – manual pages के लिए search की जाने वाली directories की list।
- **OSTYPE** – operating system का type।
- **PS1** – bash में default prompt।
- **PATH** – उन सभी directories के paths store करता है जिनमें वे binary files मौजूद होती हैं जिन्हें आप file का नाम specify करके execute करना चाहते हैं, न कि relative या absolute path से।
- **PWD** – current working directory।
- **SHELL** – current command shell का path (उदाहरण के लिए, **/bin/bash**)।
- **TERM** – current terminal type (उदाहरण के लिए, **xterm**)।
- **TZ** – आपका time zone।
- **USER** – आपका current username।

## hacking के लिए interesting variables

हर variable समान रूप से उपयोगी नहीं होता। offensive perspective से उन variables को प्राथमिकता दें जो **search paths**, **startup files**, **dynamic linker behavior**, या **audit/logging** को बदलते हैं।

### **HISTFILESIZE**

**इस variable की value को 0 में बदलें**, ताकि जब आप **अपना session समाप्त करें**, तो **history file** (\~/.bash_history) **0 lines तक truncate** हो जाए।
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

इस **variable की value को 0** में बदलें, ताकि commands **in-memory history में محفوظ न रहें** और **history file** (\~/.bash_history) में वापस न लिखे जाएँ।
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

यदि **इस variable का value `ignorespace` या `ignoreboth` पर set है**, तो आगे एक अतिरिक्त space वाली कोई भी command history में save नहीं की जाएगी।
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** को **`/dev/null`** पर सेट करें या इसे पूरी तरह unset कर दें। यह आमतौर पर केवल history size बदलने से अधिक विश्वसनीय होता है।
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Processes **proxy** में घोषित proxy का उपयोग करके **http या https** के माध्यम से internet से connect होंगे।
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy और no_proxy

- `all_proxy`: उन tools/protocols के लिए default proxy जो इसे support करते हैं।
- `no_proxy`: bypass list (hosts/domains/CIDRs), जिन्हें सीधे connect करना चाहिए।
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Tool के आधार पर lowercase और uppercase variants, दोनों का उपयोग किया जा सकता है (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)।

### SSL_CERT_FILE & SSL_CERT_DIR

Processes **इन env variables** में निर्दिष्ट certificates पर trust करेंगे। यह **`curl`**, **`git`**, Python HTTP clients या package managers जैसे tools को attacker द्वारा नियंत्रित CA पर trust कराने के लिए उपयोगी है (उदाहरण के लिए, interception proxy को legitimate दिखाने के लिए)।
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

यदि कोई privileged wrapper/script commands को **absolute paths के बिना** execute करता है, तो `PATH` में मौजूद **पहली attacker-controlled directory** जीतती है। यही `sudo`, cron jobs, shell wrappers और custom SUID helpers में होने वाले कई **PATH hijacks** का primitive है। `env_keep+=PATH`, कमजोर `secure_path`, या ऐसे wrappers खोजें जो `tar`, `service`, `cp`, `python` आदि को नाम से call करते हैं।
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
पूर्ण privilege-escalation chains के लिए `PATH` का दुरुपयोग करने वाले उदाहरण देखें [Linux Privilege Escalation](linux-privilege-escalation/README.md)।

### **HOME & XDG_CONFIG_HOME**

`HOME` केवल किसी directory का reference नहीं है: कई tools `$HOME` या `$XDG_CONFIG_HOME` से **dotfiles**, **plugins**, और **per-user configuration** को automatically load करते हैं। यदि कोई privileged workflow इन values को preserve करता है, तो **config injection** binary hijacking की तुलना में आसान हो सकता है।
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
दिलचस्प targets में `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, और `.terraformrc` जैसी tool-specific files शामिल हैं।

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

ये variables **dynamic linker** को प्रभावित करते हैं:

- `LD_PRELOAD`: अतिरिक्त shared objects को सबसे पहले load करने के लिए बाध्य करता है।
- `LD_LIBRARY_PATH`: library search directories को आगे रखता है।
- `LD_AUDIT`: ऐसी auditor libraries load करता है जो library loading और symbol resolution को observe करती हैं।

यदि कोई privileged command इन्हें preserve करता है, तो ये **hooking**, **instrumentation**, और **privilege escalation** के लिए अत्यंत उपयोगी होते हैं। **secure-execution** mode (`AT_SECURE`, जैसे setuid/setgid/capabilities) में loader इनमें से कई variables को हटा देता है या प्रतिबंधित कर देता है। हालांकि, उस शुरुआती loader stage में मौजूद parser bugs का प्रभाव अब भी गंभीर होता है, क्योंकि वे target program से **पहले** run होते हैं।
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` शुरुआती glibc behavior (उदाहरण के लिए, allocator tunables) को बदलता है और exploit labs में बहुत उपयोगी है। यह security perspective से भी महत्वपूर्ण है, क्योंकि **dynamic loader इसे बहुत शुरुआती चरण में parse करता है**। 2023 का **Looney Tunables** bug इस बात की अच्छी याद दिलाता है कि loader में parse किया गया एक single environment variable, SUID programs के विरुद्ध **local privilege-escalation primitive** बन सकता है।
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV और ENV**

यदि **Bash** को **non-interactively** शुरू किया जाता है, तो यह `BASH_ENV` की जाँच करता है और target script चलाने से पहले उस फ़ाइल को source करता है। जब Bash को `sh` के रूप में invoke किया जाता है, या POSIX-style interactive mode में चलाया जाता है, तो `ENV` से भी consult किया जा सकता है। यदि environment attacker-controlled हो, तो shell wrapper को code execution में बदलने का यह एक classic तरीका है।
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash स्वयं इन startup files को अक्षम कर देता है जब **real/effective IDs अलग होते हैं**, जब तक कि `-p` का उपयोग न किया जाए, इसलिए सटीक व्यवहार इस बात पर निर्भर करता है कि wrapper shell को कैसे invoke करता है।

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP और PYTHONINSPECT**

ये variables Python के start होने के तरीके को बदलते हैं:

- `PYTHONPATH`: import search paths को prepend करता है।
- `PYTHONHOME`: standard library tree को relocate करता है।
- `PYTHONSTARTUP`: interactive prompt से पहले एक file execute करता है।
- `PYTHONINSPECT=1`: script समाप्त होने के बाद interactive mode में प्रवेश करता है।

ये maintenance scripts, debuggers, shells और ऐसे wrappers के विरुद्ध उपयोगी हैं जो Python को controllable environment के साथ call करते हैं। `python -E` और `python -I` सभी `PYTHON*` variables को ignore करते हैं।
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT और PERL5LIB**

Perl में भी उतने ही उपयोगी startup variables होते हैं:

- `PERL5LIB`: library directories को prepend करता है।
- `PERL5OPT`: switches को इस तरह inject करता है, जैसे वे हर `perl` command line में दिए गए हों।

इससे **automatic module loading** को force किया जा सकता है या target script के कुछ महत्वपूर्ण करने से पहले interpreter behavior बदला जा सकता है। Perl इन variables को **taint / setuid / setgid** contexts में ignore करता है, लेकिन सामान्य root-run wrappers, CI jobs, installers और custom sudoers rules के लिए ये अब भी बहुत महत्वपूर्ण हैं।
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
यही विचार अन्य runtimes (`RUBYOPT`, `NODE_OPTIONS`, आदि) में भी लागू होता है: जब भी किसी privileged wrapper द्वारा interpreter launch किया जाए, तो उन env vars को खोजें जो **module loading** या **startup behavior** को संशोधित करते हैं।

post-exploitation के दृष्टिकोण से यह भी याद रखें कि inherited environments में अक्सर **credentials**, **proxy settings**, **service tokens**, या **cloud keys** मौजूद होते हैं। `/proc/<PID>/environ` और `systemd` `Environment=` hunting के लिए [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) देखें।

### PS1

अपने prompt का रूप बदलें।

[**यह एक उदाहरण है**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: यह एक उदाहरण है](<../images/image (897).png>)

सामान्य user:

![PERL5OPT & PERL5LIB - PS1: एक, दो और तीन background किए गए jobs](<../images/image (740).png>)

एक, दो और तीन background किए गए jobs:

![PERL5OPT & PERL5LIB - PS1: एक, दो और तीन background किए गए jobs](<../images/image (145).png>)

एक background job, एक stopped job और last command सही ढंग से पूरा नहीं हुआ:

![PERL5OPT & PERL5LIB - PS1: एक background job, एक stopped job और last command सही ढंग से पूरा नहीं हुआ](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
