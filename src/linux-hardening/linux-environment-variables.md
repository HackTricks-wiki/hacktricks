# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## ग्लोबल variables

ग्लोबल variables **will be** inherited by **child processes**.

आप अपनी current session के लिए एक global variable बना सकते हैं, ऐसा करके:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
यह variable आपकी current sessions और इसके child processes द्वारा accessible होगा।

आप एक variable को **remove** कर सकते हैं इस तरह:
```bash
unset MYGLOBAL
```
## लोकल variables

**local variables** केवल **current shell/script** द्वारा ही **accessed** की जा सकती हैं।
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
यदि आप inherited environments के अंदर **credentials** या **interesting service configuration** ढूँढ रहे हैं, तो [Linux Post Exploitation](linux-post-exploitation/README.md) भी देखें।

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** द्वारा इस्तेमाल किया जाने वाला display. यह variable आमतौर पर **:0.0** पर set होता है, जिसका मतलब current computer पर पहला display है।
- **EDITOR** – user का preferred text editor।
- **HISTFILESIZE** – history file में मौजूद lines की maximum संख्या।
- **HISTSIZE** – जब user अपना session finish करता है, तब history file में जोड़ी जाने वाली lines की संख्या
- **HOME** – आपका home directory।
- **HOSTNAME** – computer का hostname।
- **LANG** – आपकी current language।
- **MAIL** – user के mail spool का location। आमतौर पर **/var/spool/mail/USER**।
- **MANPATH** – manual pages search करने के लिए directories की list।
- **OSTYPE** – operating system का type।
- **PS1** – bash में default prompt।
- **PATH** – उन सभी directories का path store करता है जिनमें binary files होती हैं जिन्हें आप file का नाम देकर, relative या absolute path के बिना, execute करना चाहते हैं।
- **PWD** – current working directory।
- **SHELL** – current command shell का path (उदाहरण के लिए, **/bin/bash**)।
- **TERM** – current terminal type (उदाहरण के लिए, **xterm**)।
- **TZ** – आपका time zone।
- **USER** – आपका current username।

## Interesting variables for hacking

हर variable उतना useful नहीं होता। offensive perspective से, उन variables को प्राथमिकता दें जो **search paths**, **startup files**, **dynamic linker behavior**, या **audit/logging** बदलते हैं।

### **HISTFILESIZE**

**इस variable का value 0** कर दें, ताकि जब आप अपना **session end** करें तो **history file** (\~/.bash_history) **0 lines तक truncated** हो जाए।
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**इस variable का value 0 करें**, ताकि commands **in-memory history** में **सहेजी न जाएँ** और **history file** (\~/.bash_history) में वापस न लिखी जाएँ।
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

यदि इस वेरिएबल का **value `ignorespace` या `ignoreboth`** पर set है, तो extra space से शुरू होने वाला कोई भी command history में save नहीं होगा।
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** को **`/dev/null`** पर point करें या इसे पूरी तरह unset करें। यह आमतौर पर सिर्फ history size बदलने से ज़्यादा reliable होता है।
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

प्रक्रियाएँ इंटरनेट से **http या https** के माध्यम से जुड़ने के लिए यहाँ घोषित **proxy** का उपयोग करेंगी।
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: tools/protocols के लिए default proxy जो इसे honor करते हैं।
- `no_proxy`: bypass list (hosts/domains/CIDRs) जो सीधे connect करनी चाहिए।
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
टूल के आधार पर lowercase और uppercase variants दोनों का उपयोग किया जा सकता है (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)।

### SSL_CERT_FILE & SSL_CERT_DIR

Processes **these env variables** में indicated certificates पर trust करेंगे। यह **`curl`**, **`git`**, Python HTTP clients, या package managers जैसे tools को attacker द्वारा controlled CA पर trust करवाने के लिए useful है (for example, interception proxy को legitimate दिखाने के लिए)।
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

यदि कोई privileged wrapper/script commands को **without absolute paths** execute करता है, तो `PATH` में **पहली attacker-controlled directory** जीतती है। यही primitive कई **PATH hijacks** in `sudo`, cron jobs, shell wrappers, और custom SUID helpers के पीछे है। `env_keep+=PATH`, कमजोर `secure_path`, या ऐसे wrappers देखें जो `tar`, `service`, `cp`, `python`, आदि को name से call करते हैं।
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
पूर्ण privilege-escalation chains जो `PATH` का abuse करती हैं, उनके लिए [Linux Privilege Escalation](privilege-escalation/README.md) देखें।

### **HOME & XDG_CONFIG_HOME**

`HOME` सिर्फ एक directory reference नहीं है: कई tools अपने आप **dotfiles**, **plugins**, और **per-user configuration** को `$HOME` या `$XDG_CONFIG_HOME` से load करते हैं। अगर कोई privileged workflow इन values को preserve करता है, तो **config injection** binary hijacking से ज़्यादा आसान हो सकती है।
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
रोचक targets में `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, और tool-specific files जैसे `.terraformrc` शामिल हैं।

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

ये variables **dynamic linker** को प्रभावित करते हैं:

- `LD_PRELOAD`: extra shared objects को पहले load करने के लिए force करता है।
- `LD_LIBRARY_PATH`: library search directories को prepend करता है।
- `LD_AUDIT`: auditor libraries load करता है जो library loading और symbol resolution को observe करती हैं।

ये **hooking**, **instrumentation**, और **privilege escalation** के लिए बेहद valuable हैं, अगर कोई privileged command इन्हें preserve करता है। **secure-execution** mode (`AT_SECURE`, जैसे setuid/setgid/capabilities) में, loader इनमें से कई variables को strip या restrict कर देता है। हालांकि, उस early loader stage में parser bugs अभी भी high-impact होते हैं क्योंकि वे **target program** से **पहले** run होते हैं।
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` शुरुआती glibc व्यवहार (उदाहरण के लिए, allocator tunables) को बदलता है और exploit labs में बहुत उपयोगी है। यह security perspective से भी महत्वपूर्ण है क्योंकि **dynamic loader इसे बहुत जल्दी parse करता है**। 2023 का **Looney Tunables** bug एक अच्छा reminder था कि loader में parse किया गया एक single environment variable SUID programs के खिलाफ एक **local privilege-escalation primitive** बन सकता है।
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

यदि **Bash** को **non-interactively** शुरू किया जाता है, तो यह `BASH_ENV` को check करता है और target script चलाने से पहले उस file को source करता है। जब Bash को `sh` के रूप में invoke किया जाता है, या POSIX-style interactive mode में, तो `ENV` भी consult किया जा सकता है। यह shell wrapper को code execution में बदलने का एक classic तरीका है, अगर environment attacker-controlled हो।
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash स्वयं इन startup files को तब disable कर देता है जब **real/effective IDs अलग हों** जब तक कि `-p` उपयोग न किया जाए, इसलिए exact behavior इस बात पर निर्भर करता है कि wrapper shell को कैसे invoke करता है।

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

ये variables Python के start होने के तरीके को बदलते हैं:

- `PYTHONPATH`: import search paths को पहले जोड़ता है।
- `PYTHONHOME`: standard library tree को relocate करता है।
- `PYTHONSTARTUP`: interactive prompt से पहले एक file execute करता है।
- `PYTHONINSPECT=1`: script खत्म होने के बाद interactive mode में चला जाता है।

ये maintenance scripts, debuggers, shells, और wrappers के खिलाफ useful हैं जो controllable environment के साथ Python call करते हैं। `python -E` और `python -I` सभी `PYTHON*` variables को ignore करते हैं।
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl में भी उतने ही उपयोगी startup variables हैं:

- `PERL5LIB`: library directories को prepend करता है।
- `PERL5OPT`: switches inject करता है जैसे वे हर `perl` command line पर हों।

यह **automatic module loading** को मजबूर कर सकता है या target script के कुछ भी interesting करने से पहले interpreter behavior बदल सकता है। Perl इन variables को **taint / setuid / setgid** contexts में ignore करता है, लेकिन normal root-run wrappers, CI jobs, installers, और custom sudoers rules में ये फिर भी बहुत important होते हैं।
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
वही विचार अन्य runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.) में भी दिखाई देता है: जब भी किसी interpreter को privileged wrapper द्वारा लॉन्च किया जाता है, ऐसे env vars खोजें जो **module loading** या **startup behavior** को modify करते हों।

post-exploitation के दृष्टिकोण से, यह भी याद रखें कि inherited environments में अक्सर **credentials**, **proxy settings**, **service tokens**, या **cloud keys** होते हैं। `/proc/<PID>/environ` और `systemd` `Environment=` hunting के लिए [Linux Post Exploitation](linux-post-exploitation/README.md) देखें।

### PS1

अपने prompt का look बदलें।

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
