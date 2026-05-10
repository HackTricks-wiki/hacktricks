# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Global variables **child processes** द्वारा inherit की जाएंगी।

आप अपनी current session के लिए एक global variable इस तरह बना सकते हैं:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
यह variable आपकी current sessions और उनके child processes के लिए accessible होगा।

आप किसी variable को इस तरह **remove** कर सकते हैं:
```bash
unset MYGLOBAL
```
## लोकल variables

**लोकल variables** केवल **current shell/script** द्वारा ही **accessed** किए जा सकते हैं।
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
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** द्वारा उपयोग किया जाने वाला display. यह variable आमतौर पर **:0.0** पर set होता है, जिसका मतलब है current computer पर पहला display.
- **EDITOR** – user का पसंदीदा text editor.
- **HISTFILESIZE** – history file में contained lines की अधिकतम संख्या.
- **HISTSIZE** – जब user अपना session खत्म करता है, तब history file में add की जाने वाली lines की संख्या
- **HOME** – आपका home directory.
- **HOSTNAME** – computer का hostname.
- **LANG** – आपकी current language.
- **MAIL** – user के mail spool का location. आमतौर पर **/var/spool/mail/USER**.
- **MANPATH** – manual pages search करने के लिए directories की list.
- **OSTYPE** – operating system का type.
- **PS1** – bash में default prompt.
- **PATH** – उन सभी directories का path store करता है जिनमें binary files होती हैं जिन्हें आप file का नाम specify करके execute करना चाहते हैं, न कि relative या absolute path से.
- **PWD** – current working directory.
- **SHELL** – current command shell का path (उदाहरण के लिए, **/bin/bash**).
- **TERM** – current terminal type (उदाहरण के लिए, **xterm**).
- **TZ** – आपका time zone.
- **USER** – आपका current username.

## Interesting variables for hacking

हर variable उतना useful नहीं होता। offensive perspective से, उन variables को प्राथमिकता दें जो **search paths**, **startup files**, **dynamic linker behavior**, या **audit/logging** बदलते हैं।

### **HISTFILESIZE**

**इस variable का value 0** कर दें, ताकि जब आप अपना **session end** करें, तो **history file** (\~/.bash_history) **0 lines** तक truncate हो जाए।
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**commands** को **in-memory history** में **सहेजा नहीं** जाएगा और **history file** (\~/.bash_history) में वापस **लिखा नहीं** जाएगा, इसके लिए **इस variable के value को 0** कर दें।
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

यदि इस variable का **value `ignorespace` या `ignoreboth`** पर set है, तो extra space से शुरू किया गया कोई भी command history में save नहीं होगा।
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file** को **`/dev/null`** पर point करें या इसे पूरी तरह unset करें। यह आमतौर पर केवल history size बदलने से ज्यादा reliable होता है।
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Processes **proxy** का उपयोग करेंगे जो यहाँ घोषित है, ताकि **http या https** के through इंटरनेट से connect कर सकें।
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: tools/protocols के लिए डिफ़ॉल्ट proxy जो इसे honor करते हैं।
- `no_proxy`: bypass list (hosts/domains/CIDRs) जो directly connect करनी चाहिए।
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
टूल के आधार पर lowercase और uppercase variants दोनों का उपयोग किया जा सकता है (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)।

### SSL_CERT_FILE & SSL_CERT_DIR

Processes **these env variables** में बताए गए certificates पर trust करेंगे। यह **`curl`**, **`git`**, Python HTTP clients, या package managers जैसे tools को attacker-controlled CA पर trust कराने के लिए useful है (उदाहरण के लिए, interception proxy को legitimate दिखाने के लिए)।
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

यदि कोई privileged wrapper/script commands को **absolute paths** के बिना execute करता है, तो `PATH` में **पहला attacker-controlled directory** जीतता है। यही primitive कई **PATH hijacks** के पीछे है, जैसे `sudo`, cron jobs, shell wrappers, और custom SUID helpers में। `env_keep+=PATH`, weak `secure_path`, या ऐसे wrappers देखें जो `tar`, `service`, `cp`, `python`, आदि को नाम से call करते हैं।
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

`HOME` केवल एक directory reference नहीं है: कई tools अपने आप **dotfiles**, **plugins**, और **per-user configuration** को `$HOME` या `$XDG_CONFIG_HOME` से load करते हैं। अगर कोई privileged workflow इन values को preserve करता है, तो **config injection** binary hijacking से आसान हो सकता है।
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesting targets include `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, and tool-specific files such as `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

ये variables **dynamic linker** को प्रभावित करते हैं:

- `LD_PRELOAD`: अतिरिक्त shared objects को पहले लोड करने के लिए force करता है।
- `LD_LIBRARY_PATH`: library search directories को prepand करता है।
- `LD_AUDIT`: auditor libraries को लोड करता है जो library loading और symbol resolution को observe करती हैं।

ये **hooking**, **instrumentation**, और **privilege escalation** के लिए बेहद valuable हैं, अगर कोई privileged command इन्हें preserve करता है। **secure-execution** mode (`AT_SECURE`, जैसे setuid/setgid/capabilities) में, loader इनमें से कई variables को strip या restrict करता है। हालांकि, उस early loader stage में parser bugs अभी भी high-impact होते हैं क्योंकि वे **target program** से **पहले** run होते हैं।
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` glibc के शुरुआती behavior को बदलता है (उदाहरण के लिए, allocator tunables) और exploit labs में बहुत उपयोगी है। यह security perspective से भी महत्वपूर्ण है क्योंकि **dynamic loader इसे बहुत जल्दी parse करता है**। 2023 का **Looney Tunables** bug एक अच्छा reminder था कि loader में parse होने वाला एक single environment variable SUID programs के खिलाफ एक **local privilege-escalation primitive** बन सकता है।
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

यदि **Bash** **non-interactively** शुरू होता है, तो यह `BASH_ENV` को जांचता है और target script चलाने से पहले उस file को source करता है। जब Bash को `sh` के रूप में invoke किया जाता है, या POSIX-style interactive mode में, तो `ENV` को भी consult किया जा सकता है। यह shell wrapper को code execution में बदलने का एक classic तरीका है, अगर environment attacker-controlled हो।
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash स्वयं इन startup files को disable कर देता है जब **real/effective IDs अलग हों** जब तक `-p` का उपयोग न किया जाए, इसलिए exact behavior इस पर निर्भर करता है कि wrapper shell को कैसे invoke करता है।

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

ये variables बदलते हैं कि Python कैसे start होता है:

- `PYTHONPATH`: import search paths को पहले जोड़ता है।
- `PYTHONHOME`: standard library tree को relocate करता है।
- `PYTHONSTARTUP`: interactive prompt से पहले एक file execute करता है।
- `PYTHONINSPECT=1`: script खत्म होने के बाद interactive mode में चला जाता है।

ये maintenance scripts, debuggers, shells, और wrappers के खिलाफ उपयोगी हैं जो controllable environment के साथ Python call करते हैं। `python -E` और `python -I` सभी `PYTHON*` variables को ignore करते हैं।
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl के पास समान रूप से उपयोगी startup variables हैं:

- `PERL5LIB`: library directories को पहले जोड़ता है।
- `PERL5OPT`: switches inject करता है जैसे वे हर `perl` command line पर हों।

यह **automatic module loading** को force कर सकता है या target script के कुछ interesting करने से पहले interpreter behavior बदल सकता है। Perl इन variables को **taint / setuid / setgid** contexts में ignore करता है, लेकिन normal root-run wrappers, CI jobs, installers, और custom sudoers rules में ये फिर भी बहुत important होते हैं।
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
वही विचार अन्य runtimes (`RUBYOPT`, `NODE_OPTIONS`, आदि) में भी दिखाई देता है: जब भी किसी interpreter को किसी privileged wrapper द्वारा launch किया जाता है, ऐसे env vars खोजें जो **module loading** या **startup behavior** को modify करते हैं।

post-exploitation के नजरिए से, यह भी याद रखें कि inherited environments में अक्सर **credentials**, **proxy settings**, **service tokens**, या **cloud keys** होते हैं। `/proc/<PID>/environ` और `systemd` `Environment=` hunting के लिए [Linux Post Exploitation](linux-post-exploitation/README.md) देखें।

### PS1

अपना prompt कैसा दिखता है, उसे बदलें।

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
