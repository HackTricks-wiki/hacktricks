# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **michakato tanzu**.

Unaweza kuunda kigezo cha kimataifa kwa kipindi chako cha sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Variable hii itapatikana katika sessions zako za sasa na processes zake child.

Unaweza **kuondoa** variable kwa kufanya:
```bash
unset MYGLOBAL
```
## Vigeu vya ndani

**Vigeu vya ndani** vinaweza tu **kufikiwa** na **shell/script** ya sasa.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodhesha variables za sasa
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Yaliyomo kwenye `/proc/*/environ` yametenganishwa kwa **NUL**, hivyo variants hizi kwa kawaida ni rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ikiwa unatafuta **credentials** au **interesting service configuration** ndani ya mazingira yaliyorithiwa, pia angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Vigezo vya kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display inayotumiwa na **X**. Kigezo hiki kwa kawaida huwekwa kuwa **:0.0**, kumaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – text editor anayependelewa na mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye history file.
- **HISTSIZE** – idadi ya mistari inayoongezwa kwenye history file mtumiaji anapomaliza session yake.
- **HOME** – directory ya home yako.
- **HOSTNAME** – hostname ya kompyuta.
- **LANG** – language yako ya sasa.
- **MAIL** – eneo la mail spool ya mtumiaji. Kwa kawaida ni **/var/spool/mail/USER**.
- **MANPATH** – orodha ya directories za kutafutwa kwa manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt chaguomsingi katika bash.
- **PATH** – huhifadhi path ya directories zote zilizo na binary files unazotaka kutekeleza kwa kutaja tu jina la file, badala ya kutumia relative au absolute path.
- **PWD** – working directory ya sasa.
- **SHELL** – path ya command shell ya sasa, kwa mfano, **/bin/bash**.
- **TERM** – aina ya terminal ya sasa, kwa mfano, **xterm**.
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Vigezo vya kuvutia vya hacking

Si kila kigezo kina manufaa sawa. Kwa mtazamo wa offensive, weka kipaumbele kwa vigezo vinavyobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

Badilisha **value ya kigezo hiki kuwa 0**, ili unapomaliza **session yako**, **history file** (\~/.bash_history) **ikatwe hadi mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **value ya variable hii iwe 0**, ili commands **zisihifadhiwe kwenye in-memory history** na zisiandikwe tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **value ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, command yoyote iliyoanza kwa space ya ziada haitahifadhiwa kwenye history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Elekeza **faili la historia** kwenye **`/dev/null`** au `unset` kabisa. Hii kwa kawaida inaaminika zaidi kuliko kubadilisha tu ukubwa wa historia.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotangazwa hapa kuunganishwa kwenye intaneti kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy ya msingi kwa tools/protocols zinazoiheshimu.
- `no_proxy`: orodha ya bypass (hosts/domains/CIDRs) zinazopaswa kuunganishwa moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Zote mbili, herufi ndogo na herufi kubwa, zinaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini certificates zilizoonyeshwa katika **vigezo hivi vya env**. Hii ni muhimu ili kufanya tools kama **`curl`**, **`git`**, HTTP clients za Python, au package managers ziitumaini CA inayodhibitiwa na attacker (kwa mfano, kufanya interception proxy ionekane halali).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa privileged wrapper/script itatekeleza commands **bila kutumia absolute paths**, directory ya kwanza inayodhibitiwa na attacker ndani ya `PATH` ndiyo itakayotumika. Hii ndiyo primitive inayowezesha **PATH hijacks** nyingi katika `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python`, na kadhalika kwa majina yao.
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
Kwa minyororo kamili ya privilege-escalation inayotumia vibaya `PATH`, angalia [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` si rejeleo la saraka pekee: tools nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **per-user configuration** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa privileged workflow itahifadhi values hizi, **config injection** inaweza kuwa rahisi kuliko binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Mifano ya targets zinazovutia ni `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, pamoja na files mahususi za tools kama `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Variables hizi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada zipakiwe kwanza.
- `LD_LIBRARY_PATH`: huweka directories za kutafutia libraries mwanzoni.
- `LD_AUDIT`: hupakia auditor libraries zinazofuatilia upakiaji wa libraries na symbol resolution.

Ni zenye thamani kubwa sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa command yenye privileges itazihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia nyingi ya variables hizi. Hata hivyo, parser bugs katika hatua hiyo ya awali ya loader bado zina impact kubwa kwa sababu hutekelezwa **kabla** ya target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader huichanganua mapema sana**. Bug ya **Looney Tunables** ya mwaka 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayochanganuliwa na loader inaweza kuwa **local privilege-escalation primitive** dhidi ya programu za SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa **non-interactively**, hukagua `BASH_ENV` na kusource faili hilo kabla ya kuendesha script inayolengwa. Bash inapoitwa kama `sh`, au katika hali ya interactive ya mtindo wa POSIX, `ENV` pia inaweza kuchunguzwa. Hii ni njia ya kawaida ya kubadilisha shell wrapper kuwa **code execution** ikiwa environment inadhibitiwa na attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash yenyewe huzima startup files hizi wakati **real/effective IDs zinatofautiana** isipokuwa `-p` itumike, hivyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa mwangalifu na privileged wrappers zinazoita `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: IDs zinapolingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV`, na shell state inayohusiana, ambayo vinginevyo ingepuuzwa.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Variables hizi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: ongeza import search paths mwanzoni.
- `PYTHONHOME`: hamisha standard library tree.
- `PYTHONSTARTUP`: tekeleza file kabla ya interactive prompt.
- `PYTHONINSPECT=1`: ingia kwenye interactive mode baada ya script kumaliza.

Ni muhimu dhidi ya maintenance scripts, debuggers, shells, na wrappers zinazoita Python zikiwa na environment inayoweza kudhibitiwa. `python -E` na `python -I` hupuuza variables zote za `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Mfano wa hivi karibuni wa ulimwengu halisi ulikuwa LPE ya **needrestart** ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya process isiyo na privileges kutoka `/proc/<PID>/environ`, kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye path inayodhibitiwa na mshambuliaji, hivyo Python iliendesha attacker code wakati wa initialization yake yenyewe, kabla hata script iliyowekwa hard-coded kwenye helper haijawa muhimu.

### **PERL5OPT & PERL5LIB**

Perl ina startup variables zenye manufaa sawa:

- `PERL5LIB`: huongeza directories za library mwanzoni.
- `PERL5OPT`: huingiza switches kana kwamba zilikuwa kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla script lengwa haijafanya chochote cha kuvutia. Perl hupuuza variables hizi katika mazingira ya **taint / setuid / setgid**, lakini bado ni muhimu sana kwa wrappers zinazoendeshwa kama root, CI jobs, installers, na custom sudoers rules.
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

`NODE_OPTIONS` huongeza mwanzoni **Node.js CLI flags** kwenye kila mchakato wa `node` unaorithi environment. Hii huifanya iwe muhimu dhidi ya wrappers, CI jobs, wasaidizi wa Electron, na sudo rules ambazo hatimaye huendesha Node. Flags zinazovutia zaidi kwa mashambulizi kwa kawaida ni:

- `--require <file>`: hupakia mapema faili ya CommonJS kabla ya script inayolengwa.
- `--import <module>`: hupakia mapema ES module kabla ya script inayolengwa.

Node hukataa baadhi ya flags hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa wazi na huchakatwa **kabla** ya command-line arguments za kawaida.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Kwa **gadget chains** za mbali zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, **prototype-pollution to RCE**), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby hutoa aina hiyo hiyo ya matumizi mabaya wakati wa kuanzisha:

- `RUBYLIB`: tanguliza saraka kwenye njia ya upakiaji ya Ruby.
- `RUBYOPT`: ingiza chaguo za mstari wa amri kama vile `-r` katika kila mwito wa `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Vulnerabilities za **needrestart** za mwaka 2024 zilionyesha kuwa hii si hila ya maabara tu: helper huyo huyo anayemilikiwa na root ambaye alikuwa katika hatari ya kutumiwa vibaya kwa `PYTHONPATH` angeweza pia kulazimishwa kuendesha Ruby ikiwa na `RUBYLIB` inayodhibitiwa na mshambuliaji, na kupakia `enc/encdb.so` kutoka kwenye directory ya mshambuliaji.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya tools hazisomi tu path kutoka kwenye environment; hupitisha value hiyo kwa **shell**, **editor**, au **input preprocessor**. Hii hufanya variables zifuatazo zivutie hasa pale wrapper yenye privileges inapoendesha `git`, `man`, `less`, au text viewers zinazofanana:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: huchagua pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: huchagua editor command, mara nyingi pamoja na arguments.
- `LESSOPEN`, `LESSCLOSE`: hufafanua pre/post-processors zinazoendeshwa wakati `less` inapofungua file.
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
Git pia inasaidia **env-only config injection** bila kugusa disk kupitia `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, na `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Kwa mtazamo wa post-exploitation, pia kumbuka kuwa environments zilizorithiwa mara nyingi huwa na **credentials**, **proxy settings**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) kwa uwindaji wa `/proc/<PID>/environ` na `systemd` `Environment=`.

### PS1

Badilisha jinsi prompt yako inavyoonekana.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (740).png>)

Kazi moja, mbili na tatu zinazoendeshwa chinichini:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (145).png>)

Kazi moja ya chinichini, moja iliyosimamishwa, na command ya mwisho haikukamilika kwa usahihi:

![PERL5OPT & PERL5LIB - PS1: Kazi moja ya chinichini, moja iliyosimamishwa, na command ya mwisho haikukamilika kwa usahihi](<../images/image (715).png>)

## Marejeleo

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
