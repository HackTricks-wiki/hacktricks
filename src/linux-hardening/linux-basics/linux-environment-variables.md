# Vigezo vya Mazingira vya Linux

{{#include ../../banners/hacktricks-training.md}}

## Vigezo vya kimataifa

Vigezo vya kimataifa **vitarithiwa** na **process za watoto**.

Unaweza kuunda kigezo cha kimataifa kwa session yako ya sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Kigezo hiki kitapatikana katika vipindi vyako vya sasa na michakato yake tanzu.

Unaweza **kuondoa** kigezo kwa kufanya:
```bash
unset MYGLOBAL
```
## Vigezo vya ndani

**Vigezo vya ndani** vinaweza tu **kufikiwa** na **shell/script** ya sasa.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Orodhesha vigezo vya sasa
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Yaliyomo kwenye `/proc/*/environ` ni **NUL-separated**, kwa hivyo mibadala hii kwa kawaida ni rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ikiwa unatafuta **credentials** au **interesting service configuration** ndani ya environments zilizorithiwa, pia angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables za kawaida

Kutoka: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display inayotumiwa na **X**. Variable hii kwa kawaida huwekwa kuwa **:0.0**, ikimaanisha display ya kwanza kwenye computer ya sasa.
- **EDITOR** – text editor anayependelewa na mtumiaji.
- **HISTFILESIZE** – idadi ya juu zaidi ya mistari iliyo kwenye history file.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye history file mtumiaji anapomaliza session yake
- **HOME** – directory yako ya nyumbani.
- **HOSTNAME** – hostname ya computer.
- **LANG** – language yako ya sasa.
- **MAIL** – mahali pa mail spool ya mtumiaji. Kwa kawaida **/var/spool/mail/USER**.
- **MANPATH** – orodha ya directories za kutafutwa kwa manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt ya kawaida katika bash.
- **PATH** – huhifadhi path ya directories zote zilizo na binary files unazotaka ku-execute kwa kutaja tu jina la file, badala ya kutumia relative au absolute path.
- **PWD** – working directory ya sasa.
- **SHELL** – path ya command shell ya sasa (kwa mfano, **/bin/bash**).
- **TERM** – aina ya terminal ya sasa (kwa mfano, **xterm**).
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Variables zinazovutia kwa hacking

Si kila variable ina manufaa sawa. Kwa mtazamo wa offensive, weka kipaumbele kwa variables zinazobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

Badilisha **value ya variable hii iwe 0**, ili unapomaliza **session yako**, **history file** (\~/.bash_history) **ikatwe hadi iwe na mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya variable hii iwe 0**, ili commands **zisitunzwe kwenye history ya in-memory** na zisiandikwe tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **thamani ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, command yoyote inayoanza na nafasi ya ziada haitahifadhiwa kwenye history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Elekeza **history file** kwenye **`/dev/null`** au ifanye unset kabisa. Hii kwa kawaida ni ya kuaminika zaidi kuliko kubadilisha tu ukubwa wa history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Processes zitatumia **proxy** iliyotangazwa hapa kuunganishwa kwenye internet kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy chaguomsingi kwa zana/protocols zinazoiheshimu.
- `no_proxy`: orodha ya bypass (hosts/domains/CIDRs) zinazopaswa kuunganishwa moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Matoleo ya herufi ndogo na herufi kubwa yanaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Michakato itaamini certificates zilizoonyeshwa katika **env variables hizi**. Hii ni muhimu ili kufanya tools kama vile **`curl`**, **`git`**, HTTP clients za Python, au package managers ziitumaini CA inayodhibitiwa na attacker (kwa mfano, kufanya interception proxy ionekane halali).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa privileged wrapper/script itatekeleza commands **bila absolute paths**, directory ya kwanza inayodhibitiwa na attacker kwenye `PATH` ndiyo itakayotumika. Hii ndiyo primitive inayotumika katika **PATH hijacks** nyingi kwenye `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazoita `tar`, `service`, `cp`, `python`, n.k. kwa majina.
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

`HOME` si rejeleo la directory pekee: tools nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **per-user configuration** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa privileged workflow itahifadhi values hizi, **config injection** inaweza kuwa rahisi kuliko binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Madhumuni ya kuvutia yanajumuisha `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, na faili mahususi za tools kama vile `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Variable hizi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada zipakiwe kwanza.
- `LD_LIBRARY_PATH`: huweka directories za kutafutia libraries mwanzoni.
- `LD_AUDIT`: hupakia auditor libraries zinazofuatilia upakiaji wa libraries na utatuzi wa symbols.

Ni muhimu sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa command yenye privileges itazihifadhi. Katika hali ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia nyingi ya variable hizi. Hata hivyo, parser bugs katika hatua hiyo ya awali ya loader bado zina athari kubwa kwa sababu huendeshwa **kabla** ya target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kwa mtazamo wa usalama kwa sababu **dynamic loader huichanganua mapema sana**. Bug ya **Looney Tunables** ya mwaka 2023 ilikuwa ukumbusho mzuri kwamba environment variable moja inayochanganuliwa kwenye loader inaweza kuwa **local privilege-escalation primitive** dhidi ya programu za SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa **non-interactively**, hukagua `BASH_ENV` na kupakia faili hilo kabla ya kuendesha target script. Bash inapoombwa kama `sh`, au katika hali ya mwingiliano ya mtindo wa POSIX, `ENV` pia inaweza kuchunguzwa. Hii ni njia ya kawaida ya kubadilisha shell wrapper kuwa code execution ikiwa mazingira yanadhibitiwa na attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash yenyewe huzima mafaili haya ya kuanzisha wakati **real/effective IDs zinatofautiana**, isipokuwa `-p` itumike; kwa hivyo tabia halisi hutegemea jinsi wrapper inavyoanzisha shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Vigezo hivi hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: huongeza mwanzoni njia za kutafuta imports.
- `PYTHONHOME`: huhamisha mti wa standard library.
- `PYTHONSTARTUP`: hutekeleza faili kabla ya prompt ya interactive.
- `PYTHONINSPECT=1`: huingia kwenye interactive mode baada ya script kumaliza.

Ni muhimu dhidi ya maintenance scripts, debuggers, shells na wrappers zinazoiita Python zikiwa na environment inayoweza kudhibitiwa. `python -E` na `python -I` hupuuza vigezo vyote vya `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ina startup variables zenye manufaa sawa:

- `PERL5LIB`: huweka library directories mwanzoni.
- `PERL5OPT`: huingiza switches kana kwamba zilikuwa kwenye kila command line ya `perl`.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla script lengwa haijafanya jambo lolote muhimu. Perl hupuuza variables hizi katika mazingira ya **taint / setuid / setgid**, lakini bado zina umuhimu mkubwa kwa normal root-run wrappers, CI jobs, installers, na custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Wazo hilo hilo inaonekana katika runtimes nyingine (`RUBYOPT`, `NODE_OPTIONS`, n.k.): wakati wowote interpreter inapozinduliwa na wrapper yenye privileges, tafuta env vars zinazobadilisha **upakiaji wa modules** au **tabia ya kuanza**.

Kwa mtazamo wa post-exploitation, pia kumbuka kwamba environments zilizorithiwa mara nyingi huwa na **credentials**, **mipangilio ya proxy**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) kwa utafutaji wa `/proc/<PID>/environ` na `systemd` `Environment=`.

### PS1

Badilisha mwonekano wa prompt yako.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Huu ni mfano](<../images/image (897).png>)

Mtumiaji wa kawaida:

![PERL5OPT & PERL5LIB - PS1: Jobs moja, mbili na tatu zinazoendeshwa background](<../images/image (740).png>)

Jobs moja, mbili na tatu zinazoendeshwa background:

![PERL5OPT & PERL5LIB - PS1: Jobs moja, mbili na tatu zinazoendeshwa background](<../images/image (145).png>)

Job moja ya background, job moja iliyosimamishwa, na command ya mwisho haikukamilika kwa usahihi:

![PERL5OPT & PERL5LIB - PS1: Job moja ya background, job moja iliyosimamishwa, na command ya mwisho haikukamilika kwa usahihi](<../images/image (715).png>)

## Marejeo

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
