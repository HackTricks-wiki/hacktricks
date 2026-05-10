# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Vigezo vya kimataifa **vitakuwa** vimerithiwa na **child processes**.

Unaweza kuunda kigezo cha kimataifa kwa session yako ya sasa kwa kufanya:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Tofauti hii itapatikana na sessions zako za sasa na child processes zake.

Unaweza **kuondoa** variable kwa kufanya:
```bash
unset MYGLOBAL
```
## Vigeu vya ndani

**Vigeu vya ndani** vinaweza tu **kufikiwa** na **shell/script ya sasa**.
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
Maudhui ya `/proc/*/environ` yamegawanywa kwa **NUL**, kwa hivyo matoleo haya kwa kawaida huwa rahisi kusoma:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display inayotumiwa na **X**. Kigezo hiki kwa kawaida huwekwa kuwa **:0.0**, ambayo inamaanisha display ya kwanza kwenye kompyuta ya sasa.
- **EDITOR** – kihariri cha maandishi anachopendelea mtumiaji.
- **HISTFILESIZE** – idadi ya juu ya mistari iliyomo kwenye faili ya history.
- **HISTSIZE** – Idadi ya mistari inayoongezwa kwenye faili ya history mtumiaji anapomaliza session yake
- **HOME** – saraka yako ya home.
- **HOSTNAME** – hostname ya kompyuta.
- **LANG** – lugha yako ya sasa.
- **MAIL** – eneo la mail spool ya mtumiaji. Kwa kawaida **/var/spool/mail/USER**.
- **MANPATH** – orodha ya saraka za kutafuta manual pages.
- **OSTYPE** – aina ya operating system.
- **PS1** – prompt ya default katika bash.
- **PATH** – huhifadhi path ya saraka zote zinazoshikilia binary files unazotaka kuendesha kwa kutaja tu jina la file na si kwa relative au absolute path.
- **PWD** – saraka ya sasa ya kazi.
- **SHELL** – path ya current command shell (kwa mfano, **/bin/bash**).
- **TERM** – aina ya current terminal (kwa mfano, **xterm**).
- **TZ** – time zone yako.
- **USER** – username yako ya sasa.

## Interesting variables for hacking

Sio kila variable ni muhimu kwa kiwango sawa. Kutoka kwa mtazamo wa offensive, zingatia variables zinazobadilisha **search paths**, **startup files**, **dynamic linker behavior**, au **audit/logging**.

### **HISTFILESIZE**

Badilisha **value ya variable hii kuwa 0**, ili unapomaliza **session yako** faili ya **history** (\~/.bash_history) iwe **truncated hadi mistari 0**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Badilisha **thamani ya variable hii iwe 0**, ili commands **zisihifadhiwe kwenye in-memory history** na hazitaandikwa tena kwenye **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ikiwa **thamani ya variable hii imewekwa kuwa `ignorespace` au `ignoreboth`**, amri yoyote iliyoanzishwa na nafasi ya ziada haitahifadhiwa kwenye history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Elekeza **history file** kwenda **`/dev/null`** au uiondoe kabisa. Hii kwa kawaida ni ya kuaminika zaidi kuliko kubadilisha tu ukubwa wa history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Michakato itatumia **proxy** iliyotangazwa hapa kuunganishwa na intaneti kupitia **http au https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proksi chaguo-msingi kwa tools/protocols zinazoiheshimu.
- `no_proxy`: orodha ya bypass (hosts/domains/CIDRs) ambazo zinapaswa kuunganishwa moja kwa moja.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Toleo zote za herufi ndogo na herufi kubwa zinaweza kutumika kulingana na tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Processes zitaamini certificates zilizoonyeshwa katika **env variables hizi**. Hii ni useful ili kufanya tools kama **`curl`**, **`git`**, Python HTTP clients, au package managers ziitegemee CA inayodhibitiwa na attacker (kwa mfano, ili kufanya interception proxy ionekane legitimate).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ikiwa wrapper/script yenye ruhusa za juu inatekeleza amri **bila absolute paths**, **saraka ya kwanza inayodhibitiwa na mshambuliaji** ndani ya `PATH` ndiyo hushinda. Hii ndiyo primitive iliyo nyuma ya nyingi za **PATH hijacks** katika `sudo`, cron jobs, shell wrappers, na custom SUID helpers. Tafuta `env_keep+=PATH`, `secure_path` dhaifu, au wrappers zinazotumia `tar`, `service`, `cp`, `python`, n.k. kwa jina.
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
Kwa minyororo kamili ya privilege-escalation inayotumia `PATH`, angalia [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` si tu rejeleo la saraka: zana nyingi hupakia kiotomatiki **dotfiles**, **plugins**, na **per-user configuration** kutoka `$HOME` au `$XDG_CONFIG_HOME`. Ikiwa mtiririko wa kazi wenye privilege unahifadhi thamani hizi, **config injection** inaweza kuwa rahisi kuliko binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesting targets include `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, and tool-specific files such as `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Vigezo hivi huathiri **dynamic linker**:

- `LD_PRELOAD`: hulazimisha shared objects za ziada kupakiwa kwanza.
- `LD_LIBRARY_PATH`: huongeza prepend kwenye library search directories.
- `LD_AUDIT`: hupakia auditor libraries zinazofuatilia library loading na symbol resolution.

Ni muhimu sana kwa **hooking**, **instrumentation**, na **privilege escalation** ikiwa privileged command inavihifadhi. Katika mode ya **secure-execution** (`AT_SECURE`, kwa mfano setuid/setgid/capabilities), loader huondoa au kuzuia vigezo vingi hivi. Hata hivyo, parser bugs katika hatua hiyo ya awali ya loader bado ni za athari kubwa kwa sababu zinafanya kazi **kabla** ya target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` hubadilisha tabia ya mapema ya glibc (kwa mfano, allocator tunables) na ni muhimu sana katika exploit labs. Pia ni muhimu kutoka kwa mtazamo wa usalama kwa sababu **dynamic loader hui-parse mapema sana**. Bug ya 2023 **Looney Tunables** ilikuwa ukumbusho mzuri kwamba environment variable moja inayoparsiwa kwenye loader inaweza kuwa **local privilege-escalation primitive** dhidi ya program za SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ikiwa **Bash** imeanzishwa **non-interactively**, huangalia `BASH_ENV` na ku-sources faili hilo kabla ya kuendesha script lengwa. Bash inapoitwa kama `sh`, au katika POSIX-style interactive mode, `ENV` pia inaweza kuangaliwa. Hii ni njia ya kawaida ya kugeuza shell wrapper kuwa code execution ikiwa environment inadhibitiwa na mshambuliaji.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash yenyewe huzima hizi startup files wakati **real/effective IDs zinatofautiana** isipokuwa `-p` itumike, hivyo tabia halisi inategemea jinsi wrapper inavyomwita shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Hivi variables hubadilisha jinsi Python inavyoanza:

- `PYTHONPATH`: weka mapema import search paths.
- `PYTHONHOME`: hamisha standard library tree.
- `PYTHONSTARTUP`: execute file kabla ya interactive prompt.
- `PYTHONINSPECT=1`: ingia interactive mode baada ya script kumaliza.

Ni muhimu dhidi ya maintenance scripts, debuggers, shells, na wrappers zinazoita Python na controllable environment. `python -E` na `python -I` hupuuza variables zote za `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ina variables za kuanzisha zenye matumizi sawa:

- `PERL5LIB`: ongeza mwanzo kwenye saraka za library.
- `PERL5OPT`: ingiza switches kana kwamba ziko kwenye kila `perl` command line.

Hii inaweza kulazimisha **automatic module loading** au kubadilisha tabia ya interpreter kabla script lengwa haijafanya chochote cha maana. Perl hupuuza variables hizi katika mazingira ya **taint / setuid / setgid**, lakini bado zina umuhimu mkubwa kwa normal root-run wrappers, CI jobs, installers, na custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Wazo sawa inaonekana katika runtimes nyingine (`RUBYOPT`, `NODE_OPTIONS`, n.k.): wakati wowote interpreter inapozinduliwa na privileged wrapper, tafuta env vars zinazobadilisha **module loading** au **startup behavior**.

Kutoka kwa mtazamo wa post-exploitation, pia kumbuka kwamba inherited environments mara nyingi huwa na **credentials**, **proxy settings**, **service tokens**, au **cloud keys**. Angalia [Linux Post Exploitation](linux-post-exploitation/README.md) kwa `/proc/<PID>/environ` na utafutaji wa `systemd` `Environment=`.

### PS1

Badilisha jinsi prompt yako inavyoonekana.

[**Huu ni mfano**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

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
