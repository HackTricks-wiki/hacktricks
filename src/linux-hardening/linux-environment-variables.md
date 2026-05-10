# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal** geërf word deur **child processes**.

Jy kan 'n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees vir jou huidige sessies en sy kinderprosesse.

Jy kan ’n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige shell/script** **toegang** verkry.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lys huidige veranderlikes
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Die inhoud van `/proc/*/environ` is **NUL-geskei**, so hierdie variante is gewoonlik makliker om te lees:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – die skerm wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik ingestel op **:0.0**, wat die eerste skerm op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeur-teksredigeerder.
- **HISTFILESIZE** – die maksimum aantal lyne wat in die history-lêer vervat is.
- **HISTSIZE** – Aantal lyne wat by die history-lêer gevoeg word wanneer die gebruiker sy sessie voltooi
- **HOME** – jou tuisgids.
- **HOSTNAME** – die gasheernaam van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se posspool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys van gidse om vir handleidingbladsye te soek.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die verstek prompt in bash.
- **PATH** – stoor die pad van al die gidse wat binêre lêers bevat wat jy wil uitvoer deur net die naam van die lêer te spesifiseer en nie die relatiewe of absolute pad nie.
- **PWD** – die huidige werkende gids.
- **SHELL** – die pad na die huidige command shell (byvoorbeeld, **/bin/bash**).
- **TERM** – die huidige terminaltipe (byvoorbeeld, **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interesting variables for hacking

Not every variable is equally useful. From an offensive perspective, prioritize variables that change **search paths**, **startup files**, **dynamic linker behavior**, or **audit/logging**.

### **HISTFILESIZE**

Change the **value of this variable to 0**, so when you **end your session** the **history file** (\~/.bash_history) will be **truncated to 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die in-memory history gehou word nie** en nie teruggeskryf sal word na die **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

As die **waarde van hierdie veranderlike ingestel is op `ignorespace` of `ignoreboth`**, sal enige opdrag met ’n ekstra spasie vooraan nie in die history gestoor word nie.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Wys die **history file** na **`/dev/null`** of ontset dit heeltemal. Dit is gewoonlik meer betroubaar as om net die history size te verander.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier verklaar is gebruik om via **http of https** aan die internet te koppel.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: verstek-proxy vir tools/protokolle wat dit eerbiedig.
- `no_proxy`: omseillys (gashere/domeine/CIDRs) wat direk behoort te verbind.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Beide kleinletters- en hoofletters-variante kan gebruik word, afhangende van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate wat in **hierdie env variables** aangedui word, vertrou. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP clients, of package managers te laat vertrou op ’n CA wat deur die attacker beheer word (byvoorbeeld, om ’n interception proxy legitiem te laat lyk).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

As ’n bevoorregte wrapper/script opdragte **sonder absolute paths** uitvoer, wen die **eerste aanvaller-beheerde directory** in `PATH`. Dit is die primitief agter baie **PATH hijacks** in `sudo`, cron jobs, shell wrappers, en custom SUID helpers. Soek vir `env_keep+=PATH`, swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. by naam aanroep.
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
Vir volledige privilege-escalation-kettings wat `PATH` misbruik, kyk na [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is nie net ’n gidsverwysing nie: baie gereedskap laai outomaties **dotfiles**, **plugins**, en **per-gebruiker-konfigurasie** vanaf `$HOME` of `$XDG_CONFIG_HOME`. As ’n bevoorregte werkvloei hierdie waardes behou, kan **config injection** makliker wees as binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante teikens sluit in `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, en tool-spesifieke lêers soos `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dynamic linker**:

- `LD_PRELOAD`: forseer ekstra shared objects om eerste gelaai te word.
- `LD_LIBRARY_PATH`: voeg library search directories vooraan.
- `LD_AUDIT`: laai auditor libraries wat library loading en symbol resolution waarneem.

Hulle is uiters waardevol vir **hooking**, **instrumentation**, en **privilege escalation** as ’n geprivilegieerde command hulle behou. In **secure-execution** modus (`AT_SECURE`, bv. setuid/setgid/capabilities), stroop of beperk die loader baie van hierdie veranderlikes. Parser bugs in daardie vroeë loader-fase is egter steeds hoë-impak omdat hulle **voor** die target program loop.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld, allocator tunables) en is baie nuttig in exploit labs. Dit maak ook vanuit ’n sekuriteitsperspektief saak omdat die **dynamic loader dit baie vroeg ontleed**. Die 2023 **Looney Tunables**-bug was ’n goeie herinnering dat ’n enkele omgewingsveranderlike wat in die loader ontleed word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** begin word, dit kontroleer `BASH_ENV` en source daardie lêer voordat dit die teikenskrip uitvoer. Wanneer Bash as `sh` opgeroep word, of in POSIX-styl interaktiewe modus, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell-wrapper in code execution te verander as die environment deur die attacker beheer word.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash self deaktiveer hierdie opstartlêers wanneer die **regte/effective IDs verskil** tensy `-p` gebruik word, so die presiese gedrag hang af van hoe die wrapper die shell aanroep.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Hierdie veranderlikes verander hoe Python begin:

- `PYTHONPATH`: voeg import-soekpaaie vooraan by.
- `PYTHONHOME`: herposisioneer die standaard library-boom.
- `PYTHONSTARTUP`: voer ’n lêer uit voor die interaktiewe prompt.
- `PYTHONINSPECT=1`: skakel oor na interaktiewe modus nadat ’n script klaar is.

Hulle is nuttig teen maintenance scripts, debuggers, shells, en wrappers wat Python met ’n beheerbare environment aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*` veranderlikes.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl het ewe nuttige opstart-veranderlikes:

- `PERL5LIB`: voeg biblioteek-gidse vooraan by.
- `PERL5OPT`: voeg switches in asof hulle op elke `perl` command line was.

Dit kan **automatic module loading** afdwing of interpretergedrag verander voordat die teikenskrip enigiets interessant doen. Perl ignoreer hierdie veranderlikes in **taint / setuid / setgid**-kontekste, maar hulle is steeds baie belangrik vir normale root-run wrappers, CI jobs, installers, en custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Dieselfde idee verskyn in ander runtimes (`RUBYOPT`, `NODE_OPTIONS`, ens.): wanneer ’n interpreter deur ’n bevoorregte wrapper geloods word, soek na env vars wat **module loading** of **startup behavior** wysig.

Vanuit ’n post-exploitation perspektief, onthou ook dat geërfde environments dikwels **credentials**, **proxy settings**, **service tokens**, of **cloud keys** bevat. Kyk na [Linux Post Exploitation](linux-post-exploitation/README.md) vir `/proc/<PID>/environ` en `systemd` `Environment=` hunting.

### PS1

Verander hoe jou prompt lyk.

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
