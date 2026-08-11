# Linux-omgewingsveranderlikes

## Globale veranderlikes

Die globale veranderlikes **sal** deur **child processes** oorgeërf word.

Jy kan ’n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal toeganklik wees vir jou huidige sessies en hul child processes.

Jy kan ’n veranderlike **verwyder** deur:
```bash
unset MYGLOBAL
```
## Plaaslike veranderlikes

Die **plaaslike veranderlikes** kan slegs deur die **huidige shell/script** **verkry** word.
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

Van: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – die skerm wat deur **X** gebruik word. Hierdie veranderlike is gewoonlik op **:0.0** gestel, wat die eerste skerm op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeurteksredigeerder.
- **HISTFILESIZE** – die maksimum aantal reëls wat in die geskiedenislêer vervat kan wees.
- **HISTSIZE** – die aantal reëls wat by die geskiedenislêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die gasheernaam van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se pos-spool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys gidse waarin daar vir handleidingbladsye gesoek moet word.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die verstekprompt in bash.
- **PATH** – stoor die pad van al die gidse wat binêre lêers bevat wat jy wil uitvoer deur slegs die lêernaam te spesifiseer en nie ’n relatiewe of absolute pad nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die pad na die huidige command shell (byvoorbeeld, **/bin/bash**).
- **TERM** – die huidige terminaaltipe (byvoorbeeld, **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

Nie elke veranderlike is ewe nuttig nie. Vanuit ’n offensiewe perspektief moet veranderlikes wat **soekpaaie**, **opstartlêers**, **dynamic linker-gedrag** of **ouditering/aanmelding** verander, voorkeur geniet.

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat die **geskiedenislêer** (\~/.bash_history) wanneer jy jou **sessie beëindig**, na **0 reëls afgekap** sal word.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die geheuegeskiedenis gehou word nie** en nie na die **geskiedenislêer** (\~/.bash_history) geskryf sal word nie.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

As die **waarde van hierdie veranderlike op `ignorespace` of `ignoreboth` gestel is**, sal enige opdrag wat met ’n ekstra spasie voorafgegaan word, nie in die history gestoor word nie.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Wys die **geskiedenislêer** na **`/dev/null`** of deaktiveer dit heeltemal. Dit is gewoonlik meer betroubaar as om slegs die geskiedenisgrootte te verander.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier verklaar word, gebruik om deur **http of https** aan die internet te koppel.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: verstekproxy vir nutsgoed/protokolle wat dit respekteer.
- `no_proxy`: omseilingslys (gashere/domeine/CIDR's) wat direk moet koppel.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Beide kleinletter- en hooflettervariante kan gebruik word, afhangend van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie omgewingsveranderlikes** aangedui word. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP-clients of pakketbestuurders ’n CA te laat vertrou wat deur die aanvaller beheer word (byvoorbeeld om ’n interception proxy legitiem te laat lyk).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

As 'n bevoorregte wrapper/script opdragte **sonder absolute paaie** uitvoer, wen die **eerste aanvaller-beheerde gids** in `PATH`. Dit is die primitief agter baie **PATH hijacks** in `sudo`, cron jobs, shell wrappers en pasgemaakte SUID helpers. Soek na `env_keep+=PATH`, swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. volgens naam aanroep.
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
Vir volledige privilege-escalation-kettings wat `PATH` misbruik, raadpleeg [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is nie slegs ’n gidsverwysing nie: baie nutsprogramme laai outomaties **dotfiles**, **plugins** en **per-gebruiker-konfigurasie** vanaf `$HOME` of `$XDG_CONFIG_HOME`. Indien ’n bevoorregte workflow hierdie waardes behou, kan **config injection** makliker wees as binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante teikens sluit `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` en tool-spesifieke lêers soos `.terraformrc` in.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dynamic linker**:

- `LD_PRELOAD`: dwing ekstra shared objects om eerste gelaai te word.
- `LD_LIBRARY_PATH`: voeg biblioteek-soekgidse vooraan by.
- `LD_AUDIT`: laai auditor-biblioteke wat biblioteeklaaiing en simboolresolusie waarneem.

Hulle is uiters waardevol vir **hooking**, **instrumentation** en **privilege escalation** indien ’n bevoorregte bevel hulle behou. In **secure-execution**-modus (`AT_SECURE`, byvoorbeeld setuid/setgid/capabilities) verwyder of beperk die loader baie van hierdie veranderlikes. Parser-bugs in daardie vroeë loader-stadium het egter steeds ’n groot impak omdat hulle **voor** die teikenprogram uitgevoer word.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld allocator tunables) en is baie nuttig in exploit-laboratoriums. Dit is ook vanuit ’n sekuriteitsperspektief belangrik omdat die **dynamic loader dit baie vroeg ontleed**. Die 2023-**Looney Tunables**-bug was ’n goeie herinnering dat ’n enkele omgewingsveranderlike wat in die loader ontleed word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** gestart word, kontroleer dit `BASH_ENV` en source daardie lêer voordat die teikenskrip uitgevoer word. Wanneer Bash as `sh`, of in POSIX-styl interaktiewe modus, aangeroep word, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell-wrapper in code execution te verander indien die omgewing aanvaller-beheer word.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoreer hierdie opstartlêers wanneer die **werklike/effektiewe ID's verskil**; `-p` behou die effektiewe ID, maar aktiveer nie daardie opstartlêers nie, dus hang die presiese gedrag af van hoe die wrapper die shell aanroep. Wees versigtig met bevoorregte wrappers wat `setuid()`/`setgid()` **voor** die launch van Bash aanroep: sodra die ID's weer ooreenstem, kan Bash `BASH_ENV`, `ENV` en verwante shell-status vertrou wat andersins geïgnoreer sou word.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Hierdie veranderlikes verander hoe Python start:

- `PYTHONPATH`: voeg import-soekpaaie vooraan.
- `PYTHONHOME`: verskuif die standaardbiblioteek-boom.
- `PYTHONSTARTUP`: voer 'n lêer uit vóór die interaktiewe prompt.
- `PYTHONINSPECT=1`: gaan oor na interaktiewe modus nadat 'n script voltooi is.

Hulle is nuttig teen maintenance scripts, debuggers, shells en wrappers wat Python met 'n beheerbare omgewing aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*`-veranderlikes.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
'n Onlangse werklike voorbeeld was die 2024 **needrestart** LPE op Ubuntu/Debian-stelsels: die root-owned scanner het 'n onbegunstigde proses se `PYTHONPATH` vanaf `/proc/<PID>/environ` gekopieer en daarna Python uitgevoer. Die gepubliseerde exploit het `importlib/__init__.so` in die aanvaller-beheerde pad geplaas, sodat Python aanvallerkode tydens sy eie initialisering uitgevoer het, voordat die helper se hardgekodeerde script enigsins saak gemaak het.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl het ewe nuttige startup-veranderlikes:

- `PERL5LIB`: voeg library-gidse vooraan.
- `PERL5OPT`: inject switches asof dit op elke `perl`-command line was.

Dit kan **automatic module loading** afdwing of interpreter-gedrag verander voordat die target script enigiets interessants doen. Perl ignoreer hierdie veranderlikes in **taint / setuid / setgid**-kontekste, maar hulle is steeds baie belangrik vir normale root-run wrappers, CI-jobs, installers en custom sudoers-reëls.
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

`NODE_OPTIONS` voeg **Node.js CLI flags** vooraf by elke `node`-proses wat die omgewing oorerf. Dit maak dit nuttig teen wrappers, CI-take, Electron-helpers en sudo-reëls wat uiteindelik Node aanroep. Die interessantste flags vanuit ’n offensiewe oogpunt is gewoonlik:

- `--require <file>`: laai ’n CommonJS-lêer vooraf voordat die teikenskrip uitgevoer word.
- `--import <module>`: laai ’n ES-module vooraf voordat die teikenskrip uitgevoer word.

Node verwerp sommige gevaarlike flags in `NODE_OPTIONS`, maar `--require` en `--import` word uitdruklik toegelaat en word **voor** die gewone command-line-argumente verwerk.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Vir afgeleë gadget chains wat `NODE_OPTIONS` indirek stel (byvoorbeeld prototype-pollution to RCE), kyk na [hierdie ander bladsy](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bied dieselfde klas opstartmisbruik:

- `RUBYLIB`: voeg gidse vooraan Ruby se load path.
- `RUBYOPT`: inject command-line options soos `-r` in elke `ruby`-invocation.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die 2024 **needrestart**-kwesbaarhede het getoon dat dit nie net ’n laboratoriumtruuk is nie: dieselfde root-owned helper wat kwesbaar was vir `PYTHONPATH`-misbruik, kon ook gedwing word om Ruby met ’n aanvaller-beheerde `RUBYLIB` uit te voer, wat `enc/encdb.so` vanuit ’n aanvaller-gids gelaai het.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Sommige tools lees nie net ’n path vanuit die environment nie; hulle gee die waarde aan ’n **shell**, ’n **editor** of ’n **input preprocessor**. Dit maak die volgende variables veral interessant wanneer ’n bevoorregte wrapper `git`, `man`, `less` of soortgelyke tekskykers uitvoer:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: kies die pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: kies die editor command, dikwels met arguments.
- `LESSOPEN`, `LESSCLOSE`: definieer pre/post-processors wat loop wanneer `less` ’n file oopmaak.
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
Vanuit ’n post-exploitation-perspektief, onthou ook dat geërfde omgewings dikwels **credentials**, **proxy settings**, **service tokens** of **cloud keys** bevat. Gaan na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) vir jagtogte na `/proc/<PID>/environ` en `systemd` se `Environment=`.

### PS1

Verander hoe jou prompt lyk.

[**Dit is ’n voorbeeld**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dit is ’n voorbeeld](<../images/image (897).png>)

Gereelde gebruiker:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take wat in die agtergrond loop](<../images/image (740).png>)

Een, twee en drie take wat in die agtergrond loop:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take wat in die agtergrond loop](<../images/image (145).png>)

Een taak in die agtergrond, een gestopte taak, en die laaste opdrag het nie korrek voltooi nie:

![PERL5OPT & PERL5LIB - PS1: Een taak in die agtergrond, een gestopte taak, en die laaste opdrag het nie korrek voltooi nie](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash-opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI-dokumentasie - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Algemene omgewingsveranderlikes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Plaaslike voorregeskalering in glibc se ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
