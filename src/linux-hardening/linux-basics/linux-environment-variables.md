# Linux promenljive okruženja

{{#include ../../banners/hacktricks-training.md}}

## Globalne promenljive

**Globalne promenljive će** naslediti **procesi-potomci**.

Globalnu promenljivu za trenutnu sesiju možete kreirati na sledeći način:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova promenljiva će biti dostupna u vašim trenutnim sesijama i njihovim podređenim procesima.

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
Sadržaj datoteka `/proc/*/environ` razdvojen je **NUL-karakterima**, pa su ove varijante obično lakše za čitanje:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ako tražite **credentials** ili **zanimljivu konfiguraciju servisa** unutar nasleđenih okruženja, pogledajte i [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Uobičajene promenljive

Izvor: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display koji koristi **X**. Ova promenljiva je obično podešena na **:0.0**, što znači prvi display na trenutnom računaru.
- **EDITOR** – tekstualni editor koji korisnik preferira.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u history fajlu.
- **HISTSIZE** – broj linija dodatih u history fajl kada korisnik završi sesiju.
- **HOME** – vaš home direktorijum.
- **HOSTNAME** – hostname računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma u kojima treba tražiti manual stranice.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanju do svih direktorijuma koji sadrže binarne fajlove koje želite da izvršite navođenjem samo imena fajla, a ne relativnom ili apsolutnom putanjom.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – putanja do trenutnog command shell-a (na primer, **/bin/bash**).
- **TERM** – trenutni tip terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Zanimljive promenljive za hacking

Nije svaka promenljiva podjednako korisna. Iz perspektive ofanzivnog pristupa, prioritet dajte promenljivama koje menjaju **search paths**, **startup files**, ponašanje **dynamic linker-a** ili **audit/logging**.

### **HISTFILESIZE**

Promenite **vrednost ove promenljive na 0**, kako bi se prilikom **završetka sesije** **history fajl** (\~/.bash_history) **skratio na 0 linija**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove promenljive na 0** kako se komande **ne bi čuvale u istoriji u memoriji** i kako se ne bi upisivale u **datoteku istorije** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ako je **vrednost ove promenljive podešena na `ignorespace` ili `ignoreboth`**, nijedna komanda kojoj prethodi dodatni razmak neće biti sačuvana u istoriji.
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

Procesi će koristiti ovde deklarisani **proxy** za povezivanje sa internetom putem **http** ili **https**.
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
Mogu se koristiti i varijante sa malim i velikim slovima, u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env varijablama**. Ovo je korisno za omogućavanje alatima kao što su **`curl`**, **`git`**, Python HTTP klijenti ili package manageri da veruju CA-u pod kontrolom napadača (na primer, kako bi interception proxy izgledao legitimno).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ako privilegovani wrapper/script izvršava komande **bez apsolutnih putanja**, pobeđuje **prvi direktorijum pod kontrolom napadača** u promenljivoj `PATH`. Ovo je osnova mnogih **PATH hijack** napada u `sudo`-u, cron poslovima, shell wrapperima i prilagođenim SUID helperima. Potražite `env_keep+=PATH`, slabi `secure_path` ili wrapere koji pozivaju `tar`, `service`, `cp`, `python` itd. po imenu.
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

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **per-user configuration** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani tok rada očuva ove vrednosti, **config injection** može biti lakši od **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i fajlove specifične za alate, kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dynamic linker**:

- `LD_PRELOAD`: prisiljava učitavanje dodatnih shared objekata pre ostalih.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak liste.
- `LD_AUDIT`: učitava auditor biblioteke koje nadgledaju učitavanje biblioteka i razrešavanje simbola.

Izuzetno su korisne za **hooking**, **instrumentation** i **privilege escalation** ako ih privilegovana komanda očuva. U režimu **secure-execution** (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, parser bugovi u toj ranoj fazi loadera i dalje imaju veliki uticaj jer se izvršavaju **pre** ciljnog programa.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, podešavanja alokatora) i veoma je korisna u exploit labovima. Takođe je važna iz bezbednosne perspektive zato što **dynamic loader veoma rano parsira ovu promenljivu**. Greška **Looney Tunables** iz 2023. godine bila je dobar podsetnik da jedna environment promenljiva koju loader parsira može postati **primitive za lokalnu eskalaciju privilegija** protiv SUID programa.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i učitava tu datoteku pre pokretanja ciljne skripte. Kada se Bash pozove kao `sh`, ili u interaktivnom POSIX režimu, može se proveravati i `ENV`. Ovo je klasičan način da se shell wrapper pretvori u izvršavanje koda ako napadač kontroliše okruženje.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash sam onemogućava ove startup fajlove kada se **realni/efektivni ID-ovi razlikuju**, osim ako se koristi `-p`, tako da tačno ponašanje zavisi od toga kako wrapper pokreće shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ove promenljive menjaju način na koji se Python pokreće:

- `PYTHONPATH`: dodaje putanje za pretragu import-a na početak.
- `PYTHONHOME`: menja lokaciju stabla standardne biblioteke.
- `PYTHONSTARTUP`: izvršava fajl pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prelazi u interaktivni režim nakon završetka skripte.

Korisne su protiv skripti za održavanje, debugger-a, shell-ova i wrapper-a koji pozivaju Python sa okruženjem koje se može kontrolisati. `python -E` i `python -I` ignorišu sve `PYTHON*` promenljive.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ima podjednako korisne startup promenljive:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak putanje.
- `PERL5OPT`: ubacuje switches kao da se nalaze u svakoj `perl` komandnoj liniji.

Ovo može da nametne **automatic module loading** ili promeni ponašanje interpreter-a pre nego što ciljana skripta uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u **taint / setuid / setgid** kontekstima, ali su i dalje veoma važne za uobičajene root-run wrappers, CI jobs, installers i prilagođena sudoers pravila.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Ista ideja se pojavljuje i u drugim runtime okruženjima (`RUBYOPT`, `NODE_OPTIONS`, itd.): kada interpreter pokreće privileged wrapper, potražite env promenljive koje menjaju **učitavanje modula** ili **ponašanje pri pokretanju**.

Iz perspektive post-exploitation-a, takođe imajte na umu da nasleđena okruženja često sadrže **credentials**, **proxy podešavanja**, **service tokene** ili **cloud ključeve**. Pogledajte [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) za `/proc/<PID>/environ` i pronalaženje `systemd` `Environment=` podešavanja.

### PS1

Promenite izgled svog prompta.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Ovo je primer](<../images/image (897).png>)

Običan korisnik:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri job-a pokrenuta u pozadini](<../images/image (740).png>)

Jedan, dva i tri job-a pokrenuta u pozadini:

![PERL5OPT & PERL5LIB - PS1: Jedan, dva i tri job-a pokrenuta u pozadini](<../images/image (145).png>)

Jedan job u pozadini, jedan zaustavljen i poslednja komanda nije uspešno završena:

![PERL5OPT & PERL5LIB - PS1: Jedan job u pozadini, jedan zaustavljen i poslednja komanda nije uspešno završena](<../images/image (715).png>)

## Reference

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
