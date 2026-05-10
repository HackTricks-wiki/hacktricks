# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Globalne promenljive

Globalne promenljive **biće** nasleđene od strane **child processes**.

Možete kreirati globalnu promenljivu za vašu trenutnu sesiju tako što ćete uraditi:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova varijabla će biti dostupna u vašim trenutnim sesijama i njihovim child procesima.

Možete **ukloniti** varijablu na sledeći način:
```bash
unset MYGLOBAL
```
## Lokalне promenljive

**Lokalne promenljive** mogu da budu **pristupene** samo iz **trenutnog shell-a/script-a**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista trenutnih varijabli
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Sadržaj `/proc/*/environ` je **razdvojen NUL-ovima**, pa su ove varijante obično lakše za čitanje:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ako tražite **credentials** ili **interesting service configuration** unutar inherited environments, takođe proverite [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display koji koristi **X**. Ova varijabla je obično postavljena na **:0.0**, što znači prvi display na trenutnom računaru.
- **EDITOR** – korisnikov omiljeni tekst editor.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u history fajlu.
- **HISTSIZE** – Broj linija dodatih u history fajl kada korisnik završi svoju sesiju
- **HOME** – vaš home direktorijum.
- **HOSTNAME** – hostname računara.
- **LANG** – vaš trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma za pretragu manual page-ova.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva putanju svih direktorijuma koji sadrže binarne fajlove koje želite da izvršite samo navođenjem imena fajla, a ne relativne ili apsolutne putanje.
- **PWD** – trenutni working directory.
- **SHELL** – putanja do trenutnog command shell-a (na primer, **/bin/bash**).
- **TERM** – trenutni tip terminala (na primer, **xterm**).
- **TZ** – vaša vremenska zona.
- **USER** – vaše trenutno korisničko ime.

## Interesting variables for hacking

Nije svaka varijabla jednako korisna. Iz ofensivne perspektive, prioritet dajte varijablama koje menjaju **search paths**, **startup files**, **dynamic linker behavior**, ili **audit/logging**.

### **HISTFILESIZE**

Promenite **vrednost ove varijable na 0**, tako da kada **završite sesiju** **history fajl** (\~/.bash_history) bude **skraćen na 0 linija**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promeni **vrednost ove promenljive na 0**, tako da se komande **ne čuvaju u istoriji u memoriji** i neće biti upisane nazad u **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ako je **vrednost ove promenljive postavljena na `ignorespace` ili `ignoreboth`**, svaka komanda kojoj je dodat dodatni razmak na početku neće biti sačuvana u istoriji.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Usmeri **history file** na **`/dev/null`** ili ga potpuno unsetuj. Ovo je obično pouzdanije nego samo menjati veličinu history-ja.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesi će koristiti **proxy** deklarisan ovde za povezivanje na internet preko **http ili https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga poštuju.
- `no_proxy`: lista zaobilaženja (hostovi/domeni/CIDR-ovi) koji treba da se povezuju direktno.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
I mala i velika slova varijante mogu se koristiti u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env variables**. Ovo je korisno da bi alati kao što su **`curl`**, **`git`**, Python HTTP klijenti, ili package managers verovali CA koji kontroliše napadač (na primer, da bi se interception proxy učinio legitimnim).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ako privilegovani wrapper/script izvršava komande **bez apsolutnih path-ova**, **prvi attacker-controlled direktorijum** u `PATH` pobeđuje. Ovo je primitiv iza mnogih **PATH hijacks** u `sudo`, cron jobs, shell wrappers i custom SUID helpers. Traži `env_keep+=PATH`, slabi `secure_path`, ili wrapper-e koji pozivaju `tar`, `service`, `cp`, `python`, itd. po imenu.
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
Za kompletne privilege-escalation lance koji zloupotrebljavaju `PATH`, pogledajte [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins** i **per-user configuration** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani workflow zadrži ove vrednosti, **config injection** može biti lakša od binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Zanimljive mete uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, i fajlove specifične za alate kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dynamic linker**:

- `LD_PRELOAD`: prisiljava dodatne shared objects da se učitaju prve.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak.
- `LD_AUDIT`: učitava auditor biblioteke koje posmatraju učitavanje biblioteka i rezoluciju simbola.

One su izuzetno vredne za **hooking**, **instrumentation**, i **privilege escalation** ako privilegovana komanda sačuva njihove vrednosti. U **secure-execution** modu (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, parser bagovi u toj ranoj loader fazi i dalje imaju veliki uticaj jer se izvršavaju **pre** ciljnog programa.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano glibc ponašanje (na primer, allocator tunables) i veoma je koristan u exploit labs. Takođe je važan iz bezbednosne perspektive zato što **dynamic loader ga parsira veoma rano**. Greška iz 2023. **Looney Tunables** je bila dobar podsetnik da jedna environment variable koja se parsira u loader-u može da postane **local privilege-escalation primitive** protiv SUID programa.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ako se **Bash** pokrene **ne-interaktivno**, proverava `BASH_ENV` i učitava taj fajl pre pokretanja ciljnog skripta. Kada se Bash pozove kao `sh`, ili u POSIX-stilu interaktivnog režima, `ENV` se takođe može konsultovati. Ovo je klasičan način da se shell wrapper pretvori u izvršavanje koda ako je environment pod kontrolom napadača.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash sam onemogućava ove startup fajlove kada se **real/effective IDs razlikuju** osim ako se ne koristi `-p`, tako da tačno ponašanje zavisi od toga kako wrapper poziva shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ove varijable menjaju kako Python pokreće:

- `PYTHONPATH`: dodaje import search paths na početak.
- `PYTHONHOME`: relocira standard library tree.
- `PYTHONSTARTUP`: izvršava fajl pre interaktivnog prompta.
- `PYTHONINSPECT=1`: ulazi u interactive mode nakon što se script završi.

Korisne su protiv maintenance scripts, debuggers, shells i wrappera koji pozivaju Python sa controllable environment. `python -E` i `python -I` ignorišu sve `PYTHON*` varijable.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ima jednako korisne startup promenljive:

- `PERL5LIB`: prepend library directories.
- `PERL5OPT`: inject switches as if they were on every `perl` command line.

Ovo može da forsira **automatic module loading** ili da promeni ponašanje interpreter-a pre nego što target script uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u **taint / setuid / setgid** kontekstima, ali i dalje imaju veliki značaj za obične root-run wrappers, CI jobs, installers i custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Ista ideja se pojavljuje i u drugim runtime-ovima (`RUBYOPT`, `NODE_OPTIONS`, itd.): kad god interpreter pokreće privileged wrapper, traži env vars koje menjaju **module loading** ili **startup behavior**.

Iz post-exploitation perspektive, imaj na umu i da inherited environments često sadrže **credentials**, **proxy settings**, **service tokens**, ili **cloud keys**. Pogledaj [Linux Post Exploitation](linux-post-exploitation/README.md) za `/proc/<PID>/environ` i `systemd` `Environment=` hunting.

### PS1

Promeni kako izgleda tvoj prompt.

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
