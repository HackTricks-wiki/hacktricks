# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Globalne promenljive

Globalne promenljive **biće** nasleđene od strane **child processes**.

Možete kreirati globalnu promenljivu za vašu trenutnu sesiju tako što ćete:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova varijabla će biti dostupna vašim trenutnim sesijama i njihovim child procesima.

Možete je **ukloniti** na sledeći način:
```bash
unset MYGLOBAL
```
## Lokalne promenljive

**Lokalne promenljive** mogu da budu **pristupane** samo od strane **trenutnog shell-a/scripta**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Izlistaj trenutne varijable
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Sadržaj `/proc/*/environ` je **razdvojen NUL znakovima**, pa su ove varijante obično lakše za čitanje:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Ako tražite **credentials** ili **interesting service configuration** unutar inherited environments, takođe proverite [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – display koji koristi **X**. Ova varijabla je obično postavljena na **:0.0**, što znači prvi display na trenutnom računaru.
- **EDITOR** – korisnikov preferirani tekst editor.
- **HISTFILESIZE** – maksimalan broj linija sadržanih u history fajlu.
- **HISTSIZE** – broj linija koje se dodaju u history fajl kada korisnik završi svoju sesiju
- **HOME** – tvoj home direktorijum.
- **HOSTNAME** – hostname računara.
- **LANG** – tvoj trenutni jezik.
- **MAIL** – lokacija korisnikovog mail spool-a. Obično **/var/spool/mail/USER**.
- **MANPATH** – lista direktorijuma koje treba pretražiti za manual stranice.
- **OSTYPE** – tip operativnog sistema.
- **PS1** – podrazumevani prompt u bash-u.
- **PATH** – čuva path svih direktorijuma koji sadrže binarne fajlove koje želiš da izvršiš samo navođenjem imena fajla, a ne relativnog ili apsolutnog path-a.
- **PWD** – trenutni radni direktorijum.
- **SHELL** – path do trenutnog command shell-a (na primer, **/bin/bash**).
- **TERM** – trenutni terminal tip (na primer, **xterm**).
- **TZ** – tvoja vremenska zona.
- **USER** – tvoje trenutno korisničko ime.

## Interesting variables for hacking

Nije svaka varijabla jednako korisna. Iz ofanzivne perspektive, prioritet dajte varijablama koje menjaju **search paths**, **startup files**, **dynamic linker behavior**, ili **audit/logging**.

### **HISTFILESIZE**

Promeni **vrednost ove varijable na 0**, tako da kada **završiš sesiju** **history fajl** (\~/.bash_history) bude **skraćen na 0 linija**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove varijable na 0**, tako da se komande **ne čuvaju u istoriji u memoriji** i neće biti upisane nazad u **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Ako je **vrednost ove promenljive postavljena na `ignorespace` ili `ignoreboth`**, svaka komanda kojoj je ispred dodat razmak neće biti sačuvana u history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Usmerite **history file** na **`/dev/null`** ili ga potpuno unsetujte. Ovo je obično pouzdanije nego samo menjanje veličine history-ja.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Procesi će koristiti **proxy** deklarisan ovde za povezivanje na internet preko **http** ili **https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: podrazumevani proxy za alate/protokole koji ga poštuju.
- `no_proxy`: lista izuzetaka (hostovi/domeni/CIDR opsezi) koji treba da se povezuju direktno.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Mogu se koristiti i lowercase i uppercase varijante u zavisnosti od alata (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Procesi će verovati sertifikatima navedenim u **ovim env variables**. Ovo je korisno da bi alati kao što su **`curl`**, **`git`**, Python HTTP klijenti ili package managers verovali CA-u kojim upravlja napadač (na primer, da bi interception proxy izgledao legitimno).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Ako privilegovani wrapper/script izvršava komande **bez apsolutnih path-ova**, **prvi attacker-controlled direktorijum** u `PATH` pobeđuje. Ovo je primitiv koji stoji iza mnogih **PATH hijacks** u `sudo`, cron jobs, shell wrappers i custom SUID helperima. Traži `env_keep+=PATH`, slab `secure_path`, ili wrappere koji pozivaju `tar`, `service`, `cp`, `python`, itd. po imenu.
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
Za potpune lance za eskalaciju privilegija koji zloupotrebljavaju `PATH`, proveri [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` nije samo referenca na direktorijum: mnogi alati automatski učitavaju **dotfiles**, **plugins**, i **konfiguraciju po korisniku** iz `$HOME` ili `$XDG_CONFIG_HOME`. Ako privilegovani workflow sačuva ove vrednosti, **config injection** može biti lakši nego binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Zanimljivi targeti uključuju `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` i fajlove specifične za alat kao što je `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Ove promenljive utiču na **dynamic linker**:

- `LD_PRELOAD`: forsira da se dodatni shared objects učitaju prvi.
- `LD_LIBRARY_PATH`: dodaje direktorijume za pretragu biblioteka na početak.
- `LD_AUDIT`: učitava auditor libraries koje posmatraju učitavanje biblioteka i razrešavanje simbola.

One su izuzetno vredne za **hooking**, **instrumentation** i **privilege escalation** ako privilegovana komanda sačuva njihov sadržaj. U **secure-execution** modu (`AT_SECURE`, npr. setuid/setgid/capabilities), loader uklanja ili ograničava mnoge od ovih promenljivih. Međutim, parser bugs u toj ranoj loader fazi su i dalje veoma ozbiljni jer se izvršavaju **pre** ciljnog programa.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` menja rano ponašanje glibc-a (na primer, allocator tunables) i vrlo je koristan u exploit labovima. Takođe je važan iz bezbednosne perspektive zato što ga **dinamički loader parsira veoma rano**. Greška **Looney Tunables** iz 2023. bila je dobar podsetnik da jedna environment variable koju parsira loader može postati **lokalni privilege-escalation primitive** protiv SUID programa.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Ako se **Bash** pokrene **neinteraktivno**, proverava `BASH_ENV` i učitava taj fajl pre pokretanja ciljnog skripta. Kada se Bash poziva kao `sh`, ili u POSIX-stilu interaktivnog režima, može se takođe proveriti `ENV`. Ovo je klasičan način da se shell wrapper pretvori u izvršavanje koda ako je okruženje pod kontrolom napadača.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash sam po sebi onemogućava ove startup fajlove kada se **realni/efektivni ID-jevi razlikuju** osim ako se ne koristi `-p`, tako da tačno ponašanje zavisi od toga kako wrapper poziva shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Ove varijable menjaju način na koji Python startuje:

- `PYTHONPATH`: dodaje import putanje pre ostalih.
- `PYTHONHOME`: premešta standardno stablo biblioteka.
- `PYTHONSTARTUP`: izvršava fajl pre interaktivnog prompta.
- `PYTHONINSPECT=1`: prebacuje u interaktivni režim nakon što se skripta završi.

Korisne su protiv maintenance skripti, debagera, shell-ova i wrappera koji pozivaju Python sa kontrolisanim okruženjem. `python -E` i `python -I` ignorišu sve `PYTHON*` varijable.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ima jednako korisne startup promenljive:

- `PERL5LIB`: dodaje direktorijume biblioteka na početak.
- `PERL5OPT`: ubacuje switch-eve kao da su bili na svakoj `perl` komandnoj liniji.

Ovo može da forsira **automatsko učitavanje modula** ili promeni ponašanje interpretatora pre nego što ciljna skripta uradi bilo šta zanimljivo. Perl ignoriše ove promenljive u **taint / setuid / setgid** kontekstima, ali i dalje mnogo znače za normalne root-run wrapper-e, CI poslove, instalere i custom sudoers pravila.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Ista ideja se pojavljuje i u drugim runtajmima (`RUBYOPT`, `NODE_OPTIONS`, itd.): kad god se interpreter pokreće preko privilegovanog wrappera, traži env varijable koje menjaju **učitavanje modula** ili **ponašanje pri pokretanju**.

Sa post-exploitation stanovišta, takođe zapamti da nasleđena okruženja često sadrže **credentials**, **proxy podešavanja**, **service tokens**, ili **cloud keys**. Pogledaj [Linux Post Exploitation](linux-post-exploitation/README.md) za `/proc/<PID>/environ` i `systemd` `Environment=` hunting.

### PS1

Promeni kako tvoj prompt izgleda.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

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
