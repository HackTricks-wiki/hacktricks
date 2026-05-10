# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομηθούν από **θυγατρικές διεργασίες**.

Μπορείς να δημιουργήσεις μια καθολική μεταβλητή για την τρέχουσα συνεδρία σου κάνοντας:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες συνεδρίες σας και τις θυγατρικές διεργασίες τους.

Μπορείτε να **αφαιρέσετε** μια μεταβλητή κάνοντας:
```bash
unset MYGLOBAL
```
## Τοπικές μεταβλητές

Οι **τοπικές μεταβλητές** μπορούν να **προσπελαστούν** μόνο από το **τρέχον shell/script**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Λίστα τρεχουσών μεταβλητών
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Το περιεχόμενο του `/proc/*/environ` είναι **NUL-separated**, οπότε αυτές οι παραλλαγές συνήθως είναι πιο εύκολες να διαβαστούν:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Αν ψάχνετε για **credentials** ή **interesting service configuration** μέσα σε inherited environments, ελέγξτε επίσης το [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – το display που χρησιμοποιείται από το **X**. Αυτή η variable είναι συνήθως ορισμένη σε **:0.0**, που σημαίνει το πρώτο display στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος text editor του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο history file.
- **HISTSIZE** – αριθμός γραμμών που προστίθενται στο history file όταν ο χρήστης ολοκληρώσει τη session του
- **HOME** – ο home directory σας.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα των directories που θα αναζητηθούν για manual pages.
- **OSTYPE** – ο τύπος του operating system.
- **PS1** – το default prompt στο bash.
- **PATH** – αποθηκεύει το path όλων των directories που περιέχουν binary files τα οποία θέλετε να εκτελείτε απλώς καθορίζοντας το name του file και όχι με relative ή absolute path.
- **PWD** – το τρέχον working directory.
- **SHELL** – το path προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων terminal type (για παράδειγμα, **xterm**).
- **TZ** – η time zone σας.
- **USER** – το τρέχον username σας.

## Interesting variables for hacking

Δεν είναι όλες οι variables εξίσου χρήσιμες. Από offensive perspective, δώστε προτεραιότητα σε variables που αλλάζουν **search paths**, **startup files**, **dynamic linker behavior**, ή **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **value αυτής της variable σε 0**, ώστε όταν **τελειώσετε τη session σας** το **history file** (\~/.bash_history) να **truncated σε 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μην διατηρούνται στο history της μνήμης** και να μην εγγράφονται πίσω στο **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή έχει μπροστά της ένα επιπλέον κενό δεν θα αποθηκευτεί στο history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Δείξτε το **history file** στο **`/dev/null`** ή απο-ορίστε το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από το να αλλάζετε μόνο το history size.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Οι διεργασίες θα χρησιμοποιούν το **proxy** που δηλώνεται εδώ για να συνδεθούν στο internet μέσω **http or https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: προεπιλεγμένο proxy για εργαλεία/protocols που το υποστηρίζουν.
- `no_proxy`: λίστα παράκαμψης (hosts/domains/CIDRs) που πρέπει να συνδέονται απευθείας.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Τόσο τα lowercase όσο και τα uppercase variants μπορεί να χρησιμοποιηθούν ανάλογα με το tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Τα processes θα εμπιστεύονται τα certificates που υποδεικνύονται σε **these env variables**. Αυτό είναι χρήσιμο για να κάνεις tools όπως **`curl`**, **`git`**, Python HTTP clients ή package managers να εμπιστευτούν ένα CA ελεγχόμενο από τον attacker (για παράδειγμα, ώστε ένα interception proxy να φαίνεται legitimate).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Αν ένα privileged wrapper/script εκτελεί εντολές **χωρίς absolute paths**, τότε το **πρώτο attacker-controlled directory** στο `PATH` κερδίζει. Αυτή είναι η primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζήτησε `env_keep+=PATH`, weak `secure_path`, ή wrappers που καλούν `tar`, `service`, `cp`, `python`, κ.λπ. με όνομα.
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
Για πλήρεις αλυσίδες privilege-escalation που κάνουν abuse το `PATH`, δείτε [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι μόνο μια αναφορά καταλόγου: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **ρυθμίσεις ανά χρήστη** από `$HOME` ή `$XDG_CONFIG_HOME`. Αν μια privileged workflow διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι πιο εύκολο από το binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Ενδιαφέροντα targets περιλαμβάνουν τα `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, και tool-specific files όπως το `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

These variables influence the **dynamic linker**:

- `LD_PRELOAD`: force extra shared objects to be loaded first.
- `LD_LIBRARY_PATH`: prepend library search directories.
- `LD_AUDIT`: load auditor libraries that observe library loading and symbol resolution.

Είναι εξαιρετικά πολύτιμα για **hooking**, **instrumentation**, και **privilege escalation** αν μια privileged command τα διατηρεί. Σε **secure-execution** mode (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις variables. Ωστόσο, parser bugs σε εκείνο το early loader stage εξακολουθούν να έχουν υψηλό impact επειδή εκτελούνται **before** the target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει πρώιμη συμπεριφορά του glibc (για παράδειγμα, allocator tunables) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από πλευράς ασφάλειας επειδή ο **dynamic loader το αναλύει πολύ νωρίς**. Το bug του 2023 **Looney Tunables** ήταν μια καλή υπενθύμιση ότι ένα μόνο environment variable που αναλύεται στον loader μπορεί να γίνει **local privilege-escalation primitive** εναντίον SUID προγραμμάτων.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** ξεκινήσει **non-interactively**, ελέγχει το `BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το target script. Όταν το Bash καλείται ως `sh`, ή σε POSIX-style interactive mode, το `ENV` μπορεί επίσης να ληφθεί υπόψη. Αυτός είναι ένας κλασικός τρόπος να μετατρέψεις ένα shell wrapper σε code execution αν το environment ελέγχεται από attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το Bash απενεργοποιεί αυτά τα startup files όταν τα **real/effective IDs διαφέρουν** εκτός αν χρησιμοποιηθεί το `-p`, οπότε η ακριβής συμπεριφορά εξαρτάται από το πώς το wrapper καλεί το shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο που ξεκινά το Python:

- `PYTHONPATH`: προσθέτει prepend τα import search paths.
- `PYTHONHOME`: μετακινεί το standard library tree.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μπαίνει σε interactive mode αφού ολοκληρωθεί ένα script.

Είναι χρήσιμες απέναντι σε maintenance scripts, debuggers, shells και wrappers που καλούν το Python με controllable environment. Τα `python -E` και `python -I` αγνοούν όλες τις `PYTHON*` variables.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Το Perl έχει εξίσου χρήσιμες startup variables:

- `PERL5LIB`: προσθέτει στην αρχή library directories.
- `PERL5OPT`: εισάγει switches σαν να ήταν σε κάθε `perl` command line.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script κάνει οτιδήποτε ενδιαφέρον. Το Perl αγνοεί αυτές τις variables σε **taint / setuid / setgid** contexts, αλλά εξακολουθούν να έχουν μεγάλη σημασία για normal root-run wrappers, CI jobs, installers, και custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Η ίδια ιδέα εμφανίζεται και σε άλλα runtimes (`RUBYOPT`, `NODE_OPTIONS`, κ.λπ.): κάθε φορά που ένας interpreter εκκινείται από ένα privileged wrapper, αναζήτησε env vars που τροποποιούν το **module loading** ή τη **startup behavior**.

Από post-exploitation σκοπιά, θυμήσου επίσης ότι τα inherited environments συχνά περιέχουν **credentials**, **proxy settings**, **service tokens**, ή **cloud keys**. Δες [Linux Post Exploitation](linux-post-exploitation/README.md) για `/proc/<PID>/environ` και `systemd` `Environment=` hunting.

### PS1

Άλλαξε το πώς φαίνεται το prompt σου.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

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
