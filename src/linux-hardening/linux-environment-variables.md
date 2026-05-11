# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

Οι global variables **θα** κληρονομηθούν από **child processes**.

Μπορείς να δημιουργήσεις ένα global variable για το τρέχον session σου κάνοντας:
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
Τα περιεχόμενα του `/proc/*/environ` είναι **διαχωρισμένα με NUL**, οπότε αυτές οι παραλλαγές συνήθως είναι πιο εύκολες να διαβαστούν:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Αν ψάχνετε για **credentials** ή **interesting service configuration** μέσα σε inherited environments, ελέγξτε επίσης το [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος text editor του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο history file.
- **HISTSIZE** – Αριθμός γραμμών που προστίθενται στο history file όταν ο χρήστης ολοκληρώνει τη συνεδρία του
- **HOME** – το home directory σας.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα των directories που θα αναζητηθούν για manual pages.
- **OSTYPE** – ο τύπος του operating system.
- **PS1** – το default prompt στο bash.
- **PATH** – αποθηκεύει το path όλων των directories που περιέχουν binary files τα οποία θέλετε να εκτελείτε απλώς καθορίζοντας το όνομα του αρχείου και όχι με relative ή absolute path.
- **PWD** – ο τρέχων working directory.
- **SHELL** – το path προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων terminal type (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον username σας.

## Interesting variables for hacking

Not every variable is equally useful. From an offensive perspective, prioritize variables that change **search paths**, **startup files**, **dynamic linker behavior**, or **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας** το **history file** (\~/.bash_history) να **περικοπεί σε 0 γραμμές**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μην διατηρούνται στο ιστορικό στη μνήμη** και να μην εγγράφονται ξανά στο **history file** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή με ένα επιπλέον κενό στην αρχή δεν θα αποθηκευτεί στο history.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Δείξτε το **history file** στο **`/dev/null`** ή unset το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από το να αλλάξετε μόνο το history size.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Οι διεργασίες θα χρησιμοποιούν το **proxy** που δηλώνεται εδώ για να συνδέονται στο internet μέσω **http ή https**.
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
Τόσο οι lowercase όσο και οι uppercase εκδοχές μπορεί να χρησιμοποιηθούν ανάλογα με το tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα certificates που υποδεικνύονται σε **these env variables**. Αυτό είναι χρήσιμο για να κάνεις tools όπως **`curl`**, **`git`**, Python HTTP clients, ή package managers να εμπιστευτούν ένα CA που ελέγχεται από τον attacker (για παράδειγμα, για να κάνεις ένα interception proxy να φαίνεται legitimate).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Αν ένα privileged wrapper/script εκτελεί εντολές **χωρίς absolute paths**, ο **πρώτος attacker-controlled directory** στο `PATH` κερδίζει. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζήτησε `env_keep+=PATH`, αδύναμο `secure_path`, ή wrappers που καλούν `tar`, `service`, `cp`, `python`, κ.λπ. με όνομα.
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
Για πλήρεις αλυσίδες privilege-escalation που καταχρώνται το `PATH`, δείτε [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι μόνο μια αναφορά σε directory: πολλά tools φορτώνουν αυτόματα **dotfiles**, **plugins** και **per-user configuration** από `$HOME` ή `$XDG_CONFIG_HOME`. Αν μια privileged workflow διατηρεί αυτές τις τιμές, η **config injection** μπορεί να είναι πιο εύκολη από το binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesting targets include `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, and tool-specific files such as `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Αυτές οι μεταβλητές επηρεάζουν τον **dynamic linker**:

- `LD_PRELOAD`: επιβάλλει να φορτωθούν πρώτα επιπλέον shared objects.
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή καταλόγους αναζήτησης βιβλιοθηκών.
- `LD_AUDIT`: φορτώνει auditor libraries που παρακολουθούν το library loading και το symbol resolution.

Είναι εξαιρετικά πολύτιμες για **hooking**, **instrumentation**, και **privilege escalation** αν μια privileged command τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, bugs στον parser σε αυτό το αρχικό στάδιο του loader εξακολουθούν να έχουν μεγάλο αντίκτυπο επειδή εκτελούνται **πριν από το target program**.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` αλλάζει την early συμπεριφορά της glibc (για παράδειγμα, allocator tunables) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από πλευράς ασφάλειας επειδή ο **dynamic loader το αναλύει πολύ νωρίς**. Το bug του 2023 **Looney Tunables** ήταν μια καλή υπενθύμιση ότι μια και μόνο environment variable που αναλύεται στον loader μπορεί να γίνει **local privilege-escalation primitive** απέναντι σε SUID programs.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** ξεκινήσει **μη διαδραστικά**, ελέγχει το `BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το target script. Όταν το Bash καλείται ως `sh`, ή σε POSIX-style interactive mode, το `ENV` μπορεί επίσης να ληφθεί υπόψη. Αυτός είναι ένας κλασικός τρόπος να μετατρέψεις ένα shell wrapper σε code execution αν το environment ελέγχεται από attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το Bash απενεργοποιεί αυτά τα startup files όταν τα **real/effective IDs διαφέρουν** εκτός αν χρησιμοποιηθεί το `-p`, οπότε η ακριβής συμπεριφορά εξαρτάται από το πώς το wrapper καλεί το shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Αυτές οι variables αλλάζουν το πώς ξεκινά το Python:

- `PYTHONPATH`: προσθέτει μπροστά import search paths.
- `PYTHONHOME`: μεταφέρει το standard library tree.
- `PYTHONSTARTUP`: εκτελεί ένα file πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μπαίνει σε interactive mode αφού ολοκληρωθεί ένα script.

Είναι χρήσιμες απέναντι σε maintenance scripts, debuggers, shells, και wrappers που καλούν το Python με controllable environment. Το `python -E` και το `python -I` αγνοούν όλες τις `PYTHON*` variables.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Το Perl έχει εξίσου χρήσιμες startup variables:

- `PERL5LIB`: προσθέτει πρώτα library directories.
- `PERL5OPT`: inject switches σαν να ήταν σε κάθε `perl` command line.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script κάνει οτιδήποτε ενδιαφέρον. Το Perl αγνοεί αυτές τις variables σε **taint / setuid / setgid** contexts, αλλά παραμένουν πολύ σημαντικές για normal root-run wrappers, CI jobs, installers, και custom sudoers rules.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Η ίδια ιδέα εμφανίζεται και σε άλλα runtimes (`RUBYOPT`, `NODE_OPTIONS`, κ.λπ.): κάθε φορά που ένας interpreter εκκινεί μέσω ενός privileged wrapper, ψάξε για env vars που τροποποιούν **module loading** ή τη **startup behavior**.

Από post-exploitation σκοπιά, θυμήσου επίσης ότι τα inherited environments συχνά περιέχουν **credentials**, **proxy settings**, **service tokens** ή **cloud keys**. Δες το [Linux Post Exploitation](linux-post-exploitation/README.md) για `/proc/<PID>/environ` και `systemd` `Environment=` hunting.

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
