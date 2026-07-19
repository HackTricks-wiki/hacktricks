# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομούνται από τις **θυγατρικές διεργασίες**.

Μπορείτε να δημιουργήσετε μια καθολική μεταβλητή για την τρέχουσα συνεδρία σας ως εξής:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες συνεδρίες σας και τις θυγατρικές διεργασίες τους.

Μπορείτε να **αφαιρέσετε** μια μεταβλητή εκτελώντας:
```bash
unset MYGLOBAL
```
## Τοπικές μεταβλητές

Οι **τοπικές μεταβλητές** μπορούν να είναι **προσβάσιμες** μόνο από το **τρέχον shell/script**.
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
Τα περιεχόμενα του `/proc/*/environ` είναι **διαχωρισμένα με NUL**, επομένως αυτές οι παραλλαγές είναι συνήθως πιο εύκολες στην ανάγνωση:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Αν αναζητάτε **credentials** ή **ενδιαφέρουσα διαμόρφωση υπηρεσιών** μέσα σε inherited environments, ελέγξτε επίσης το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Συνηθισμένες μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος επεξεργαστής κειμένου του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο history file.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο history file όταν ο χρήστης ολοκληρώνει τη συνεδρία του.
- **HOME** – ο home κατάλογός σας.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα καταλόγων στους οποίους γίνεται αναζήτηση για manual pages.
- **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
- **PS1** – το default prompt στο bash.
- **PATH** – αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν binary files τα οποία θέλετε να εκτελείτε, καθορίζοντας απλώς το όνομα του αρχείου και όχι σχετική ή απόλυτη διαδρομή.
- **PWD** – ο τρέχων working directory.
- **SHELL** – η διαδρομή προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων τύπος terminal (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον username σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι κάθε μεταβλητή εξίσου χρήσιμη. Από offensive perspective, δώστε προτεραιότητα σε μεταβλητές που αλλάζουν τα **search paths**, τα **startup files**, τη **συμπεριφορά του dynamic linker** ή το **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας** το **history file** (\~/.bash_history) να **περικοπεί σε 0 γραμμές**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μην διατηρούνται στο ιστορικό της μνήμης** και να μην εγγράφονται ξανά στο **αρχείο ιστορικού** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή έχει ένα επιπλέον κενό στην αρχή της δεν θα αποθηκεύεται στο ιστορικό.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Ορίστε το **history file** στο **`/dev/null`** ή εκτελέστε `unset` για να το καταργήσετε πλήρως. Αυτό είναι συνήθως πιο αξιόπιστο από την απλή αλλαγή του μεγέθους του history.
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

- `all_proxy`: προεπιλεγμένος proxy για εργαλεία/πρωτόκολλα που τον υποστηρίζουν.
- `no_proxy`: λίστα παράκαμψης (hosts/domains/CIDRs) που πρέπει να συνδέονται απευθείας.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Μπορούν να χρησιμοποιηθούν τόσο οι πεζές όσο και οι κεφαλαίες παραλλαγές, ανάλογα με το εργαλείο (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις μεταβλητές περιβάλλοντος**. Αυτό είναι χρήσιμο για να κάνουν εργαλεία όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι package managers να εμπιστεύονται μια CA που ελέγχεται από τον attacker (για παράδειγμα, ώστε ένα interception proxy να φαίνεται νόμιμο).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Εάν ένα privileged wrapper/script εκτελεί commands **χωρίς absolute paths**, κερδίζει ο **πρώτος attacker-controlled directory** στο `PATH`. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζητήστε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. βάσει ονόματος.
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
Για πλήρεις αλυσίδες privilege-escalation που κάνουν abuse του `PATH`, δείτε το [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι μόνο αναφορά σε directory: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **per-user configuration** από τα `$HOME` ή `$XDG_CONFIG_HOME`. Αν ένα privileged workflow διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι ευκολότερο από το binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Ενδιαφέροντες στόχοι περιλαμβάνουν τα `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` και αρχεία ειδικά για εργαλεία, όπως το `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Αυτές οι μεταβλητές επηρεάζουν τον **dynamic linker**:

- `LD_PRELOAD`: επιβάλλει τη φόρτωση επιπλέον shared objects πρώτα.
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή directories αναζήτησης βιβλιοθηκών.
- `LD_AUDIT`: φορτώνει auditor libraries που παρακολουθούν τη φόρτωση βιβλιοθηκών και την επίλυση symbols.

Είναι εξαιρετικά χρήσιμες για **hooking**, **instrumentation** και **privilege escalation**, εάν μια privileged εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, parser bugs σε αυτό το αρχικό στάδιο του loader εξακολουθούν να έχουν σημαντικό αντίκτυπο, επειδή εκτελούνται **πριν** από το target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά του glibc σε πρώιμο στάδιο (για παράδειγμα, τα allocator tunables) και είναι ιδιαίτερα χρήσιμο σε exploit labs. Έχει επίσης σημασία από άποψη ασφάλειας, επειδή ο **dynamic loader το αναλύει σε πολύ πρώιμο στάδιο**. Το bug **Looney Tunables** του 2023 υπενθύμισε ότι μία μόνο environment variable που αναλύεται στον loader μπορεί να μετατραπεί σε **primitive τοπικής κλιμάκωσης προνομίων** εναντίον προγραμμάτων SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** ξεκινήσει **μη διαδραστικά**, ελέγχει το `BASH_ENV` και κάνει source σε αυτό το αρχείο πριν εκτελέσει το target script. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, μπορεί επίσης να συμβουλευτεί το `ENV`. Αυτός είναι ένας κλασικός τρόπος να μετατραπεί ένα shell wrapper σε code execution, αν το environment ελέγχεται από attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το ίδιο το Bash απενεργοποιεί αυτά τα αρχεία εκκίνησης όταν τα **real/effective IDs διαφέρουν**, εκτός αν χρησιμοποιηθεί το `-p`, επομένως η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper εκκινεί το shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο εκκίνησης της Python:

- `PYTHONPATH`: προσθέτει στην αρχή paths αναζήτησης για imports.
- `PYTHONHOME`: μετακινεί το δέντρο της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μεταβαίνει σε interactive mode αφού ολοκληρωθεί ένα script.

Είναι χρήσιμες εναντίον maintenance scripts, debuggers, shells και wrappers που καλούν την Python με environment το οποίο μπορεί να ελεγχθεί. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Η Perl διαθέτει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή.
- `PERL5OPT`: εισάγει switches σαν να υπήρχαν στη γραμμή εντολών κάθε `perl`.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script κάνει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να είναι πολύ σημαντικές για κανονικά root-run wrappers, CI jobs, installers και προσαρμοσμένους κανόνες sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Η ίδια ιδέα εμφανίζεται και σε άλλα runtimes (`RUBYOPT`, `NODE_OPTIONS`, κ.λπ.): κάθε φορά που ένας interpreter εκκινείται από ένα privileged wrapper, αναζητήστε env vars που τροποποιούν το **module loading** ή το **startup behavior**.

Από την οπτική του post-exploitation, να θυμάστε επίσης ότι τα inherited environments συχνά περιέχουν **credentials**, **proxy settings**, **service tokens** ή **cloud keys**. Ελέγξτε το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) για το `/proc/<PID>/environ` και την αναζήτηση του `systemd` `Environment=`.

### PS1

Αλλάξτε την εμφάνιση του prompt σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Αυτό είναι ένα παράδειγμα](<../images/image (897).png>)

Κανονικός χρήστης:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (740).png>)

Μία, δύο και τρεις εργασίες στο background:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (145).png>)

Μία εργασία στο background, μία σταματημένη και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![PERL5OPT & PERL5LIB - PS1: Μία εργασία στο background, μία σταματημένη και η τελευταία εντολή δεν ολοκληρώθηκε σωστά](<../images/image (715).png>)

## Αναφορές

- [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
