# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομούνται από τις **θυγατρικές διεργασίες**.

Μπορείτε να δημιουργήσετε μια καθολική μεταβλητή για την τρέχουσα συνεδρία σας εκτελώντας:
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
Τα περιεχόμενα του `/proc/*/environ` διαχωρίζονται με **NUL**, επομένως αυτές οι παραλλαγές είναι συνήθως πιο εύκολες στην ανάγνωση:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Αν αναζητάτε **credentials** ή **ενδιαφέρουσες ρυθμίσεις υπηρεσιών** μέσα σε inherited environments, ελέγξτε επίσης το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Κοινές μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος text editor του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο history file.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο history file όταν ο χρήστης ολοκληρώνει τη συνεδρία του.
- **HOME** – ο home directory σας.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα directories στα οποία γίνεται αναζήτηση για manual pages.
- **OSTYPE** – ο τύπος του operating system.
- **PS1** – το default prompt στο bash.
- **PATH** – αποθηκεύει τη διαδρομή όλων των directories που περιέχουν binary files τα οποία θέλετε να εκτελέσετε, καθορίζοντας απλώς το όνομα του file και όχι relative ή absolute path.
- **PWD** – το τρέχον working directory.
- **SHELL** – το path προς το τρέχον command shell, για παράδειγμα **/bin/bash**.
- **TERM** – ο τρέχων τύπος terminal, για παράδειγμα **xterm**.
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον username σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι κάθε μεταβλητή εξίσου χρήσιμη. Από offensive perspective, δώστε προτεραιότητα σε μεταβλητές που αλλάζουν **search paths**, **startup files**, τη **dynamic linker behavior** ή το **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας**, το **history file** (\~/.bash_history) να **περιοριστεί σε 0 γραμμές**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μη διατηρούνται στο ιστορικό της μνήμης** και να μην εγγράφονται ξανά στο **αρχείο ιστορικού** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή ξεκινά με ένα επιπλέον κενό δεν θα αποθηκεύεται στο ιστορικό.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Ορίστε το **αρχείο ιστορικού** στο **`/dev/null`** ή καταργήστε το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από την απλή αλλαγή του μεγέθους του ιστορικού.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Οι διεργασίες θα χρησιμοποιούν το **proxy** που δηλώνεται εδώ για να συνδεθούν στο διαδίκτυο μέσω **http ή https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: προεπιλεγμένο proxy για εργαλεία/πρωτόκολλα που το υποστηρίζουν.
- `no_proxy`: λίστα παράκαμψης (`hosts`/`domains`/`CIDRs`) που πρέπει να συνδέονται απευθείας.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Μπορούν να χρησιμοποιηθούν παραλλαγές με πεζούς και κεφαλαίους χαρακτήρες, ανάλογα με το εργαλείο (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις env variables**. Αυτό είναι χρήσιμο για να κάνουν εργαλεία όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι package managers να εμπιστεύονται μια CA που ελέγχεται από τον attacker (για παράδειγμα, ώστε ένα interception proxy να φαίνεται νόμιμο).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Αν ένα privileged wrapper/script εκτελεί εντολές **χωρίς absolute paths**, κερδίζει ο **πρώτος κατάλογος που ελέγχεται από τον attacker** στο `PATH`. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζητήστε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. με το όνομά τους.
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
Για πλήρεις αλυσίδες privilege-escalation που κάνουν abuse στο `PATH`, δείτε το [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι απλώς μια αναφορά σε κατάλογο: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **per-user configuration** από το `$HOME` ή το `$XDG_CONFIG_HOME`. Αν μια privileged workflow διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι ευκολότερο από το binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Ενδιαφέροντες στόχοι περιλαμβάνουν τα `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` και αρχεία ειδικά για εργαλεία, όπως το `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Αυτές οι μεταβλητές επηρεάζουν τον **dynamic linker**:

- `LD_PRELOAD`: επιβάλλει τη φόρτωση επιπλέον shared objects πρώτα.
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή καταλόγους αναζήτησης βιβλιοθηκών.
- `LD_AUDIT`: φορτώνει auditor libraries που παρατηρούν τη φόρτωση βιβλιοθηκών και την επίλυση συμβόλων.

Είναι εξαιρετικά χρήσιμες για **hooking**, **instrumentation** και **privilege escalation**, εάν μια privileged εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, parser bugs σε αυτό το πρώιμο στάδιο του loader εξακολουθούν να έχουν σημαντικό αντίκτυπο, επειδή εκτελούνται **πριν** από το target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά του glibc σε πρώιμο στάδιο (για παράδειγμα, τις ρυθμίσεις του allocator) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από άποψη ασφάλειας, επειδή ο **dynamic loader το αναλύει σε πολύ πρώιμο στάδιο**. Το bug **Looney Tunables** του 2023 ήταν μια καλή υπενθύμιση ότι μία μόνο μεταβλητή περιβάλλοντος που αναλύεται από τον loader μπορεί να μετατραπεί σε **primitive τοπικής κλιμάκωσης προνομίων** εναντίον προγραμμάτων SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** εκκινηθεί **μη διαδραστικά**, ελέγχει το `BASH_ENV` και εκτελεί το συγκεκριμένο αρχείο πριν εκτελέσει το target script. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, ενδέχεται να ελεγχθεί και το `ENV`. Αυτός είναι ένας κλασικός τρόπος για να μετατραπεί ένα shell wrapper σε code execution, αν το environment ελέγχεται από attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το ίδιο το Bash απενεργοποιεί αυτά τα αρχεία εκκίνησης όταν τα **real/effective IDs διαφέρουν**, εκτός αν χρησιμοποιείται το `-p`, επομένως η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper εκκινεί το shell. Να είστε προσεκτικοί με privileged wrappers που καλούν `setuid()`/`setgid()` **πριν** από την εκκίνηση του Bash: μόλις τα IDs ταιριάξουν ξανά, το Bash ενδέχεται να εμπιστευτεί τα `BASH_ENV`, `ENV` και τη σχετική κατάσταση του shell, τα οποία διαφορετικά θα αγνοούνταν.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο εκκίνησης της Python:

- `PYTHONPATH`: προσθέτει διαδρομές αναζήτησης για import.
- `PYTHONHOME`: μετακινεί το δέντρο της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μεταβαίνει σε interactive mode μετά την ολοκλήρωση ενός script.

Είναι χρήσιμες εναντίον maintenance scripts, debuggers, shells και wrappers που καλούν την Python με controllable environment. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Ένα πρόσφατο παράδειγμα από τον πραγματικό κόσμο ήταν το LPE του 2024 στο **needrestart** σε συστήματα Ubuntu/Debian: ο scanner που εκτελούνταν ως root αντέγραψε το `PYTHONPATH` μιας μη προνομιούχας διεργασίας από το `/proc/<PID>/environ` και στη συνέχεια εκτέλεσε Python. Το δημοσιευμένο exploit τοποθέτησε το `importlib/__init__.so` στη διαδρομή που ελεγχόταν από τον attacker, ώστε η Python να εκτελέσει κώδικα του attacker κατά τη δική της αρχικοποίηση, πριν καν παίξει ρόλο το hard-coded script του helper.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Η Perl διαθέτει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή της διαδρομής αναζήτησης.
- `PERL5OPT`: εισάγει switches σαν να υπήρχαν στη γραμμή εντολών κάθε `perl`.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script εκτελέσει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να έχουν μεγάλη σημασία για συνηθισμένα root-run wrappers, CI jobs, installers και custom κανόνες sudoers.
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

Το `NODE_OPTIONS` προσθέτει προκαταβολικά **Node.js CLI flags** σε κάθε διεργασία `node` που κληρονομεί το περιβάλλον. Αυτό το καθιστά χρήσιμο εναντίον wrappers, CI jobs, βοηθητικών διεργασιών του Electron και κανόνων sudo που τελικά εκτελούν Node. Τα πιο ενδιαφέροντα flags από επιθετική άποψη είναι συνήθως:

- `--require <file>`: φορτώνει προκαταβολικά ένα αρχείο CommonJS πριν από το script-στόχο.
- `--import <module>`: φορτώνει προκαταβολικά ένα ES module πριν από το script-στόχο.

Το Node απορρίπτει ορισμένα επικίνδυνα flags στο `NODE_OPTIONS`, αλλά τα `--require` και `--import` επιτρέπονται ρητά και υποβάλλονται σε επεξεργασία **πριν** από τα κανονικά ορίσματα της γραμμής εντολών.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Για remote gadget chains που ορίζουν έμμεσα το `NODE_OPTIONS` (για παράδειγμα, prototype-pollution to RCE), ελέγξτε [αυτήν τη σελίδα](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Το Ruby προσφέρει την ίδια κατηγορία startup abuse:

- `RUBYLIB`: προσθέτει καταλόγους στην αρχή του load path του Ruby.
- `RUBYOPT`: εισάγει command-line options, όπως το `-r`, σε κάθε invocation του `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Οι ευπάθειες του **needrestart** το 2024 έδειξαν ότι αυτό δεν είναι απλώς ένα τέχνασμα εργαστηρίου: ο ίδιος helper με δικαιώματα root που ήταν ευάλωτος σε κατάχρηση του `PYTHONPATH` μπορούσε επίσης να εξαναγκαστεί να εκτελέσει Ruby με ένα ελεγχόμενο από τον attacker `RUBYLIB`, φορτώνοντας το `enc/encdb.so` από έναν κατάλογο του attacker.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Ορισμένα εργαλεία δεν διαβάζουν απλώς μια διαδρομή από το environment· περνούν την τιμή σε ένα **shell**, έναν **editor** ή έναν **input preprocessor**. Αυτό καθιστά τις παρακάτω μεταβλητές ιδιαίτερα ενδιαφέρουσες όταν ένα privileged wrapper εκτελεί τα `git`, `man`, `less` ή παρόμοια εργαλεία προβολής κειμένου:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: επιλέγουν την εντολή pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: επιλέγουν την εντολή editor, συχνά μαζί με arguments.
- `LESSOPEN`, `LESSCLOSE`: ορίζουν pre/post-processors που εκτελούνται όταν το `less` ανοίγει ένα αρχείο.
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
Το Git υποστηρίζει επίσης **έγχυση ρυθμίσεων μόνο μέσω environment** χωρίς πρόσβαση στον δίσκο, μέσω των `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` και `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Από την perspective του post-exploitation, να θυμάστε επίσης ότι τα κληρονομημένα environments συχνά περιέχουν **credentials**, **proxy settings**, **service tokens** ή **cloud keys**. Ελέγξτε το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) για το `/proc/<PID>/environ` και την αναζήτηση του `systemd` `Environment=`.

### PS1

Αλλάξτε την εμφάνιση του prompt σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Αυτό είναι ένα παράδειγμα](<../images/image (897).png>)

Κανονικός χρήστης:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (740).png>)

Μία, δύο και τρεις εργασίες στο background:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (145).png>)

Μία εργασία στο background, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![PERL5OPT & PERL5LIB - PS1: Μία εργασία στο background, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά](<../images/image (715).png>)

## Αναφορές

- [1] [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Τεκμηρίωση CLI του Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Συνηθισμένες environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation στο ld.so του glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
