# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομούνται από τις **θυγατρικές διεργασίες**.

Μπορείτε να δημιουργήσετε μια καθολική μεταβλητή για την τρέχουσα συνεδρία σας ως εξής:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Αυτή η μεταβλητή θα είναι προσβάσιμη από τις τρέχουσες sessions και τις θυγατρικές διεργασίες τους.

Μπορείτε να **αφαιρέσετε** μια μεταβλητή εκτελώντας:
```bash
unset MYGLOBAL
```
## Local variables

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
Τα περιεχόμενα του `/proc/*/environ` είναι **διαχωρισμένα με NUL**, επομένως αυτές οι παραλλαγές είναι συνήθως πιο εύκολες στην ανάγνωση:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Αν αναζητάτε **credentials** ή **ενδιαφέρουσα διαμόρφωση υπηρεσιών** μέσα σε περιβάλλοντα που έχουν κληρονομηθεί, ελέγξτε επίσης το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Κοινές μεταβλητές

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος επεξεργαστής κειμένου του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο αρχείο ιστορικού.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης ολοκληρώνει τη συνεδρία του.
- **HOME** – ο προσωπικός σας κατάλογος.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα καταλόγων στους οποίους γίνεται αναζήτηση για σελίδες εγχειριδίων.
- **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
- **PS1** – το προεπιλεγμένο prompt στο bash.
- **PATH** – αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν binary files τα οποία θέλετε να εκτελείτε, καθορίζοντας απλώς το όνομα του αρχείου και όχι τη σχετική ή απόλυτη διαδρομή.
- **PWD** – ο τρέχων κατάλογος εργασίας.
- **SHELL** – η διαδρομή προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων τύπος terminal (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον username σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι κάθε μεταβλητή εξίσου χρήσιμη. Από offensive perspective, δώστε προτεραιότητα σε μεταβλητές που αλλάζουν **search paths**, **startup files**, τη **dynamic linker behavior** ή το **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας**, το **αρχείο ιστορικού** (\~/.bash_history) να **περικοπεί σε 0 γραμμές**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές να **μη διατηρούνται στο ιστορικό της μνήμης** και να μην εγγράφονται ξανά στο **αρχείο ιστορικού** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή έχει ως πρόθεμα ένα επιπλέον κενό δεν θα αποθηκευτεί στο history.
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

- `all_proxy`: προεπιλεγμένος proxy για εργαλεία/πρωτόκολλα που τον υποστηρίζουν.
- `no_proxy`: λίστα παράκαμψης (hosts/domains/CIDRs) που θα πρέπει να συνδέονται απευθείας.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Μπορούν να χρησιμοποιηθούν τόσο οι πεζές όσο και οι κεφαλαίες παραλλαγές, ανάλογα με το tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις μεταβλητές περιβάλλοντος**. Αυτό είναι χρήσιμο για να κάνουν εργαλεία όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι package managers να εμπιστεύονται ένα CA που ελέγχεται από τον επιτιθέμενο (για παράδειγμα, ώστε ένα interception proxy να φαίνεται νόμιμο).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Αν ένα privileged wrapper/script εκτελεί εντολές **χωρίς absolute paths**, κερδίζει ο **πρώτος directory που ελέγχεται από τον attacker** στο `PATH`. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζητήστε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. με το όνομά τους.
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
Για πλήρεις αλυσίδες privilege-escalation που κάνουν abuse του `PATH`, ελέγξτε το [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

Το `HOME` δεν είναι απλώς μια αναφορά καταλόγου: πολλά εργαλεία φορτώνουν αυτόματα **dotfiles**, **plugins** και **διαμόρφωση ανά χρήστη** από τα `$HOME` ή `$XDG_CONFIG_HOME`. Αν μια προνομιούχα ροή εργασίας διατηρεί αυτές τις τιμές, το **config injection** μπορεί να είναι ευκολότερο από το binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Ενδιαφέροντες στόχοι περιλαμβάνουν τα `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` και αρχεία ειδικά για εργαλεία, όπως το `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Αυτές οι μεταβλητές επηρεάζουν τον **dynamic linker**:

- `LD_PRELOAD`: επιβάλλει τη φόρτωση επιπλέον shared objects πρώτα.
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή directories αναζήτησης libraries.
- `LD_AUDIT`: φορτώνει auditor libraries που παρατηρούν τη φόρτωση libraries και την επίλυση symbols.

Είναι εξαιρετικά χρήσιμες για **hooking**, **instrumentation** και **privilege escalation**, εάν μια privileged εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, parser bugs σε αυτό το early loader stage εξακολουθούν να έχουν σημαντικό αντίκτυπο, επειδή εκτελούνται **πριν** από το target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά του glibc στα αρχικά στάδια (για παράδειγμα, τα allocator tunables) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από πλευράς ασφάλειας, επειδή ο **dynamic loader το αναλύει πολύ νωρίς**. Το bug **Looney Tunables** του 2023 ήταν μια καλή υπενθύμιση ότι μία μόνο μεταβλητή περιβάλλοντος που αναλύεται από τον loader μπορεί να μετατραπεί σε **primitive τοπικής κλιμάκωσης προνομίων** εναντίον προγραμμάτων SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** εκκινηθεί **μη διαδραστικά**, ελέγχει το `BASH_ENV` και κάνει source σε αυτό το αρχείο πριν εκτελέσει το script-στόχο. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, μπορεί επίσης να εξεταστεί το `ENV`. Αυτός είναι ένας κλασικός τρόπος να μετατραπεί ένα shell wrapper σε εκτέλεση κώδικα, αν το environment ελέγχεται από attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το Bash αγνοεί αυτά τα αρχεία εκκίνησης όταν τα **πραγματικά/ενεργά IDs διαφέρουν**· το `-p` διατηρεί το ενεργό ID, αλλά δεν ενεργοποιεί αυτά τα αρχεία εκκίνησης, επομένως η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper εκκινεί το shell. Να είστε προσεκτικοί με privileged wrappers που καλούν `setuid()`/`setgid()` **πριν** από την εκκίνηση του Bash: μόλις τα IDs ταιριάξουν ξανά, το Bash ενδέχεται να εμπιστευτεί τα `BASH_ENV`, `ENV` και τη σχετική κατάσταση του shell, τα οποία διαφορετικά θα αγνοούσε.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο εκκίνησης της Python:

- `PYTHONPATH`: προσθέτει στην αρχή paths αναζήτησης για imports.
- `PYTHONHOME`: μετακινεί το δέντρο της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μεταβαίνει σε interactive mode μετά την ολοκλήρωση ενός script.

Είναι χρήσιμες εναντίον maintenance scripts, debuggers, shells και wrappers που καλούν την Python με ελεγχόμενο environment. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Ένα πρόσφατο παράδειγμα από τον πραγματικό κόσμο ήταν το LPE του **needrestart** το 2024 σε συστήματα Ubuntu/Debian: ο scanner με δικαιώματα root αντέγραψε το `PYTHONPATH` μιας unprivileged διεργασίας από το `/proc/<PID>/environ` και στη συνέχεια εκτέλεσε Python. Το δημοσιευμένο exploit τοποθέτησε το `importlib/__init__.so` στη διαδρομή που ελεγχόταν από τον attacker, ώστε η Python να εκτελέσει κώδικα του attacker κατά τη δική της αρχικοποίηση, πριν καν έχει σημασία το hard-coded script του helper.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Η Perl διαθέτει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή της διαδρομής.
- `PERL5OPT`: εισάγει switches σαν να υπήρχαν σε κάθε command line της `perl`.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script κάνει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να έχουν μεγάλη σημασία για κανονικά wrappers που εκτελούνται ως root, CI jobs, installers και custom sudoers rules.
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

Το `NODE_OPTIONS` προσθέτει **Node.js CLI flags** σε κάθε διεργασία `node` που κληρονομεί το environment. Αυτό το καθιστά χρήσιμο εναντίον wrappers, CI jobs, Electron helpers και sudo rules που τελικά εκτελούν το Node. Τα πιο ενδιαφέροντα flags από επιθετική σκοπιά είναι συνήθως:

- `--require <file>`: προφορτώνει ένα αρχείο CommonJS πριν από το target script.
- `--import <module>`: προφορτώνει ένα ES module πριν από το target script.

Το Node απορρίπτει ορισμένα επικίνδυνα flags στο `NODE_OPTIONS`, αλλά τα `--require` και `--import` επιτρέπονται ρητά και υποβάλλονται σε επεξεργασία **πριν** από τα κανονικά command-line arguments.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Για απομακρυσμένες αλυσίδες gadget που ορίζουν έμμεσα το `NODE_OPTIONS` (για παράδειγμα, από prototype-pollution σε RCE), ελέγξτε [αυτήν την άλλη σελίδα](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Το Ruby προσφέρει την ίδια κατηγορία abuse κατά την εκκίνηση:

- `RUBYLIB`: προσθέτει καταλόγους στην αρχή του load path του Ruby.
- `RUBYOPT`: εισάγει options γραμμής εντολών, όπως το `-r`, σε κάθε invocation του `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Οι ευπάθειες του **needrestart** το 2024 έδειξαν ότι αυτό δεν είναι απλώς ένα τέχνασμα εργαστηρίου: ο ίδιος root-owned helper που ήταν ευάλωτος σε κατάχρηση του `PYTHONPATH` μπορούσε επίσης να εξαναγκαστεί να εκτελέσει Ruby με ένα `RUBYLIB` ελεγχόμενο από τον attacker, φορτώνοντας το `enc/encdb.so` από έναν κατάλογο του attacker.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Ορισμένα εργαλεία δεν διαβάζουν απλώς ένα path από το environment· μεταβιβάζουν την τιμή σε ένα **shell**, έναν **editor** ή έναν **input preprocessor**. Αυτό καθιστά τις παρακάτω μεταβλητές ιδιαίτερα ενδιαφέρουσες όταν ένα privileged wrapper εκτελεί `git`, `man`, `less` ή παρόμοια text viewers:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: επιλέγουν την εντολή του pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: επιλέγουν την εντολή του editor, συχνά μαζί με arguments.
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
Το Git υποστηρίζει επίσης **εισαγωγή ρυθμίσεων μόνο μέσω environment** χωρίς εγγραφή στον δίσκο, μέσω των `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` και `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Από την perspective του post-exploitation, να θυμάστε επίσης ότι τα inherited environments συχνά περιέχουν **credentials**, **proxy settings**, **service tokens** ή **cloud keys**. Ελέγξτε το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) για hunting στα `/proc/<PID>/environ` και στο `systemd` `Environment=`.

### PS1

Αλλάξτε την εμφάνιση του prompt σας.

[**Αυτό είναι ένα παράδειγμα**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Αυτό είναι ένα παράδειγμα](<../images/image (897).png>)

Regular user:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (740).png>)

Μία, δύο και τρεις εργασίες στο background:

![PERL5OPT & PERL5LIB - PS1: Μία, δύο και τρεις εργασίες στο background](<../images/image (145).png>)

Μία εργασία στο background, μία σταματημένη και η τελευταία εντολή δεν ολοκληρώθηκε σωστά:

![PERL5OPT & PERL5LIB - PS1: Μία εργασία στο background, μία σταματημένη και η τελευταία εντολή δεν ολοκληρώθηκε σωστά](<../images/image (715).png>)

## References

- [1] [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Τεκμηρίωση Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Συνηθισμένες environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation στο ld.so της glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
