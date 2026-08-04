# Dumping μνήμης σε macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artifacts μνήμης

### Αρχεία Swap

Τα αρχεία Swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως **caches όταν η physical memory είναι πλήρης**. Όταν δεν υπάρχει πλέον διαθέσιμος χώρος στη physical memory, τα δεδομένα της μεταφέρονται σε ένα αρχείο swap και στη συνέχεια επαναφέρονται στη physical memory όταν χρειάζεται. Ενδέχεται να υπάρχουν πολλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1 κ.ο.κ.

### Εικόνα Hibernate

Το αρχείο που βρίσκεται στη διαδρομή `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη **λειτουργία hibernation**. **Τα δεδομένα από τη μνήμη αποθηκεύονται σε αυτό το αρχείο όταν το OS X εισέρχεται σε hibernation**. Όταν ο υπολογιστής επανενεργοποιείται, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από το σημείο όπου σταμάτησε.

Αξίζει να σημειωθεί ότι στα σύγχρονα συστήματα MacOS, αυτό το αρχείο συνήθως είναι encrypted για λόγους ασφαλείας, γεγονός που καθιστά την ανάκτηση δύσκολη.

- Για να ελέγξετε αν είναι ενεργοποιημένη η encryption για το sleepimage, μπορείτε να εκτελέσετε την εντολή `sysctl vm.swapusage`. Αυτό θα εμφανίσει αν το αρχείο είναι encrypted.

### Logs πίεσης μνήμης

Ένα ακόμη σημαντικό αρχείο που σχετίζεται με τη μνήμη στα συστήματα MacOS είναι το **log πίεσης μνήμης**. Αυτά τα logs βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες σχετικά με τη χρήση μνήμης του συστήματος και τα συμβάντα πίεσης. Μπορούν να είναι ιδιαίτερα χρήσιμα για τη διάγνωση προβλημάτων που σχετίζονται με τη μνήμη ή για την κατανόηση του τρόπου με τον οποίο το σύστημα διαχειρίζεται τη μνήμη με την πάροδο του χρόνου.

## Dumping μνήμης με osxpmem

Για να κάνετε dump τη μνήμη σε ένα MacOS μηχάνημα, μπορείτε να χρησιμοποιήσετε το [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Αυτό αποτελεί πλέον κυρίως ένα **legacy workflow**. Το `osxpmem` εξαρτάται από τη φόρτωση ενός kernel extension, το project [Rekall](https://github.com/google/rekall) είναι archived, η τελευταία release είναι από το **2017** και το δημοσιευμένο binary στοχεύει σε **Intel Macs**. Σε σύγχρονες εκδόσεις του macOS, ιδιαίτερα σε **Apple Silicon**, η απόκτηση πλήρους RAM μέσω kext συνήθως μπλοκάρεται από τους σύγχρονους περιορισμούς των kernel extensions, το SIP και τις απαιτήσεις platform signing. Στην πράξη, στα σύγχρονα συστήματα είναι πιθανότερο να καταλήξετε σε ένα **process-scoped dump** αντί για μια εικόνα **whole-RAM**.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Αν δείτε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε ως εξής:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** μπορεί να διορθωθούν **επιτρέποντας τη φόρτωση του kext** στο "Security & Privacy --> General", απλώς **επιτρέψτε το**.

Μπορείτε επίσης να χρησιμοποιήσετε αυτό το **oneliner** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να κάνετε dump της μνήμης:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping με LLDB

Για **πρόσφατες εκδόσεις του macOS**, η πιο πρακτική προσέγγιση είναι συνήθως να κάνετε dump τη μνήμη μιας **συγκεκριμένης διεργασίας**, αντί να προσπαθήσετε να δημιουργήσετε image ολόκληρης της φυσικής μνήμης.

Το LLDB μπορεί να αποθηκεύσει ένα αρχείο πυρήνα Mach-O από έναν live στόχο:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Από προεπιλογή, αυτό συνήθως δημιουργεί ένα **skinny core**. Για να αναγκάσετε το LLDB να συμπεριλάβει όλη τη χαρτογραφημένη μνήμη της διεργασίας:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Χρήσιμες επακόλουθες εντολές πριν από το dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Αυτό συνήθως αρκεί όταν ο στόχος είναι η ανάκτηση:

- Decrypted configuration blobs
- In-memory tokens, cookies ή credentials
- Plaintext secrets που προστατεύονται μόνο κατά την αποθήκευση
- Decrypted Mach-O pages μετά από unpacking / JIT / runtime patching

Εάν ο στόχος προστατεύεται από το **hardened runtime** ή το `taskgated` αρνείται το attach, συνήθως χρειάζεστε μία από τις εξής προϋποθέσεις:

- Ο στόχος διαθέτει **`get-task-allow`**
- Ο debugger σας είναι υπογεγραμμένος με το κατάλληλο **debugger entitlement**
- Είστε **root** και ο στόχος είναι μια non-hardened third-party process

Για περισσότερες πληροφορίες σχετικά με την απόκτηση ενός task port και όσα μπορείτε να κάνετε με αυτό:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Γρήγοροι έλεγχοι πριν από το attach

Πριν αφιερώσετε χρόνο σε LLDB/Frida, επαληθεύστε γρήγορα αν ο στόχος μπορεί ρεαλιστικά να γίνει **dump**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Σε επιχειρησιακό επίπεδο, αυτό συνήθως σημαίνει:

- Μια εφαρμογή τρίτου μέρους που έχει διανεμηθεί με **`get-task-allow`** συχνά μπορεί να γίνει απευθείας dump με το LLDB, και το dump που προκύπτει ενδέχεται να εκθέσει δεδομένα που προστατεύονται από το TCC και στα οποία η εφαρμογή είχε ήδη αποκτήσει πρόσβαση.
- Ένας **hardened** στόχος χωρίς **`get-task-allow`** συνήθως θα απορρίψει τα attaches, ακόμη και ως `root`, εκτός αν ελέγχετε τα σχετικά debugger entitlements / τη διαδρομή policy.
- Οι unhardened διεργασίες τρίτων παραμένουν το ευκολότερο σημείο για χρήση των `lldb`, `vmmap`, Frida ή custom readers που βασίζονται στα `task_for_pid`/`vm_read`.

### Αναζητήστε dumpable nested helpers

Πρόσφατη έρευνα γύρω από notarized εφαρμογές macOS συνεχίζει να εντοπίζει το **`get-task-allow`** σε nested helpers αντί στο κύριο GUI binary. Όταν μια εφαρμογή ανώτερου επιπέδου φαίνεται hardened, απαριθμήστε τα **XPC services**, τα **login items**, τα **helper tools** και τα bundled CLIs πριν εγκαταλείψετε την προσπάθεια:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ένα nested executable με `get-task-allow` είναι συχνά το ευκολότερο σημείο για attach με `lldb`, dump ενός core ή ανάκτηση μνήμης με έναν custom client του `task_for_pid`, ακόμη και όταν η κύρια εφαρμογή έχει καλύτερο hardening.

## Selective dumps με Frida ή userland readers

Όταν ένα πλήρες core είναι υπερβολικά θορυβώδες, το dump μόνο των **interesting readable ranges** είναι συχνά ταχύτερο. Το Frida είναι ιδιαίτερα χρήσιμο, επειδή λειτουργεί καλά για **targeted extraction** μόλις μπορέσεις να κάνεις attach στη διεργασία.

Προσέγγιση:

1. Enumerate readable/writable ranges
2. Filter ανά module, heap, stack ή anonymous memory
3. Dump μόνο των regions που περιέχουν candidate strings, keys, protobufs, plist/XML blobs ή decrypted code/data

Minimal Frida example για dump όλων των readable anonymous ranges:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Αυτό είναι χρήσιμο όταν θέλετε να αποφύγετε τεράστια core files και να συλλέξετε μόνο:

- Chunks του App heap που περιέχουν secrets
- Anonymous regions που δημιουργούνται από custom packers ή loaders
- Σελίδες κώδικα JIT / unpacked μετά την αλλαγή των protections

Όταν ο στόχος συνεχίζει να **κάνει allocating / freeing** ενώ πραγματοποιείτε το dump, προτιμήστε το primitive **`readVolatile()`** του Frida αντί για το **`readByteArray()`** για unstable ranges. Είναι πιο αργό, αλλά αποτρέπει τον τερματισμό του στόχου αν μια σελίδα γίνει unreadable στη μέση της ανάγνωσης. Για μεγαλύτερες acquisitions, μπορεί επίσης να είναι πιο καθαρό να κάνετε stream τα chunks πίσω με **`send(..., data)`** και να τα κάνετε compress στην πλευρά του controller, αντί να δημιουργείτε χιλιάδες μικρά files μέσα στον στόχο.

Υπάρχουν επίσης παλαιότερα userland tools, όπως το [`readmem`](https://github.com/gdbinit/readmem), αλλά είναι κυρίως χρήσιμα ως **source references** για dumping τύπου `task_for_pid`/`vm_read` και δεν συντηρούνται επαρκώς για σύγχρονα workflows σε Apple Silicon.

## Snapshots Heap / VM με `.memgraph`

Αν σας ενδιαφέρουν κυρίως τα **heap objects**, το **allocation provenance** ή ένα snapshot που μπορεί να μεταφερθεί σε άλλο machine, ένα `.memgraph` είναι συχνά πιο πρακτικό από ένα τεράστιο Mach-O core. Το tooling **`leaks`** μπορεί να δημιουργήσει ένα από μια live process:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Στη συνέχεια, κάντε triage σε αυτό offline με τα τυπικά εργαλεία της Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
Το `stringdups` είναι ο κύριος λόγος για να διατηρείτε ένα capture με `-fullContent`, επειδή οι ετικέτες που περιγράφουν τα περιεχόμενα της μνήμης παραλείπονται από ένα minimal `.memgraph`.

Αυτό είναι ιδιαίτερα χρήσιμο όταν:

- Θέλετε ένα **μικρότερο, shareable snapshot** αντί για ένα πλήρες core
- Το `MallocStackLogging` ήταν ενεργοποιημένο και θέλετε **allocation backtraces**
- Γνωρίζετε ήδη μια **ενδιαφέρουσα heap address** και θέλετε να κάνετε pivot με το `malloc_history`
- Χρειάζεστε ένα γρήγορο **VM/heap breakdown** πριν αποφασίσετε αν αξίζει ο θόρυβος ενός full dump

### Differential memgraph triage

Αν ελέγχετε τον τρόπο με τον οποίο ξεκινά το target, ενεργοποιήστε το **historical allocation logging** πριν από το launch, ώστε τα μεταγενέστερα snapshots να διατηρούν χρήσιμα alloc/free backtraces:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Στη συνέχεια, καταγράψτε snapshots γύρω από την ενδιαφέρουσα ενέργεια και συγκρίνετέ τα offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Αυτός είναι ένας πρακτικός τρόπος για την απομόνωση **post-authentication objects**, **μεγάλων `CFData` buffers** ή **anonymous VM regions** που εμφανίζονται μόνο μετά από ένα στάδιο αποκρυπτογράφησης, unpacking ή ανάκτησης μυστικών.

## Targets με έντονη χρήση Swift: `swift-inspect`

Για εφαρμογές που διατηρούν δεδομένα υψηλής αξίας μέσα σε **Swift runtime objects**, το `swift-inspect` μπορεί να αποτελέσει ένα καλό συμπλήρωμα για τα LLDB ή Frida. Αντί να κάνετε πρώτα dump όλων των δεδομένων, μπορείτε να υποβάλετε ερωτήματα σε συγκεκριμένες Swift runtime structures από μια live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Αυτό είναι χρήσιμο για τον εντοπισμό:

- Μεγάλων Swift arrays που αποθηκεύουν ενδιαφέροντα δεδομένα
- Allocations metadata που αποκαλύπτουν τύπους φορτωμένους κατά το runtime
- Κατάστασης Swift concurrency (`Task`, actor, σχέσεις thread) πριν από τη διενέργεια ενός πιο στοχευμένου dump

Για περισσότερο object-level runtime triage, αφού μπορείτε ήδη να επιθεωρήσετε τη διεργασία, δείτε [τη dedicated σελίδα για objects στη μνήμη](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Γρήγορες σημειώσεις triage

- Το `sysctl vm.swapusage` παραμένει ένας γρήγορος τρόπος ελέγχου της **χρήσης swap** και του αν το swap είναι **κρυπτογραφημένο**.
- Το `sleepimage` παραμένει κυρίως σχετικό με σενάρια **hibernate/safe sleep**, αλλά τα σύγχρονα συστήματα συνήθως το προστατεύουν, επομένως θα πρέπει να αντιμετωπίζεται ως **πηγή artifact προς έλεγχο** και όχι ως αξιόπιστη διαδρομή acquisition.
- Σε πρόσφατες εκδόσεις του macOS, το **dumping σε επίπεδο διεργασίας** είναι γενικά πιο ρεαλιστικό από το **full physical memory imaging**, εκτός αν ελέγχετε την boot policy, την κατάσταση του SIP και το kext loading.

## References

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
