# Dumping μνήμης στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artifacts μνήμης

### Αρχεία Swap

Τα αρχεία swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως **caches όταν η φυσική μνήμη είναι πλήρης**. Όταν δεν υπάρχει πλέον διαθέσιμος χώρος στη φυσική μνήμη, τα δεδομένα της μεταφέρονται σε ένα αρχείο swap και στη συνέχεια επαναφέρονται στη φυσική μνήμη όταν χρειάζεται. Ενδέχεται να υπάρχουν πολλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1 κ.ο.κ.

### Εικόνα Hibernate

Το αρχείο που βρίσκεται στο `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη **λειτουργία hibernation**. **Τα δεδομένα από τη μνήμη αποθηκεύονται σε αυτό το αρχείο όταν το OS X εισέρχεται σε hibernation**. Κατά την επαναφορά της λειτουργίας του υπολογιστή, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από το σημείο όπου σταμάτησε.

Αξίζει να σημειωθεί ότι στα σύγχρονα συστήματα MacOS αυτό το αρχείο είναι συνήθως κρυπτογραφημένο για λόγους ασφαλείας, γεγονός που καθιστά την ανάκτηση δύσκολη.

- Για να ελέγξετε αν είναι ενεργοποιημένη η κρυπτογράφηση για το sleepimage, μπορείτε να εκτελέσετε την εντολή `sysctl vm.swapusage`. Αυτό θα δείξει αν το αρχείο είναι κρυπτογραφημένο.

### Logs πίεσης μνήμης

Ένα ακόμη σημαντικό αρχείο που σχετίζεται με τη μνήμη στα συστήματα MacOS είναι το **log πίεσης μνήμης**. Αυτά τα logs βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες σχετικά με τη χρήση μνήμης του συστήματος και τα συμβάντα πίεσης. Μπορούν να φανούν ιδιαίτερα χρήσιμα για τη διάγνωση προβλημάτων που σχετίζονται με τη μνήμη ή για την κατανόηση του τρόπου με τον οποίο το σύστημα διαχειρίζεται τη μνήμη με την πάροδο του χρόνου.

## Dumping μνήμης με το osxpmem

Για να κάνετε dump της μνήμης σε ένα μηχάνημα MacOS, μπορείτε να χρησιμοποιήσετε το [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Αυτό αποτελεί πλέον κυρίως **legacy workflow**. Το `osxpmem` εξαρτάται από τη φόρτωση ενός kernel extension, το project [Rekall](https://github.com/google/rekall) έχει αρχειοθετηθεί, η τελευταία έκδοση κυκλοφόρησε το **2017** και το δημοσιευμένο binary προορίζεται για **Intel Macs**. Σε σύγχρονες εκδόσεις του macOS, ιδιαίτερα σε **Apple Silicon**, η απόκτηση πλήρους RAM μέσω kext συνήθως αποκλείεται από τους σύγχρονους περιορισμούς των kernel extensions, το SIP και τις απαιτήσεις υπογραφής της πλατφόρμας. Στην πράξη, στα σύγχρονα συστήματα είναι πιθανότερο να καταλήξετε σε **dump περιορισμένο σε process** αντί για image ολόκληρης της RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Αν συναντήσετε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε ως εξής:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** μπορεί να διορθωθούν **επιτρέποντας τη φόρτωση του kext** στο "Ασφάλεια και Απόρρητο --> Γενικά"· απλώς **επιτρέψτε το**.

Μπορείτε επίσης να χρησιμοποιήσετε αυτό το **oneliner** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να κάνετε dump της μνήμης:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping μνήμης ζωντανού process με LLDB

Για **πρόσφατες εκδόσεις του macOS**, η πιο πρακτική προσέγγιση είναι συνήθως να κάνετε dump τη μνήμη ενός **συγκεκριμένου process**, αντί να προσπαθήσετε να δημιουργήσετε image ολόκληρης της physical memory.

Το LLDB μπορεί να αποθηκεύσει ένα αρχείο Mach-O core από ένα live target:
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

- Αποκρυπτογραφημένων configuration blobs
- Tokens, cookies ή credentials που βρίσκονται στη μνήμη
- Secrets σε plaintext που προστατεύονται μόνο κατά την αποθήκευση
- Αποκρυπτογραφημένων Mach-O pages μετά από unpacking / JIT / runtime patching

Αν ο στόχος προστατεύεται από το **hardened runtime** ή αν το `taskgated` αρνείται το attach, συνήθως χρειάζεστε μία από τις εξής προϋποθέσεις:

- Ο στόχος διαθέτει **`get-task-allow`**
- Ο debugger σας είναι υπογεγραμμένος με το κατάλληλο **debugger entitlement**
- Είστε **root** και ο στόχος είναι μια non-hardened third-party διεργασία

Για περισσότερο background σχετικά με την απόκτηση ενός task port και με το τι μπορεί να γίνει μέσω αυτού:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Γρήγοροι έλεγχοι πριν από το attach

Πριν αφιερώσετε χρόνο σε LLDB/Frida, επαληθεύστε γρήγορα αν ο στόχος είναι ρεαλιστικά **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Στην πράξη, αυτό συνήθως σημαίνει:

- Μια εφαρμογή τρίτου μέρους που διατίθεται με **`get-task-allow`** συχνά μπορεί να γίνει απευθείας dump με LLDB, και το dump που προκύπτει ενδέχεται να αποκαλύψει δεδομένα που προστατεύονται από το TCC και στα οποία η εφαρμογή είχε ήδη αποκτήσει πρόσβαση.<sup>[[1]](#references)</sup>
- Ένας **hardened** στόχος χωρίς `get-task-allow` συνήθως απορρίπτει τα attaches, ακόμη και ως `root`, εκτός αν ελέγχετε τα σχετικά debugger entitlements / τη διαδρομή policy.
- Οι unhard­ened διεργασίες τρίτων παραμένουν το ευκολότερο σημείο για χρήση των `lldb`, `vmmap`, Frida ή custom `task_for_pid`/`vm_read` readers.

### Αναζητήστε dumpable nested helpers

Πρόσφατη έρευνα σε notarized εφαρμογές macOS εξακολουθεί να εντοπίζει το **`get-task-allow`** σε nested helpers αντί στο κύριο GUI binary. Όταν μια εφαρμογή ανώτερου επιπέδου φαίνεται hardened, απαριθμήστε τα **XPC services**, τα **login items**, τα **helper tools** και τα bundled CLIs πριν εγκαταλείψετε την προσπάθεια:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ένα ένθετο εκτελέσιμο με `get-task-allow` είναι συχνά το ευκολότερο σημείο για σύνδεση με `lldb`, δημιουργία core dump ή ανάκτηση μνήμης με έναν προσαρμοσμένο client `task_for_pid`, ακόμη και όταν η κύρια εφαρμογή είναι καλύτερα hardened.

## Επιλεκτικά dumps με Frida ή userland readers

Όταν ένα πλήρες core dump περιέχει υπερβολικά πολλά δεδομένα, η απόρριψη μόνο των **ενδιαφερουσών αναγνώσιμων περιοχών** είναι συχνά ταχύτερη. Το Frida είναι ιδιαίτερα χρήσιμο επειδή λειτουργεί καλά για **targeted extraction** όταν μπορείτε να συνδεθείτε στη διεργασία.

Προτεινόμενη προσέγγιση:

1. Απαρίθμηση των αναγνώσιμων/εγγράψιμων περιοχών
2. Φιλτράρισμα ανά module, heap, stack ή anonymous memory
3. Dump μόνο των περιοχών που περιέχουν υποψήφιες συμβολοσειρές, κλειδιά, protobufs, blobs plist/XML ή decrypted code/data

Ελάχιστο παράδειγμα Frida για dump όλων των αναγνώσιμων anonymous ranges:
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

- App heap chunks που περιέχουν secrets
- Anonymous regions που δημιουργούνται από custom packers ή loaders
- JIT / unpacked code pages μετά την αλλαγή των protections

Όταν ο στόχος συνεχίζει να **κάνει allocate / free** ενώ πραγματοποιείτε το dump, προτιμήστε το primitive **`readVolatile()`** του Frida αντί για το **`readByteArray()`** για unstable ranges. Είναι πιο αργό, αλλά αποτρέπει τον τερματισμό του target αν μια σελίδα γίνει unreadable στη μέση της ανάγνωσης. Για μεγαλύτερες acquisitions, μπορεί επίσης να είναι πιο καθαρό να κάνετε stream τα chunks πίσω με `send(..., data)` και να τα κάνετε compress στην πλευρά του controller, αντί να δημιουργείτε χιλιάδες μικρά files μέσα στο target.

Υπάρχουν επίσης παλαιότερα userland tools, όπως το [`readmem`](https://github.com/gdbinit/readmem), αλλά είναι κυρίως χρήσιμα ως **source references** για dumping τύπου `task_for_pid`/`vm_read` και δεν συντηρούνται επαρκώς για σύγχρονα workflows σε Apple Silicon.

## Heap / VM snapshots με `.memgraph`

Αν σας ενδιαφέρουν κυρίως τα **heap objects**, το **allocation provenance** ή ένα snapshot που μπορεί να μεταφερθεί σε άλλο machine, ένα `.memgraph` είναι συχνά πιο πρακτικό από ένα τεράστιο Mach-O core. Το `leaks` tooling μπορεί να δημιουργήσει ένα από ένα live process:<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Στη συνέχεια, κάντε triage offline με τα τυπικά εργαλεία της Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
Το `stringdups` είναι ο κύριος λόγος για να διατηρείτε ένα capture με `-fullContent`, επειδή οι ετικέτες που περιγράφουν τα περιεχόμενα της μνήμης παραλείπονται από ένα minimal `.memgraph`.

Αυτό είναι ιδιαίτερα χρήσιμο όταν:

- Θέλετε ένα **μικρότερο, εύκολα διαμοιράσιμο snapshot** αντί για ένα full core
- Το `MallocStackLogging` ήταν ενεργοποιημένο και θέλετε **allocation backtraces**
- Γνωρίζετε ήδη μια **ενδιαφέρουσα heap address** και θέλετε να κάνετε pivot με το `malloc_history`
- Χρειάζεστε μια γρήγορη **ανάλυση VM/heap** προτού αποφασίσετε αν αξίζει ο θόρυβος ενός full dump

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
Αυτός είναι ένας πρακτικός τρόπος για να απομονώσετε **αντικείμενα μετά το authentication**, **μεγάλα buffers `CFData`** ή **ανώνυμες περιοχές VM** που εμφανίζονται μόνο μετά από ένα στάδιο αποκρυπτογράφησης, unpacking ή ανάκτησης secret.

## Στόχοι με έντονη χρήση Swift: `swift-inspect`

Για εφαρμογές που διατηρούν δεδομένα υψηλής αξίας μέσα σε **αντικείμενα του Swift runtime**, το `swift-inspect` μπορεί να αποτελέσει ένα καλό συμπλήρωμα των LLDB ή Frida. Αντί να κάνετε πρώτα dump των πάντων, μπορείτε να αναζητήσετε συγκεκριμένες δομές του Swift runtime από μια live διεργασία:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Αυτό είναι χρήσιμο για τον εντοπισμό:

- Μεγάλων Swift arrays που αποθηκεύουν ενδιαφέροντα δεδομένα
- Allocations μεταδεδομένων που αποκαλύπτουν types που φορτώθηκαν κατά το runtime
- Κατάστασης Swift concurrency (`Task`, actor, σχέσεις μεταξύ threads) πριν από ένα πιο στοχευμένο dump

Για πιο λεπτομερές object-level runtime triage, αφού μπορείτε ήδη να επιθεωρήσετε το process, δείτε [την ειδική σελίδα για objects στη μνήμη](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Σύντομες σημειώσεις triage

- Το `sysctl vm.swapusage` παραμένει ένας γρήγορος τρόπος ελέγχου της **χρήσης swap** και του αν το swap είναι **κρυπτογραφημένο**.
- Το `sleepimage` παραμένει κυρίως σχετικό με σενάρια **hibernate/safe sleep**, αλλά τα σύγχρονα συστήματα συνήθως το προστατεύουν, επομένως θα πρέπει να αντιμετωπίζεται ως **πηγή artifact προς έλεγχο** και όχι ως αξιόπιστη διαδρομή acquisition.
- Σε πρόσφατες εκδόσεις του macOS, το **process-level dumping** είναι γενικά πιο ρεαλιστικό από το **full physical memory imaging**, εκτός αν ελέγχετε το boot policy, την κατάσταση του SIP και τη φόρτωση των kext.

## Αναφορές

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
