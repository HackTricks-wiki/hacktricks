# Dumping μνήμης macOS

{{#include ../../../banners/hacktricks-training.md}}

## Artifacts μνήμης

### Αρχεία Swap

Τα αρχεία Swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως **caches όταν η physical memory είναι πλήρης**. Όταν δεν υπάρχει πλέον διαθέσιμος χώρος στη physical memory, τα δεδομένα της μεταφέρονται σε ένα αρχείο swap και στη συνέχεια επαναφέρονται στη physical memory όταν χρειάζεται. Ενδέχεται να υπάρχουν πολλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1 κ.ο.κ.

### Hibernate Image

Το αρχείο που βρίσκεται στη διεύθυνση `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη **λειτουργία hibernation**. **Τα δεδομένα από τη memory αποθηκεύονται σε αυτό το αρχείο όταν το OS X εκτελεί hibernation**. Κατά την αφύπνιση του υπολογιστή, το σύστημα ανακτά τα δεδομένα της memory από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από το σημείο όπου σταμάτησε.

Αξίζει να σημειωθεί ότι στα σύγχρονα συστήματα MacOS αυτό το αρχείο είναι συνήθως encrypted για λόγους ασφαλείας, γεγονός που δυσκολεύει την ανάκτηση.

- Για να ελέγξετε αν το encryption είναι ενεργοποιημένο για το sleepimage, μπορείτε να εκτελέσετε την εντολή `sysctl vm.swapusage`. Αυτό θα εμφανίσει αν το αρχείο είναι encrypted.

### Logs πίεσης μνήμης

Ένα ακόμη σημαντικό αρχείο που σχετίζεται με τη memory στα συστήματα MacOS είναι το **memory pressure log**. Αυτά τα logs βρίσκονται στη διεύθυνση `/var/log` και περιέχουν λεπτομερείς πληροφορίες σχετικά με τη χρήση της memory του συστήματος και τα συμβάντα πίεσης. Μπορούν να φανούν ιδιαίτερα χρήσιμα για τη διάγνωση προβλημάτων που σχετίζονται με τη memory ή για την κατανόηση του τρόπου με τον οποίο το σύστημα διαχειρίζεται τη memory με την πάροδο του χρόνου.

## Dumping memory με osxpmem

Για να κάνετε dump τη memory σε ένα MacOS machine, μπορείτε να χρησιμοποιήσετε το [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Αυτό είναι πλέον κυρίως ένα **legacy workflow**. Το `osxpmem` εξαρτάται από τη φόρτωση ενός kernel extension, το project [Rekall](https://github.com/google/rekall) έχει αρχειοθετηθεί, η τελευταία release είναι από το **2017** και το δημοσιευμένο binary στοχεύει σε **Intel Macs**. Στις τρέχουσες εκδόσεις macOS, ιδιαίτερα στο **Apple Silicon**, η απόκτηση πλήρους RAM με βάση kext συνήθως αποκλείεται από τους σύγχρονους περιορισμούς των kernel extensions, το SIP και τις απαιτήσεις platform-signing. Στην πράξη, στα σύγχρονα συστήματα συνήθως θα καταλήξετε να κάνετε **process-scoped dump** αντί για image ολόκληρης της RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Αν συναντήσετε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε εκτελώντας:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** ενδέχεται να διορθωθούν **επιτρέποντας τη φόρτωση του kext** στο "Security & Privacy --> General"· απλώς **επιτρέψτε το**.

Μπορείτε επίσης να χρησιμοποιήσετε αυτό το **oneliner** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να κάνετε dump τη μνήμη:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Για **recent macOS versions**, η πιο πρακτική προσέγγιση είναι συνήθως να κάνετε dump τη μνήμη ενός **specific process**, αντί να προσπαθήσετε να δημιουργήσετε image όλης της physical memory.

Το LLDB μπορεί να αποθηκεύσει ένα Mach-O core file από ένα live target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Από προεπιλογή, αυτό συνήθως δημιουργεί ένα **skinny core**. Για να εξαναγκάσετε το LLDB να συμπεριλάβει όλη τη mapped μνήμη της διεργασίας:
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
- Είστε **root** και ο στόχος είναι μια non-hardened third-party διεργασία

Για περισσότερες πληροφορίες σχετικά με την απόκτηση ενός task port και όσα μπορούν να γίνουν με αυτό:

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
Σε επιχειρησιακό επίπεδο, αυτό συνήθως σημαίνει:

- Μια εφαρμογή τρίτου μέρους που διανέμεται με **`get-task-allow`** συχνά μπορεί να γίνει απευθείας dump με το LLDB, και το dump που προκύπτει ενδέχεται να εκθέτει δεδομένα που προστατεύονται από το TCC και στα οποία η εφαρμογή είχε ήδη αποκτήσει πρόσβαση.<sup>[1]</sup>
- Ένας **hardened** στόχος χωρίς `get-task-allow` συνήθως απορρίπτει τα attach, ακόμη και ως `root`, εκτός αν ελέγχετε τα σχετικά debugger entitlements / τη διαδρομή policy.
- Οι unhardened διεργασίες τρίτων παραμένουν το ευκολότερο σημείο για τη χρήση των `lldb`, `vmmap`, Frida ή custom `task_for_pid`/`vm_read` readers.

### Αναζητήστε dumpable nested helpers

Πρόσφατη έρευνα γύρω από notarized εφαρμογές macOS εξακολουθεί να εντοπίζει το **`get-task-allow`** σε nested helpers αντί για το κύριο GUI binary. Όταν μια εφαρμογή ανώτατου επιπέδου φαίνεται hardened, απαριθμήστε τα **XPC services**, τα **login items**, τα **helper tools** και τα bundled CLIs πριν εγκαταλείψετε την προσπάθεια:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ένα nested executable με `get-task-allow` είναι συχνά το ευκολότερο σημείο για attach με `lldb`, dump ενός core ή ανάκτηση μνήμης με έναν custom client του `task_for_pid`, ακόμη και όταν η κύρια εφαρμογή διαθέτει καλύτερο hardening.

## Selective dumps με Frida ή userland readers

Όταν ένα πλήρες core περιέχει υπερβολικό θόρυβο, η λήψη μόνο των **ενδιαφερουσών readable ranges** είναι συχνά ταχύτερη. Το Frida είναι ιδιαίτερα χρήσιμο επειδή λειτουργεί καλά για **targeted extraction** όταν είναι δυνατή η προσάρτηση στη διεργασία.

Ενδεικτική προσέγγιση:

1. Enumerate readable/writable ranges
2. Filter ανά module, heap, stack ή anonymous memory
3. Dump μόνο τις περιοχές που περιέχουν candidate strings, keys, protobufs, plist/XML blobs ή decrypted code/data

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

- App heap chunks που περιέχουν secrets
- Anonymous regions που δημιουργούνται από custom packers ή loaders
- JIT / unpacked code pages μετά την αλλαγή των protections

Όταν ο στόχος συνεχίζει να κάνει **allocating / freeing** ενώ πραγματοποιείτε το dump, προτιμήστε το primitive **`readVolatile()`** της Frida αντί για το **`readByteArray()`** για ασταθείς περιοχές. Είναι πιο αργό, αλλά αποτρέπει τον τερματισμό του στόχου σε περίπτωση που μια σελίδα γίνει μη αναγνώσιμη στη μέση της ανάγνωσης. Για μεγαλύτερες acquisitions, μπορεί επίσης να είναι πιο καθαρό να κάνετε stream τα chunks πίσω με **`send(..., data)`** και να τα κάνετε compress στην πλευρά του controller, αντί να δημιουργείτε χιλιάδες μικρά αρχεία μέσα στον στόχο.

Υπάρχουν επίσης παλαιότερα userland tools, όπως το [`readmem`](https://github.com/gdbinit/readmem), αλλά είναι κυρίως χρήσιμα ως **source references** για dumping τύπου `task_for_pid`/`vm_read` και δεν συντηρούνται επαρκώς για σύγχρονα Apple Silicon workflows.

## Snapshots Heap / VM με `.memgraph`

Αν ενδιαφέρεστε κυρίως για **heap objects**, **allocation provenance** ή για ένα snapshot που μπορεί να μεταφερθεί σε άλλο machine, ένα `.memgraph` είναι συχνά πιο πρακτικό από ένα τεράστιο Mach-O core. Τα εργαλεία `leaks` μπορούν να δημιουργήσουν ένα από μια live διεργασία:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Στη συνέχεια, κάντε triage σε offline περιβάλλον με τα τυπικά εργαλεία της Apple:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
Το `stringdups` είναι ο κύριος λόγος για να διατηρείτε ένα capture με `-fullContent`, επειδή οι labels που περιγράφουν τα περιεχόμενα της μνήμης παραλείπονται από ένα minimal `.memgraph`.

Αυτό είναι ιδιαίτερα χρήσιμο όταν:

- Θέλετε ένα **μικρότερο, shareable snapshot** αντί για ένα πλήρες core
- Το `MallocStackLogging` ήταν ενεργοποιημένο και θέλετε **allocation backtraces**
- Γνωρίζετε ήδη μια **ενδιαφέρουσα heap address** και θέλετε να κάνετε pivot με το `malloc_history`
- Χρειάζεστε ένα γρήγορο **VM/heap breakdown** πριν αποφασίσετε αν αξίζει το noise ενός full dump

### Differential memgraph triage

Αν ελέγχετε τον τρόπο με τον οποίο ξεκινά το target, ενεργοποιήστε το **historical allocation logging** πριν από το launch, ώστε τα μεταγενέστερα snapshots να διατηρούν χρήσιμα alloc/free backtraces:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Στη συνέχεια, καταγράψτε snapshots πριν και μετά την ενδιαφέρουσα ενέργεια και κάντε diff σε αυτά offline:
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
Αυτός είναι ένας πρακτικός τρόπος για την απομόνωση **post-authentication objects**, **μεγάλων `CFData` buffers** ή **ανώνυμων περιοχών VM** που εμφανίζονται μόνο μετά από ένα στάδιο αποκρυπτογράφησης, unpacking ή ανάκτησης μυστικών.

## Στόχοι με έντονη χρήση Swift: `swift-inspect`

Για εφαρμογές που διατηρούν δεδομένα υψηλής αξίας μέσα σε **Swift runtime objects**, το `swift-inspect` μπορεί να αποτελέσει καλό συμπλήρωμα των LLDB ή Frida. Αντί να κάνετε πρώτα dump όλων των δεδομένων, μπορείτε να αναζητήσετε συγκεκριμένες δομές του Swift runtime από μια ενεργή διεργασία:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Αυτό είναι χρήσιμο για τον εντοπισμό:

- Μεγάλων Swift arrays που αποθηκεύουν προσωρινά ενδιαφέροντα δεδομένα
- Metadata allocations που αποκαλύπτουν types φορτωμένα κατά το runtime
- Κατάστασης Swift concurrency (`Task`, actor, thread relationships) πριν από ένα πιο στοχευμένο dump

Για περισσότερο object-level runtime triage, όταν μπορείτε ήδη να επιθεωρήσετε το process, δείτε [the dedicated page on objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Σημειώσεις για γρήγορο triage

- Το `sysctl vm.swapusage` παραμένει ένας γρήγορος τρόπος ελέγχου της **χρήσης swap** και του αν το swap είναι **κρυπτογραφημένο**.
- Το `sleepimage` παραμένει κυρίως σχετικό με σενάρια **hibernate/safe sleep**, αλλά τα σύγχρονα συστήματα συνήθως το προστατεύουν, επομένως θα πρέπει να αντιμετωπίζεται ως **πηγή artifact προς έλεγχο** και όχι ως αξιόπιστη acquisition path.
- Σε πρόσφατες εκδόσεις του macOS, το **process-level dumping** είναι γενικά πιο ρεαλιστικό από το **full physical memory imaging**, εκτός αν ελέγχετε την boot policy, την κατάσταση του SIP και τη φόρτωση των kext.

## Αναφορές

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
