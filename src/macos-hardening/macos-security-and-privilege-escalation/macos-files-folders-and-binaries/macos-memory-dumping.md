# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, όπως `/private/var/vm/swapfile0`, λειτουργούν ως **caches όταν η φυσική μνήμη είναι πλήρης**. Όταν δεν υπάρχει πλέον χώρος στη φυσική μνήμη, τα δεδομένα της μεταφέρονται σε ένα swap file και στη συνέχεια επαναφέρονται στη φυσική μνήμη όταν χρειάζεται. Μπορεί να υπάρχουν πολλά swap files, με ονόματα όπως swapfile0, swapfile1 και ούτω καθεξής.

### Hibernate Image

Το αρχείο που βρίσκεται στο `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη διάρκεια της **λειτουργίας hibernation**. **Τα δεδομένα από τη μνήμη αποθηκεύονται σε αυτό το αρχείο όταν το OS X hibernates**. Όταν ο υπολογιστής ξυπνά, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από εκεί που σταμάτησε.

Αξίζει να σημειωθεί ότι στα σύγχρονα συστήματα MacOS, αυτό το αρχείο είναι συνήθως encrypted για λόγους security, καθιστώντας την ανάκτηση δύσκολη.

- Για να ελέγξετε αν το encryption είναι enabled για το sleepimage, μπορεί να εκτελεστεί η εντολή `sysctl vm.swapusage`. Αυτό θα δείξει αν το αρχείο είναι encrypted.

### Memory Pressure Logs

Ένα ακόμη σημαντικό αρχείο σχετικό με τη μνήμη στα συστήματα MacOS είναι το **memory pressure log**. Αυτά τα logs βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες για τη χρήση μνήμης του συστήματος και τα pressure events. Μπορούν να είναι ιδιαίτερα χρήσιμα για τη διάγνωση memory-related issues ή για την κατανόηση του πώς το σύστημα διαχειρίζεται τη μνήμη με την πάροδο του χρόνου.

## Dumping memory with osxpmem

Για να κάνετε dump τη μνήμη σε ένα MacOS machine μπορείτε να χρησιμοποιήσετε [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: Αυτό είναι κυρίως ένα **legacy workflow** πλέον. Το `osxpmem` εξαρτάται από τη φόρτωση ενός kernel extension, το project [Rekall](https://github.com/google/rekall) είναι archived, το πιο πρόσφατο release είναι από το **2017**, και το published binary στοχεύει σε **Intel Macs**. Στις τρέχουσες macOS εκδόσεις, ειδικά σε **Apple Silicon**, η kext-based full-RAM acquisition συνήθως μπλοκάρεται από σύγχρονους περιορισμούς kernel-extension, SIP, και platform-signing requirements. Στην πράξη, σε σύγχρονα συστήματα θα καταλήξετε συχνότερα να κάνετε ένα **process-scoped dump** αντί για ένα whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Εάν βρείτε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε κάνοντας:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** μπορεί να διορθωθούν με το να **επιτρέψεις τη φόρτωση του kext** στο "Security & Privacy --> General", απλώς **allow** το.

Μπορείς επίσης να χρησιμοποιήσεις αυτό το **oneliner** για να κατεβάσεις την εφαρμογή, να φορτώσεις το kext και να κάνεις dump τη μνήμη:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Live process dumping with LLDB

Για **recent macOS versions**, η πιο πρακτική προσέγγιση είναι συνήθως να γίνει dump της μνήμης ενός **specific process** αντί να προσπαθήσεις να απεικονίσεις όλη τη φυσική μνήμη.

Το LLDB μπορεί να αποθηκεύσει ένα Mach-O core file από έναν live target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Από προεπιλογή, αυτό συνήθως δημιουργεί έναν **skinny core**. Για να αναγκάσεις το LLDB να συμπεριλάβει όλη τη μνήμη της χαρτογραφημένης διεργασίας:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Χρήσιμες εντολές για συνέχεια πριν το dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Αυτό συνήθως είναι αρκετό όταν ο στόχος είναι να ανακτηθούν:

- Αποκρυπτογραφημένα configuration blobs
- In-memory tokens, cookies ή credentials
- Plaintext secrets που προστατεύονται μόνο at rest
- Αποκρυπτογραφημένες Mach-O pages μετά από unpacking / JIT / runtime patching

Αν ο στόχος προστατεύεται από το **hardened runtime**, ή αν το `taskgated` αρνείται το attach, συνήθως χρειάζεσαι μία από αυτές τις συνθήκες:

- Ο στόχος έχει το **`get-task-allow`**
- Ο debugger σου είναι signed με το σωστό **debugger entitlement**
- Είσαι **root** και ο στόχος είναι ένα non-hardened third-party process

Για περισσότερες πληροφορίες σχετικά με την απόκτηση ενός task port και τι μπορεί να γίνει με αυτό:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

Πριν ξοδέψεις χρόνο σε LLDB/Frida, επαλήθευσε γρήγορα αν ο στόχος είναι ρεαλιστικά **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
Λειτουργικά, αυτό συνήθως σημαίνει:

- Μια third-party app που συνοδεύεται με **`get-task-allow`** συχνά μπορεί να γίνει άμεσα dump με LLDB, και το αποτέλεσμα μπορεί να αποκαλύψει TCC-protected δεδομένα που η app έχει ήδη προσπελάσει.
- Ένας **hardened** στόχος χωρίς `get-task-allow` συνήθως θα απορρίπτει attaches, ακόμη και ως `root`, εκτός αν ελέγχεις τα σχετικά debugger entitlements / policy path.
- Unhardened third-party processes εξακολουθούν να είναι το πιο εύκολο σημείο για να χρησιμοποιήσεις `lldb`, `vmmap`, Frida, ή custom `task_for_pid`/`vm_read` readers.

## Selective dumps with Frida or userland readers

Όταν ένα πλήρες core είναι πολύ noisy, το να κάνεις dump μόνο των **interesting readable ranges** είναι συχνά πιο γρήγορο. Το Frida είναι ιδιαίτερα χρήσιμο γιατί δουλεύει καλά για **targeted extraction** μόλις μπορέσεις να κάνεις attach στο process.

Παράδειγμα προσέγγισης:

1. Enumerate readable/writable ranges
2. Filter by module, heap, stack, or anonymous memory
3. Dump only the regions that contain candidate strings, keys, protobufs, plist/XML blobs, or decrypted code/data

Minimal Frida example to dump all readable anonymous ranges:
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
Αυτό είναι χρήσιμο όταν θέλεις να αποφύγεις τεράστια core files και να συλλέξεις μόνο:

- App heap chunks που περιέχουν secrets
- Anonymous regions που δημιουργούνται από custom packers ή loaders
- JIT / unpacked code pages μετά από αλλαγή των protections

Παλαιότερα userland tools όπως το [`readmem`](https://github.com/gdbinit/readmem) υπάρχουν επίσης, αλλά είναι κυρίως χρήσιμα ως **source references** για direct `task_for_pid`/`vm_read` style dumping και δεν συντηρούνται καλά για σύγχρονα Apple Silicon workflows.

## Heap / VM snapshots with `.memgraph`

Αν σε ενδιαφέρουν κυρίως τα **heap objects**, το **allocation provenance**, ή ένα snapshot που μπορεί να μεταφερθεί σε άλλο machine, ένα `.memgraph` είναι συχνά πιο πρακτικό από ένα τεράστιο Mach-O core. Το `leaks` tooling μπορεί να δημιουργήσει ένα από ένα live process:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Στη συνέχεια, κάνε triage offline με standard Apple tooling:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` είναι ο κύριος λόγος για να διατηρείς ένα `-fullContent` capture, επειδή οι ετικέτες που περιγράφουν τα περιεχόμενα της μνήμης παραλείπονται από ένα ελάχιστο `.memgraph`.

Αυτό είναι ιδιαίτερα χρήσιμο όταν:

- Θέλεις ένα **μικρότερο, shareable snapshot** αντί για ένα πλήρες core
- Το `MallocStackLogging` ήταν ενεργοποιημένο και θέλεις **allocation backtraces**
- Ξέρεις ήδη μια **ενδιαφέρουσα heap address** και θέλεις να κάνεις pivot με `malloc_history`
- Χρειάζεσαι ένα γρήγορο **VM/heap breakdown** πριν αποφασίσεις αν ένα πλήρες dump αξίζει τον θόρυβο

## Swift-heavy targets: `swift-inspect`

Για applications που κρατούν υψηλής αξίας δεδομένα μέσα σε **Swift runtime objects**, το `swift-inspect` μπορεί να είναι ένα καλό συμπλήρωμα στο LLDB ή το Frida. Αντί να κάνεις dump τα πάντα πρώτα, μπορείς να κάνεις query σε συγκεκριμένες Swift runtime structures από ένα live process:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Αυτό είναι χρήσιμο για να εντοπίσετε:

- Μεγάλους Swift arrays που buffer ενδιαφέροντα δεδομένα
- Metadata allocations που αποκαλύπτουν types φορτωμένα στο runtime
- Swift concurrency state (`Task`, actor, thread relationships) πριν κάνετε ένα πιο στοχευμένο dump

Για πιο object-level runtime triage, αφού μπορείτε ήδη να επιθεωρήσετε το process, δείτε [τη dedicated σελίδα για objects in memory](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Quick triage notes

- `sysctl vm.swapusage` παραμένει ένας γρήγορος τρόπος για να ελέγξετε τη **swap usage** και αν το swap είναι **encrypted**.
- Το `sleepimage` παραμένει σχετικό κυρίως για σενάρια **hibernate/safe sleep**, αλλά τα σύγχρονα systems συνήθως το προστατεύουν, οπότε θα πρέπει να αντιμετωπίζεται ως **artifact source to check**, όχι ως αξιόπιστη acquisition path.
- Σε πρόσφατες macOS releases, το **process-level dumping** είναι γενικά πιο ρεαλιστικό από το **full physical memory imaging**, εκτός αν ελέγχετε boot policy, SIP state και kext loading.

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
