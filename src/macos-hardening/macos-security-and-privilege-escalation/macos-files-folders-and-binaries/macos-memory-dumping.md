# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Αντικείμενα μνήμης

### Αρχεία swap

Τα αρχεία swap, όπως το `/private/var/vm/swapfile0`, λειτουργούν ως προσωρινή αποθήκευση όταν η φυσική μνήμη γεμίσει. Όταν δεν υπάρχει πλέον διαθέσιμος χώρος στη φυσική μνήμη, τα δεδομένα της μεταφέρονται σε ένα swap file και στη συνέχεια επαναφορτώνονται στη φυσική μνήμη όταν απαιτείται. Μπορεί να υπάρχουν πολλαπλά αρχεία swap, με ονόματα όπως swapfile0, swapfile1 κ.ο.κ.

### Εικόνα αδρανοποίησης

Το αρχείο στο `/private/var/vm/sleepimage` είναι κρίσιμο κατά τη διάρκεια της **λειτουργίας αδρανοποίησης**. **Τα δεδομένα της μνήμης αποθηκεύονται σε αυτό το αρχείο όταν το OS X αδρανοποιείται**. Όταν ο υπολογιστής ξυπνήσει, το σύστημα ανακτά τα δεδομένα μνήμης από αυτό το αρχείο, επιτρέποντας στον χρήστη να συνεχίσει από όπου σταμάτησε.

Αξίζει να σημειωθεί ότι σε σύγχρονα συστήματα macOS, αυτό το αρχείο συνήθως είναι κρυπτογραφημένο για λόγους ασφάλειας, κάνοντας την ανάκτηση δύσκολη.

- Για να ελεγχθεί αν η κρυπτογράφηση είναι ενεργοποιημένη για το sleepimage, μπορεί να εκτελεστεί η εντολή `sysctl vm.swapusage`. Αυτό θα δείξει αν το αρχείο είναι κρυπτογραφημένο.

### Καταγραφές πίεσης μνήμης

Ένα ακόμη σημαντικό αρχείο σχετικό με τη μνήμη σε συστήματα macOS είναι το **memory pressure log**. Αυτά τα logs βρίσκονται στο `/var/log` και περιέχουν λεπτομερείς πληροφορίες για τη χρήση της μνήμης του συστήματος και τα συμβάντα πίεσης μνήμης. Μπορούν να είναι ιδιαίτερα χρήσιμα για τη διάγνωση προβλημάτων μνήμης ή για την κατανόηση του πώς το σύστημα διαχειρίζεται τη μνήμη με την πάροδο του χρόνου.

## Dumping memory with osxpmem

Για να κάνετε dump της μνήμης σε ένα MacOS μηχάνημα μπορείτε να χρησιμοποιήσετε [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Σημείωση**: Αυτό είναι πλέον κυρίως ένα **legacy workflow**. `osxpmem` εξαρτάται από το φόρτωμα μιας kernel extension, το [Rekall](https://github.com/google/rekall) project είναι αρχειοθετημένο, η τελευταία έκδοση είναι από **2017**, και το δημοσιευμένο binary στοχεύει **Intel Macs**. Σε τρέχουσες εκδόσεις macOS, ειδικά σε **Apple Silicon**, kext-based full-RAM acquisition συνήθως αποκλείεται από τους σύγχρονους περιορισμούς kernel-extension, SIP, και τις απαιτήσεις platform-signing. Στην πράξη, σε μοντέρνα συστήματα πιο συχνά θα καταλήξετε να κάνετε ένα **process-scoped dump** αντί για μια εικόνα ολόκληρης της RAM.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Αν βρείτε αυτό το σφάλμα: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Μπορείτε να το διορθώσετε κάνοντας:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Άλλα σφάλματα** μπορεί να διορθωθούν επιτρέποντας τη φόρτωση του kext στο "Security & Privacy --> General", απλώς **επιτρέψτε** το.

Μπορείτε επίσης να χρησιμοποιήσετε αυτό το **oneliner** για να κατεβάσετε την εφαρμογή, να φορτώσετε το kext και να dump τη μνήμη:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping ζωντανής διεργασίας με LLDB

Για τις **πρόσφατες εκδόσεις macOS**, η πιο πρακτική προσέγγιση είναι συνήθως να κάνετε dump τη μνήμη μιας **συγκεκριμένης διεργασίας** αντί να προσπαθήσετε να image όλη τη φυσική μνήμη.

Το LLDB μπορεί να αποθηκεύσει ένα Mach-O core file από έναν live target:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Από προεπιλογή αυτό συνήθως δημιουργεί ένα **skinny core**. Για να αναγκάσετε το LLDB να συμπεριλάβει ολόκληρη τη χαρτογραφημένη μνήμη της διαδικασίας:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Χρήσιμες εντολές πριν το dumping:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Αυτό είναι συνήθως αρκετό όταν ο στόχος είναι η ανάκτηση:

- Αποκρυπτογραφημένα configuration blobs
- tokens στη μνήμη, cookies ή διαπιστευτήρια
- Μυστικά σε plaintext που προστατεύονται μόνο at rest
- Αποκρυπτογραφημένες σελίδες Mach-O μετά από unpacking / JIT / runtime patching

If the target is protected by the **hardened runtime**, or if `taskgated` denies the attach, you typically need one of these conditions:

- The target carries **`get-task-allow`**
- Your debugger is signed with the proper **debugger entitlement**
- You are **root** and the target is a non-hardened third-party process

Για περισσότερα σχετικά με την απόκτηση ενός task port και τι μπορεί να γίνει με αυτό:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Επιλεκτικά dumps με Frida ή userland readers

When a full core is too noisy, dumping only **interesting readable ranges** is often faster. Frida is especially useful because it works well for **targeted extraction** once you can attach to the process.

Παράδειγμα προσέγγισης:

1. Απαρίθμηση των readable/writable ranges
2. Φιλτράρισμα κατά module, heap, stack ή anonymous memory
3. Κάντε dump μόνο τις περιοχές που περιέχουν πιθανές συμβολοσειρές, κλειδιά, protobufs, plist/XML blobs, ή αποκρυπτογραφημένο κώδικα/δεδομένα

Ελάχιστο παράδειγμα Frida για το dump όλων των readable anonymous ranges:
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
Αυτό είναι χρήσιμο όταν θέλετε να αποφύγετε γιγαντιαία core files και να συλλέξετε μόνο:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Παλιότερα userland εργαλεία όπως το [`readmem`](https://github.com/gdbinit/readmem) υπάρχουν επίσης, αλλά είναι κυρίως χρήσιμα ως **αναφορές πηγής** για άμεσο dumping τύπου `task_for_pid`/`vm_read` και δεν συντηρούνται καλά για σύγχρονα Apple Silicon workflows.

## Σημειώσεις γρήγορης αξιολόγησης

- `sysctl vm.swapusage` εξακολουθεί να είναι ένας γρήγορος τρόπος για να ελέγξετε την **χρήση swap** και αν το swap είναι **κρυπτογραφημένο**.
- `sleepimage` παραμένει σχετικό κυρίως για σενάρια **hibernate/safe sleep**, αλλά τα σύγχρονα συστήματα το προστατεύουν συνήθως, οπότε πρέπει να θεωρείται ως μια **πηγή artifacts προς έλεγχο**, όχι ως αξιόπιστη οδός απόκτησης.
- Σε πρόσφατες εκδόσεις macOS, το **process-level dumping** είναι γενικά πιο ρεαλιστικό από την **full physical memory imaging**, εκτός αν έχετε έλεγχο του boot policy, της κατάστασης SIP, και του kext loading.

## Αναφορές

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
