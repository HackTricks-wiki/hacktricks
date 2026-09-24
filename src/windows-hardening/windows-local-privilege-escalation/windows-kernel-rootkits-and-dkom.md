# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Πεδίο εφαρμογής

Ένα post-compromise implant μπορεί να φορτώσει έναν signed kernel driver ως service και να εκθέσει ένα user-mode control plane μέσω του `IRP_MJ_DEVICE_CONTROL`. Η υπογραφή του driver απλώς διασφαλίζει ότι τα Windows αποδέχονται το image· δεν καθιστά ασφαλή την εξουσιοδότηση των IOCTL, τις memory operations, τα callbacks ή τα hooks. Ένα rootkit που αναλύθηκε χρησιμοποιούσε τρεις handlers κατά την κανονική λειτουργία, αλλά εξέθετε δεκάδες επιπλέον post-exploitation primitives, επομένως το reverse engineering πρέπει να καλύπτει ολόκληρο τον dispatcher και όχι μόνο τα requests που παρατηρήθηκαν σε ένα malware trace.<sup>[[1]](#references)</sup>

## Triage signed-driver και IOCTL

Ξεκινήστε από το `DriverEntry`, καταγράψτε τα device objects και τα DOS symbolic links, εντοπίστε τη ρουτίνα `MajorFunction[IRP_MJ_DEVICE_CONTROL]` και χαρτογραφήστε κάθε comparison/table entry που καταλήγει σε handler. Συγκρίνετε τα names που ανοίγει το user mode με τα names που δημιουργεί στην πραγματικότητα ο driver: σε μία παρατηρημένη αλυσίδα ανοίχτηκε το `\\.\msagent`, ενώ ο driver δημιούργησε τα `\Device\ToolTool` και `\DosDevices\ToolTool`. Αυτή η ασυμφωνία μπορεί να εντοπίσει άλλο sample/configuration, λογική αρχικοποίησης που λείπει ή ασυνέπεια στην ανάλυση.<sup>[[1]](#references)</sup>

Αποκωδικοποιήστε κάθε control code πριν ανακατασκευάσετε τη δομή εισόδου του.<sup>[[1]](#references)</sup>
```python
def decode_ioctl(code):
return {
"device_type": code >> 16,
"access": (code >> 14) & 3,
"function": (code >> 2) & 0xfff,
"method": code & 3,
}

for code in (0x2220F0, 0x222120, 0x2221E0):
print(hex(code), decode_ioctl(code))
```
Αυτοί οι τρεις κωδικοί αποκωδικοποιούνται ως `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` και `METHOD_BUFFERED`. Αυτό **δεν** αποδεικνύει ότι ένας unprivileged caller μπορεί να τους προσπελάσει: ελέγξτε επίσης το device DACL, τη δημιουργία/το άνοιγμα μέσω dispatch, τους ελέγχους caller ανά αίτημα, τα αναμενόμενα μήκη buffer, τους embedded pointers, τη διαχείριση του κύκλου ζωής των PID και το αν ο handler εμπιστεύεται ένα PID ή flag που παρέχεται από τον caller.<sup>[[1]](#references)</sup>

Όταν το implant χρησιμοποιεί μόνο ένα υποσύνολο εντολών, ομαδοποιήστε τους υπόλοιπους handlers ανά primitive αντί να τους απορρίψετε ως dead code. Ένας multifunction driver έχει εκθέσει όλες τις παρακάτω κατηγορίες:<sup>[[1]](#references)</sup>

- **Έλεγχος/διαμόρφωση:** ενεργοποίηση ή απενεργοποίηση της κατάστασης του rootkit· προσθήκη, αφαίρεση, αναζήτηση ή εκκαθάριση protected paths, processes και C2 addresses.
- **Χειρισμός διεργασιών:** τερματισμός ενός PID, unmap του image του, injection με `NtCreateThreadEx`, απόκρυψη/επαναφορά processes ή user modules και αφαίρεση PPL protection.
- **Χειρισμός kernel:** unlink ενός loaded driver, απαρίθμηση/απενεργοποίηση/επαναφορά notification callbacks, manual map άλλου driver και εγγραφή σε αυθαίρετη kernel address.
- **Χειρισμός objects:** διαγραφή/αποκρυπτογράφηση files και δημιουργία ή τροποποίηση registry values.

## Εξαιρέσεις trusted-process

Ένα χρήσιμο design pattern είναι ένα IOCTL που καταχωρεί ένα PID μαζί με ένα **trusted** flag. Το ίδιο trust lookup χρησιμοποιείται έπειτα από file, registry, process και thread filters: τα untrusted tools λαμβάνουν φιλτραρισμένα αποτελέσματα απαρίθμησης, μειωμένα handle rights ή `STATUS_ACCESS_DENIED`, ενώ το implant μπορεί να συνεχίσει να ενημερώνει τα δικά του κρυφά objects. Αντιμετωπίστε το ως authorization boundary και επαληθεύστε πώς γίνονται τα entries authenticated, synchronized και removed μετά από έξοδο process ή επαναχρησιμοποίηση PID.<sup>[[1]](#references)</sup>

Τα rootkits μπορούν να αποθηκεύουν policy σε τιμές `REG_MULTI_SZ` και να μεταγλωττίζουν λίστες file, directory, registry-key, registry-value, ignored-image, protected-image και hidden-image σε AVL trees. Κατά την ανάλυση, ακολουθήστε κάθε reader και writer αυτών των shared trees· αυτό συνδέει τη registry configuration, τα IOCTLs, τα callbacks και τη filtering logic ακόμη και όταν τα function names έχουν αφαιρεθεί.<sup>[[1]](#references)</sup>

## Απόκρυψη process και module μέσω DKOM

### `EPROCESS.ActiveProcessLinks`

Τα offsets του `ActiveProcessLinks` διαφέρουν ανά Windows build. Ένα version-tolerant rootkit μπορεί να ελέγξει γνωστά candidates και έπειτα να σαρώσει το `EPROCESS` για ένα self-consistent `LIST_ENTRY`, οι neighbors του οποίου δείχνουν πίσω στο candidate. Διατηρεί το offset που εντοπίστηκε, αποκρύπτει ένα process επανασυνδέοντας τα `Flink`/`Blink` των neighbors του και διατηρεί την κατάσταση ώστε να επανασυνδέσει το entry αργότερα. Το process συνεχίζει να εκτελείται, αλλά εξαφανίζεται από enumerators που διατρέχουν τη λίστα active-process.<sup>[[1]](#references)</sup>

Αυτό είναι **DKOM**, όχι termination. Η ανίχνευση θα πρέπει να συγκρίνει αποτελέσματα βασισμένα σε λίστες με ανεξάρτητα στοιχεία, όπως pool/object scans, thread ownership, handle tables, scheduler artifacts και kernel memory inspection. Ένα process που είναι ορατό σε ένα scan αλλά απουσιάζει από την canonical list είναι πιο σημαντικό από οποιαδήποτε από τις δύο όψεις μεμονωμένα.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Το αντίστοιχο module-hiding primitive εντοπίζει το target entry στο `PsLoadedModuleList` και τροποποιεί τους adjacent `Flink`/`Blink` pointers. Ο driver παραμένει mapped και executable, αλλά τα list-backed module queries δεν τον περιλαμβάνουν. Συγκρίνετε τη loader list με executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses και dispatch pointers που καταλήγουν εκτός ενός listed image.<sup>[[1]](#references)</sup>

## Προστασία και cloaking μέσω callbacks

Ένα rootkit μπορεί να συνδυάζει documented callback frameworks με DKOM και hooks:<sup>[[1]](#references)</sup>

- Οι `ObRegisterCallbacks` pre-operation handlers για `PsProcessType` και `PsThreadType` αφαιρούν rights που χρησιμοποιούνται για termination, VM access, duplication ή thread manipulation όταν ένας untrusted caller ανοίγει ένα protected target. Καταγράψτε το callback altitude και επιλύστε κάθε callback address στο module που του ανήκει.
- Τα `PsSetCreateProcessNotifyRoutineEx` και `PsSetLoadImageNotifyRoutine` διατηρούν την protected/ignored/hidden process state καθώς εμφανίζονται processes και images· ένα one-time process walk μπορεί να συμπληρώσει objects που υπήρχαν πριν από την registration.
- Ένα filesystem minifilter αρνείται την πρόσβαση σε configured paths. Μια ασυνήθιστη υλοποίηση μπορεί να δημιουργεί το `Instances` key, να επιλέγει δυναμικά ένα altitude και να κάνει increment/retry όταν το `FltRegisterFilter` αναφέρει collision.
- Μια routine `CmRegisterCallbackEx` μπορεί να αποκρύπτει protected names από την απαρίθμηση και να αρνείται direct open, rename, set ή delete operations, ενώ εξαιρεί registered trusted processes.

Συσχετίστε τις registrations του `ObRegisterCallbacks`, τα registry-callback altitudes, το output του `fltmc filters`, τα service `Instances` keys και τα callback addresses. Αν τα κανονικά tools φιλτράρονται, εξετάστε αυτές τις structures από ένα offline memory image ή άλλο trusted acquisition layer.<sup>[[1]](#references)</sup>

## Φιλτράρισμα αποτελεσμάτων Nsiproxy

Η απόκρυψη δικτυακής δραστηριότητας μπορεί να στοχεύει το `\Driver\Nsiproxy`: λάβετε το driver object με `ObReferenceObjectByName`, αποθηκεύστε έναν handler pointer, αντικαταστήστε τον με ένα wrapper και αφαιρέστε τα επιστρεφόμενα IPv4 records που ταιριάζουν με μια IOCTL-managed C2 list πριν τα λάβει το user mode. Οι εφαρμογές που βασίζονται στα φιλτραρισμένα NSI data μπορεί πλέον να μην εμφανίζουν τη σύνδεση, παρότι η traffic εξακολουθεί να υπάρχει.<sup>[[1]](#references)</sup>

Συγκρίνετε τις host connection views με packet capture, WFP/ETW telemetry και kernel-memory network objects. Εξετάστε επίσης τα `Nsiproxy` dispatch/handler pointers και επιβεβαιώστε ότι καθένα επιλύεται μέσα στο αναμενόμενο signed module· ένας pointer προς unlisted mapping μπορεί να συνδέσει το network filtering με DKOM του `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Checklist διερεύνησης

Το ισχυρότερο signal είναι η διαφωνία μεταξύ layers, όχι ένα filename ή hash. Συσχετίστε:<sup>[[1]](#references)</sup>

1. Δημιουργία kernel service και ένας signed driver του οποίου η ηλικία του certificate, ο publisher ή το path δεν είναι συνεπής με το εγκατεστημένο προϊόν.
2. Δημιουργία device, DOS links και IOCTL traffic, συμπεριλαμβανομένων mismatched user-mode και kernel device names.
3. Ένα PID registration request που ακολουθείται από failures άλλων processes να ανοίξουν, να απαριθμήσουν, να τροποποιήσουν ή να διαγράψουν τα ίδια objects.
4. Object/registry/process/image callbacks, minifilter instances και hooks των οποίων οι addresses δεν ανήκουν σε έναν driver που απαριθμείται κανονικά.
5. Διαφορές μεταξύ list-based και scan-based inventories για processes, modules, callbacks και network.

## References

- [1] [Kaspersky Securelist - Το HoneyMyte ενισχύει το CoolClient με ένα Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
