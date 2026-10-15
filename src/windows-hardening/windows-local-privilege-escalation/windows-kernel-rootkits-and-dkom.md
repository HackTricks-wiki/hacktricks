# Windows Kernel Rootkits και DKOM

{{#include ../../banners/hacktricks-training.md}}

## Πεδίο εφαρμογής

Ένα implant μετά την παραβίαση μπορεί να φορτώσει ένα υπογεγραμμένο kernel driver ως υπηρεσία και να παρέχει ένα επίπεδο ελέγχου user-mode μέσω του `IRP_MJ_DEVICE_CONTROL`. Η υπογραφή του driver απλώς επιβεβαιώνει ότι τα Windows αποδέχονται το image· δεν καθιστά ασφαλείς την εξουσιοδότηση IOCTL, τις λειτουργίες μνήμης, τα callbacks ή τα hooks. Ένα rootkit που αναλύθηκε χρησιμοποιούσε τρεις handlers κατά την κανονική λειτουργία, αλλά διέθετε δεκάδες επιπλέον primitives για post-exploitation. Επομένως, το reverse engineering πρέπει να καλύπτει ολόκληρο τον dispatcher και όχι μόνο τα requests που παρατηρήθηκαν σε ένα trace malware.<sup>[[1]](#references)</sup>

## Διαλογή signed driver και IOCTL

Ξεκινήστε από το `DriverEntry`, καταγράψτε τα device objects και τα DOS symbolic links, εντοπίστε τη ρουτίνα `MajorFunction[IRP_MJ_DEVICE_CONTROL]` και χαρτογραφήστε κάθε σύγκριση/εγγραφή πίνακα που οδηγεί σε handler. Διασταυρώστε τα ονόματα που ανοίγει το user mode με εκείνα που δημιουργεί πράγματι ο driver: σε μία παρατηρημένη αλυσίδα ανοίχτηκε το `\\.\msagent`, ενώ ο driver δημιούργησε τα `\Device\ToolTool` και `\DosDevices\ToolTool`. Αυτή η ασυμφωνία μπορεί να υποδεικνύει διαφορετικό sample/ρύθμιση, λογική αρχικοποίησης που λείπει ή ασυνέπεια στην ανάλυση.<sup>[[1]](#references)</sup>

Αποκωδικοποιήστε κάθε control code πριν ανασυνθέσετε τη δομή εισόδου του.<sup>[[1]](#references)</sup>

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

Αυτοί οι τρεις κωδικοί αποκωδικοποιούνται ως `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` και `METHOD_BUFFERED`. Αυτό **δεν** αποδεικνύει ότι ένας μη προνομιούχος caller μπορεί να τους προσπελάσει: ελέγξτε επίσης το device DACL, το create/open dispatch, τους ελέγχους caller ανά αίτημα, τα αναμενόμενα μήκη buffer, τους ενσωματωμένους δείκτες, τον χειρισμό του κύκλου ζωής PID και αν ο handler εμπιστεύεται PID ή flag που παρέχει ο caller.<sup>[[1]](#references)</sup>

Όταν το implant χρησιμοποιεί μόνο ένα υποσύνολο εντολών, ομαδοποιήστε τους υπόλοιπους handlers ανά primitive αντί να τους απορρίψετε ως νεκρό κώδικα. Ένας multifunction driver έχει εκθέσει όλες τις παρακάτω κατηγορίες:<sup>[[1]](#references)</sup>

- **Έλεγχος/παραμετροποίηση:** εναλλαγή κατάστασης rootkit· προσθήκη, αφαίρεση, αναζήτηση ή εκκαθάριση προστατευμένων paths, processes και C2 addresses.
- **Χειρισμός processes:** τερματισμός PID, αποχαρτογράφηση του image του, injection με `NtCreateThreadEx`, απόκρυψη/επαναφορά processes ή user modules και αφαίρεση προστασίας PPL.
- **Χειρισμός kernel:** unlink ενός φορτωμένου driver, απαρίθμηση/απενεργοποίηση/επαναφορά notification callbacks, χειροκίνητη χαρτογράφηση άλλου driver και εγγραφή σε αυθαίρετη διεύθυνση kernel.
- **Χειρισμός objects:** διαγραφή/αποκρυπτογράφηση αρχείων και δημιουργία ή τροποποίηση τιμών registry.

## Χειροκίνητη χαρτογράφηση kernel μέσω ευάλωτου υπογεγραμμένου driver

Ένας υπογεγραμμένος driver με λειτουργίες ανάγνωσης/εγγραφής μνήμης kernel μπορεί να παρέχει loader για ένα unsigned driver image, χωρίς να ζητήσει από τα Windows να φορτώσουν αυτό το image ως κανονικό driver.<sup>[[2]](#references)[[7]](#references)</sup> Το παράδειγμα LocalStranger ανοίγει μια υπάρχουσα συσκευή `\\.\WinNotify`· ο κώδικάς του δεν δείχνει ότι ένας μη προνομιούχος χρήστης μπορεί να εγκαταστήσει, να εκκινήσει ή να ανοίξει τον driver σε έναν αυθαίρετο host.<sup>[[2]](#references)[[3]](#references)</sup> Ο mapper δέχεται ένα image path, αναζητά τη βάση του φορτωμένου kernel και χρησιμοποιεί τα IOCTL ανάγνωσης/εγγραφής εικονικής μνήμης της συσκευής.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Για να μετατρέψει αυτή την πρόσβαση ανάγνωσης/εγγραφής σε κλήση kernel, ο mapper διαβάζει ένα immediate της βάσης PTE από το `MmGetVirtualForPhysical` και διασχίζει τις εγγραφές paging που καλύπτουν το `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Ο υπολογισμός PTE είναι `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`· ο κώδικας ελέγχει επίσης για PDE μεγάλης σελίδας.<sup>[[5]](#references)[[7]](#references)</sup> Κάνει προσωρινά εγγράψιμη την εγγραφή που καλύπτει τη διεύθυνση, αντικαθιστά την είσοδο syscall με ένα jump προς την επιθυμητή συνάρτηση kernel, καλεί το user-mode stub `NtAddAtom` και, στη συνέχεια, επαναφέρει τα αρχικά bytes και την εγγραφή σελίδας.<sup>[[6]](#references)</sup>

Ο mapper χρησιμοποιεί αυτή τη διαδρομή κλήσης για το `ExAllocatePool`, χαρτογραφεί PE sections, imports και relocations στο image, το γράφει στην allocation και καλεί το entry point του.<sup>[[7]](#references)[[8]](#references)</sup> Αυτή η υλοποίηση δέχεται μόνο x64, relocatable PE images· η ανάγνωση της βάσης PTE υποθέτει επίσης σταθερή διάταξη `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Αντιμετωπίστε το ως εξαρτώμενο από το build, όχι ως ανεξάρτητο KASLR bypass ή απόδειξη ότι το HVCI ή το PatchGuard επιτρέπει τη χαρτογράφηση.<sup>[[5]](#references)[[8]](#references)</sup> Για χρήση του kernel R/W μόνο για δεδομένα, δείτε την [κλοπή token SYSTEM](arbitrary-kernel-rw-token-theft.md).

## Εξαιρέσεις για trusted processes

Ένα χρήσιμο μοτίβο σχεδίασης είναι ένα IOCTL που καταχωρίζει ένα PID μαζί με ένα **trusted** flag. Η ίδια αναζήτηση trust χρησιμοποιείται από τα file, registry, process και thread filters: τα μη έμπιστα εργαλεία λαμβάνουν φιλτραρισμένα αποτελέσματα απαρίθμησης, μειωμένα handle rights ή `STATUS_ACCESS_DENIED`, ενώ το implant μπορεί να ενημερώνει τα δικά του κρυμμένα objects. Αντιμετωπίστε το ως όριο εξουσιοδότησης και επαληθεύστε πώς γίνεται η ταυτοποίηση, ο συγχρονισμός και η αφαίρεση των εγγραφών μετά τον τερματισμό process ή την επαναχρησιμοποίηση PID.<sup>[[1]](#references)</sup>

Τα rootkits μπορούν να διατηρούν policy σε τιμές `REG_MULTI_SZ` και να μεταγλωττίζουν λίστες αρχείων, καταλόγων, registry keys, registry values, ignored images, protected images και hidden images σε AVL trees. Κατά την ανάλυση, ανιχνεύστε κάθε reader και writer αυτών των κοινόχρηστων trees· συνδέουν την παραμετροποίηση registry, τα IOCTLs, τα callbacks και τη λογική filtering ακόμη κι όταν έχουν αφαιρεθεί τα ονόματα των συναρτήσεων.<sup>[[1]](#references)</sup>

## Απόκρυψη process και module μέσω DKOM

### `EPROCESS.ActiveProcessLinks`

Τα offsets του `ActiveProcessLinks` διαφέρουν ανά build των Windows. Ένα rootkit ανθεκτικό στις εκδόσεις μπορεί να δοκιμάσει γνωστά candidates και, στη συνέχεια, να σαρώσει το `EPROCESS` για ένα συνεπές `LIST_ENTRY` του οποίου οι γειτονικοί κόμβοι δείχνουν πίσω στο candidate. Διατηρεί το offset που εντοπίστηκε, αποκρύπτει ένα process επανασυνδέοντας τα `Flink`/`Blink` των γειτονικών κόμβων του και αποθηκεύει την κατάσταση ώστε να συνδέσει ξανά την εγγραφή αργότερα. Το process συνεχίζει να εκτελείται, αλλά εξαφανίζεται από enumerators που διασχίζουν την active-process list.<sup>[[1]](#references)</sup>

Αυτό είναι **DKOM**, όχι τερματισμός. Η ανίχνευση πρέπει να συγκρίνει αποτελέσματα που βασίζονται σε λίστες με ανεξάρτητα στοιχεία, όπως σαρώσεις pool/object, ιδιοκτησία thread, πίνακες handle, artifacts του scheduler και επιθεώρηση μνήμης kernel. Ένα process που εντοπίζεται από σάρωση αλλά απουσιάζει από την κανονική λίστα είναι πιο σημαντικό από οποιαδήποτε από τις δύο όψεις μεμονωμένα.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Το αντίστοιχο primitive απόκρυψης module εντοπίζει την εγγραφή-στόχο στο `PsLoadedModuleList` και τροποποιεί τους δείκτες `Flink`/`Blink` των γειτονικών κόμβων. Ο driver παραμένει χαρτογραφημένος και εκτελέσιμος, αλλά τα ερωτήματα module που βασίζονται στη λίστα δεν τον περιλαμβάνουν. Συγκρίνετε τη λίστα loader με εκτελέσιμες χαρτογραφήσεις kernel, pool tags, objects συσκευών/driver, service keys, διευθύνσεις callback και dispatch pointers που βρίσκονται εκτός καταχωρισμένου image.<sup>[[1]](#references)</sup>

## Προστασία και απόκρυψη μέσω callbacks

Ένα rootkit μπορεί να συνδυάσει documented callback frameworks με DKOM και hooks:<sup>[[1]](#references)</sup>

- Οι pre-operation handlers του `ObRegisterCallbacks` για τα `PsProcessType` και `PsThreadType` αφαιρούν δικαιώματα που χρησιμοποιούνται για τερματισμό, πρόσβαση VM, duplication ή χειρισμό thread, όταν ένας μη έμπιστος caller ανοίγει έναν προστατευμένο στόχο. Καταγράψτε το altitude του callback και αντιστοιχίστε κάθε διεύθυνση callback στο module που την κατέχει.
- Τα `PsSetCreateProcessNotifyRoutineEx` και `PsSetLoadImageNotifyRoutine` διατηρούν την κατάσταση protected/ignored/hidden καθώς εμφανίζονται processes και images· μια αρχική σάρωση processes μπορεί να συμπληρώσει τα objects που υπήρχαν πριν από την εγγραφή.
- Ένα filesystem minifilter αρνείται την πρόσβαση σε ρυθμισμένα paths. Μια ασυνήθιστη υλοποίηση μπορεί να δημιουργήσει το `Instances` key, να επιλέξει δυναμικά ένα altitude και να το αυξάνει/δοκιμάζει ξανά όταν το `FltRegisterFilter` αναφέρει σύγκρουση.
- Μια ρουτίνα `CmRegisterCallbackEx` μπορεί να αποκρύπτει προστατευμένα ονόματα από την απαρίθμηση και να αρνείται άμεσο άνοιγμα, μετονομασία, ορισμό ή διαγραφή, εξαιρώντας παράλληλα καταχωρισμένα trusted processes.

Συσχετίστε τις εγγραφές `ObRegisterCallbacks`, τα altitudes των registry callbacks, την έξοδο του `fltmc filters`, τα service `Instances` keys και τις διευθύνσεις callback. Αν τα κανονικά εργαλεία φιλτράρονται, επιθεωρήστε αυτές τις δομές από offline memory image ή από άλλο έμπιστο επίπεδο απόκτησης δεδομένων.<sup>[[1]](#references)</sup>

## Φιλτράρισμα αποτελεσμάτων Nsiproxy

Η απόκρυψη δικτύου μπορεί να στοχεύσει το `\Driver\Nsiproxy`: να λάβει το driver object με `ObReferenceObjectByName`, να αποθηκεύσει έναν handler pointer, να τον αντικαταστήσει με wrapper και να αφαιρεί εγγραφές IPv4 που επιστρέφονται και αντιστοιχούν σε μια λίστα C2 που διαχειρίζονται IOCTLs, πριν τις λάβει το user mode. Οι εφαρμογές που βασίζονται στα φιλτραρισμένα δεδομένα NSI ενδέχεται να μην εμφανίζουν πλέον τη σύνδεση, παρότι η κίνηση εξακολουθεί να υπάρχει.<sup>[[1]](#references)</sup>

Συγκρίνετε τις όψεις συνδέσεων του host με packet capture, τηλεμετρία WFP/ETW και objects δικτύου στη μνήμη kernel. Επιθεωρήστε επίσης τους dispatch/handler pointers του `Nsiproxy` και επιβεβαιώστε ότι ο καθένας αντιστοιχεί στο αναμενόμενο υπογεγραμμένο module· ένας pointer σε μη καταχωρισμένη χαρτογράφηση μπορεί να συνδέσει το network filtering με το DKOM του `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Λίστα ελέγχου διερεύνησης

Το ισχυρότερο σήμα είναι η ασυμφωνία μεταξύ επιπέδων, όχι ένα μεμονωμένο filename ή hash. Συσχετίστε:<sup>[[1]](#references)</sup>

1. Δημιουργία kernel-service και έναν υπογεγραμμένο driver του οποίου η ηλικία πιστοποιητικού, ο publisher ή το path δεν συνάδει με το εγκατεστημένο προϊόν.
2. Δημιουργία device, DOS links και κίνηση IOCTL, συμπεριλαμβανομένων ασύμβατων ονομάτων device σε user mode και kernel.
3. Αίτημα καταχώρισης PID και, στη συνέχεια, αποτυχίες άλλων processes να ανοίξουν, απαριθμήσουν, τροποποιήσουν ή διαγράψουν τα ίδια objects.
4. Object/registry/process/image callbacks, minifilter instances και hooks των οποίων οι διευθύνσεις δεν ανήκουν σε driver που απαριθμείται κανονικά.
5. Διαφορές μεταξύ απογραφών process, module, callback και δικτύου που βασίζονται σε λίστες και σε σαρώσεις.

## References

- [1] [Kaspersky Securelist - Το HoneyMyte ενισχύει το CoolClient με υπογεγραμμένο Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [README του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Αρχικοποίηση driver του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Γραμμή εντολών mapper του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Επίλυση kernel exports και βάσης PTE του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampoline κλήσης kernel του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Allocation και κλήση entry point του mapper του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [Χαρτογράφηση PE του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Πλαίσιο kernel και syscall του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrappers IOCTL εικονικής μνήμης του LocalStranger](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
