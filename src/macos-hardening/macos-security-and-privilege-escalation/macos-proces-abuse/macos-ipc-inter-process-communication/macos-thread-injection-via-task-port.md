# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Αρχικά, η συνάρτηση `task_threads()` καλείται στο task port για τη λήψη μιας λίστας threads από το remote task. Επιλέγεται ένα thread για hijacking. Αυτή η προσέγγιση διαφέρει από τις συμβατικές μεθόδους code-injection, καθώς η δημιουργία ενός νέου remote thread απαγορεύεται λόγω του mitigation που αποκλείει τη `thread_create_running()`.<sup>[[1]](#references)</sup>

Για τον έλεγχο του thread, καλείται η `thread_suspend()`, η οποία διακόπτει την εκτέλεσή του.<sup>[[1]](#references)</sup>

Οι μόνες επιτρεπόμενες λειτουργίες στο remote thread είναι η **διακοπή** και η **εκκίνησή** του, καθώς και η **ανάκτηση**/**τροποποίηση** των τιμών των registers του. Οι remote function calls ξεκινούν με τη ρύθμιση των registers `x0` έως `x7` στα **arguments**, τη ρύθμιση του `pc` ώστε να δείχνει στην επιθυμητή function και τη συνέχιση της εκτέλεσης του thread. Για να διασφαλιστεί ότι το thread δεν θα καταρρεύσει μετά την επιστροφή, απαιτείται ο εντοπισμός της.<sup>[[1]](#references)</sup>

Μια στρατηγική περιλαμβάνει την καταχώριση ενός **exception handler** για το remote thread μέσω της `thread_set_exception_ports()`, με τη ρύθμιση του register `lr` σε μια μη έγκυρη διεύθυνση πριν από την κλήση της function. Αυτό προκαλεί exception μετά την εκτέλεση της function, στέλνοντας ένα μήνυμα στο exception port και επιτρέποντας την επιθεώρηση της κατάστασης του thread για την ανάκτηση της τιμής επιστροφής. Εναλλακτικά, όπως υιοθετήθηκε από το exploit *triple_fetch* του Ian Beer, το `lr` ρυθμίζεται ώστε να εκτελεί loop επ’ άπειρον. Στη συνέχεια, τα registers του thread παρακολουθούνται συνεχώς μέχρι το `pc` να δείχνει σε αυτή την instruction.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Η επόμενη φάση περιλαμβάνει τη δημιουργία Mach ports για τη διευκόλυνση της επικοινωνίας με το remote thread. Αυτά τα ports είναι απαραίτητα για τη μεταφορά αυθαίρετων send/receive rights μεταξύ tasks.<sup>[[1]](#references)</sup>

Για αμφίδρομη επικοινωνία, δημιουργούνται δύο Mach receive rights: ένα στο local task και ένα στο remote task. Στη συνέχεια, ένα send right για κάθε port μεταφέρεται στο αντίστοιχο task, επιτρέποντας την ανταλλαγή μηνυμάτων.<sup>[[1]](#references)</sup>

Εστιάζοντας στο local port, το receive right διατηρείται από το local task. Το port δημιουργείται με τη `mach_port_allocate()`. Η πρόκληση είναι η μεταφορά ενός send right προς αυτό το port στο remote task.<sup>[[1]](#references)</sup>

Μια στρατηγική περιλαμβάνει τη χρήση της `thread_set_special_port()` για την τοποθέτηση ενός send right προς το local port στο `THREAD_KERNEL_PORT` του remote thread. Στη συνέχεια, δίνεται εντολή στο remote thread να καλέσει τη `mach_thread_self()` για την ανάκτηση του send right.<sup>[[1]](#references)</sup>

Για το remote port, η διαδικασία αντιστρέφεται ουσιαστικά. Το remote thread κατευθύνεται να δημιουργήσει ένα Mach port μέσω της `mach_reply_port()` (καθώς η `mach_port_allocate()` δεν είναι κατάλληλη λόγω του μηχανισμού επιστροφής της). Μετά τη δημιουργία του port, καλείται η `mach_port_insert_right()` στο remote thread για τη δημιουργία ενός send right. Αυτό το right αποθηκεύεται προσωρινά στον kernel μέσω της `thread_set_special_port()`. Πίσω στο local task, χρησιμοποιείται η `thread_get_special_port()` στο remote thread για την απόκτηση ενός send right προς το νεοδημιουργημένο Mach port στο remote task.<sup>[[1]](#references)</sup>

Η ολοκλήρωση αυτών των βημάτων έχει ως αποτέλεσμα τη δημιουργία των Mach ports, θέτοντας τις βάσεις για αμφίδρομη επικοινωνία.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Σε αυτή την ενότητα, η εστίαση βρίσκεται στη χρήση του execute primitive για τη δημιουργία βασικών memory read/write primitives. Αυτά τα αρχικά βήματα είναι κρίσιμα για την απόκτηση μεγαλύτερου ελέγχου επί του remote process, αν και τα primitives σε αυτό το στάδιο δεν θα έχουν πολλές χρήσεις. Σύντομα, θα αναβαθμιστούν σε πιο προηγμένες εκδόσεις.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Ο στόχος είναι η ανάγνωση και η εγγραφή μνήμης με τη χρήση συγκεκριμένων functions. Για **ανάγνωση μνήμης**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Για **εγγραφή στη μνήμη**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Αυτές οι συναρτήσεις αντιστοιχούν στο ακόλουθο assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Εντοπισμός κατάλληλων functions

Μια σάρωση κοινών libraries αποκάλυψε κατάλληλους candidates για αυτές τις operations:<sup>[[1]](#references)</sup>

1. **Ανάγνωση memory — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Εγγραφή μνήμης — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Για να εκτελέσετε εγγραφή 64-bit σε αυθαίρετη διεύθυνση:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Με αυτά τα primitives καθιερωμένα, το έδαφος είναι πλέον έτοιμο για τη δημιουργία shared memory, γεγονός που σηματοδοτεί σημαντική πρόοδο στον έλεγχο της remote process.<sup>[[1]](#references)</sup>

## 4. Ρύθμιση Shared Memory

Στόχος είναι η εγκαθίδρυση shared memory μεταξύ των local και remote tasks, απλοποιώντας τη μεταφορά δεδομένων και διευκολύνοντας την κλήση functions με πολλαπλά arguments. Η προσέγγιση αξιοποιεί το `libxpc` και τον τύπο object `OS_xpc_shmem`, ο οποίος βασίζεται σε Mach memory entries.<sup>[[1]](#references)</sup>

### Επισκόπηση της διαδικασίας

1. **Κατανομή μνήμης**
* Διάθεση μνήμης για sharing με χρήση της `mach_vm_allocate()`.
* Χρήση της `xpc_shmem_create()` για τη δημιουργία ενός object `OS_xpc_shmem` για την allocated region.
2. **Δημιουργία shared memory στη remote process**
* Διάθεση μνήμης για το object `OS_xpc_shmem` στη remote process (`remote_malloc`).
* Αντιγραφή του local template object· απαιτείται ακόμη fix-up του embedded Mach send right στο offset `0x18`.
3. **Διόρθωση του Mach memory entry**
* Εισαγωγή ενός send right με `thread_set_special_port()` και overwrite του πεδίου `0x18` με το name του remote entry.
4. **Ολοκλήρωση**
* Validation του remote object και mapping του με remote call προς τη `xpc_shmem_remote()`.

## 5. Επίτευξη Πλήρους Ελέγχου

Μόλις είναι διαθέσιμα η arbitrary execution και ένα shared-memory back-channel, ουσιαστικά αποκτάτε τον πλήρη έλεγχο της target process:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — χρήση της `memcpy()` μεταξύ local και shared regions.
* **Function calls με > 8 args** — τοποθέτηση των επιπλέον arguments στο stack σύμφωνα με το arm64 calling convention.
* **Mach port transfer** — μεταφορά rights σε Mach messages μέσω των established ports.
* **File-descriptor transfer** — αξιοποίηση των fileports (δείτε το *triple_fetch*).

Όλα αυτά περιλαμβάνονται στη library [`threadexec`](https://github.com/bazad/threadexec) για εύκολη επαναχρησιμοποίηση.

---

## 6. Nuances του Apple Silicon (arm64e)

Σε συσκευές Apple Silicon (arm64e), τα **Pointer Authentication Codes (PAC)** προστατεύουν όλες τις return addresses και πολλά function pointers. Οι τεχνικές thread-hijacking που *επαναχρησιμοποιούν υπάρχοντα code* συνεχίζουν να λειτουργούν, επειδή οι αρχικές τιμές στα `lr`/`pc` διαθέτουν ήδη έγκυρες PAC signatures. Προβλήματα προκύπτουν όταν προσπαθείτε να κάνετε jump σε attacker-controlled memory:

1. Διάθεση executable memory μέσα στην target process (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Αντιγραφή του payload σας.
3. Μέσα στη *remote* process, υπογραφή του pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ορίστε `pc = ptr` στο state του hijacked thread.

Εναλλακτικά, παραμείνετε PAC-compliant συνδέοντας υπάρχοντα gadgets/functions (παραδοσιακό ROP).

## 7. Detection & Hardening με EndpointSecurity

Το framework **EndpointSecurity (ES)** εκθέτει kernel events που επιτρέπουν στους defenders να παρατηρούν ή να μπλοκάρουν απόπειρες thread-injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – ενεργοποιείται όταν μια process ζητά το port ενός άλλου task (π.χ. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – εκπέμπεται κάθε φορά που δημιουργείται ένα thread σε *διαφορετικό* task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (προστέθηκε στο macOS 14 Sonoma) – υποδεικνύει manipulation των registers ενός υπάρχοντος thread.

Minimal Swift client που εκτυπώνει events για remote threads:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Εκτέλεση ερωτημάτων με το **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Παράγοντες του hardened runtime

Η διανομή της εφαρμογής σας **χωρίς** το entitlement `com.apple.security.get-task-allow` εμποδίζει attackers χωρίς root να αποκτήσουν το task-port της. Το System Integrity Protection (SIP) εξακολουθεί να αποκλείει την πρόσβαση σε πολλά Apple binaries, αλλά το λογισμικό τρίτων πρέπει να κάνει opt-out ρητά.

## 8. Πρόσφατα Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC που επιδεικνύει PAC-aware thread hijacking σε Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper που χρησιμοποιείται από αρκετούς EDR vendors για την ανίχνευση events `REMOTE_THREAD_CREATE` |

> Η ανάγνωση του source code αυτών των projects είναι χρήσιμη για την κατανόηση των αλλαγών στα APIs που εισήχθησαν στα macOS 13/14 και για τη διατήρηση συμβατότητας μεταξύ Intel ↔ Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
