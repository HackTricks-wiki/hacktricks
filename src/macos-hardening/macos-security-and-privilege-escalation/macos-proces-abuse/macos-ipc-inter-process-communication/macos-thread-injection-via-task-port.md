# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Αρχικά, η συνάρτηση `task_threads()` καλείται στο task port για τη λήψη μιας λίστας threads από το remote task. Επιλέγεται ένα thread για hijacking. Αυτή η προσέγγιση διαφέρει από τις συμβατικές μεθόδους code injection, καθώς η δημιουργία ενός νέου remote thread απαγορεύεται λόγω του mitigation που αποκλείει τη `thread_create_running()`.<sup>[[1]](#references)</sup>

Για τον έλεγχο του thread, καλείται η `thread_suspend()`, διακόπτοντας την εκτέλεσή του.<sup>[[1]](#references)</sup>

Οι μόνες επιτρεπόμενες λειτουργίες στο remote thread περιλαμβάνουν το **stopping** και το **starting** του, καθώς και την **ανάκτηση**/**τροποποίηση** των register values του. Οι remote function calls ξεκινούν με την τοποθέτηση των `arguments` στα registers `x0` έως `x7`, τη ρύθμιση του `pc` ώστε να δείχνει στην επιθυμητή function και την επανεκκίνηση του thread. Για να διασφαλιστεί ότι το thread δεν θα καταρρεύσει μετά την επιστροφή, απαιτείται ο εντοπισμός της return.<sup>[[1]](#references)</sup>

Μια στρατηγική περιλαμβάνει την καταχώριση ενός **exception handler** για το remote thread με χρήση της `thread_set_exception_ports()`, καθώς και τη ρύθμιση του register `lr` σε μια invalid address πριν από την κλήση της function. Αυτό προκαλεί ένα exception μετά την εκτέλεση της function, στέλνοντας ένα message στο exception port και επιτρέποντας την επιθεώρηση της κατάστασης του thread για την ανάκτηση της return value. Εναλλακτικά, όπως υιοθετήθηκε από το exploit *triple_fetch* του Ian Beer, το `lr` ρυθμίζεται ώστε να εκτελεί loop επ’ αόριστον· στη συνέχεια, τα registers του thread παρακολουθούνται συνεχώς μέχρι το `pc` να δείξει σε αυτή την instruction.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Η επόμενη φάση περιλαμβάνει τη δημιουργία Mach ports για τη διευκόλυνση της επικοινωνίας με το remote thread. Αυτά τα ports είναι απαραίτητα για τη μεταφορά αυθαίρετων send/receive rights μεταξύ tasks.<sup>[[1]](#references)</sup>

Για bidirectional communication, δημιουργούνται δύο Mach receive rights: ένα στο local task και ένα στο remote task. Στη συνέχεια, ένα send right για κάθε port μεταφέρεται στο αντίστοιχο task, επιτρέποντας την ανταλλαγή messages.<sup>[[1]](#references)</sup>

Εστιάζοντας στο local port, το receive right διατηρείται από το local task. Το port δημιουργείται με τη `mach_port_allocate()`. Η πρόκληση είναι η μεταφορά ενός send right προς αυτό το port στο remote task.<sup>[[1]](#references)</sup>

Μια στρατηγική περιλαμβάνει την αξιοποίηση της `thread_set_special_port()` για την τοποθέτηση ενός send right προς το local port στο `THREAD_KERNEL_PORT` του remote thread. Στη συνέχεια, το remote thread καθοδηγείται να καλέσει τη `mach_thread_self()` για την ανάκτηση του send right.<sup>[[1]](#references)</sup>

Για το remote port, η διαδικασία είναι ουσιαστικά αντίστροφη. Το remote thread καθοδηγείται να δημιουργήσει ένα Mach port μέσω της `mach_reply_port()` (καθώς η `mach_port_allocate()` είναι ακατάλληλη λόγω του μηχανισμού επιστροφής της). Μετά τη δημιουργία του port, καλείται η `mach_port_insert_right()` στο remote thread για τη δημιουργία ενός send right. Αυτό το right αποθηκεύεται στη συνέχεια στον kernel μέσω της `thread_set_special_port()`. Πίσω στο local task, η `thread_get_special_port()` χρησιμοποιείται στο remote thread για την απόκτηση ενός send right προς το νεοδημιουργημένο Mach port στο remote task.<sup>[[1]](#references)</sup>

Η ολοκλήρωση αυτών των βημάτων έχει ως αποτέλεσμα τη δημιουργία των Mach ports, θέτοντας τις βάσεις για bidirectional communication.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Σε αυτή την ενότητα, η εστίαση είναι στη χρήση του execute primitive για τη δημιουργία βασικών memory read/write primitives. Αυτά τα αρχικά βήματα είναι κρίσιμα για την απόκτηση μεγαλύτερου ελέγχου πάνω στο remote process, αν και τα primitives σε αυτό το στάδιο δεν θα έχουν πολλές χρήσεις. Σύντομα, θα αναβαθμιστούν σε πιο προηγμένες εκδόσεις.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Ο στόχος είναι η ανάγνωση και η εγγραφή memory με τη χρήση συγκεκριμένων functions. Για **reading memory**:
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
Οι παρακάτω συναρτήσεις αντιστοιχούν στο ακόλουθο assembly:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Εντοπισμός κατάλληλων συναρτήσεων

Μια σάρωση των κοινών βιβλιοθηκών αποκάλυψε κατάλληλους υποψήφιους για αυτές τις λειτουργίες:<sup>[[1]](#references)</sup>

1. **Ανάγνωση μνήμης — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Εγγραφή στη μνήμη — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Για να εκτελέσετε εγγραφή 64-bit σε αυθαίρετη διεύθυνση:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Με αυτά τα primitives καθορισμένα, το στάδιο είναι έτοιμο για τη δημιουργία κοινόχρηστης μνήμης, σηματοδοτώντας σημαντική πρόοδο στον έλεγχο της remote process.<sup>[[1]](#references)</sup>

## 4. Ρύθμιση κοινόχρηστης μνήμης

Ο στόχος είναι η δημιουργία κοινόχρηστης μνήμης μεταξύ των local και remote tasks, απλοποιώντας τη μεταφορά δεδομένων και διευκολύνοντας την κλήση functions με πολλαπλά arguments. Η προσέγγιση αξιοποιεί το `libxpc` και τον τύπο object `OS_xpc_shmem`, ο οποίος βασίζεται σε Mach memory entries.<sup>[[1]](#references)</sup>

### Επισκόπηση της διαδικασίας

1. **Κατανομή μνήμης**
* Δεσμεύστε μνήμη για sharing χρησιμοποιώντας τη `mach_vm_allocate()`.
* Χρησιμοποιήστε τη `xpc_shmem_create()` για να δημιουργήσετε ένα object `OS_xpc_shmem` για την allocated region.
2. **Δημιουργία κοινόχρηστης μνήμης στη remote process**
* Δεσμεύστε μνήμη για το object `OS_xpc_shmem` στη remote process (`remote_malloc`).
* Αντιγράψτε το local template object· απαιτείται ακόμη fix-up του embedded Mach send right στο offset `0x18`.
3. **Διόρθωση του Mach memory entry**
* Εισαγάγετε ένα send right με τη `thread_set_special_port()` και αντικαταστήστε το πεδίο `0x18` με το όνομα του remote entry.
4. **Ολοκλήρωση**
* Επικυρώστε το remote object και κάντε map σε αυτό με remote call στη `xpc_shmem_remote()`.

## 5. Επίτευξη πλήρους ελέγχου

Μόλις είναι διαθέσιμα arbitrary execution και ένα shared-memory back-channel, ουσιαστικά έχετε τον πλήρη έλεγχο της target process:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — χρησιμοποιήστε τη `memcpy()` μεταξύ local και shared regions.
* **Function calls με > 8 args** — τοποθετήστε τα επιπλέον arguments στο stack σύμφωνα με το arm64 calling convention.
* **Mach port transfer** — μεταφέρετε rights σε Mach messages μέσω των established ports.
* **File-descriptor transfer** — αξιοποιήστε τα fileports (δείτε το *triple_fetch*).

Όλα αυτά είναι ενσωματωμένα στη library [`threadexec`](https://github.com/bazad/threadexec) για εύκολη επαναχρησιμοποίηση.

---

## 6. Ιδιαιτερότητες του Apple Silicon (arm64e)

Σε συσκευές Apple Silicon (arm64e), οι **Pointer Authentication Codes (PAC)** προστατεύουν όλες τις return addresses και πολλά function pointers. Οι τεχνικές thread-hijacking που *επαναχρησιμοποιούν υπάρχοντα code* συνεχίζουν να λειτουργούν, επειδή οι αρχικές τιμές στα `lr`/`pc` περιέχουν ήδη έγκυρες PAC signatures. Τα προβλήματα προκύπτουν όταν προσπαθείτε να κάνετε jump σε memory που ελέγχεται από τον attacker:

1. Δεσμεύστε executable memory μέσα στην target process (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Αντιγράψτε το payload σας.
3. Μέσα στη *remote* process υπογράψτε το pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ορίστε `pc = ptr` στην κατάσταση του hijacked thread.

Εναλλακτικά, παραμείνετε συμβατοί με το PAC, συνδέοντας υπάρχοντα gadgets/functions (traditional ROP).

## 7. Detection & Hardening with EndpointSecurity

Το framework **EndpointSecurity (ES)** εκθέτει kernel events που επιτρέπουν στους defenders να παρατηρούν ή να αποκλείουν απόπειρες thread injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – ενεργοποιείται όταν μια process ζητά το port ενός άλλου task (π.χ. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – εκπέμπεται κάθε φορά που δημιουργείται ένα thread σε *διαφορετικό* task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (προστέθηκε στο macOS 14 Sonoma) – υποδεικνύει χειραγώγηση registers ενός υπάρχοντος thread.

Minimal Swift client που εκτυπώνει remote-thread events:
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
### Παράγοντες του Hardened Runtime

Η διανομή της εφαρμογής σας **χωρίς** το entitlement `com.apple.security.get-task-allow` εμποδίζει μη-root attackers να αποκτήσουν το task-port της. Το System Integrity Protection (SIP) εξακολουθεί να αποκλείει την πρόσβαση σε πολλά Apple binaries, αλλά το λογισμικό τρίτων πρέπει να εξαιρεθεί ρητά.

## 8. Πρόσφατα Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Συμπαγές PoC που επιδεικνύει PAC-aware thread hijacking σε Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper που χρησιμοποιείται από αρκετούς EDR vendors για την εμφάνιση `REMOTE_THREAD_CREATE` events |

> Η μελέτη του source code αυτών των projects είναι χρήσιμη για την κατανόηση των αλλαγών στα APIs που εισήχθησαν στα macOS 13/14 και για τη διατήρηση συμβατότητας μεταξύ Intel ↔ Apple Silicon.

## References

- [1] [Παράκαμψη περιορισμών platform binary με task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Τεκμηρίωση Apple Developer](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
