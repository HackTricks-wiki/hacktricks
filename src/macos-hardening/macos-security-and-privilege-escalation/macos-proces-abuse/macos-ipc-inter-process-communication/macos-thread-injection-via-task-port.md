# macOS Thread Injection μέσω Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Αρχικά, η συνάρτηση `task_threads()` καλείται στο task port για τη λήψη μιας λίστας threads από το remote task. Επιλέγεται ένα thread για hijacking. Αυτή η προσέγγιση διαφέρει από τις συμβατικές μεθόδους code-injection, καθώς η δημιουργία ενός νέου remote thread απαγορεύεται λόγω του mitigation που αποκλείει τη `thread_create_running()`.<sup>[[1]](#references)</sup>

Για τον έλεγχο του thread, καλείται η `thread_suspend()`, διακόπτοντας την εκτέλεσή του.<sup>[[1]](#references)</sup>

Οι μόνες επιτρεπόμενες λειτουργίες στο remote thread είναι η **διακοπή** και η **εκκίνησή** του, καθώς και η **ανάκτηση**/**τροποποίηση** των τιμών των registers του. Οι remote function calls ξεκινούν με την τοποθέτηση των **arguments** στα registers `x0` έως `x7`, τη ρύθμιση του `pc` ώστε να δείχνει στην επιθυμητή function και την επανεκκίνηση του thread. Για να διασφαλιστεί ότι το thread δεν θα καταρρεύσει μετά την επιστροφή, απαιτείται ο εντοπισμός της επιστροφής.<sup>[[1]](#references)</sup>

Μια στρατηγική είναι η καταχώριση ενός **exception handler** για το remote thread μέσω της `thread_set_exception_ports()`, με ρύθμιση του register `lr` σε μια μη έγκυρη διεύθυνση πριν από την κλήση της function. Αυτό προκαλεί ένα exception μετά την εκτέλεση της function, στέλνοντας ένα μήνυμα στο exception port και επιτρέποντας την επιθεώρηση της κατάστασης του thread για την ανάκτηση της return value. Εναλλακτικά, όπως υιοθετήθηκε από το exploit *triple_fetch* του Ian Beer, το `lr` ρυθμίζεται ώστε να εκτελεί loop επ’ άπειρον. Στη συνέχεια, τα registers του thread παρακολουθούνται συνεχώς μέχρι το `pc` να δείχνει σε αυτή την instruction.<sup>[[1]](#references)</sup>

## 2. Mach ports για communication

Η επόμενη φάση περιλαμβάνει τη δημιουργία Mach ports για τη διευκόλυνση της communication με το remote thread. Αυτά τα ports είναι απαραίτητα για τη μεταφορά αυθαίρετων send/receive rights μεταξύ tasks.<sup>[[1]](#references)</sup>

Για bidirectional communication, δημιουργούνται δύο Mach receive rights: ένα στο local και ένα στο remote task. Στη συνέχεια, ένα send right για κάθε port μεταφέρεται στο αντίστοιχο task, επιτρέποντας την ανταλλαγή messages.<sup>[[1]](#references)</sup>

Εστιάζοντας στο local port, το receive right διατηρείται από το local task. Το port δημιουργείται με `mach_port_allocate()`. Η πρόκληση έγκειται στη μεταφορά ενός send right προς αυτό το port μέσα στο remote task.<sup>[[1]](#references)</sup>

Μια στρατηγική περιλαμβάνει τη χρήση της `thread_set_special_port()` για την τοποθέτηση ενός send right προς το local port στο `THREAD_KERNEL_PORT` του remote thread. Στη συνέχεια, το remote thread καλείται να εκτελέσει τη `mach_thread_self()` για να ανακτήσει το send right.<sup>[[1]](#references)</sup>

Για το remote port, η διαδικασία είναι ουσιαστικά αντίστροφη. Το remote thread καθοδηγείται να δημιουργήσει ένα Mach port μέσω της `mach_reply_port()` (καθώς η `mach_port_allocate()` δεν είναι κατάλληλη λόγω του μηχανισμού επιστροφής της). Μετά τη δημιουργία του port, καλείται η `mach_port_insert_right()` στο remote thread για τη δημιουργία ενός send right. Αυτό το right αποθηκεύεται στη συνέχεια στον kernel μέσω της `thread_set_special_port()`. Πίσω στο local task, χρησιμοποιείται η `thread_get_special_port()` στο remote thread για την απόκτηση ενός send right προς το νεοδημιουργημένο Mach port στο remote task.<sup>[[1]](#references)</sup>

Η ολοκλήρωση αυτών των βημάτων έχει ως αποτέλεσμα τη δημιουργία Mach ports, θέτοντας τις βάσεις για bidirectional communication.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Σε αυτή την ενότητα, η εστίαση είναι στη χρήση του execute primitive για τη δημιουργία βασικών memory read/write primitives. Αυτά τα αρχικά βήματα είναι κρίσιμα για την απόκτηση μεγαλύτερου ελέγχου πάνω στο remote process, αν και τα primitives σε αυτό το στάδιο δεν θα έχουν πολλές χρήσεις. Σύντομα, θα αναβαθμιστούν σε πιο προηγμένες εκδόσεις.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Ο στόχος είναι η ανάγνωση και εγγραφή memory με τη χρήση συγκεκριμένων functions. Για **reading memory**:
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
### Εντοπισμός κατάλληλων συναρτήσεων

Μια σάρωση κοινών βιβλιοθηκών αποκάλυψε κατάλληλους υποψηφίους για αυτές τις λειτουργίες:<sup>[[1]](#references)</sup>

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
Με αυτά τα primitives καθορισμένα, το στάδιο είναι έτοιμο για τη δημιουργία shared memory, σηματοδοτώντας σημαντική πρόοδο στον έλεγχο του remote process.<sup>[[1]](#references)</sup>

## 4. Ρύθμιση Shared Memory

Στόχος είναι η εγκαθίδρυση shared memory μεταξύ local και remote tasks, απλοποιώντας τη μεταφορά δεδομένων και διευκολύνοντας την κλήση functions με πολλαπλά arguments. Η προσέγγιση αξιοποιεί το `libxpc` και τον τύπο object `OS_xpc_shmem`, ο οποίος βασίζεται σε Mach memory entries.<sup>[[1]](#references)</sup>

### Επισκόπηση της διαδικασίας

1. **Κατανομή μνήμης**
* Κατανομή μνήμης για sharing με χρήση του `mach_vm_allocate()`.
* Χρήση του `xpc_shmem_create()` για τη δημιουργία ενός object `OS_xpc_shmem` για την allocated περιοχή.
2. **Δημιουργία shared memory στο remote process**
* Κατανομή μνήμης για το object `OS_xpc_shmem` στο remote process (`remote_malloc`).
* Αντιγραφή του local template object· απαιτείται ακόμη fix-up του embedded Mach send right στο offset `0x18`.
3. **Διόρθωση του Mach memory entry**
* Εισαγωγή send right με `thread_set_special_port()` και overwrite του πεδίου `0x18` με το name του remote entry.
4. **Ολοκλήρωση**
* Επικύρωση του remote object και mapping του με remote call στο `xpc_shmem_remote()`.

## 5. Επίτευξη Πλήρους Ελέγχου

Μόλις είναι διαθέσιμα arbitrary execution και ένα shared-memory back-channel, ουσιαστικά αποκτάτε τον πλήρη έλεγχο του target process:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — χρήση του `memcpy()` μεταξύ local και shared περιοχών.
* **Function calls με > 8 args** — τοποθέτηση των επιπλέον arguments στο stack σύμφωνα με το arm64 calling convention.
* **Mach port transfer** — μεταφορά rights σε Mach messages μέσω των established ports.
* **File-descriptor transfer** — αξιοποίηση των fileports (δείτε το *triple_fetch*).

Όλα αυτά περιλαμβάνονται στη library [`threadexec`](https://github.com/bazad/threadexec) για εύκολη επαναχρησιμοποίηση.

---

## 6. Nuances του Apple Silicon (arm64e)

Σε συσκευές Apple Silicon (arm64e), τα **Pointer Authentication Codes (PAC)** προστατεύουν όλες τις return addresses και πολλά function pointers. Οι τεχνικές thread-hijacking που *reuse existing code* εξακολουθούν να λειτουργούν, επειδή οι αρχικές τιμές στα `lr`/`pc` φέρουν ήδη έγκυρες PAC signatures. Προβλήματα προκύπτουν όταν προσπαθείτε να κάνετε jump σε memory που ελέγχεται από τον attacker:

1. Κατανομή executable memory μέσα στο target (`mach_vm_allocate` + `mprotect(PROT_EXEC)` στο remote).
2. Αντιγραφή του payload σας.
3. Μέσα στο *remote* process, υπογραφή του pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ορίστε το `pc = ptr` στην κατάσταση του hijacked thread.

Εναλλακτικά, παραμείνετε συμβατοί με το PAC, συνδέοντας υπάρχοντα gadgets/functions (traditional ROP).

## 7. Ανίχνευση και Hardening με το EndpointSecurity

Το **EndpointSecurity (ES)** framework εκθέτει kernel events που επιτρέπουν στους defenders να παρατηρούν ή να μπλοκάρουν απόπειρες thread-injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – ενεργοποιείται όταν ένα process ζητά το port ενός άλλου task (π.χ. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – εκπέμπεται κάθε φορά που δημιουργείται ένα thread σε διαφορετικό task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (προστέθηκε στο macOS 14 Sonoma) – υποδεικνύει manipulation των registers ενός υπάρχοντος thread.

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
Ερωτήματα με **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Ζητήματα Hardened Runtime

Η διανομή της εφαρμογής σας **χωρίς** το entitlement `com.apple.security.get-task-allow` εμποδίζει non-root attackers να αποκτήσουν το task-port της. Το System Integrity Protection (SIP) εξακολουθεί να αποκλείει την πρόσβαση σε πολλά Apple binaries, αλλά το λογισμικό τρίτων πρέπει να κάνει ρητά opt-out.

## 8. Πρόσφατα Public Tools (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC που επιδεικνύει PAC-aware thread hijacking σε Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity helper που χρησιμοποιείται από αρκετούς EDR vendors για την εμφάνιση events `REMOTE_THREAD_CREATE` |

> Η ανάγνωση του source code αυτών των projects είναι χρήσιμη για την κατανόηση των αλλαγών στα API που εισήχθησαν στα macOS 13/14 και για τη διατήρηση συμβατότητας μεταξύ Intel ↔ Apple Silicon.

## Παραπομπές

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
