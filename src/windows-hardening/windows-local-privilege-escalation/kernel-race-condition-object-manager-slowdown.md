# Εκμετάλλευση Kernel Race Condition μέσω Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί το να επιμηκύνεις το race window έχει σημασία

Πολλά Windows kernel LPEs ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο υλικό ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε ~2 µs, αφήνοντας σχεδόν μηδενικό χρόνο για να αλλάξει η ελεγχόμενη κατάσταση πριν εκτελεστεί η ασφαλής ενέργεια. Αναγκάζοντας σκοπίμως την αναζήτηση στο Object Manager Namespace (OMNS) στο βήμα 2 να διαρκέσει δεκάδες μικροδευτερόλεπτα, ο επιτιθέμενος κερδίζει αρκετό χρόνο για να κερδίζει σταθερά αλλιώς ασυνεπείς races χωρίς να χρειάζονται χιλιάδες προσπάθειες.

## Εσωτερικά της αναζήτησης του Object Manager — εν συντομία

* **OMNS structure** – Τα ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται κατά κατάλογο. Κάθε συστατικό αναγκάζει τον kernel να βρει/ανοίξει ένα *Object Directory* και να συγκρίνει Unicode strings. Symbolic links (π.χ. drive letters) μπορεί να διασχίζονται καθ’ οδόν.
* **UNICODE_STRING limit** – Τα OM paths μεταφέρονται μέσα σε ένα `UNICODE_STRING` του οποίου το `Length` είναι μια 16-bit τιμή. Το απόλυτο όριο είναι 65 535 bytes (32 767 UTF-16 codepoints). Με προθέματα όπως `\BaseNamedObjects\`, ο επιτιθέμενος εξακολουθεί να ελέγχει ≈32 000 χαρακτήρες.
* **Attacker prerequisites** – Οποιοσδήποτε χρήστης μπορεί να δημιουργήσει αντικείμενα κάτω από εγγράψιμους καταλόγους όπως `\BaseNamedObjects`. Όταν ο ευάλωτος κώδικας χρησιμοποιεί ένα όνομα εκεί μέσα, ή ακολουθεί ένα symbolic link που καταλήγει εκεί, ο επιτιθέμενος ελέγχει την απόδοση της αναζήτησης χωρίς ειδικά προνόμια.

## Μέθοδος επιβράδυνσης #1 — Μονή μέγιστη συνιστώσα

Το κόστος επίλυσης ενός component είναι περίπου γραμμικά ανάλογο με το μήκος του επειδή ο kernel πρέπει να πραγματοποιήσει μια Unicode σύγκριση σε κάθε εγγραφή στον γονικό κατάλογο. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει αμέσως τη λανθάνουσα κατάσταση του `NtOpenEvent` από ~2 µs σε ~35 µs σε Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Πρακτικές σημειώσεις*

- Μπορείτε να φτάσετε το όριο μήκους χρησιμοποιώντας οποιοδήποτε named kernel object (events, sections, semaphores…).
- Symbolic links ή reparse points μπορούν να δείξουν ένα σύντομο «victim» όνομα σε αυτό το γιγάντιο component ώστε το slowdown να εφαρμόζεται διαφανώς.
- Επειδή όλα βρίσκονται σε user-writable namespaces, το payload λειτουργεί από ένα standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Μια πιο επιθετική παραλλαγή δημιουργεί μια αλυσίδα χιλιάδων directories (`\BaseNamedObjects\A\A\...\X`). Κάθε hop ενεργοποιεί τη directory resolution logic (ACL checks, hash lookups, reference counting), οπότε η καθυστέρηση ανά επίπεδο είναι μεγαλύτερη από μια απλή string compare. Με ~16 000 επίπεδα (περιορισμένα από το ίδιο `UNICODE_STRING` μέγεθος), οι εμπειρικοί χρόνοι υπερβαίνουν το όριο των 35 µs που επιτυγχάνεται από long single components.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Tips:

* Εναλλάσσετε τον χαρακτήρα ανά επίπεδο (`A/B/C/...`) αν ο γονικός κατάλογος αρχίσει να απορρίπτει διπλότυπα.
* Κρατήστε έναν πίνακα handle ώστε να μπορείτε να διαγράψετε την αλυσίδα καθαρά μετά την exploitation για να αποφύγετε τη ρύπανση του namespace.

## Μέτρηση του race window

Ενσωματώστε ένα γρήγορο harness μέσα στο exploit σας για να μετρήσετε πόσο μεγάλο γίνεται το window στο hardware του θύματος. Το απόσπασμα παρακάτω ανοίγει το target object `iterations` φορές και επιστρέφει το μέσο κόστος ανά άνοιγμα χρησιμοποιώντας `QueryPerformanceCounter`.
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Τα αποτελέσματα τροφοδοτούν άμεσα τη στρατηγική ορχήστρωσης του race (π.χ., αριθμός νημάτων εργασίας που χρειάζονται, διαστήματα ύπνου, πόσο νωρίς πρέπει να αλλάξετε την κοινή κατάσταση).

## Exploitation workflow

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Create the long component or directory chain under `\BaseNamedObjects` (or another writable OM root).
- Create a symbolic link so that the name the kernel expects now resolves to the slow path. You can point the vulnerable driver’s directory lookup to your structure without touching the original target.
3. **Trigger the race**
- Thread A (victim) executes the vulnerable code and blocks inside the slow lookup.
- Thread B (attacker) flips the guarded state (e.g., swaps a file handle, rewrites a symbolic link, toggles object security) while Thread A is occupied.
- When Thread A resumes and performs the privileged action, it observes stale state and performs the attacker-controlled operation.
4. **Clean up** – Delete the directory chain and symbolic links to avoid leaving suspicious artifacts or breaking legitimate IPC users.

## Operational considerations

- **Combine primitives** – You can use a long name *per level* in a directory chain for even higher latency until you exhaust the `UNICODE_STRING` size.
- **One-shot bugs** – The expanded window (tens of microseconds) makes “single trigger” bugs realistic when paired with CPU affinity pinning or hypervisor-assisted preemption.
- **Side effects** – The slowdown only affects the malicious path, so overall system performance remains unaffected; defenders will rarely notice unless they monitor namespace growth.
- **Cleanup** – Keep handles to every directory/object you create so you can call `NtMakeTemporaryObject`/`NtClose` afterwards. Unbounded directory chains may persist across reboots otherwise.

## Defensive notes

- Kernel code that relies on named objects should re-validate security-sensitive state *after* the open, or take a reference before the check (closing the TOCTOU gap).
- Enforce upper bounds on OM path depth/length before dereferencing user-controlled names. Rejecting overly long names forces attackers back into the microsecond window.
- Instrument object manager namespace growth (ETW `Microsoft-Windows-Kernel-Object`) to detect suspicious thousands-of-components chains under `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
