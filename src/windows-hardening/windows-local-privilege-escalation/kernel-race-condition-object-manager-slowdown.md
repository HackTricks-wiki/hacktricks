# Kernel Race Condition Exploitation μέσω Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία η επιμήκυνση του race window

Πολλά Windows kernel LPEs ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο hardware ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε ~2 µs, αφήνοντας σχεδόν καθόλου χρόνο για να αλλάξει η ελεγχόμενη κατάσταση πριν εκτελεστεί η ασφαλής ενέργεια. Με το σκόπιμο να καθυστερήσουμε την αναζήτηση στο Object Manager Namespace (OMNS) στο βήμα 2 ώστε να διαρκεί δεκάδες μικροδευτερόλεπτα, ο επιτιθέμενος αποκτά αρκετό χρόνο για να κερδίζει σταθερά αγώνες (races) που αλλιώς θα ήταν ασταθείς, χωρίς να χρειάζονται χιλιάδες προσπάθειες.

## Εσωτερικά της αναζήτησης του Object Manager με λίγα λόγια

* **OMNS structure** – Ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται κατά κατάλογο. Κάθε συνιστώσα αναγκάζει τον kernel να βρει/ανοίξει έναν *Object Directory* και να συγκρίνει συμβολοσειρές Unicode. Συμβολικοί σύνδεσμοι (π.χ., γράμματα δίσκων) μπορεί να διασχιστούν στην πορεία.
* **UNICODE_STRING limit** – Οι OM διαδρομές μεταφέρονται μέσα σε ένα `UNICODE_STRING` του οποίου το `Length` είναι μια 16-bit τιμή. Το απόλυτο όριο είναι 65 535 bytes (32 767 μονάδες κώδικα UTF-16). Με προθέματα όπως `\BaseNamedObjects\`, ο επιτιθέμενος εξακολουθεί να ελέγχει ≈32 000 χαρακτήρες.
* **Attacker prerequisites** – Οποιοσδήποτε χρήστης μπορεί να δημιουργήσει αντικείμενα κάτω από εγγράψιμους καταλόγους όπως `\BaseNamedObjects`. Όταν ο ευπαθής κώδικας χρησιμοποιεί ένα όνομα εκεί μέσα, ή ακολουθεί έναν συμβολικό σύνδεσμο που καταλήγει εκεί, ο επιτιθέμενος ελέγχει την απόδοση της αναζήτησης χωρίς ειδικά προνόμια.

## Slowdown primitive #1 – Single maximal component

Το κόστος επίλυσης μιας συνιστώσας είναι περίπου γραμμικό σε σχέση με το μήκος της, επειδή ο kernel πρέπει να εκτελέσει μια σύγκριση Unicode απέναντι σε κάθε εγγραφή στον γονικό κατάλογο. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει άμεσα την καθυστέρηση του `NtOpenEvent` από ~2 µs σε ~35 µs σε Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Πρακτικές σημειώσεις*

- Μπορείτε να φτάσετε το όριο μήκους χρησιμοποιώντας οποιοδήποτε ονομασμένο kernel object (events, sections, semaphores…).
- Symbolic links ή reparse points μπορούν να δείξουν ένα σύντομο “victim” όνομα σε αυτό το γιγαντιαίο component ώστε η επιβράδυνση να εφαρμόζεται διαφανώς.
- Επειδή όλα υπάρχουν σε user-writable namespaces, το payload λειτουργεί από ένα standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Μια πιο επιθετική παραλλαγή δημιουργεί μια αλυσίδα χιλιάδων καταλόγων (`\BaseNamedObjects\A\A\...\X`). Κάθε βήμα ενεργοποιεί τη λογική επίλυσης καταλόγου (ACL checks, hash lookups, reference counting), οπότε η καθυστέρηση ανά επίπεδο είναι μεγαλύτερη από μια απλή σύγκριση συμβολοσειράς. Με ~16 000 επίπεδα (περιορισμένα από το ίδιο μέγεθος `UNICODE_STRING`), οι εμπειρικές μετρήσεις χρόνου ξεπερνούν το όριο των 35 µs που επιτυγχάνεται από τα μεγάλα μεμονωμένα components.
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
Συμβουλές:

* Εναλλάσσετε τον χαρακτήρα ανά επίπεδο (`A/B/C/...`) αν ο γονικός κατάλογος αρχίσει να απορρίπτει τα διπλότυπα.
* Κρατήστε έναν πίνακα handle ώστε να μπορείτε να διαγράψετε την αλυσίδα καθαρά μετά την εκμετάλλευση, για να αποφύγετε τη ρύπανση του namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (λεπτά αντί για μικροδευτερόλεπτα)

Object directories support **shadow directories** (fallback lookups) and bucketed hash tables for entries. Abuse both plus the 64-component symbolic-link reparse limit to multiply slowdown without exceeding the `UNICODE_STRING` length:

1. Create two directories under `\BaseNamedObjects`, e.g. `A` (shadow) and `A\A` (target). Create the second using the first as the shadow directory (`NtCreateDirectoryObjectEx`), so missing lookups in `A` fall through to `A\A`.
2. Fill each directory with thousands of **colliding names** that land in the same hash bucket (e.g., varying trailing digits while keeping the same `RtlHashUnicodeString` value). Lookups now degrade to O(n) linear scans inside a single directory.
3. Build a chain of ~63 **object manager symbolic links** that repeatedly reparse into the long `A\A\…` suffix, consuming the reparse budget. Each reparse restarts parsing from the top, multiplying the collision cost.
4. Lookup of the final component (`...\\0`) now takes **λεπτά** on Windows 11 when 16 000 collisions are present per directory, providing a practically guaranteed race win for one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Γιατί έχει σημασία*: Μια καθυστέρηση διάρκειας λεπτών μετατρέπει τα one-shot race-based LPEs σε deterministic exploits.

### 2025 retest notes & ready-made tooling

- James Forshaw republished the technique with updated timings on Windows 11 24H2 (ARM64). Baseline opens remain ~2 µs; a 32 kB component raises this to ~35 µs, and shadow-dir + collision + 63-reparse chains still reach ~3 minutes, confirming the primitives survive current builds. Source code and perf harness are in the refreshed Project Zero post.
- You can script setup using the public `symboliclink-testing-tools` bundle: `CreateObjectDirectory.exe` to spawn the shadow/target pair and `NativeSymlink.exe` in a loop to emit the 63-hop chain. This avoids hand-written `NtCreate*` wrappers and keeps ACLs consistent.

## Measuring your race window

Embed a quick harness inside your exploit to measure how large the window becomes on the victim hardware. The snippet below opens the target object `iterations` times and returns the average per-open cost using `QueryPerformanceCounter`.
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
Τα αποτελέσματα τροφοδοτούν άμεσα τη στρατηγική ορχήστρωσης του race (π.χ., αριθμός των worker threads που χρειάζονται, sleep intervals, πόσο νωρίς πρέπει να flip-άρετε την shared state).

## Ροή εκμετάλλευσης

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Create the long component or directory chain under `\BaseNamedObjects` (or another writable OM root).
- Create a symbolic link so that the name the kernel expects now resolves to the slow path. You can point the vulnerable driver’s directory lookup to your structure without touching the original target.
3. **Trigger the race**
- Thread A (victim) executes the vulnerable code and blocks inside the slow lookup.
- Thread B (attacker) flips the guarded state (e.g., swaps a file handle, rewrites a symbolic link, toggles object security) while Thread A is occupied.
- When Thread A resumes and performs the privileged action, it observes stale state and performs the attacker-controlled operation.
4. **Clean up** – Delete the directory chain and symbolic links to avoid leaving suspicious artifacts or breaking legitimate IPC users.

## Λειτουργικές επισημάνσεις

- **Combine primitives** – Μπορείτε να χρησιμοποιήσετε ένα μεγάλο όνομα *per level* σε μια αλυσίδα καταλόγων για ακόμη υψηλότερη καθυστέρηση μέχρι να εξαντλήσετε το `UNICODE_STRING` μέγεθος.
- **One-shot bugs** – Το επεκταμένο παράθυρο (δεκάδες μικροδευτερόλεπτα έως λεπτά) κάνει τα “single trigger” bugs ρεαλιστικά όταν συνδυάζονται με CPU affinity pinning ή hypervisor-assisted preemption.
- **Side effects** – Η επιβράδυνση επηρεάζει μόνο τη malicious path, οπότε η συνολική απόδοση του συστήματος παραμένει ανεπηρέαστη· οι defenders σπάνια θα το παρατηρήσουν εκτός αν παρακολουθούν την ανάπτυξη του namespace.
- **Cleanup** – Κρατήστε handles για κάθε directory/object που δημιουργείτε ώστε να μπορείτε να καλέσετε `NtMakeTemporaryObject`/`NtClose` αργότερα. Διαφορετικά, απεριόριστες αλυσίδες καταλόγων μπορεί να επιμείνουν μετά από reboots.
- **File-system races** – Αν το ευάλωτο path τελικά επιλύεται μέσω NTFS, μπορείτε να στοιβάξετε ένα Oplock (π.χ., `SetOpLock.exe` από το ίδιο toolkit) στο backing file ενώ τρέχει το OM slowdown, παγώνοντας τον consumer για επιπλέον milliseconds χωρίς να αλλάξετε το OM graph.

## Αμυντικές σημειώσεις

- Ο kernel κώδικας που βασίζεται σε named objects θα πρέπει να επαληθεύει εκ νέου την security-sensitive κατάσταση *μετά* το open, ή να παίρνει ένα reference πριν τον έλεγχο (κλείνοντας το TOCTOU κενό).
- Επιβάλετε ανώτατα όρια στο OM path depth/length πριν το dereference των user-controlled ονομάτων. Η απόρριψη υπερβολικά μακρών ονομάτων αναγκάζει τους attackers πίσω στο παράθυρο των microseconds.
- Instrument το growth του object manager namespace (ETW `Microsoft-Windows-Kernel-Object`) για να εντοπίζετε ύποπτες αλυσίδες με χιλιάδες components κάτω από `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
