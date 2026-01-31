# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί η διεύρυνση του race window έχει σημασία

Πολλά Windows kernel LPEs ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο hardware ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε ~2 µs, αφήνοντας σχεδόν καθόλου χρόνο για να αλλάξει η ελεγχόμενη κατάσταση πριν εκτελεστεί η ασφαλής ενέργεια. Με το σκόπιμο να αναγκάσει κανείς την αναζήτηση στο Object Manager Namespace (OMNS) στο βήμα 2 να διαρκέσει δεκάδες μικροδευτερόλεπτα, ο attacker αποκτά αρκετό χρόνο για να κερδίσει σταθερά αλλιώς ασταθείς races χωρίς να χρειάζεται χιλιάδες προσπάθειες.

## Object Manager lookup internals in a nutshell

* **OMNS structure** – Τα ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται κατά κατάλογο. Κάθε συστατικό αναγκάζει το kernel να βρει/ανοίξει έναν *Object Directory* και να συγκρίνει Unicode strings. Symbolic links (π.χ., drive letters) μπορούν να διασχιστούν στην πορεία.
* **UNICODE_STRING limit** – Οι OM διαδρομές μεταφέρονται μέσα σε ένα `UNICODE_STRING` του οποίου το `Length` είναι μια 16-bit τιμή. Το απόλυτο όριο είναι 65 535 bytes (32 767 UTF-16 codepoints). Με προθέματα όπως `\BaseNamedObjects\`, ο attacker εξακολουθεί να ελέγχει περίπου 32 000 χαρακτήρες.
* **Attacker prerequisites** – Οποιοσδήποτε user μπορεί να δημιουργήσει objects κάτω από writable directories όπως `\BaseNamedObjects`. Όταν ο vulnerable code χρησιμοποιεί ένα όνομα μέσα εκεί, ή ακολουθεί ένα symbolic link που καταλήγει εκεί, ο attacker ελέγχει την απόδοση της αναζήτησης χωρίς ειδικά privileges.

## Slowdown primitive #1 – Single maximal component

Το κόστος επίλυσης ενός συστατικού είναι περίπου γραμμικό ως προς το μήκος του, επειδή το kernel πρέπει να εκτελέσει μια Unicode σύγκριση σε κάθε καταχώρηση του γονικού καταλόγου. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει αμέσως την καθυστέρηση του `NtOpenEvent` από ~2 µs σε ~35 µs σε Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Symbolic links ή reparse points μπορούν να δείξουν ένα σύντομο “victim” όνομα σε αυτό το γιγάντιο component ώστε η επιβράδυνση να εφαρμόζεται διαφανώς.
- Επειδή όλα βρίσκονται σε user-writable namespaces, το payload λειτουργεί από ένα standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Μια πιο επιθετική παραλλαγή δημιουργεί μια αλυσίδα χιλιάδων καταλόγων (`\BaseNamedObjects\A\A\...\X`). Κάθε άλμα ενεργοποιεί τη λογική επίλυσης καταλόγων (ACL checks, hash lookups, reference counting), οπότε η καθυστέρηση ανά επίπεδο είναι υψηλότερη από μια απλή σύγκριση συμβολοσειράς. Με ~16 000 επίπεδα (περιορισμένα από το ίδιο `UNICODE_STRING` μέγεθος), οι εμπειρικές μετρήσεις ξεπερνούν το όριο των 35 µs που επιτυγχάνεται από μακριά μεμονωμένα components.
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

* Alternate the character per level (`A/B/C/...`) if the parent directory starts rejecting duplicates.
* Keep a handle array so you can delete the chain cleanly after exploitation to avoid polluting the namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

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
*Γιατί έχει σημασία*: Μια επιβράδυνση διάρκειας λεπτών μετατρέπει τα one-shot race-based LPEs σε deterministic exploits.

## Μέτρηση του race window

Ενσωματώστε ένα γρήγορο harness μέσα στο exploit σας για να μετρήσετε πόσο μεγάλο γίνεται το παράθυρο στο hardware του θύματος. Το απόσπασμα παρακάτω ανοίγει το αντικείμενο-στόχο `iterations` φορές και επιστρέφει το μέσο κόστος ανά άνοιγμα χρησιμοποιώντας `QueryPerformanceCounter`.
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
Τα αποτελέσματα τροφοδοτούν απευθείας τη στρατηγική ορχήστρωσης του race (π.χ., αριθμός worker threads που χρειάζονται, διαστήματα ύπνου, πόσο νωρίς πρέπει να αλλάξετε το shared state).

## Ροή εκμετάλλευσης

1. **Locate the vulnerable open** – Trace the kernel path (via symbols, ETW, hypervisor tracing, or reversing) until you find an `NtOpen*`/`ObOpenObjectByName` call that walks an attacker-controlled name or a symbolic link in a user-writable directory.
2. **Replace that name with a slow path**
- Create the long component or directory chain under `\BaseNamedObjects` (or another writable OM root).
- Create a symbolic link so that the name the kernel expects now resolves to the slow path. You can point the vulnerable driver’s directory lookup to your structure without touching the original target.
3. **Trigger the race**
- Thread A (victim) εκτελεί τον ευάλωτο κώδικα και μπλοκάρεται μέσα στην αργή αναζήτηση.
- Thread B (attacker) αλλάζει την προστατευόμενη κατάσταση (π.χ., ανταλλάσσει ένα file handle, ξαναγράφει ένα symbolic link, αλλάζει το object security) ενώ το Thread A είναι δεσμευμένο.
- Όταν το Thread A συνεχίσει και εκτελέσει την privileged ενέργεια, θα δει stale state και θα εκτελέσει την ενέργεια που ελέγχεται από τον attacker.
4. **Clean up** – Διαγράψτε την αλυσίδα καταλόγων και τα symbolic links για να αποφύγετε το αφήσιμο ύποπτων artifacts ή το σπάσιμο νόμιμων χρηστών IPC.

## Επιχειρησιακές παρατηρήσεις

- **Combine primitives** – Μπορείτε να χρησιμοποιήσετε ένα μεγάλο όνομα *ανά επίπεδο* σε μια αλυσίδα καταλόγων για ακόμη μεγαλύτερη καθυστέρηση έως ότου εξαντλήσετε το μέγεθος του `UNICODE_STRING`.
- **One-shot bugs** – Το διευρυμένο παράθυρο (δεκάδες μικροδευτερόλεπτα έως λεπτά) κάνει τα “single trigger” bugs ρεαλιστικά όταν συνδυαστούν με CPU affinity pinning ή hypervisor-assisted preemption.
- **Side effects** – Η επιβράδυνση επηρεάζει μόνο την κακόβουλη διαδρομή, οπότε η συνολική απόδοση του συστήματος παραμένει ανεπηρέαστη· οι defenders σπάνια θα το παρατηρήσουν εκτός αν παρακολουθούν την αύξηση του namespace.
- **Cleanup** – Κρατήστε handles για κάθε directory/object που δημιουργείτε ώστε να μπορείτε να καλέσετε `NtMakeTemporaryObject`/`NtClose` μετά. Οι απεριόριστες αλυσίδες καταλόγων ενδέχεται να επιμείνουν ανάμεσα σε reboots.

## Σημειώσεις άμυνας

- Ο kernel κώδικας που βασίζεται σε named objects θα πρέπει να επαληθεύει ξανά security-sensitive state *μετά* το open, ή να παίρνει ένα reference πριν τον έλεγχο (κλείνοντας το TOCTOU gap).
- Εφαρμόστε άνω όρια στο βάθος/μήκος της OM διαδρομής πριν κάνετε dereference σε user-controlled ονόματα. Η απόρριψη υπερβολικά μακρών ονομάτων αναγκάζει τον attacker πίσω στο μικροδευτερολέπτων παράθυρο.
- Instrument το growth του object manager namespace (ETW `Microsoft-Windows-Kernel-Object`) για να εντοπίζετε ύποπτες αλυσίδες χιλιάδων components κάτω από `\BaseNamedObjects`.

## References

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
