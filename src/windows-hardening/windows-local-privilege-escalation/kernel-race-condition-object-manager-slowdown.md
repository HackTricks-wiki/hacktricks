# Exploitation of Kernel Race Condition via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία η διεύρυνση του race window

Πολλά Windows kernel LPE ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο hardware, ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε περίπου 2 µs, αφήνοντας σχεδόν καθόλου χρόνο για την αλλαγή της ελεγμένης κατάστασης πριν εκτελεστεί η secure ενέργεια. Αναγκάζοντας σκόπιμα το Object Manager Namespace (OMNS) lookup στο βήμα 2 να διαρκεί δεκάδες microseconds, ο attacker αποκτά αρκετό χρόνο ώστε να κερδίζει με συνέπεια races που διαφορετικά θα ήταν ασταθή, χωρίς να χρειάζεται χιλιάδες προσπάθειες.<sup>[[1]](#references)</sup>

## Τα εσωτερικά του Object Manager lookup με λίγα λόγια

* **Δομή OMNS** – Ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται directory-by-directory. Κάθε component προκαλεί την εύρεση/το άνοιγμα ενός *Object Directory* από τον kernel και τη σύγκριση Unicode strings. Τα symbolic links (π.χ. drive letters) μπορεί να ακολουθηθούν κατά τη διαδρομή.
* **Όριο UNICODE_STRING** – Τα OM paths μεταφέρονται μέσα σε ένα `UNICODE_STRING`, του οποίου το `Length` είναι τιμή 16 bit. Το απόλυτο όριο είναι 65 535 bytes (32 767 UTF-16 codepoints). Με prefixes όπως το `\BaseNamedObjects\`, ο attacker εξακολουθεί να ελέγχει περίπου 32 000 χαρακτήρες.
* **Προαπαιτούμενα attacker** – Οποιοσδήποτε user μπορεί να δημιουργήσει objects κάτω από writable directories όπως το `\BaseNamedObjects`. Όταν ο ευάλωτος κώδικας χρησιμοποιεί ένα όνομα στο εσωτερικό τους ή ακολουθεί ένα symbolic link που καταλήγει εκεί, ο attacker ελέγχει την απόδοση του lookup χωρίς special privileges.<sup>[[1]](#references)</sup>

## Primitive slowdown #1 – Single maximal component

Το κόστος επίλυσης ενός component είναι περίπου γραμμικό ως προς το μήκος του, επειδή ο kernel πρέπει να εκτελέσει Unicode comparison έναντι κάθε entry στο parent directory. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει αμέσως το latency του `NtOpenEvent` από περίπου 2 µs σε περίπου 35 µs στα Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Πρακτικές σημειώσεις*

- Μπορείτε να φτάσετε το length limit χρησιμοποιώντας οποιοδήποτε named kernel object (events, sections, semaphores…).
- Τα symbolic links ή τα reparse points μπορούν να δείχνουν από ένα σύντομο όνομα “victim” σε αυτό το giant component, ώστε το slowdown να εφαρμόζεται διαφανώς.
- Επειδή όλα βρίσκονται σε user-writable namespaces, το payload λειτουργεί από standard user integrity level.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Deep recursive directories

Μια πιο επιθετική παραλλαγή δεσμεύει μια αλυσίδα χιλιάδων directories (`\BaseNamedObjects\A\A\...\X`). Κάθε hop ενεργοποιεί τη logic επίλυσης directory (ACL checks, hash lookups, reference counting), επομένως το latency ανά level είναι υψηλότερο από ένα απλό string compare. Με περίπου 16.000 levels (με περιορισμό από το ίδιο μέγεθος `UNICODE_STRING`), τα empirical timings ξεπερνούν το όριο των 35 µs που επιτυγχάνεται με μεγάλα single components.
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

* Εναλλάσσετε τον χαρακτήρα ανά επίπεδο (`A/B/C/...`) αν ο parent directory αρχίσει να απορρίπτει duplicates.
* Διατηρείτε έναν πίνακα handles, ώστε να μπορείτε να διαγράψετε καθαρά την αλυσίδα μετά το exploitation και να αποφύγετε τη ρύπανση του namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (λεπτά αντί για microseconds)

Τα object directories υποστηρίζουν **shadow directories** (fallback lookups) και hash tables με buckets για τα entries. Εκμεταλλευτείτε και τα δύο, καθώς και το όριο των 64 components για symbolic-link reparse, ώστε να πολλαπλασιάσετε το slowdown χωρίς να υπερβείτε το μήκος του `UNICODE_STRING`:

1. Δημιουργήστε δύο directories κάτω από το `\BaseNamedObjects`, π.χ. `A` (shadow) και `A\A` (target). Δημιουργήστε το δεύτερο χρησιμοποιώντας το πρώτο ως shadow directory (`NtCreateDirectoryObjectEx`), ώστε τα missing lookups στο `A` να καταλήγουν στο `A\A`.
2. Γεμίστε κάθε directory με χιλιάδες **colliding names** που καταλήγουν στο ίδιο hash bucket (π.χ. αλλάζοντας τα trailing digits ενώ διατηρείτε την ίδια τιμή `RtlHashUnicodeString`). Τα lookups πλέον υποβαθμίζονται σε O(n) linear scans μέσα σε ένα μόνο directory.
3. Δημιουργήστε μια αλυσίδα περίπου 63 **object manager symbolic links** που κάνουν επανειλημμένα reparse στο μεγάλο suffix `A\A\…`, καταναλώνοντας το reparse budget. Κάθε reparse επανεκκινεί το parsing από την αρχή, πολλαπλασιάζοντας το collision cost.
4. Το lookup του τελικού component (`...\\0`) διαρκεί πλέον **λεπτά** στα Windows 11 όταν υπάρχουν 16 000 collisions ανά directory, παρέχοντας πρακτικά εγγυημένη νίκη στο race για one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Γιατί έχει σημασία*: Μια επιβράδυνση διάρκειας μερικών λεπτών μετατρέπει τα one-shot race-based LPEs σε deterministic exploits.<sup>[[1]](#references)</sup>

### Σημειώσεις επανελέγχου του 2025 και έτοιμα εργαλεία

- Ο James Forshaw αναδημοσίευσε την τεχνική με ενημερωμένους χρόνους στα Windows 11 24H2 (ARM64). Τα baseline ανοίγματα παραμένουν περίπου στα 2 µs· ένα component μεγέθους 32 kB τα αυξάνει περίπου στα 35 µs, ενώ οι αλυσίδες shadow-dir + collision + 63-reparse εξακολουθούν να φτάνουν περίπου τα 3 λεπτά, επιβεβαιώνοντας ότι τα primitives λειτουργούν και στις τρέχουσες builds. Ο πηγαίος κώδικας και το perf harness βρίσκονται στη νέα ανάρτηση του Project Zero.<sup>[[1]](#references)</sup>
- Μπορείτε να κάνετε script το setup χρησιμοποιώντας το public bundle `symboliclink-testing-tools`: το `CreateObjectDirectory.exe` δημιουργεί το ζεύγος shadow/target και το `NativeSymlink.exe`, σε loop, δημιουργεί την αλυσίδα των 63 hops. Αυτό αποφεύγει wrappers `NtCreate*` γραμμένα χειροκίνητα και διατηρεί τα ACLs συνεπή.<sup>[[2]](#references)</sup>

## Μέτρηση του race window σας

Ενσωματώστε ένα σύντομο harness στο exploit σας, ώστε να μετρήσετε πόσο μεγάλο γίνεται το window στο hardware του θύματος. Το παρακάτω snippet ανοίγει το target object `iterations` φορές και επιστρέφει το μέσο κόστος ανά άνοιγμα, χρησιμοποιώντας το `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Τα αποτελέσματα τροφοδοτούν άμεσα τη στρατηγική orchestration του race (π.χ. τον αριθμό των worker threads που απαιτούνται, τα διαστήματα sleep και το πόσο νωρίς πρέπει να αλλάξετε την κοινόχρηστη κατάσταση).

## Ροή εργασίας exploitation

1. **Εντοπίστε το ευάλωτο open** – Παρακολουθήστε τη διαδρομή του kernel (μέσω symbols, ETW, hypervisor tracing ή reversing) μέχρι να βρείτε μια κλήση `NtOpen*`/`ObOpenObjectByName` που διασχίζει ένα όνομα ελεγχόμενο από τον attacker ή ένα symbolic link σε directory εγγράψιμο από τον χρήστη.
2. **Αντικαταστήστε αυτό το όνομα με ένα slow path**
- Δημιουργήστε το long component ή την αλυσίδα directories κάτω από το `\BaseNamedObjects` (ή κάποιο άλλο εγγράψιμο OM root).
- Δημιουργήστε ένα symbolic link, ώστε το όνομα που αναμένει ο kernel να επιλύεται πλέον στο slow path. Μπορείτε να κατευθύνετε το directory lookup του ευάλωτου driver στη δομή σας χωρίς να αγγίξετε το αρχικό target.
3. **Ενεργοποιήστε το race**
- Το Thread A (victim) εκτελεί τον ευάλωτο κώδικα και μπλοκάρει μέσα στο slow lookup.
- Το Thread B (attacker) αλλάζει την προστατευμένη κατάσταση (π.χ. αντικαθιστά ένα file handle, ξαναγράφει ένα symbolic link ή αλλάζει τις ρυθμίσεις ασφάλειας ενός object) ενώ το Thread A είναι απασχολημένο.
- Όταν το Thread A συνεχίσει και εκτελέσει την privileged ενέργεια, παρατηρεί stale state και εκτελεί την operation που ελέγχεται από τον attacker.
4. **Κάντε cleanup** – Διαγράψτε την αλυσίδα directories και τα symbolic links, ώστε να μην αφήσετε ύποπτα artifacts ή να διακόψετε legitimate IPC users.<sup>[[1]](#references)</sup>

## Λειτουργικές considerations

- **Συνδυάστε primitives** – Μπορείτε να χρησιμοποιήσετε ένα long name *ανά level* σε μια αλυσίδα directories για ακόμη μεγαλύτερο latency, μέχρι να εξαντλήσετε το μέγεθος του `UNICODE_STRING`.
- **One-shot bugs** – Το διευρυμένο window (από δεκάδες microseconds έως minutes) καθιστά ρεαλιστικά τα “single trigger” bugs όταν συνδυάζονται με CPU affinity pinning ή hypervisor-assisted preemption.
- **Side effects** – Η slowdown επηρεάζει μόνο το malicious path, επομένως η συνολική απόδοση του συστήματος παραμένει ανεπηρέαστη· οι defenders σπάνια θα το αντιληφθούν, εκτός αν παρακολουθούν την ανάπτυξη του namespace.
- **Cleanup** – Διατηρήστε handles για κάθε directory/object που δημιουργείτε, ώστε να μπορείτε να καλέσετε `NtMakeTemporaryObject`/`NtClose` στη συνέχεια. Διαφορετικά, οι unbounded directory chains ενδέχεται να παραμείνουν και μετά από reboot.
- **File-system races** – Αν το vulnerable path τελικά επιλύεται μέσω NTFS, μπορείτε να τοποθετήσετε ένα Oplock (π.χ. το `SetOpLock.exe` από το ίδιο toolkit) στο backing file ενώ εκτελείται το OM slowdown, παγώνοντας τον consumer για επιπλέον milliseconds χωρίς να τροποποιήσετε το OM graph.<sup>[[2]](#references)</sup>

## Defensive notes

- Ο kernel code που βασίζεται σε named objects θα πρέπει να επανεπικυρώνει την security-sensitive κατάσταση *μετά* το open ή να λαμβάνει reference πριν από το check (κλείνοντας το TOCTOU gap).
- Επιβάλετε upper bounds στο βάθος/μήκος του OM path πριν από το dereferencing ονομάτων που ελέγχονται από τον χρήστη. Η απόρριψη υπερβολικά μεγάλων ονομάτων αναγκάζει τους attackers να επιστρέψουν στο window των microseconds.
- Instrument την ανάπτυξη του Object Manager namespace (ETW `Microsoft-Windows-Kernel-Object`) για την ανίχνευση ύποπτων chains με χιλιάδες components κάτω από το `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)

{{#include ../../banners/hacktricks-training.md}}
