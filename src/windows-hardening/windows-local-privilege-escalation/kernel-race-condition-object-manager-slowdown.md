# Kernel Race Condition Exploitation via Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί η επιμήκυνση του race window έχει σημασία

Πολλά Windows kernel LPEs ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο υλικό ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε ~2 µs, αφήνοντας σχεδόν καθόλου χρόνο για να αλλάξει η ελεγχόμενη κατάσταση πριν εκτελεστεί η ασφαλής ενέργεια. Με το σκόπιμο επιμήκυνση της αναζήτησης στο Object Manager Namespace (OMNS) στο βήμα 2 ώστε να διαρκεί δεκάδες μικροδευτερόλεπτα, ο επιτιθέμενος κερδίζει αρκετό χρόνο για να κερδίζει σταθερά σε διαφορετικά ασταθή races χωρίς να χρειάζονται χιλιάδες προσπάθειες.

## Εσωτερικά της αναζήτησης του Object Manager εν συντομία

* **OMNS structure** – Ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται κατά κατάλογο. Κάθε συστατικό προκαλεί στον kernel να βρει/ανοίξει έναν *Object Directory* και να συγκρίνει Unicode strings. Symbolic links (π.χ. γράμματα δίσκων) μπορεί να διασχιστούν στην πορεία.
* **UNICODE_STRING limit** – Οι OM διαδρομές μεταφέρονται μέσα σε ένα `UNICODE_STRING` του οποίου το `Length` είναι μια 16-bit τιμή. Το απόλυτο όριο είναι 65 535 bytes (32 767 UTF-16 codepoints). Με προθέματα όπως `\BaseNamedObjects\`, ο επιτιθέμενος εξακολουθεί να ελέγχει ≈32 000 χαρακτήρες.
* **Attacker prerequisites** – Οποιοσδήποτε χρήστης μπορεί να δημιουργήσει αντικείμενα κάτω από εγγράψιμους καταλόγους όπως `\BaseNamedObjects`. Όταν ο ευάλωτος κώδικας χρησιμοποιεί ένα όνομα εκεί μέσα, ή ακολουθεί ένα symbolic link που καταλήγει εκεί, ο επιτιθέμενος ελέγχει την απόδοση της αναζήτησης χωρίς ειδικά προνόμια.

## Μηχανισμός επιβράδυνσης #1 – Single maximal component

Το κόστος επίλυσης ενός συστατικού είναι περίπου γραμμικό ως προς το μήκος του επειδή ο kernel πρέπει να εκτελέσει μια σύγκριση Unicode έναντι κάθε εγγραφής στον γονικό κατάλογο. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει άμεσα τη λανθάνουσα κατάσταση του `NtOpenEvent` από ~2 µs σε ~35 µs σε Windows 11 24H2 (Snapdragon X Elite testbed).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Πρακτικές σημειώσεις*

- Μπορείτε να φτάσετε το όριο μήκους χρησιμοποιώντας οποιοδήποτε ονομασμένο kernel αντικείμενο (events, sections, semaphores…).
- Symbolic links ή reparse points μπορούν να δείξουν ένα σύντομο “victim” όνομα σε αυτό το γιγάντιο component ώστε η επιβράδυνση να εφαρμόζεται διαφανώς.
- Εφόσον όλα υπάρχουν σε user-writable namespaces, το payload λειτουργεί από ένα standard user integrity level.

## Slowdown primitive #2 – Deep recursive directories

Μια πιο επιθετική παραλλαγή δεσμεύει μια αλυσίδα χιλιάδων directories (`\BaseNamedObjects\A\A\...\X`). Κάθε βήμα ενεργοποιεί τη directory resolution logic (ACL checks, hash lookups, reference counting), οπότε η καθυστέρηση ανά επίπεδο είναι μεγαλύτερη από μια απλή σύγκριση συμβολοσειράς. Με ~16 000 επίπεδα (περιορισμένα από το ίδιο μέγεθος `UNICODE_STRING`), οι εμπειρικές χρονικές μετρήσεις ξεπερνούν το όριο των 35 µs που επιτυγχάνεται από long single components.
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

* Χρησιμοποίησε εναλλασσόμενο χαρακτήρα ανά επίπεδο (`A/B/C/...`) αν ο γονικός κατάλογος αρχίσει να απορρίπτει διπλότυπα.
* Διατήρησε έναν πίνακα handle ώστε να μπορείς να διαγράψεις την αλυσίδα καθαρά μετά την exploitation, για να αποφύγεις τη ρύπανση του namespace.

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minutes instead of microseconds)

Οι κατάλογοι αντικειμένων υποστηρίζουν **shadow directories** (εφεδρικές αναζητήσεις) και bucketed hash tables για τις εγγραφές. Κακοποίησε και τα δύο μαζί με το όριο 64-component symbolic-link reparse για να πολλαπλασιάσεις την επιβράδυνση χωρίς να υπερβείς το μήκος του `UNICODE_STRING`:

1. Δημιούργησε δύο καταλόγους κάτω από `\BaseNamedObjects`, π.χ. `A` (shadow) και `A\A` (target). Δημιούργησε τον δεύτερο χρησιμοποιώντας τον πρώτο ως το shadow directory (`NtCreateDirectoryObjectEx`), έτσι ώστε οι ελλείπουσες αναζητήσεις στο `A` να περνούν στο `A\A`.
2. Γέμισε κάθε κατάλογο με χιλιάδες **colliding names** που καταλήγουν στο ίδιο hash bucket (π.χ. διαφοροποιώντας τα τελικά ψηφία ενώ διατηρείς την ίδια τιμή `RtlHashUnicodeString`). Οι αναζητήσεις πλέον υποβαθμίζονται σε O(n) γραμμικές σαρώσεις εντός ενός μόνο καταλόγου.
3. Δημιούργησε μια αλυσίδα περίπου 63 **object manager symbolic links** που επαναλαμβανόμενα κάνουν reparse στο μακρύ επίθημα `A\A\…`, καταναλώνοντας τον προϋπολογισμό reparse. Κάθε reparse επανεκκινεί το parsing από την αρχή, πολλαπλασιάζοντας το κόστος των collisions.
4. Η αναζήτηση του τελικού στοιχείου (`...\\0`) τώρα παίρνει **λεπτά** σε Windows 11 όταν υπάρχουν 16 000 collisions ανά κατάλογο, παρέχοντας μια πρακτικά εγγυημένη race win για one-shot kernel LPEs.
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

Ενσωματώστε ένα γρήγορο harness μέσα στο exploit σας για να μετρήσετε πόσο μεγάλο γίνεται το window στο hardware του θύματος. Το ακόλουθο απόσπασμα ανοίγει το αντικείμενο-στόχο `iterations` φορές και επιστρέφει το μέσο κόστος ανά άνοιγμα χρησιμοποιώντας `QueryPerformanceCounter`.
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
Τα αποτελέσματα τροφοδοτούν άμεσα τη στρατηγική ορχήστρωσης του race (π.χ., αριθμός worker threads που απαιτούνται, διαστήματα ύπνου, πόσο νωρίς πρέπει να αλλάξετε την κοινή κατάσταση).

## Ροή εκμετάλλευσης

1. **Εντοπίστε το ευάλωτο open** – Ακολουθήστε τη διαδρομή του kernel (μέσω symbols, ETW, hypervisor tracing ή reversing) έως ότου βρείτε μια κλήση `NtOpen*`/`ObOpenObjectByName` που περπατάει ένα όνομα υπό τον έλεγχο του attacker ή ένα symbolic link σε έναν κατάλογο εγγράψιμο από χρήστη.
2. **Αντικαταστήστε εκείνο το όνομα με μια αργή διαδρομή**
- Δημιουργήστε το μακρύ component ή την αλυσίδα καταλόγων κάτω από `\BaseNamedObjects` (ή άλλη εγγράψιμη OM root).
- Δημιουργήστε ένα symbolic link ώστε το όνομα που περιμένει το kernel πλέον να επιλύεται στην αργή διαδρομή. Μπορείτε να κατευθύνετε το directory lookup του ευάλωτου driver στη δική σας δομή χωρίς να αγγίξετε τον αρχικό στόχο.
3. **Προκαλέστε το race**
- Thread A (θύμα) εκτελεί τον ευάλωτο κώδικα και μπλοκάρεται μέσα στην αργή αναζήτηση.
- Thread B (επιτιθέμενος) αλλάζει την προστατευόμενη κατάσταση (π.χ., ανταλλάσσει ένα file handle, ξαναγράφει ένα symbolic link, αλλάζει το object security) ενώ το Thread A είναι δεσμευμένο.
- Όταν το Thread A συνεχίσει και εκτελέσει την προνομιούχα ενέργεια, θα παρατηρήσει ξεπερασμένη κατάσταση και θα εκτελέσει την ενέργεια υπό τον έλεγχο του επιτιθέμενου.
4. **Καθαρισμός** – Διαγράψτε την αλυσίδα καταλόγων και τα symbolic links για να αποφύγετε την εναπόθεση ύποπτων artifacts ή το σπάσιμο νόμιμων IPC χρηστών.

## Λειτουργικές παρατηρήσεις

- **Combine primitives** – Μπορείτε να χρησιμοποιήσετε ένα μακρύ όνομα *ανά επίπεδο* σε μια αλυσίδα καταλόγων για ακόμα μεγαλύτερη λανθάνουσα κατάσταση έως ότου εξαντλήσετε το μέγεθος του `UNICODE_STRING`.
- **One-shot bugs** – Το διευρυμένο παράθυρο (δεκάδες μικροδευτερόλεπτα έως λεπτά) κάνει τα “single trigger” bugs ρεαλιστικά όταν συνδυαστούν με CPU affinity pinning ή hypervisor-assisted preemption.
- **Παραπλευρές επιπτώσεις** – Η επιβράδυνση επηρεάζει μόνο την κακόβουλη διαδρομή, έτσι η συνολική απόδοση του συστήματος παραμένει ανέπαφη· οι υπερασπιστές σπάνια θα το προσέξουν εκτός αν παρακολουθούν την ανάπτυξη του namespace.
- **Καθαρισμός** – Κρατήστε handles για κάθε directory/object που δημιουργείτε ώστε να μπορείτε να καλέσετε `NtMakeTemporaryObject`/`NtClose` μετά. Διαφορετικά, απεριόριστες αλυσίδες καταλόγων μπορεί να διατηρηθούν μετά από επανεκκινήσεις.

## Σημειώσεις άμυνας

- Ο kernel κώδικας που εξαρτάται από named objects πρέπει να επαληθεύει ξανά την κατάσταση ευαίσθητη στην ασφάλεια *μετά* το open, ή να παίρνει ένα reference πριν τον έλεγχο (κλείνοντας το κενό TOCTOU).
- Επιβάλετε άνω όρια στο βάθος/μήκος της OM path πριν κάνετε dereference σε ονόματα υπό τον έλεγχο του χρήστη. Η απόρριψη υπερβολικά μακρών ονομάτων αναγκάζει τους επιτιθέμενους να επιστρέψουν στο μικροδευτερολέπτων παράθυρο.
- Καταγράψτε την ανάπτυξη του namespace του object manager (ETW `Microsoft-Windows-Kernel-Object`) για να εντοπίσετε ύποπτες αλυσίδες χιλιάδων συστατικών κάτω από `\BaseNamedObjects`.

## Αναφορές

- [Project Zero – Windows Exploitation Techniques: Winning Race Conditions with Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)

{{#include ../../banners/hacktricks-training.md}}
