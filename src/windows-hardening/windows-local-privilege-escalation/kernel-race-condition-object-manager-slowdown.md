# Exploitation Kernel Race Condition μέσω Object Manager Slow Paths

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία η επιμήκυνση του race window

Πολλά Windows kernel LPEs ακολουθούν το κλασικό μοτίβο `check_state(); NtOpenX("name"); privileged_action();`. Σε σύγχρονο hardware, ένα cold `NtOpenEvent`/`NtOpenSection` επιλύει ένα σύντομο όνομα σε περίπου 2 µs, αφήνοντας σχεδόν καθόλου χρόνο για την αλλαγή της ελεγμένης κατάστασης πριν εκτελεστεί η secure action. Αναγκάζοντας σκόπιμα το Object Manager Namespace (OMNS) lookup στο βήμα 2 να διαρκεί δεκάδες microseconds, ο attacker αποκτά αρκετό χρόνο ώστε να κερδίζει με συνέπεια races που διαφορετικά θα ήταν ασταθή, χωρίς να χρειάζεται χιλιάδες προσπάθειες.<sup>[[1]](#references)</sup>

## Τα εσωτερικά του Object Manager lookup με λίγα λόγια

* **Δομή OMNS** – Ονόματα όπως `\BaseNamedObjects\Foo` επιλύονται directory-by-directory. Κάθε component προκαλεί στον kernel την εύρεση/άνοιγμα ενός *Object Directory* και τη σύγκριση Unicode strings. Symbolic links (π.χ. drive letters) ενδέχεται να διασχίζονται κατά τη διαδρομή.
* **Όριο UNICODE_STRING** – Οι διαδρομές OM μεταφέρονται μέσα σε ένα `UNICODE_STRING`, του οποίου το `Length` είναι τιμή 16 bit. Το απόλυτο όριο είναι 65 535 bytes (32 767 UTF-16 codepoints). Με prefixes όπως `\BaseNamedObjects\`, ο attacker εξακολουθεί να ελέγχει περίπου 32 000 χαρακτήρες.
* **Προαπαιτούμενα attacker** – Οποιοσδήποτε user μπορεί να δημιουργήσει objects κάτω από writable directories όπως το `\BaseNamedObjects`. Όταν ο ευάλωτος κώδικας χρησιμοποιεί ένα όνομα μέσα σε αυτό ή ακολουθεί ένα symbolic link που καταλήγει εκεί, ο attacker ελέγχει την απόδοση του lookup χωρίς special privileges.<sup>[[1]](#references)</sup>

## Slowdown primitive #1 – Single maximal component

Το κόστος επίλυσης ενός component είναι περίπου γραμμικό ως προς το μήκος του, επειδή ο kernel πρέπει να εκτελέσει Unicode comparison με κάθε entry στο parent directory. Η δημιουργία ενός event με όνομα μήκους 32 kB αυξάνει αμέσως το latency του `NtOpenEvent` από περίπου 2 µs σε περίπου 35 µs στα Windows 11 24H2 (Snapdragon X Elite testbed).
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
- Τα symbolic links ή τα reparse points μπορούν να δείχνουν από ένα σύντομο όνομα “victim” σε αυτό το τεράστιο component, ώστε η επιβράδυνση να εφαρμόζεται διαφανώς.
- Επειδή όλα βρίσκονται σε namespaces εγγράψιμα από τον χρήστη, το payload λειτουργεί από ένα standard user integrity level.<sup>[[1]](#references)</sup>

## Μηχανισμός επιβράδυνσης #2 – Βαθιά αναδρομικά directories

Μια πιο επιθετική παραλλαγή εκχωρεί μια αλυσίδα χιλιάδων directories (`\BaseNamedObjects\A\A\...\X`). Κάθε hop ενεργοποιεί τη λογική επίλυσης directories (ACL checks, hash lookups, reference counting), επομένως το latency ανά επίπεδο είναι υψηλότερο από αυτό ενός απλού string compare. Με περίπου 16 000 levels (περιορίζονται από το ίδιο μέγεθος `UNICODE_STRING`), οι εμπειρικοί χρόνοι ξεπερνούν το όριο των 35 µs που επιτυγχάνεται με μεγάλα single components.
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

* Εναλλάσσετε τον χαρακτήρα ανά επίπεδο (`A/B/C/...`) αν ο γονικός κατάλογος αρχίσει να απορρίπτει διπλότυπα.
* Διατηρείτε έναν πίνακα handles, ώστε να μπορείτε να διαγράψετε καθαρά την αλυσίδα μετά το exploitation και να αποφύγετε τη ρύπανση του namespace.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (λεπτά αντί για microseconds)

Οι κατάλογοι αντικειμένων υποστηρίζουν **shadow directories** (αναζητήσεις fallback) και hash tables με buckets για τις καταχωρίσεις. Καταχραστείτε και τα δύο, μαζί με το όριο των 64 reparses για symbolic links, ώστε να πολλαπλασιάσετε την επιβράδυνση χωρίς να υπερβείτε το μήκος του `UNICODE_STRING`:

1. Δημιουργήστε δύο directories κάτω από το `\BaseNamedObjects`, για παράδειγμα `A` (shadow) και `A\A` (target). Δημιουργήστε το δεύτερο χρησιμοποιώντας το πρώτο ως shadow directory (`NtCreateDirectoryObjectEx`), ώστε οι αναζητήσεις που αποτυγχάνουν στο `A` να συνεχίζονται στο `A\A`.
2. Γεμίστε κάθε directory με χιλιάδες **colliding names** που καταλήγουν στο ίδιο hash bucket (για παράδειγμα, μεταβάλλοντας τα τελικά ψηφία και διατηρώντας την ίδια τιμή `RtlHashUnicodeString`). Οι αναζητήσεις υποβαθμίζονται πλέον σε γραμμικές σαρώσεις O(n) μέσα σε έναν μόνο directory.
3. Δημιουργήστε μια αλυσίδα περίπου 63 **object manager symbolic links** που κάνουν επανειλημμένα reparse στο μεγάλο suffix `A\A\…`, καταναλώνοντας το reparse budget. Κάθε reparse επανεκκινεί το parsing από την αρχή, πολλαπλασιάζοντας το κόστος των collisions.
4. Η αναζήτηση του τελικού component (`...\\0`) διαρκεί πλέον **λεπτά** στα Windows 11 όταν υπάρχουν 16 000 collisions ανά directory, παρέχοντας πρακτικά εγγυημένη νίκη σε race conditions για one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Γιατί έχει σημασία*: Μια επιβράδυνση διάρκειας μερικών λεπτών μετατρέπει τα one-shot race-based LPEs σε deterministic exploits.<sup>[[1]](#references)</sup>

### Σημειώσεις επανελέγχου 2025 και έτοιμα εργαλεία

- Ο James Forshaw αναδημοσίευσε την τεχνική με ενημερωμένους χρονισμούς στα Windows 11 24H2 (ARM64). Τα baseline opens παραμένουν περίπου στα 2 µs· ένα component μεγέθους 32 kB το αυξάνει περίπου στα 35 µs, ενώ οι αλυσίδες shadow-dir + collision + 63-reparse εξακολουθούν να φτάνουν περίπου τα 3 λεπτά, επιβεβαιώνοντας ότι τα primitives εξακολουθούν να λειτουργούν στα τρέχοντα builds. Ο πηγαίος κώδικας και το perf harness βρίσκονται στη νεότερη ανάρτηση του Project Zero.<sup>[[1]](#references)</sup>
- Μπορείτε να αυτοματοποιήσετε το setup χρησιμοποιώντας το public bundle `symboliclink-testing-tools`: το `CreateObjectDirectory.exe` δημιουργεί το ζεύγος shadow/target και το `NativeSymlink.exe`, μέσα σε loop, δημιουργεί την αλυσίδα των 63 hops. Έτσι αποφεύγονται τα χειρόγραφα `NtCreate*` wrappers και διατηρούνται συνεπή τα ACLs.<sup>[[2]](#references)</sup>

## Measuring your race window

Ενσωματώστε ένα γρήγορο harness στο exploit σας, ώστε να μετρήσετε πόσο μεγάλο γίνεται το window στο hardware του victim. Το παρακάτω snippet ανοίγει το target object `iterations` φορές και επιστρέφει το μέσο κόστος ανά open χρησιμοποιώντας το `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Τα αποτελέσματα τροφοδοτούν άμεσα τη στρατηγική orchestration του race (π.χ. τον αριθμό των worker threads που απαιτούνται, τα sleep intervals και το πόσο νωρίς χρειάζεται να αλλάξετε την κοινόχρηστη κατάσταση).

## Ροή εργασίας exploitation

1. **Εντοπίστε το ευάλωτο open** – Ανιχνεύστε τη διαδρομή του kernel (μέσω symbols, ETW, hypervisor tracing ή reversing) μέχρι να βρείτε μια κλήση `NtOpen*`/`ObOpenObjectByName` που διασχίζει ένα όνομα ελεγχόμενο από τον attacker ή ένα symbolic link σε κατάλογο εγγράψιμο από τον χρήστη.
2. **Αντικαταστήστε αυτό το όνομα με ένα slow path**
- Δημιουργήστε το long component ή την αλυσίδα καταλόγων κάτω από το `\BaseNamedObjects` (ή κάποια άλλη εγγράψιμη OM root).
- Δημιουργήστε ένα symbolic link, ώστε το όνομα που αναμένει ο kernel να επιλύεται πλέον στο slow path. Μπορείτε να κατευθύνετε το directory lookup του ευάλωτου driver στη δομή σας χωρίς να αγγίξετε τον αρχικό προορισμό.
3. **Ενεργοποιήστε το race**
- Το Thread A (victim) εκτελεί τον ευάλωτο κώδικα και μπλοκάρει μέσα στο slow lookup.
- Το Thread B (attacker) αλλάζει τη guarded state (π.χ. αντικαθιστά ένα file handle, ξαναγράφει ένα symbolic link ή αλλάζει το object security) ενώ το Thread A είναι απασχολημένο.
- Όταν το Thread A συνεχίσει και εκτελέσει την privileged action, παρατηρεί stale state και εκτελεί την operation που ελέγχεται από τον attacker.
4. **Εκκαθάριση** – Διαγράψτε την αλυσίδα καταλόγων και τα symbolic links, ώστε να μην αφήσετε ύποπτα artifacts ή να διακόψετε legitimate IPC users.<sup>[[1]](#references)</sup>

## Εφαρμοσμένη αλυσίδα: mutable Cloud Files placeholders + Object Manager path switching

Το [ShieldBreak](https://github.com/MSNightmare/ShieldBreak), που δημοσιεύτηκε ως bypass για το RoguePlanet (CVE-2026-50656), επιδεικνύει ένα ευρύτερο exploitation pattern: κάνει έναν privileged scanner να ταξινομήσει μία αναπαράσταση ενός logical file και, στη συνέχεια, αλλάζει τόσο τα bytes του όσο και το namespace resolution πριν το remediation το χρησιμοποιήσει. Το PoC συνδυάζει ένα Cloud Files hydration TOCTOU, ένα Object Manager shadow-directory fallback, capture ονομάτων που δημιουργούνται από το CLFS και ένα local administrative-share link, ώστε να μετατρέψει το Defender cleanup σε protected DLL write.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Αντικατάσταση περιεχομένου μέσω Cloud Files hydration

Καταχωρίστε έναν κατάλογο εγγράψιμο από τον attacker ως Cloud Files sync root, συνδέστε ένα `CF_CALLBACK_TYPE_FETCH_DATA` callback και δημιουργήστε ένα placeholder του οποίου το advertised size αντιστοιχεί σε ένα deterministic detection trigger, όπως το EICAR ZIP. Το πρώτο fetch επιστρέφει το trigger και αλλάζει την callback state· τα επόμενα fetch επιστρέφουν το payload. Αφού ο scanner ταξινομήσει την πρώτη αναπαράσταση, λάβετε το transfer key και επανεκκινήστε το hydration με metadata μεγέθους ίσου με του payload, έπειτα εξαναγκάστε το hydration έως το EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Το security boundary αποτυγχάνει αν τα scan, verdict και remediation αναφέρονται μόνο σε ένα pathname ή placeholder identity: κανένα από τα δύο δεν εγγυάται ότι ένα μεταγενέστερο hydration θα επιστρέψει τα bytes που εξετάστηκαν.<sup>[[4]](#references)</sup>

### 2. Μεταβολή ενός invariant path μέσω shadow-directory fallback

Δημιουργήστε έναν target Object Manager directory και έναν δεύτερο directory με `NtCreateDirectoryObjectEx`, περνώντας το target handle ως shadow/fallback directory. Τοποθετήστε ένα same-named `WD_SCAN` entry και στα δύο resolution layers: το visible entry δείχνει στο normal working directory, ενώ το fallback entry δείχνει στο `\CLFS\??\<working-directory>`. Παρέχετε στο Defender μόνο το invariant path παρακάτω· η διαγραφή του visible link όσο η λειτουργία είναι ενεργή κάνει το ίδιο string να καταλήξει στο CLFS-backed entry.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Αυτό διαφέρει από τη χρήση shadow directories μόνο για την επιβράδυνση της αναζήτησης: ο attacker αλλάζει το **meaning** μιας προηγουμένως αποδεκτής διαδρομής χωρίς να τροποποιήσει το string της.<sup>[[4]](#references)</sup>

### 3. Καταγράψτε το generated name και εγκαταστήστε ένα filename-specific link

Παρακολουθήστε τον working directory με το `ReadDirectoryChangesW`. Στο πρώτο `FILE_ACTION_ADDED`, αφαιρέστε το ορατό `WD_SCAN` link για να ενεργοποιήσετε το fallback lookup. Καταγράψτε το δεύτερο generated filename, ανοίξτε το σχετικό με το CLFS αρχείο και κλειδώστε το range `0..MAXLONGLONG` με το `LockFileEx`. Ενώ η privileged operation έχει stalled, αντικαταστήστε το `WD_SCAN` στον ορατό directory με έναν πραγματικό Object Manager directory και δημιουργήστε ένα child symbolic link με όνομα βασισμένο στο observed filename (το PoC αφαιρεί τους τέσσερις τελευταίους χαρακτήρες του). Κατευθύνετέ το στον protected destination μέσω local SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Η μη προνομιούχα διεργασία δεν μπορεί να γράψει η ίδια σε αυτόν τον προορισμό, όμως το context SYSTEM του Defender μπορεί να διασχίσει το loopback administrative share. Ο συνδυασμός παρατήρησης generated names με ένα filename-specific Object Manager link εξαλείφει την ανάγκη πρόβλεψης του remediation artifact εκ των προτέρων.<sup>[[4]](#references)</sup>

### 4. Σταθεροποίηση του cleanup race και ενεργοποίηση privileged loader

Πριν από τη σάρωση, το PoC αποθηκεύει ένα έγκυρο PE (`ntdll.dll`) στο `:stream` NTFS alternate data stream του placeholder. Αφού η ανακατεύθυνση δημιουργήσει το protected base file, ανοίγει το `phoneinfo.dll:stream` με execute access και διατηρεί ενεργό ένα `PAGE_EXECUTE_READ | SEC_IMAGE` mapping, ενώ το cleanup συνεχίζεται· τα ενεργά file/section objects περιορίζουν τη διαγραφή ή την αντικατάσταση κατά το final race. Το restarted hydration επιστρέφει πλέον το payload DLL αντί για το EICAR, οπότε το protected base file περιέχει code που ελέγχεται από τον attacker.<sup>[[4]](#references)</sup>

Στη συνέχεια, ένα protected write μετατρέπεται σε SYSTEM execution με την τοποθέτηση ενός crafted `Report.wer` κάτω από το `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` και την invocation του `\Microsoft\Windows\Windows Error Reporting\QueueReporting` μέσω του Task Scheduler COM API. Σε αυτή την αλυσίδα, το privileged WER processing φορτώνει το planted `C:\Windows\System32\phoneinfo.dll`· μια named-pipe connection χρησιμοποιείται ως payload execution signal.<sup>[[4]](#references)</sup>

### Detection pivots

Οι χρήσιμες συσχετίσεις είναι πιο συγκεκριμένες από οποιοδήποτε μεμονωμένο temporary filename και καλύπτουν όλες τις namespace transitions της αλυσίδας:<sup>[[4]](#references)</sup>

- Ένας newly registered Cloud Files provider, ακολουθούμενος από EICAR detection και `CF_OPERATION_TYPE_RESTART_HYDRATION` στο ίδιο placeholder.
- Object Manager paths που περιέχουν `WD_TARGET_*`, `WD_SHADOW_*` ή `WD_SCAN`, ειδικά ένα scan path κάτω από το `\\.\globalroot\BaseNamedObjects\Restricted\`.
- CLFS file creation, ακολουθούμενο από exclusive whole-file lock και loopback access στο `\\127.0.0.1\C$\Windows\System32\*.dll` από ένα privileged security process.
- Creation ενός System32 DLL μαζί με ένα NTFS ADS, ακολουθούμενο από `SEC_IMAGE` mapping του stream.
- Ένα attacker-created WER queue entry, ακολουθούμενο από ένα unusual manual run του `\Microsoft\Windows\Windows Error Reporting\QueueReporting` και ένα image load του planted DLL.

## Επιχειρησιακές considerations

- **Συνδυάστε primitives** – Μπορείτε να χρησιμοποιήσετε ένα long name *ανά level* σε μια directory chain για ακόμη υψηλότερο latency, μέχρι να εξαντλήσετε το μέγεθος του `UNICODE_STRING`.
- **One-shot bugs** – Το διευρυμένο window (δεκάδες microseconds έως minutes) καθιστά ρεαλιστικά τα “single trigger” bugs όταν συνδυάζονται με CPU affinity pinning ή hypervisor-assisted preemption.
- **Side effects** – Το slowdown επηρεάζει μόνο το malicious path, οπότε η συνολική απόδοση του συστήματος παραμένει ανεπηρέαστη· οι defenders σπάνια θα το παρατηρήσουν, εκτός αν παρακολουθούν την αύξηση του namespace.
- **Cleanup** – Διατηρήστε handles σε κάθε directory/object που δημιουργείτε, ώστε να μπορείτε να καλέσετε `NtMakeTemporaryObject`/`NtClose` στη συνέχεια. Διαφορετικά, unbounded directory chains ενδέχεται να παραμείνουν μετά από reboot.
- **File-system races** – Αν το vulnerable path τελικά επιλύεται μέσω NTFS, μπορείτε να τοποθετήσετε ένα Oplock (π.χ. το `SetOpLock.exe` από το ίδιο toolkit) στο backing file ενώ εκτελείται το OM slowdown, παγώνοντας τον consumer για επιπλέον milliseconds χωρίς να τροποποιήσετε το OM graph.<sup>[[2]](#references)</sup>

## Αμυντικές σημειώσεις

- Ο kernel code που βασίζεται σε named objects θα πρέπει να επανεπικυρώνει το security-sensitive state *μετά* το open ή να λαμβάνει reference πριν από τον έλεγχο (κλείνοντας το TOCTOU gap).
- Επιβάλετε upper bounds στο OM path depth/length πριν από το dereferencing user-controlled names. Η απόρριψη υπερβολικά long names αναγκάζει τους attackers να επιστρέψουν στο microsecond window.
- Κάντε instrument την αύξηση του object manager namespace (ETW `Microsoft-Windows-Kernel-Object`) για τον εντοπισμό ύποπτων chains με χιλιάδες components κάτω από το `\BaseNamedObjects`.

## References

- [1] [Project Zero – Τεχνικές Exploitation στα Windows: Κερδίζοντας Race Conditions με Path Lookups](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
