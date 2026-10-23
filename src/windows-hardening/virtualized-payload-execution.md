# Εκτέλεση Virtualized Payload και αποφυγή εντοπισμού από Custom VM

{{#include ../banners/hacktricks-training.md}}

Το virtualization μεταγλωττίζει την επιθετική λογική σε ένα guest instruction set και την εκτελεί με έναν native interpreter. Σε αντίθεση με έναν packer, ο οποίος τελικά πρέπει να εκθέσει τις αρχικές native instructions στη μνήμη, ένα virtualized payload μπορεί να διατηρεί την προστατευμένη λογική ως bytecode καθ’ όλη τη διάρκεια ζωής του. Έτσι καταργείται αυτό το συγκεκριμένο παράθυρο αποσυσκευασίας, αλλά **δεν** αποκρύπτεται η συμπεριφορά που είναι ορατή στο host, όπως τα syscalls, η δικτυακή δραστηριότητα ή το όριο μεταξύ VM και native κλήσεων.<sup>[[2]](#references)[[3]](#references)</sup>

## WebAssembly re-hosting για αποφυγή static analysis

Αντί να τροποποιηθεί ένα εργαλείο Go με πολλές signatures, μπορεί να μεταγλωττιστεί ως guest `wasip1` και να ενσωματωθεί σε ξεχωριστό native loader. Το guest δημιουργείται με βάση ένα patched GOROOT, στο οποίο μη υποστηριζόμενες λειτουργίες όπως οι `net.Dial`, `net.Listen`, `os/exec` και `os.Pipe` καλούν μέσω `//go:wasmimport`· στη συνέχεια, ένα Wazero host module υλοποιεί sockets, λειτουργίες διεργασιών, κλήσεις Win32 και κλήσεις macOS framework. Έτσι διατηρείται ανέπαφη η χρήση του Go API από το αρχικό project, ενώ το μεγαλύτερο μέρος της λογικής του μεταφέρεται σε ένα κρυπτογραφημένο WASM module, το οποίο τα static PE εργαλεία ενδέχεται να μην κατανοούν.<sup>[[4]](#references)</sup>

### Γέφυρα από linear memory σε native APIs

Ένας guest pointer είναι offset 32 bit μέσα στη WASM linear memory, όχι host virtual address. Πριν από μια native κλήση, η γέφυρα μπορεί να μεταφράσει ένα όρισμα μόνο όταν έχει επισημανθεί ως local pointer και βρίσκεται εντός του εύρους `0x10000 <= value < wasmMemorySize`, αποδίδοντας `wasmMemoryBase + value`. Το κατώτερο όριο αποτρέπει την τροποποίηση μικρών handles, flags και `nil`· masks ανά API, που δημιουργούνται από το `win32metadata`, διακρίνουν πραγματικούς pointers από handles, μεγέθη και διευθύνσεις remote processes, με overrides για ανακριβή ή αμφίσημα metadata.<sup>[[4]](#references)</sup>

Τα native APIs μπορούν επίσης να επιστρέψουν host pointers μέσω guest output buffers. Ένας mirror table μπορεί να αντιστοιχίσει σε τέτοια αντικείμενα αναπαραστάσεις guest-memory και να διατηρεί αντίστροφη αντιστοίχιση στην αρχική host address. Το COM απαιτεί mirroring τόσο του interface όσο και του vtable: οι data pointers μπορούν να ακολουθηθούν και να γίνουν mirror, ενώ οι executable pointers σε περιοχές `MEM_IMAGE` πρέπει να παραμείνουν opaque tokens, καθώς το WASM δεν μπορεί να εκτελέσει native instructions. Αυτό το μοντέλο δεν υποστηρίζει άμεσα APIs host-to-guest callbacks, όπως τα `EnumWindows` ή `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Πολυμορφισμός WASM VM ανά build

Το runtime και το payload μπορούν να μετασχηματίζονται μαζί σε κάθε build: ανακατεύεται ο πίνακας opcode-to-handler, ξαναγράφεται κάθε guest opcode σύμφωνα με τη νέα αντιστοίχιση, τυχαιοποιούνται τα section identifiers, αντικαθίσταται το τυπικό magic `\0asm` με έναν marker ειδικό για το build και αλλάζει το runtime cache magic. Έτσι, ο ίδιος source code παράγει modules με διαφορετικά byte, ενώ τα συνηθισμένα WASM εργαλεία δεν μπορούν να αναλύσουν το payload μέχρι ο analyst να ανακτήσει την custom αντιστοίχιση και το framing από τον host loader.<sup>[[4]](#references)</sup>

Για reverse engineering, ξεκινήστε από τον native host αντί να κάνετε carving μόνο με βάση το `\0asm`: εντοπίστε τον compiled marker, τη διαδρομή αποκρυπτογράφησης του module, τον πίνακα opcode dispatch και τις `env` host-function registrations, και έπειτα ανακατασκευάστε ένα standard module ή instrument το import boundary. Η γέφυρα παραμένει χρήσιμο behavioral choke point, επειδή οι κλήσεις για δικτύωση, δημιουργία διεργασιών, πρόσβαση στο registry, dynamic loading και γενικό Win32 dispatch περνούν από αυτήν, ακόμη κι όταν το ενσωματωμένο bytecode αλλάζει σε κάθε build.<sup>[[4]](#references)</sup>

### Συγκάλυψη του εξωτερικού Go executable

Η αλλαγή μόνο του guest εξακολουθεί να αφήνει έναν αναγνωρίσιμο loader. Οι επιδεικνυόμενοι μετασχηματισμοί του εξωτερικού binary ενσωματώνουν πυκνά symbol profiles που συλλέχθηκαν από νόμιμα Go projects στο `gopclntab`, εναλλάσσουν ένα μικρό και εύλογο σύνολο από DLL imports και μεταβάλλουν τα PE `VERSIONINFO` και τα Authenticode identity strings. Αυτοί οι μετασχηματισμοί στοχεύουν στα static και machine-learning χαρακτηριστικά του container· δεν αφαιρούν τη runtime συμπεριφορά που εκθέτουν τα host shims.<sup>[[4]](#references)</sup>

## Μοντέλο εκτέλεσης

Ένας συμπαγής virtualized loader μπορεί να διαχωρίζει την εκτέλεση στα ακόλουθα επίπεδα.<sup>[[3]](#references)</sup>

1. Μεταγλωττίστε freestanding C, BOF source ή runtime libraries μέσω LLVM σε custom bytecode ISA.
2. Εκκινήστε έναν μικρό native interpreter και αρχικοποιήστε μια αντιστοίχιση opcode ειδική για το build.
3. Εκτελέστε τον ίδιο τον PE linker-loader ως bytecode: αναλύστε headers, αντιστοιχίστε sections, εφαρμόστε relocations, επιλύστε imports και συμπληρώστε το IAT.
4. Διατηρήστε τις κλήσεις guest-to-guest μέσα στον interpreter. Δρομολογήστε τους στόχους εκτός της περιοχής bytecode, όπως τις imported DLL functions, μέσω ενός native host-call thunk.
5. Μεταφέρετε βοηθητικές λειτουργίες, όπως το HTTP framing, το TLS και τμήματα του C runtime, πίσω από το ίδιο όριο ερμηνείας.

Αυτό το μοντέλο αποφεύγει την εκχώρηση ξεχωριστής native code region για κάθε plugin και εμποδίζει την εμφάνιση του αρχικού payload ως αναγνωρίσιμης ροής x86-64 instructions. Παραμένει, ωστόσο, ένα όριο αποφυγής εντοπισμού/obfuscation και όχι όριο ασφαλείας: ο native interpreter και κάθε εξωτερική επίδραση εξακολουθούν να είναι παρατηρήσιμα.<sup>[[2]](#references)[[3]](#references)</sup>

## Γέφυρα shared memory του host

Μια απομονωμένη VM αναπαριστά τους pointers ως offsets σε ένα guest buffer, επομένως κάθε διέλευση από host API απαιτεί μετάφραση pointers και ειδικό χειρισμό των output parameters. Αντίθετα, μια VM με shared memory καθιστά τις guest addresses έγκυρες host-process addresses. Έτσι, οι αναγνώσεις και οι εγγραφές μπορούν να χρησιμοποιούν λειτουργίες τύπου `memcpy`, ενώ ένας pointer που επιστρέφεται από native allocation ECALL μπορεί να γίνει άμεσα dereference από το bytecode. Το RISC-Y Business έδειξε ότι αυτός ο σχεδιασμός μπορεί να περιορίσει τη γέφυρα στην ανάκτηση του PEB και στην εκτέλεση αυθαίρετων host calls.<sup>[[1]](#references)</sup>

Για Windows x64, το virtual register file μπορεί να αντικατοπτρίζει το ABI: τοποθετήστε τα πρώτα τέσσερα integer ή pointer arguments στα `RCX`, `RDX`, `R8` και `R9`, ενώ τα επόμενα arguments και το shadow space τοποθετούνται στο stack. Όταν ένα virtual `CALL` καταλήγει εκτός της περιοχής bytecode, ένα universal thunk μεταφέρει αυτήν την κατάσταση σε native call και αντιγράφει την τιμή επιστροφής πίσω στη VM. Έτσι επιτρέπονται κλήσεις IAT, heap allocation και socket operations χωρίς pointer fixups.<sup>[[2]](#references)[[3]](#references)</sup>

Το τίμημα είναι η πλήρης απώλεια απομόνωσης. Η αλλοίωση της guest memory μπορεί να επηρεάσει άμεσα το host, οι native callees μπορούν να διατηρούν ή να τροποποιούν guest pointers και ο interpreter πρέπει να θεωρεί το bytecode πλήρως έμπιστο. Τα native-to-VM callbacks χρειάζονται επίσης αντίστροφη γέφυρα· μια VM που υποστηρίζει μόνο outbound calls δεν μπορεί να εξυπηρετήσει άμεσα APIs βασισμένα σε callbacks, όπως το `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Πολυμορφισμός ISA ανά build

Μια custom ISA σταθερού μήκους απλοποιεί το decoding, το dispatch, τα relocations και την αντιστοίχιση virtual registers. Το Centurion χρησιμοποιεί format instructions 18 byte, εμπνευσμένο από το x86-64, ανταλλάσσοντας την πυκνότητα κώδικα με την προβλέψιμη ανάλυση, ενώ αφήνει ανοιχτό και το ενδεχόμενο μετάφρασης υπαρχόντων x86-64 artifacts σε bytecode.<sup>[[3]](#references)</sup>

Η τυχαιοποίηση της αντιστοίχισης opcode-to-handler σε κάθε build κάνει την ίδια guest logic να παράγει διαφορετικές ακολουθίες byte. Η κρυπτογράφηση του mapping table και η ανάκτησή του μόνο κατά το runtime αφαιρούν επιπλέον ένα σταθερό opcode dictionary από τον δίσκο. Αυτό δυσκολεύει τις σταθερές signatures και τους επαναχρησιμοποιήσιμους κανόνες disassembly, αλλά δεν καθιστά αυτόματα πολυμορφικά τον native dispatcher, τη ρουτίνα αποκρυπτογράφησης του table ή το host-call boundary.<sup>[[3]](#references)</sup>

## Μεταφορά του περιβάλλοντος εκτέλεσης μέσα στη VM

Η διεργασία host μπορεί να περιοριστεί σε primitives μνήμης, syscall και socket, ενώ freestanding libraries παρέχουν υπηρεσίες υψηλότερου επιπέδου μέσα στη VM. Για παράδειγμα, το FreeRTOS coreHTTP μπορεί να υλοποιήσει HTTP framing και το mbedTLS μπορεί να υλοποιήσει TLS χωρίς κλήσεις στο WinHTTP ή σε API TLS του λειτουργικού συστήματος. Τα raw sockets μέσω του `afd.sys` ή παρόμοιας διεπαφής αποτελούν τότε το στενό native όριο δικτύωσης.<sup>[[3]](#references)</sup>

Αυτός ο σχεδιασμός **Bring Your Own Execution Environment (BYOEE)** μπορεί επίσης να τοποθετήσει το PE loading, την υποστήριξη runtime και ένα in-memory filesystem πίσω από τον interpreter. Μειώνει τις αναγνωρίσιμες native υλοποιήσεις αντί να εξαλείφει το telemetry: οι λειτουργίες raw socket εξακολουθούν να είναι ορατές, ενώ περιβάλλοντα που απαιτούν ρητά proxies ή TLS interception μπορεί να εμποδίσουν τη λειτουργία του σχεδιασμού δικτύωσης.<sup>[[3]](#references)</sup>

## Επιλεκτική native επιτάχυνση

Η ερμηνεία κάθε instruction είναι ιδιαίτερα δαπανηρή στην κρυπτογραφία δημόσιου κλειδιού. Ένας πρακτικός διαχωρισμός χρησιμοποιεί τα `MBEDTLS_ALT` hooks του mbedTLS ως διεπαφή software coprocessor: διατηρεί το TLS state, την ανάλυση πιστοποιητικών, τη διαπραγμάτευση, την εκχώρηση μνήμης και τον κώδικα bignum υψηλού επιπέδου σε bytecode, αλλά δρομολογεί τους απαιτητικούς αριθμητικούς πυρήνες του `bignum_core.c` μέσω native ECALLs. Στο prototype Centurion, τα `bignum.c`, `bignum_mod.c` και `bignum_mod_raw.c` παρέμειναν virtualized, ενώ οι εσωτερικοί βρόχοι εκτελούνταν native, μειώνοντας ένα ECDHE handshake από λεπτά σε δευτερόλεπτα.<sup>[[3]](#references)</sup>

Κάντε τους accelerators προαιρετικούς, ώστε τα payloads που δεν χρειάζονται TLS να παραλείπουν τα πρόσθετα native entry points. Αυτό το μοτίβο γενικεύεται σε κάθε workload interpreter: πρώτα κάντε profiling και έπειτα εκθέστε το μικρότερο δυνατό native primitive αντί να μεταφέρετε ολόκληρο το subsystem εκτός VM.<sup>[[3]](#references)</sup>

Το Centurion επικύρωσε την πλήρη αλυσίδα με ένα TLS 1.2 bind shell: ο bytecode loader αντιστοίχισε το PE, οι socket calls πέρασαν από το universal thunk, το mbedTLS χειρίστηκε το πρωτόκολλο μέσα στη VM και τα native ECALLs επιτάχυναν την αριθμητική ECDHE. Έτσι, ο native interpreter μεγέθους περίπου 18 KB υποστήριξε ένα κρυπτογραφημένο command channel χωρίς να υλοποιήσει το payload ως native x86-64 code.<sup>[[3]](#references)</sup>

## Σημεία αναφοράς για reverse engineering και εντοπισμό

Τα παρακάτω αποτελούν πρακτικά σημεία ανάλυσης που προκύπτουν από την αρχιτεκτονική· το virtualization αλλάζει το πού παρατηρούν οι analysts τη συμπεριφορά, αλλά δεν την καταργεί.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Εντοπίστε τον βρόχο fetch/decode/dispatch, τον virtual program counter, το register file και την επαναλαμβανόμενη εκτέλεση instructions σταθερού μήκους.
- Κάντε dump τον opcode table μετά την runtime αποκρυπτογράφηση και αντιστοιχίστε τις διευθύνσεις των handlers σε σημασιολογικές λειτουργίες, αντί να αναζητάτε κρυπτογραφημένο bytecode στον δίσκο.
- Σταματήστε την εκτέλεση στο universal thunk ή στον ECALL dispatcher, για να καταγράψετε τον native target, τα virtual argument registers, τα stack arguments και την τιμή επιστροφής.
- Ανιχνεύστε την πρόσβαση στο PEB, την επίλυση exports, την ανάλυση PE headers, τις εγγραφές relocations και τη συμπλήρωση του IAT, ακόμη κι όταν η υλοποίηση του loader είναι bytecode.
- Συσχετίστε τη δημιουργία sockets και την κίνηση `afd.sys` με την απουσία των αναμενόμενων κλήσεων WinHTTP ή native TLS· οι high-level imports που λείπουν αποτελούν ένδειξη, όχι απόδειξη, κακόβουλης συμπεριφοράς.
- Αντιμετωπίστε τους native arithmetic accelerators ως semantic choke points: οι callers τους μπορούν να αποκαλύψουν δραστηριότητα key exchange και επικύρωσης πιστοποιητικών, ενώ η γύρω TLS state machine παραμένει virtualized.

Για workflows ανάλυσης που ξεκινούν από τον dispatcher αντί από το αρχικό control-flow graph, ανατρέξτε στις [οδηγίες ανάλυσης malware για virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Λειτουργικοί περιορισμοί

Το virtualization επιφέρει overhead ερμηνείας, αυξάνει την πολυπλοκότητα του toolchain και του ABI και δεν επιλύει τον εντοπισμό βάσει συμπεριφοράς. Η shared memory είναι εξ ορισμού μη ασφαλής, η δικτύωση μέσω raw sockets μπορεί να αποτύχει πίσω από υποχρεωτικά proxies και τα Win32 APIs με πολλά callbacks απαιτούν native-to-VM trampolines. Ο interpreter, η γέφυρα syscall και οι native accelerators εξακολουθούν επίσης να αποτελούν συμβατικό native αποτύπωμα, το οποίο οι defenders μπορούν να εντοπίσουν με signatures ή να instrument.<sup>[[2]](#references)[[3]](#references)</sup>

## Σχετικές σελίδες

Για ανάλυση του VMProtect 3.x packing, δείτε [emulated unpacking και επιδιόρθωση imports](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Δημιουργία μιας RISC-V Virtual Machine για Obfuscation Payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming στην εποχή του EDR — Αποφυγή εντοπισμού μέσω Malware Virtualisation](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Bring Your Own Execution Environment](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Μπείτε στο WasmForge: Μεταγλώττιση του Sliver σε WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
