# Εκτέλεση Virtualized Payload και Evasion με Custom VM

{{#include ../banners/hacktricks-training.md}}

Το virtualization του payload μεταγλωττίζει offensive logic σε ένα guest instruction set και το εκτελεί με native interpreter. Σε αντίθεση με έναν packer, ο οποίος πρέπει τελικά να εκθέσει στη μνήμη τις αρχικές native instructions, ένα virtualized payload μπορεί να διατηρεί την προστατευμένη λογική ως bytecode σε όλη τη διάρκεια ζωής του. Έτσι καταργείται αυτό το συγκεκριμένο παράθυρο unpacking, αλλά **δεν** αποκρύπτεται η συμπεριφορά που είναι ορατή στο host, όπως τα syscalls, η δραστηριότητα δικτύου ή το όριο κλήσεων VM-to-native.<sup>[[2]](#references)[[3]](#references)</sup>

## Μοντέλο εκτέλεσης

Ένας compact virtualized loader μπορεί να διαχωρίζει την εκτέλεση στα εξής επίπεδα.<sup>[[3]](#references)</sup>

1. Μεταγλώττισε freestanding C, BOF source ή runtime libraries μέσω LLVM σε custom bytecode ISA.
2. Εκκίνησε έναν μικρό native interpreter και αρχικοποίησε ένα build-specific opcode mapping.
3. Εκτέλεσε τον ίδιο τον PE linker-loader ως bytecode: κάνε parse τις κεφαλίδες, κάνε map τα sections, εφάρμοσε relocations, κάνε resolve τα imports και συμπλήρωσε το IAT.
4. Διατήρησε τις κλήσεις guest-to-guest μέσα στον interpreter. Δρομολόγησε τους στόχους εκτός της περιοχής bytecode, όπως τις συναρτήσεις εισαγόμενων DLL, μέσω ενός native host-call thunk.
5. Μετέφερε υποστηρικτικές λειτουργίες, όπως HTTP framing, TLS και τμήματα του C runtime, πίσω από το ίδιο όριο ερμηνείας.

Αυτό το μοντέλο αποφεύγει την εκχώρηση ξεχωριστής native code region για κάθε plugin και εμποδίζει την εμφάνιση του αρχικού payload ως αναγνωρίσιμης ροής x86-64 instructions. Παραμένει, ωστόσο, όριο evasion/obfuscation και όχι όριο ασφαλείας: ο native interpreter και κάθε εξωτερικό αποτέλεσμα παραμένουν παρατηρήσιμα.<sup>[[2]](#references)[[3]](#references)</sup>

## Γέφυρα shared memory προς το host

Μια απομονωμένη VM αναπαριστά τους pointers ως offsets μέσα σε ένα guest buffer, επομένως κάθε κλήση API προς το host απαιτεί μετάφραση pointers και ειδικό χειρισμό των output parameters. Αντίθετα, μια VM με shared memory καθιστά τις guest addresses έγκυρες διευθύνσεις της host process. Έτσι, οι αναγνώσεις και οι εγγραφές μπορούν να χρησιμοποιούν λειτουργίες τύπου `memcpy`, ενώ ένας pointer που επιστρέφεται από native allocation ECALL μπορεί να γίνει απευθείας dereference από bytecode. Το RISC-Y Business έδειξε ότι αυτός ο σχεδιασμός μπορεί να περιορίσει τη γέφυρα στην ανάκτηση του PEB και την εκτέλεση αυθαίρετων κλήσεων προς το host.<sup>[[1]](#references)</sup>

Για Windows x64, το virtual register file μπορεί να αντικατοπτρίζει το ABI: τοποθέτησε τα πρώτα τέσσερα integer ή pointer arguments στα `RCX`, `RDX`, `R8` και `R9`, ενώ τα επόμενα arguments και το shadow space βρίσκονται στο stack. Όταν μια virtual `CALL` επιλύεται εκτός της περιοχής bytecode, ένα universal thunk μεταφέρει αυτή την κατάσταση σε native call και αντιγράφει την τιμή επιστροφής πίσω στη VM. Έτσι επιτρέπονται κλήσεις IAT, heap allocation και λειτουργίες socket χωρίς pointer fixups.<sup>[[2]](#references)[[3]](#references)</sup>

Το τίμημα είναι η πλήρης απώλεια της απομόνωσης. Η αλλοίωση της guest memory μπορεί να επηρεάσει άμεσα το host, οι native callees μπορούν να διατηρήσουν ή να τροποποιήσουν guest pointers και ο interpreter πρέπει να θεωρεί το bytecode πλήρως έμπιστο. Τα native-to-VM callbacks χρειάζονται επίσης αντίστροφη γέφυρα· μια VM που υποστηρίζει μόνο εξερχόμενες κλήσεις δεν μπορεί να εξυπηρετήσει απευθείας APIs που βασίζονται σε callbacks, όπως το `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Πολυμορφισμός ISA ανά build

Μια custom ISA σταθερού πλάτους απλοποιεί το decoding, το dispatch, τις relocations και το virtual-register mapping. Το Centurion χρησιμοποιεί format instructions 18 bytes, εμπνευσμένο από το x86-64, το οποίο ανταλλάσσει την πυκνότητα κώδικα με προβλέψιμο parsing και αφήνει επίσης ανοιχτό το ενδεχόμενο μετάφρασης υπαρχόντων x86-64 artifacts σε bytecode.<sup>[[3]](#references)</sup>

Η τυχαιοποίηση του mapping opcode-to-handler σε κάθε build κάνει την ίδια guest logic να παράγει διαφορετικές ακολουθίες bytes. Η κρυπτογράφηση του mapping table και η ανάκτησή του μόνο κατά το runtime αφαιρούν επιπλέον ένα σταθερό opcode dictionary από τον δίσκο. Αυτό δυσκολεύει τις σταθερές signatures και τους επαναχρησιμοποιήσιμους κανόνες disassembly, αλλά δεν καθιστά αυτόματα πολυμορφικά τον native dispatcher, τη ρουτίνα αποκρυπτογράφησης του table ή το όριο host-call.<sup>[[3]](#references)</sup>

## Μεταφορά του περιβάλλοντος εκτέλεσης μέσα στη VM

Η host process μπορεί να περιοριστεί σε primitives μνήμης, syscall και socket, ενώ freestanding libraries παρέχουν υπηρεσίες υψηλότερου επιπέδου μέσα στη VM. Για παράδειγμα, το FreeRTOS coreHTTP μπορεί να υλοποιήσει HTTP framing και το mbedTLS μπορεί να υλοποιήσει TLS χωρίς κλήσεις στο WinHTTP ή σε API TLS του λειτουργικού συστήματος. Τα raw sockets μέσω του `afd.sys` ή παρόμοιας διεπαφής αποτελούν τότε το στενό native όριο δικτύωσης.<sup>[[3]](#references)</sup>

Αυτός ο σχεδιασμός **Bring Your Own Execution Environment (BYOEE)** μπορεί επίσης να τοποθετήσει τη φόρτωση PE, την υποστήριξη runtime και ένα in-memory filesystem πίσω από τον interpreter. Μειώνει τις αναγνωρίσιμες native υλοποιήσεις αντί να εξαλείφει την τηλεμετρία: οι λειτουργίες raw socket παραμένουν ορατές, ενώ περιβάλλοντα που απαιτούν ρητούς proxies ή TLS interception ενδέχεται να εμποδίσουν τη λειτουργία του σχεδιασμού δικτύωσης.<sup>[[3]](#references)</sup>

## Επιλεκτική native επιτάχυνση

Η ερμηνεία κάθε instruction είναι ιδιαίτερα δαπανηρή στην κρυπτογραφία δημόσιου κλειδιού. Ένας πρακτικός διαχωρισμός χρησιμοποιεί τα hooks `MBEDTLS_ALT` του mbedTLS ως διεπαφή software coprocessor: διατηρεί την κατάσταση TLS, το certificate parsing, τη διαπραγμάτευση, την allocation και τον high-level κώδικα bignum σε bytecode, αλλά δρομολογεί τους υπολογιστικούς kernels που εκτελούνται συχνά από το `bignum_core.c` μέσω native ECALLs. Στο prototype του Centurion, τα `bignum.c`, `bignum_mod.c` και `bignum_mod_raw.c` παρέμειναν virtualized, ενώ οι εσωτερικοί βρόχοι εκτελούνταν natively, μειώνοντας ένα ECDHE handshake από λεπτά σε δευτερόλεπτα.<sup>[[3]](#references)</sup>

Κάνε τους accelerators προαιρετικούς, ώστε τα payloads που δεν χρειάζονται TLS να παραλείπουν τα πρόσθετα native entry points. Αυτό το μοτίβο γενικεύεται σε κάθε workload interpreter: πρώτα κάνε profiling και έπειτα έκθεσε το μικρότερο δυνατό native primitive, αντί να μεταφέρεις ολόκληρο subsystem εκτός VM.<sup>[[3]](#references)</sup>

Το Centurion επικύρωσε ολόκληρη την αλυσίδα με ένα TLS 1.2 bind shell: ο bytecode loader έκανε map το PE, οι κλήσεις socket περνούσαν από το universal thunk, το mbedTLS χειριζόταν το πρωτόκολλο μέσα στη VM και τα native ECALLs επιτάχυναν την αριθμητική ECDHE. Έτσι, ο native interpreter μεγέθους περίπου 18 KB υποστήριζε ένα κρυπτογραφημένο command channel χωρίς να υλοποιεί το payload ως native κώδικα x86-64.<sup>[[3]](#references)</sup>

## Σημεία αναφοράς για reversing και detection

Τα παρακάτω αποτελούν πρακτικά σημεία αναφοράς για ανάλυση, συναγόμενα από την αρχιτεκτονική· το virtualization αλλάζει το πού παρατηρούν οι analysts τη συμπεριφορά, αλλά δεν την εξαλείφει.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Εντόπισε τον βρόχο fetch/decode/dispatch, τον virtual program counter, το register file και τα επαναλαμβανόμενα βήματα σταθερού πλάτους instructions.
- Κάνε dump τον opcode table μετά την αποκρυπτογράφησή του κατά το runtime και αντιστοίχισε τις διευθύνσεις των handlers σε σημασιολογικές λειτουργίες, αντί να αναζητάς κρυπτογραφημένο bytecode στον δίσκο.
- Βάλε breakpoint στο universal thunk ή στον ECALL dispatcher για να καταγράψεις τον native στόχο, τα virtual argument registers, τα stack arguments και την τιμή επιστροφής.
- Ανίχνευσε την πρόσβαση στο PEB, την επίλυση exports, το parsing των PE headers, τις εγγραφές relocations και τη συμπλήρωση του IAT, ακόμη κι όταν η υλοποίηση του loader είναι bytecode.
- Συσχέτισε τη δημιουργία sockets και την κίνηση `afd.sys` με την απουσία αναμενόμενων κλήσεων WinHTTP ή native TLS· η απουσία high-level imports αποτελεί ένδειξη, όχι απόδειξη, benign συμπεριφοράς.
- Αντιμετώπισε τους native arithmetic accelerators ως σημασιολογικά chokepoints: οι callers τους μπορούν να αποκαλύψουν δραστηριότητα ανταλλαγής κλειδιών και επικύρωσης πιστοποιητικών, ενώ η περιβάλλουσα TLS state machine παραμένει virtualized.

Για workflows ανάλυσης που ξεκινούν από τον dispatcher αντί από το αρχικό control-flow graph, δες τις [οδηγίες malware analysis για virtualizing packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Λειτουργικοί περιορισμοί

Το virtualization επιφέρει overhead από την ερμηνεία, αυξάνει την πολυπλοκότητα του toolchain και του ABI και δεν επιλύει το behavioral detection. Η shared memory είναι εξ ορισμού μη ασφαλής, η δικτύωση μέσω raw sockets μπορεί να αποτύχει πίσω από υποχρεωτικούς proxies και τα Win32 APIs που βασίζονται εκτενώς σε callbacks απαιτούν native-to-VM trampolines. Ο interpreter, η γέφυρα syscall και τυχόν native accelerators παραμένουν επίσης ένα συμβατικό native αποτύπωμα, το οποίο οι defenders μπορούν να ταυτοποιήσουν με signatures ή να instrumentάρουν.<sup>[[2]](#references)[[3]](#references)</sup>

## Σχετικές σελίδες

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Κατασκευή μιας RISC-V Virtual Machine για Obfuscation Payload](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming στην εποχή του EDR — Evasion μέσω Malware Virtualisation](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — Φέρτε το δικό σας περιβάλλον εκτέλεσης](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
