# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Ο **πυρήνας του macOS είναι το XNU**, ακρωνύμιο του "X is Not Unix". Αυτός ο πυρήνας αποτελείται θεμελιωδώς από το **Mach microkernel** (το οποίο θα συζητηθεί αργότερα), **και** στοιχεία από το Berkeley Software Distribution (**BSD**). Το XNU παρέχει επίσης μια πλατφόρμα για **kernel drivers μέσω ενός συστήματος που ονομάζεται I/O Kit**. Ο πυρήνας XNU αποτελεί μέρος του open source project Darwin, επομένως **ο πηγαίος κώδικάς του είναι ελεύθερα προσβάσιμος**.

Από την οπτική γωνία ενός security researcher ή ενός Unix developer, το **macOS** μπορεί να μοιάζει αρκετά **παρόμοιο** με ένα σύστημα **FreeBSD**, με κομψό GUI και πλήθος προσαρμοσμένων εφαρμογών. Οι περισσότερες εφαρμογές που έχουν αναπτυχθεί για BSD μεταγλωττίζονται και εκτελούνται σε macOS χωρίς να χρειάζονται τροποποιήσεις, καθώς τα command-line tools που είναι οικεία στους Unix users υπάρχουν όλα στο macOS. Ωστόσο, επειδή ο πυρήνας XNU ενσωματώνει το Mach, υπάρχουν ορισμένες σημαντικές διαφορές μεταξύ ενός παραδοσιακού Unix-like συστήματος και του macOS, και αυτές οι διαφορές μπορεί να προκαλέσουν πιθανά προβλήματα ή να προσφέρουν μοναδικά πλεονεκτήματα.

Open source version of XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Το Mach είναι ένα **microkernel** σχεδιασμένο ώστε να είναι **UNIX-compatible**. Μία από τις βασικές αρχές σχεδιασμού του ήταν να **ελαχιστοποιήσει** την ποσότητα **κώδικα** που εκτελείται στον χώρο του **kernel** και, αντίθετα, να επιτρέψει σε πολλές τυπικές λειτουργίες του kernel, όπως το file system, το networking και το I/O, να **εκτελούνται ως user-level tasks**.

Στο XNU, το Mach είναι **υπεύθυνο για πολλές από τις κρίσιμες λειτουργίες χαμηλού επιπέδου** που συνήθως χειρίζεται ένας kernel, όπως ο προγραμματισμός των processors, το multitasking και η διαχείριση virtual memory.

### BSD

Ο **kernel** XNU επίσης **ενσωματώνει** σημαντική ποσότητα κώδικα που προέρχεται από το project **FreeBSD**. Αυτός ο κώδικας **εκτελείται ως μέρος του kernel μαζί με το Mach**, στον ίδιο χώρο διευθύνσεων. Ωστόσο, ο κώδικας FreeBSD μέσα στο XNU μπορεί να διαφέρει σημαντικά από τον αρχικό κώδικα FreeBSD, επειδή χρειάστηκαν τροποποιήσεις για να διασφαλιστεί η συμβατότητά του με το Mach. Το FreeBSD συνεισφέρει σε πολλές λειτουργίες του kernel, όπως:

- Διαχείριση processes
- Διαχείριση signals
- Βασικοί μηχανισμοί ασφάλειας, συμπεριλαμβανομένης της διαχείρισης users και groups
- Υποδομή system calls
- TCP/IP stack και sockets
- Firewall και packet filtering

Η κατανόηση της αλληλεπίδρασης μεταξύ BSD και Mach μπορεί να είναι σύνθετη, λόγω των διαφορετικών εννοιολογικών τους frameworks. Για παράδειγμα, το BSD χρησιμοποιεί processes ως θεμελιώδη μονάδα εκτέλεσης, ενώ το Mach λειτουργεί με βάση τα threads. Αυτή η ασυμφωνία επιλύεται στο XNU με την **αντιστοίχιση κάθε BSD process σε ένα Mach task** που περιέχει ακριβώς ένα Mach thread. Όταν χρησιμοποιείται το BSD system call `fork()`, ο κώδικας BSD μέσα στον kernel χρησιμοποιεί λειτουργίες του Mach για να δημιουργήσει μια δομή task και thread.

Επιπλέον, **το Mach και το BSD διατηρούν διαφορετικά security models**: το security model του **Mach** βασίζεται στα **port rights**, ενώ το security model του BSD βασίζεται στην **ιδιοκτησία των processes**. Οι διαφορές μεταξύ αυτών των δύο models έχουν περιστασιακά οδηγήσει σε local privilege-escalation vulnerabilities. Εκτός από τα τυπικά system calls, υπάρχουν επίσης **Mach traps που επιτρέπουν σε user-space programs να αλληλεπιδρούν με τον kernel**. Αυτά τα διαφορετικά στοιχεία συνθέτουν τη σύνθετη, hybrid αρχιτεκτονική του macOS kernel.

### I/O Kit - Drivers

Το I/O Kit είναι ένα open-source, object-oriented **device-driver framework** στον XNU kernel και χειρίζεται **dynamically loaded device drivers**. Επιτρέπει την προσθήκη modular κώδικα στον kernel on-the-fly, υποστηρίζοντας διαφορετικό hardware.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors in macOS Architecture

Οι πλατφόρμες της Apple βασίζονται σε αρκετούς coprocessors, ώστε να διατηρούν τις εργασίες που είναι ευαίσθητες ως προς το latency εκτός των κύριων cores και να απομονώνουν τις security-critical functions.

- **Secure Enclave Processor (SEP)**: Ένας dedicated ARM core με δικό του microkernel και secure boot chain, που συνήθως εκτελείται στο **EL3/secure world**. Η αλληλεπίδραση πραγματοποιείται μέσω mailbox drivers στο macOS στο EL1.
- Attack surface: Οι ενημερώσεις του SEP firmware και τα user-space daemons (`seputil`, `securityd`) που λειτουργούν ως proxies για τα requests.
- Impact of compromise: Διαρροή long-term keys, παράκαμψη biometric gating και παραβίαση των protections του FileVault ή του Apple Pay.
- **System Management Controller (SMC)**: Εκτελεί proprietary firmware σε microcontroller εκτός των ARM exception levels. Το macOS (EL1) αποκτά πρόσβαση σε αυτό μέσω I/O Kit user clients.
- Attack surface: USB-C power delivery messages, interfaces διαχείρισης fan/battery και firmware update paths.
- Impact of compromise: Παράκαμψη thermal limits, εισαγωγή fake sensor data, διακοπή τροφοδοσίας ή εγκατάσταση persistent NVRAM backdoors.
- **T1/T2 Security Chips**: Εκτελούν το bridgeOS (προερχόμενο από το watchOS) κυρίως σε EL1/EL3, στους δικούς τους ARM cores. Το macOS επικοινωνεί μέσω καναλιών τύπου PCIe/USB που διαμεσολαβούνται από το IOKit.
- Attack surface: DFU/restore pathways, IPC endpoints που εκτίθενται από services όπως το `tccd` και media pipelines που γεφυρώνονται με το T2.
- Impact of compromise: Απενεργοποίηση του secure boot, αποκρυπτογράφηση περιεχομένων SSD, hijacking του camera/mic gating ή emulation HID input για stealth persistence.
- **Display Coprocessor (DCP)**: Εκτελεί firmware στο EL1, μέσα σε isolated address space που προστατεύεται από το DART (το Apple IOMMU).
- Attack surface: Interfaces `DCPAVService`, shared descriptor buffers και firmware image parsing.
- Impact of compromise: Injection arbitrary frames, snooping framebuffers ή brick του display pipeline για DoS.
- **Apple Neural Engine (ANE)**: Εκτελεί microcode σε dedicated ML cluster (χωρίς ARM EL levels). Το macOS προγραμματίζει τις εργασίες μέσω των `ANECompilerService` και IOKit.
- Attack surface: Compiled model binaries (`.ane`), Core ML APIs που τροφοδοτούν custom kernels και firmware loaders.
- Impact of compromise: Tampering ή exfiltration ML models, leak επεξεργασμένων audio/vision data ή sabotage του on-device inference.
- **AGX GPU**: Το firmware εκτελείται σε custom GPU cores με scheduler· το EL0 υποβάλλει Metal commands που επικυρώνονται από το EL1.
- Attack surface: Metal shader compiler, shared buffer mapping APIs και `com.apple.AGXFirmware` ioctl interfaces.
- Impact of compromise: DMA access στη system memory, sandbox escapes μέσω GPU drivers ή persistent firmware implants.
- **Apple Video Encoder (AVE)**: Το firmware εκτελείται στο Media Engine, σε sandbox τύπου EL1. Το macOS αλληλεπιδρά μέσω των VideoToolbox και `AppleAVE2`.
- Attack surface: Codec bitstreams, parameter sets, user-supplied buffers και firmware update blobs.
- Impact of compromise: Leak ασυμπίεστων frames, παράκαμψη DRM ή απόκτηση code execution με πρόσβαση σε DMA engines.
- **Image Signal Processor (ISP)**: Εκτελεί secure firmware στο Media Engine cluster· οι macOS camera drivers λειτουργούν στο EL1.
- Attack surface: Camera HALs, RAW frame descriptors, ISP configuration queues και firmware updates.
- Impact of compromise: Αθόρυβη καταγραφή raw camera feeds, απενεργοποίηση privacy indicators ή εισαγωγή fabricated imagery.
- **AMX Matrix cores**: Λειτουργούν ως coprocessor units που εκτίθενται στο EL0/EL1 μέσω νέων instructions.
- Attack surface: Kernel virtualization του AMX state (`thread_set_state`, context switches) και user-space code generation.
- Impact of compromise: Διαρροή των tile registers άλλων processes, fingerprinting workloads ή escalation μέσω kernel memory corruption.

Το σύγχρονο macOS αντιμετωπίζει αυτούς τους coprocessors ως trusted components στην chain of trust. Το firmware των SEP, SMC και T2 είναι signed από την Apple, ενώ τα handshake protocols (που συχνά υλοποιούνται μέσω mailboxes ή I/O Kit families) περιλαμβάνουν challenge-response checks, ώστε μόνο authenticated firmware να μπορεί να εξυπηρετεί requests.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

Το macOS είναι **εξαιρετικά περιοριστικό ως προς τη φόρτωση Kernel Extensions** (.kext), λόγω των υψηλών privileges με τα οποία θα εκτελείται ο κώδικας. Στην πραγματικότητα, από προεπιλογή είναι ουσιαστικά αδύνατο (εκτός αν βρεθεί bypass).

Στην ακόλουθη σελίδα μπορείτε επίσης να δείτε πώς να ανακτήσετε το `.kext` που φορτώνει το macOS μέσα στο **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Αντί να χρησιμοποιεί Kernel Extensions, το macOS δημιούργησε τα System Extensions, τα οποία προσφέρουν APIs σε user level για αλληλεπίδραση με τον kernel. Με αυτόν τον τρόπο, οι developers μπορούν να αποφεύγουν τη χρήση kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes & RSR (Rapid Security Response)

- Το **Cryptex** σημαίνει **CRYPTographically-sealed EXtension**. Είναι ένα sealed disk image (container) που χρησιμοποιείται από την Apple για τη φιλοξενία τμημάτων του OS (frameworks, shared libraries, apps) τα οποία είναι πιθανότερο να αλλάζουν μεταξύ major OS updates.
- Στα macOS και iOS, τα components που τοποθετούνται μέσα σε cryptexes μπορούν να γίνουν **patched ή replaced** μέσω RSR, χωρίς να χρειάζεται re-sealing ολόκληρου του system volume.
- Τα cryptexes βρίσκονται στο **Preboot volume**, μαζί με το boot firmware, και grafted στο OS file system κατά το runtime.
- Η φόρτωση του περιεχομένου ενός cryptex περιλαμβάνει validation: το σύστημα ελέγχει τα file seals, τα manifests και τα root hashes, και στη συνέχεια κάνει mount ή “graft” στο περιεχόμενο του cryptex, ώστε κατά το runtime οι εφαρμογές να χρησιμοποιούν τις cryptex versions όπου υπάρχουν.
- Στα boot logs, η φόρτωση των cryptex πραγματοποιείται μετά την αρχικοποίηση του kernel, αλλά πριν ενεργοποιηθούν πλήρως τα system services.


#### Rapid Security Response (RSR)

- Το **RSR** είναι ο μηχανισμός της Apple για την παράδοση **security patches μεταξύ regular OS updates**. Στοχεύει περιεχόμενο cryptex για την ενημέρωση ευάλωτων τμημάτων (π.χ. libraries, frameworks), χωρίς να αγγίζει το core system volume.
- Κατά την εφαρμογή ενός RSR update, η συσκευή ζητά από τον signing server της Apple ένα **Cryptex1 Image4 manifest**. Αυτό το manifest είναι cryptographically bound στη συσκευή και στο νέο cryptex content.
- Το υπάρχον AP boot ticket για το base system **δεν τροποποιείται** από το RSR. Το patch λειτουργεί προσθετικά πάνω από το sealed base OS.
- Στο macOS, ορισμένα patched components (π.χ. το Safari) ενεργοποιούνται μόλις γίνει relaunch της εφαρμογής· δεν απαιτείται πάντα πλήρες system restart.
- Τα RSRs είναι **removable**: κάθε RSR περιλαμβάνει ένα patch και ένα “antipatch” που μπορεί να κάνει rollback στην έκδοση του base OS. Κατά την αφαίρεση, το cryptex content επανέρχεται.
- Τα RSR updates είναι γενικά πολύ μικρότερα από τα full OS updates και απαιτούν χαμηλότερο battery state για την εγκατάστασή τους.


## References

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
