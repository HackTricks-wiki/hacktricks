# Υλικό για Kernel, LPE και CVE

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι μελέτες περίπτωσης καλύπτουν διαφορετικά primitives τοπικής κλιμάκωσης προνομίων. Ελέγξτε το επηρεαζόμενο προϊόν ή kernel, τη διαμόρφωση και τις προϋποθέσεις σε κάθε άρθρο πριν εφαρμόσετε κάποια τεχνική. Για ευρύτερη απαρίθμηση του host, χρησιμοποιήστε τη [λίστα ελέγχου κλιμάκωσης προνομίων Linux](../linux-privilege-escalation-checklist.md).

Για το Dirty Pipe (CVE-2022-0847), η [αρχική έρευνα](https://dirtypipe.cm4all.com/) προσδιορίζει τις διορθώσεις upstream stable στις εκδόσεις 5.10.102, 5.15.25 και 5.16.11. Μια έκδοση kernel σε παλαιότερο επηρεαζόμενο εύρος αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο: οι kernels διανομών μπορεί να περιλαμβάνουν backport διορθώσεων με διαφορετικά ονόματα εκδόσεων, ενώ το σχετικό αρχείο-στόχος πρέπει να είναι αναγνώσιμο για να είναι δυνατή η primitive εγγραφής στο page cache. Η αντικατάσταση ενός αναγνώσιμου SUID εκτελέσιμου αρχείου είναι μία πιθανή διαδρομή απόκτησης προνομίων, εφόσον εξακολουθεί να ισχύει η μετάβαση set-ID· η τροποποίηση του `/etc/passwd` και στη συνέχεια η πιστοποίηση ταυτότητας μπορεί επίσης να εξαρτάται από την τοπική στοίβα PAM. Πριν αξιολογήσετε αν είναι εφικτή η εκμετάλλευση, ελέγξτε το εγκατεστημένο πακέτο kernel του προμηθευτή, τον kernel που εκτελείται μετά την επανεκκίνηση, τα δικαιώματα του αρχείου-στόχου, την επιλογή προσάρτησης `nosuid` και το `no_new_privs`. Μην εκτελείτε δοκιμή εγγραφής κατά την παθητική απαρίθμηση. Δείτε την [κατάσταση ανά έκδοση του Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): εκτέλεση με προνόμια μέσω αναζήτησης διαδρομής διεργασιών που δεν είναι έμπιστη.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): μια διαδρομή εγγραφής πάνω στο page cache του kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ένας αγώνας στην επεξεργασία χρονομέτρων.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): πρόσβαση σε descriptors κατά τη διάρκεια ενός αγώνα εξόδου διεργασίας.

## Σχετικές μελέτες περίπτωσης Binary Exploitation

Η ενότητα Binary Exploitation εξετάζει σε μεγαλύτερο βάθος τα exploit primitives, τη διάταξη μνήμης και τις παρακάμψεις μετριασμών για αυτούς τους στόχους Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ένα σφάλμα socket αξιοποιείται για τη δημιουργία primitives ανάγνωσης και εγγραφής στον kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ένα primitive εγγραφής σε pointer επεκτείνεται μέσω pipe buffers και workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): εκμετάλλευση του kernel heap και παρακάμψεις μετριασμών.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): η ανάλυση του αγώνα από τη σκοπιά του Binary Exploitation, η οποία συνοψίζεται επίσης παραπάνω.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): εντοπισμός διευθύνσεων για εκμετάλλευση του arm64 kernel.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): μια διαδρομή μέσω GPU του Android για πρόσβαση στη μνήμη του kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ένα σφάλμα accelerator του Android που αξιοποιείται για εγγραφές στον kernel.
{{#include ../../../banners/hacktricks-training.md}}
