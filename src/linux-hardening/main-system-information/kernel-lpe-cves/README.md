# Υλικό για Kernel, LPE και CVE

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι μελέτες περίπτωσης καλύπτουν διαφορετικά primitives τοπικής κλιμάκωσης προνομίων. Ελέγξτε το επηρεαζόμενο προϊόν ή kernel, τη διαμόρφωση και τις προϋποθέσεις σε κάθε άρθρο πριν εφαρμόσετε μια τεχνική. Για ευρύτερη απαρίθμηση του host, χρησιμοποιήστε τη [λίστα ελέγχου κλιμάκωσης προνομίων Linux](../linux-privilege-escalation-checklist.md).

Για το Dirty Pipe (CVE-2022-0847), η [αρχική έρευνα](https://dirtypipe.cm4all.com/) αναφέρει ότι οι διορθώσεις upstream stable περιλαμβάνονται στις εκδόσεις 5.10.102, 5.15.25 και 5.16.11. Μια έκδοση kernel σε παλαιότερη επηρεαζόμενη σειρά αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο: οι kernels των διανομών μπορεί να περιλαμβάνουν backport διορθώσεων με διαφορετικές ονομασίες έκδοσης, ενώ το σχετικό αρχείο-στόχος πρέπει να είναι αναγνώσιμο για να λειτουργήσει το primitive εγγραφής στο page cache. Η αντικατάσταση ενός αναγνώσιμου SUID εκτελέσιμου είναι μια πιθανή διαδρομή προς την απόκτηση προνομίων, εφόσον εξακολουθεί να ισχύει η μετάβαση set-ID· η τροποποίηση του `/etc/passwd` και, στη συνέχεια, η αυθεντικοποίηση μπορεί επίσης να εξαρτάται από την τοπική στοίβα PAM. Πριν αξιολογήσετε αν είναι εφικτή η επίθεση, ελέγξτε το εγκατεστημένο πακέτο kernel του vendor, τον kernel που εκτελείται μετά την επανεκκίνηση, τα δικαιώματα του αρχείου-στόχου, την επιλογή προσάρτησης `nosuid` και το `no_new_privs`. Μην εκτελείτε δοκιμή εγγραφής κατά την παθητική απαρίθμηση. Δείτε την [κατάσταση ανά έκδοση του Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Ανακάλυψη υπηρεσίας VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): εκτέλεση με αυξημένα προνόμια μέσω ανακάλυψης διαδρομών διεργασιών που δεν είναι έμπιστες.
- [Αντικατάσταση page cache μέσω AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): διαδρομή αντικατάστασης του page cache του kernel.
- [TOCTOU στα POSIX CPU timers, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race condition στον χειρισμό χρονομέτρων.
- [Race condition εξόδου του Linux ptrace και κλοπή file descriptor με `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): πρόσβαση σε descriptor κατά τη διάρκεια race condition εξόδου μιας διεργασίας.

## Σχετικές μελέτες περίπτωσης binary exploitation

Η ενότητα Binary Exploitation εξετάζει σε μεγαλύτερο βάθος τα exploit primitives, τη διάταξη μνήμης και τις παρακάμψεις mitigations για αυτούς τους στόχους Linux kernel:

- [Use-after-free στο SKB εκτός ζώνης του AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ένα socket bug αξιοποιήθηκε για τη δημιουργία primitives ανάγνωσης και εγγραφής στον kernel.
- [Υποχείλιση scatterlist από ταυτόχρονους writers AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): ένα race condition σε writer skcipher αξιοποιήθηκε για εγγραφή στον kernel.
- [Use-after-free στο Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ένα primitive εγγραφής pointer επεκτάθηκε μέσω pipe buffers και workqueues.
- [Εγγραφή εκτός ορίων σε streams ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): εκμετάλλευση heap του kernel και παρακάμψεις mitigations.
- [TOCTOU στα POSIX CPU timers, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): η ανάλυση binary exploitation του race condition χρονομέτρων που συνοψίζεται παραπάνω.
- [Παράκαμψη KASLR του στατικού linear map στο Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): εντοπισμός διευθύνσεων για εκμετάλλευση του kernel στο arm64.
- [Παράκαμψη προνομίων GPU/SMMU Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): διαδρομή μέσω GPU Android για πρόσβαση στη μνήμη του kernel.
- [Use-after-free λόγω timeout εργασίας Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): bug επιταχυντή Android που αξιοποιείται για εγγραφές στον kernel.
{{#include ../../../banners/hacktricks-training.md}}
