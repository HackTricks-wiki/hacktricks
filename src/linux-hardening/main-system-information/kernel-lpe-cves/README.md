# Υλικό για Kernel, LPE και CVE

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι μελέτες περίπτωσης καλύπτουν διαφορετικά primitives για τοπική κλιμάκωση προνομίων. Σε κάθε άρθρο, ελέγξτε το επηρεαζόμενο προϊόν ή kernel, τη διαμόρφωση και τις προϋποθέσεις πριν εφαρμόσετε μια τεχνική. Για ευρύτερη απαρίθμηση του host, χρησιμοποιήστε τη [λίστα ελέγχου κλιμάκωσης προνομίων Linux](../linux-privilege-escalation-checklist.md).

Για το Dirty Pipe (CVE-2022-0847), η [αρχική έρευνα](https://dirtypipe.cm4all.com/) προσδιορίζει τις διορθώσεις upstream stable στις εκδόσεις 5.10.102, 5.15.25 και 5.16.11. Μια έκδοση kernel σε παλαιότερο επηρεαζόμενο εύρος αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο: οι kernel διανομών μπορεί να περιλαμβάνουν backport διορθώσεων με διαφορετικές ονομασίες εκδόσεων, ενώ το σχετικό αρχείο προορισμού πρέπει να είναι αναγνώσιμο για το primitive εγγραφής στην page cache. Η αντικατάσταση ενός αναγνώσιμου εκτελέσιμου SUID είναι ένας πιθανός δρόμος για απόκτηση προνομίων, εφόσον εξακολουθεί να ισχύει η μετάβαση set-ID· η τροποποίηση του `/etc/passwd` και, στη συνέχεια, η πιστοποίηση ταυτότητας μπορεί επίσης να εξαρτάται από την τοπική στοίβα PAM. Πριν αξιολογήσετε αν είναι εφικτή η εκμετάλλευση, ελέγξτε το εγκατεστημένο πακέτο kernel του προμηθευτή, τον kernel που εκτελείται μετά την επανεκκίνηση, τα δικαιώματα του αρχείου προορισμού, το mount `nosuid` και το `no_new_privs`. Μην εκτελείτε δοκιμή εγγραφής κατά την παθητική απαρίθμηση. Δείτε την [κατάσταση ανά έκδοση του Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): εκτέλεση με αυξημένα προνόμια μέσω μη έμπιστου εντοπισμού διαδρομής διεργασίας.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): μια διαδρομή για overwrite της page cache του kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): ένα race condition στον χειρισμό χρονομέτρων.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): πρόσβαση σε file descriptor κατά τη διάρκεια race condition εξόδου διεργασίας.

## Σχετικές μελέτες περίπτωσης binary exploitation

Η ενότητα Binary Exploitation εμβαθύνει στα exploit primitives, στη διάταξη μνήμης και στην παράκαμψη mitigations για αυτούς τους στόχους Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ένα bug socket εξελίχθηκε σε primitives ανάγνωσης και εγγραφής στον kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ένα primitive εγγραφής pointer επεκτάθηκε μέσω pipe buffers και workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): εκμετάλλευση kernel heap και παράκαμψη mitigations.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): η ανάλυση του race condition από την πλευρά του binary exploitation, η οποία συνοψίζεται επίσης παραπάνω.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): εντοπισμός διευθύνσεων για εκμετάλλευση kernel σε arm64.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): μια διαδρομή μέσω Android GPU για πρόσβαση στη μνήμη του kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): ένα bug σε Android accelerator που χρησιμοποιείται για εγγραφές στον kernel.
{{#include ../../../banners/hacktricks-training.md}}
