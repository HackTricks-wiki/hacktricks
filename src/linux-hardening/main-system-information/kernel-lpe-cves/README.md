# Υλικό για Kernel, LPE και CVE

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι μελέτες περίπτωσης καλύπτουν διαφορετικά primitives τοπικής κλιμάκωσης προνομίων. Ελέγξτε το επηρεαζόμενο προϊόν ή kernel, τις ρυθμίσεις και τις προϋποθέσεις σε κάθε άρθρο προτού εφαρμόσετε μια τεχνική. Για ευρύτερη απαρίθμηση του host, χρησιμοποιήστε τη [λίστα ελέγχου κλιμάκωσης προνομίων Linux](../linux-privilege-escalation-checklist.md).

Για το Dirty Pipe (CVE-2022-0847), η [αρχική έρευνα](https://dirtypipe.cm4all.com/) εντοπίζει τις upstream stable διορθώσεις στις εκδόσεις 5.10.102, 5.15.25 και 5.16.11. Μια έκδοση kernel που βρίσκεται σε παλαιότερη επηρεαζόμενη περιοχή αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο: οι kernels των διανομών μπορεί να έχουν ενσωματώσει διορθώσεις με διαφορετικές ονομασίες εκδόσεων, ενώ το σχετικό αρχείο-στόχος πρέπει να είναι αναγνώσιμο για να είναι εφικτό το primitive εγγραφής στο page cache. Η αντικατάσταση ενός αναγνώσιμου SUID εκτελέσιμου είναι μία πιθανή οδός προς αυξημένα προνόμια, εφόσον εξακολουθεί να ισχύει η μετάβαση set-ID· η τροποποίηση του `/etc/passwd` και η επακόλουθη αυθεντικοποίηση μπορεί επίσης να εξαρτώνται από την τοπική στοίβα PAM. Πριν αξιολογήσετε αν είναι εφικτή η εκμετάλλευση, ελέγξτε το εγκατεστημένο πακέτο kernel του προμηθευτή, τον kernel που εκτελείται μετά την επανεκκίνηση, τα δικαιώματα του αρχείου-στόχου, το `nosuid` στο mount και το `no_new_privs`. Μην εκτελείτε δοκιμή εγγραφής κατά την παθητική απαρίθμηση. Δείτε την [κατάσταση ανά έκδοση του Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [VMware Tools service discovery, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): εκτέλεση με αυξημένα προνόμια μέσω μη έμπιστου εντοπισμού διαδρομών διεργασιών.
- [AF_ALG splice page-cache overwrite, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): διαδρομή εγγραφής στο page cache του kernel.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](posix-cpu-timers-toctou-cve-2025-38352.md): race condition στον χειρισμό χρονοδιακόπτη.
- [Linux ptrace exit race and `pidfd_getfd` file-descriptor theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): πρόσβαση σε file descriptor κατά τη διάρκεια race condition εξόδου διεργασίας.

## Σχετικές μελέτες περίπτωσης binary exploitation

Η ενότητα Binary Exploitation εξετάζει σε μεγαλύτερο βάθος τα exploit primitives, τη διάταξη μνήμης και τις παρακάμψεις μετριασμών για αυτούς τους στόχους Linux kernel:

- [AF_UNIX out-of-band SKB use-after-free](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ένα socket bug που εξελίχθηκε σε primitives ανάγνωσης και εγγραφής στον kernel.
- [Futex PI use-after-free](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ένα primitive εγγραφής pointer που επεκτάθηκε μέσω pipe buffers και workqueues.
- [ksmbd streams out-of-bounds write, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): εκμετάλλευση kernel heap και παρακάμψεις μετριασμών.
- [POSIX CPU timers TOCTOU, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md): η ανάλυση binary exploitation του race condition χρονοδιακόπτη που συνοψίστηκε επίσης παραπάνω.
- [Arm64 static linear-map KASLR bypass](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): εντοπισμός διευθύνσεων για εκμετάλλευση arm64 kernel.
- [Adreno A7xx GPU/SMMU privilege bypass](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): διαδρομή GPU του Android προς πρόσβαση στη μνήμη του kernel.
- [Pixel Bigwave job-timeout use-after-free](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): bug σε accelerator Android που χρησιμοποιείται για εγγραφές στον kernel.
{{#include ../../../banners/hacktricks-training.md}}
