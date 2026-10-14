# Υλικό για Kernel, LPE και CVE

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι μελέτες περίπτωσης καλύπτουν διαφορετικά primitives για local privilege escalation. Ελέγξτε το επηρεαζόμενο προϊόν ή kernel, τη διαμόρφωση και τις προϋποθέσεις σε κάθε άρθρο πριν εφαρμόσετε μια τεχνική. Για ευρύτερη απαρίθμηση του host, χρησιμοποιήστε τη [λίστα ελέγχου για privilege escalation στο Linux](../linux-privilege-escalation-checklist.md).

Για το Dirty Pipe (CVE-2022-0847), η [αρχική έρευνα](https://dirtypipe.cm4all.com/) εντοπίζει τις upstream stable διορθώσεις στις εκδόσεις 5.10.102, 5.15.25 και 5.16.11. Μια έκδοση kernel σε παλαιότερη επηρεαζόμενη περιοχή είναι απλώς ένδειξη για περαιτέρω έλεγχο: οι kernels των διανομών μπορεί να περιλαμβάνουν backport διορθώσεων με διαφορετικά ονόματα εκδόσεων, ενώ το σχετικό αρχείο-στόχος πρέπει να είναι αναγνώσιμο για να λειτουργήσει το primitive εγγραφής στο page cache. Η αντικατάσταση ενός αναγνώσιμου SUID εκτελέσιμου είναι ένας πιθανός δρόμος προς privilege escalation, εφόσον εξακολουθεί να ισχύει η μετάβαση set-ID· η τροποποίηση του `/etc/passwd` και στη συνέχεια η πιστοποίηση μπορεί επίσης να εξαρτάται από την τοπική στοίβα PAM. Πριν αξιολογήσετε αν είναι εφικτή η εκμετάλλευση, ελέγξτε το εγκατεστημένο πακέτο kernel του κατασκευαστή, τον kernel που εκτελείται μετά την επανεκκίνηση, τα δικαιώματα του αρχείου-στόχου, το `nosuid` στο mount και το `no_new_privs`. Μην εκτελείτε probe εγγραφής κατά την παθητική απαρίθμηση. Δείτε την [κατάσταση ανά έκδοση του Ubuntu](https://ubuntu.com/security/CVE-2022-0847).

- [Εντοπισμός υπηρεσίας VMware Tools, CVE-2025-41244](vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md): εκτέλεση με αυξημένα δικαιώματα μέσω αναζήτησης διαδρομής διεργασίας που δεν είναι έμπιστη.
- [Αντικατάσταση page cache μέσω AF_ALG splice, CVE-2026-31431](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md): διαδρομή αντικατάστασης του page cache του kernel.
- [Race TOCTOU σε POSIX CPU timers και εκμετάλλευση, CVE-2025-38352](../../../binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md#root-cause-toctou-between-irq-time-expiry-and-concurrent-deletion-under-task-exit): λήξη/διαγραφή timer κατά την έξοδο task, με τις προϋποθέσεις της διαδρομής IRQ και την έρευνα για την εκμετάλλευση.
- [Race κατά την έξοδο του Linux ptrace και κλοπή file descriptor μέσω `pidfd_getfd`](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md): πρόσβαση σε descriptor κατά τη διάρκεια race εξόδου διεργασίας.

## Σχετικές μελέτες περίπτωσης binary exploitation

Η ενότητα Binary Exploitation εξετάζει λεπτομερέστερα τα exploit primitives, τη διάταξη μνήμης και την παράκαμψη mitigations για αυτούς τους Linux kernel στόχους:

- [Use-after-free σε SKB εκτός ζώνης του AF_UNIX](../../../binary-exploitation/linux-kernel-exploitation/af-unix-msg-oob-uaf-skb-primitives.md): ένα bug socket εξελίχθηκε σε primitives ανάγνωσης και εγγραφής στον kernel.
- [Underflow scatterlist λόγω ταυτόχρονων writers στο AF_ALG](../../../binary-exploitation/linux-kernel-exploitation/af-alg-concurrent-writer-scatterlist-oob.md): ένα race writer skcipher εξελίχθηκε σε εγγραφή στον kernel.
- [Use-after-free στο Futex PI](../../../binary-exploitation/linux-kernel-exploitation/futex-pi-uaf-pipe-buffer-workqueue-usermodehelper.md): ένα primitive εγγραφής pointer επεκτάθηκε μέσω pipe buffers και workqueues.
- [Εγγραφή εκτός ορίων σε streams του ksmbd, CVE-2025-37947](../../../binary-exploitation/linux-kernel-exploitation/ksmbd-streams_xattr-oob-write-cve-2025-37947.md): εκμετάλλευση kernel heap και παράκαμψη mitigations.
- [Παράκαμψη KASLR του στατικού linear map στο Arm64](../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md): εντοπισμός διευθύνσεων για εκμετάλλευση kernel σε arm64.
- [Παράκαμψη privilege μέσω GPU/SMMU στο Adreno A7xx](../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md): διαδρομή GPU στο Android για πρόσβαση στη μνήμη του kernel.
- [Use-after-free λόγω job timeout στο Pixel Bigwave](../../../binary-exploitation/linux-kernel-exploitation/pixel-bigwave-bigo-job-timeout-uaf-kernel-write.md): bug Android accelerator που χρησιμοποιήθηκε για εγγραφές στον kernel.
{{#include ../../../banners/hacktricks-training.md}}
