# Κοντέινερ και Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ένα κοντέινερ είναι μια διεργασία Linux που εκτελείται με ρυθμίσεις απομόνωσης και προνομίων. Αξιολογήστε συνολικά το runtime, τους προσαρτημένους πόρους του host, τις εκχωρημένες capabilities και τις ρυθμίσεις namespaces. Η [επισκόπηση ασφάλειας κοντέινερ](container-security/README.md) εξηγεί αυτά τα επίπεδα και παραπέμπει σε κάθε σχετικό μέτρο ελέγχου.

- Το [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) εστιάζει στην πρόσβαση στη διεπαφή διαχείρισης του containerd.
- Το [RunC privilege escalation](runc-privilege-escalation.md) καλύπτει υλικό για escalation ειδικά για το runtime.
- Η [Ασφάλεια κοντέινερ](container-security/README.md) εξηγεί τα runtimes, τα εκτεθειμένα API, τους κινδύνους των images, τα ευαίσθητα mounts, τα προνομιούχα κοντέινερ, την αξιολόγηση και τις προστασίες, όπως τα namespaces, το seccomp και τον υποχρεωτικό έλεγχο πρόσβασης.
{{#include ../../banners/hacktricks-training.md}}
