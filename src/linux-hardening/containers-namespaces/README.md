# Containers and Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ένα container είναι μια διεργασία Linux που εκτελείται με ρυθμίσεις απομόνωσης και προνομίων. Αξιολογήστε από κοινού το runtime, τους προσαρτημένους πόρους του host, τα capabilities που έχουν παραχωρηθεί και τις ρυθμίσεις των namespaces. Η [επισκόπηση ασφάλειας container](container-security/README.md) εξηγεί αυτά τα επίπεδα και παραπέμπει σε κάθε σχετικό μέτρο ελέγχου.

- Η [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) εστιάζει στην πρόσβαση στη διεπαφή διαχείρισης του containerd.
- Η [RunC privilege escalation](runc-privilege-escalation.md) καλύπτει υλικό κλιμάκωσης προνομίων ειδικό για το runtime.
- Η [ασφάλεια container](container-security/README.md) εξηγεί τα runtimes, τα εκτεθειμένα APIs, τους κινδύνους των images, τα ευαίσθητα mounts, τα προνομιούχα containers, την αξιολόγηση και μέτρα προστασίας όπως τα namespaces, το seccomp και ο υποχρεωτικός έλεγχος πρόσβασης.

{{#include ../../banners/hacktricks-training.md}}
