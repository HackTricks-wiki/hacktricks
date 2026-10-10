# Containers και Namespaces

{{#include ../../banners/hacktricks-training.md}}

Ένα container είναι μια διεργασία Linux που εκτελείται με ρυθμίσεις απομόνωσης και προνομίων. Αξιολογήστε συνολικά το runtime, τους προσαρτημένους πόρους του host, τα εκχωρημένα capabilities και τις ρυθμίσεις των namespaces. Η [επισκόπηση ασφάλειας των containers](container-security/README.md) εξηγεί αυτά τα επίπεδα και παραπέμπει σε κάθε σχετικό έλεγχο.

- Το [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) εστιάζει στην πρόσβαση στη διεπαφή διαχείρισης του containerd.
- Το [RunC privilege escalation](runc-privilege-escalation.md) καλύπτει υλικό κλιμάκωσης προνομίων ειδικό για το runtime.
- Η [ασφάλεια των containers](container-security/README.md) εξηγεί τα runtimes, τα εκτεθειμένα API, τους κινδύνους των images, τα ευαίσθητα mounts, τα privileged containers, την αξιολόγηση και τα μέτρα προστασίας, όπως namespaces, seccomp και υποχρεωτικό έλεγχο πρόσβασης.
{{#include ../../banners/hacktricks-training.md}}
