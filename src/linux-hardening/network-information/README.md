# Πληροφορίες δικτύου

{{#include ../../banners/hacktricks-training.md}}

Οι τοπικές υπηρεσίες που ακούνε, τα Unix sockets και το λογισμικό που εκτίθεται στο δίκτυο ενδέχεται να αποκαλύπτουν διαδρομές που δεν είναι ορατές σε μια εξωτερική σάρωση. Ξεκινήστε ελέγχοντας τις υπηρεσίες που ακούνε στον host και τη διεργασία που έχει στην κατοχή της κάθε endpoint.

- [Διαλογή καταγραφής κίνησης, firewall και εξερχόμενης κίνησης](traffic-capture-and-firewall-egress.md) καλύπτει την καταγραφή πακέτων, το φιλτράρισμα, τους proxy και τους ελέγχους συνδεσιμότητας.
- [Διαλογή τοπικού δικτύου και socket](local-network-and-socket-triage.md) καλύπτει υπηρεσίες loopback, Unix sockets και δίκτυα container.
- [Socket command injection](socket-command-injection.md) καλύπτει εντολές που γίνονται δεκτές μέσω εκτεθειμένων τοπικών socket.
- [Cisco vManage](cisco-vmanage.md) περιγράφει έναν συγκεκριμένο στόχο προϊόντος και σχετικούς ελέγχους.
{{#include ../../banners/hacktricks-training.md}}
