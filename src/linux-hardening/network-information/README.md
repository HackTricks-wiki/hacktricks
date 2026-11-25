# Πληροφορίες δικτύου

{{#include ../../banners/hacktricks-training.md}}

Οι τοπικοί listeners, τα Unix sockets και το λογισμικό που εκτίθεται στο δίκτυο ενδέχεται να αποκαλύπτουν διαδρομές που δεν είναι ορατές σε μια εξωτερική σάρωση. Ξεκινήστε από τις υπηρεσίες που ακούν στον host και τη διεργασία που έχει στην κατοχή της κάθε endpoint.

- Η ενότητα [Διαλογή καταγραφής κίνησης, firewall και εξερχόμενης κίνησης](traffic-capture-and-firewall-egress.md) καλύπτει την καταγραφή πακέτων, το φιλτράρισμα, τους proxies και τις δοκιμές συνδεσιμότητας.
- Η ενότητα [Διαλογή τοπικού δικτύου και socket](local-network-and-socket-triage.md) καλύπτει υπηρεσίες loopback, Unix sockets και δίκτυα container.
- Η ενότητα [Εισαγωγή εντολών μέσω socket](socket-command-injection.md) καλύπτει τις εντολές που γίνονται δεκτές μέσω εκτεθειμένων τοπικών sockets.
- Για footholds σε συσκευές Cisco SD-WAN Manager, δείτε την [τοπική κλιμάκωση προνομίων στο vManage](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md)· το ConfD CLI, το REST API και οι διαδρομές εισαγωγής αρχείων που ανήκουν στον root είναι διαφορετικά από τη γενική διαλογή socket.
{{#include ../../banners/hacktricks-training.md}}
