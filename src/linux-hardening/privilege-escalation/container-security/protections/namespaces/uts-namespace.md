# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το UTS namespace απομονώνει το **hostname** και το **NIS domain name** που βλέπει η διαδικασία. Με την πρώτη ματιά αυτό μπορεί να φαίνεται ασήμαντο σε σύγκριση με τα mount, PID ή user namespaces, αλλά αποτελεί μέρος αυτού που κάνει ένα container να φαίνεται σαν τον δικό του host. Μέσα στο namespace, το workload μπορεί να βλέπει και μερικές φορές να αλλάζει ένα hostname που είναι τοπικό σε αυτό το namespace αντί για global στο μηχάνημα.

Από μόνο του, αυτό συνήθως δεν αποτελεί το επίκεντρο μιας breakout ιστορίας. Ωστόσο, όταν το host UTS namespace κοινοποιείται, μια διαδικασία με επαρκή προνόμια μπορεί να επηρεάσει ρυθμίσεις σχετικές με την ταυτότητα του host, κάτι που μπορεί να έχει σημασία λειτουργικά και περιστασιακά σε ό,τι αφορά την ασφάλεια.

## Εργαστήριο

Μπορείτε να δημιουργήσετε ένα UTS namespace με:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Η αλλαγή του hostname παραμένει τοπική σε αυτό το UTS namespace και δεν τροποποιεί το global hostname του host. Αυτή είναι μια απλή αλλά αποτελεσματική επίδειξη της ιδιότητας απομόνωσης.

## Χρήση κατά την εκτέλεση

Τα τυπικά containers αποκτούν ένα απομονωμένο UTS namespace. Docker και Podman μπορούν να ενωθούν με το host UTS namespace μέσω `--uts=host`, και παρόμοια μοτίβα κοινοποίησης του host μπορεί να εμφανιστούν σε άλλα runtimes και συστήματα orchestration. Ωστόσο, τις περισσότερες φορές η ιδιωτική απομόνωση UTS αποτελεί απλά μέρος της κανονικής ρύθμισης container και απαιτεί λίγη προσοχή από τον χειριστή.

## Επίπτωση στην ασφάλεια

Αν και το UTS namespace συνήθως δεν είναι το πιο επικίνδυνο για να το κοινοποιήσεις, εξακολουθεί να συμβάλλει στην ακεραιότητα των ορίων του container. Εάν το host UTS namespace εκτεθεί και η διεργασία έχει τα απαραίτητα προνόμια, μπορεί να είναι σε θέση να τροποποιήσει πληροφορίες σχετικές με το hostname του host. Αυτό μπορεί να επηρεάσει monitoring, logging, λειτουργικές υποθέσεις ή scripts που λαμβάνουν αποφάσεις εμπιστοσύνης βάσει δεδομένων ταυτότητας του host.

## Κατάχρηση

Εάν το host UTS namespace κοινοποιείται, το πρακτικό ερώτημα είναι αν η διεργασία μπορεί να τροποποιήσει τις ρυθμίσεις ταυτότητας του host αντί να τις διαβάσει μόνο:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Εάν το container διαθέτει επίσης το απαραίτητο privilege, ελέγξτε αν το hostname μπορεί να αλλάξει:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Αυτό είναι κυρίως ζήτημα ακεραιότητας και λειτουργικού αντίκτυπου παρά για πλήρη escape, αλλά δείχνει ότι το container μπορεί να επηρεάσει άμεσα μια host-global ιδιότητα.

Επιπτώσεις:

- παραποίηση ταυτότητας host
- σύγχυση στα logs, στο monitoring ή στην automation που εμπιστεύονται το hostname
- συνήθως δεν είναι πλήρης escape από μόνο του εκτός αν συνδυαστεί με άλλες αδυναμίες

Σε περιβάλλοντα τύπου Docker, ένα χρήσιμο host-side detection pattern είναι:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers που εμφανίζουν `UTSMode=host` μοιράζονται το host UTS namespace και θα πρέπει να εξεταστούν πιο προσεκτικά αν επίσης διαθέτουν capabilities που τους επιτρέπουν να καλούν `sethostname()` ή `setdomainname()`.

## Έλεγχοι

Αυτές οι εντολές αρκούν για να δείξουν αν το workload έχει τη δική του προβολή hostname ή μοιράζεται το host UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Τι είναι ενδιαφέρον εδώ:

- Η αντιστοίχιση των namespace identifiers με μια host process μπορεί να υποδείξει host UTS sharing.
- Αν η αλλαγή του hostname επηρεάζει περισσότερα από το ίδιο το container, το workload έχει περισσότερη επιρροή πάνω στην host identity απ' ό,τι θα έπρεπε.
- Συνήθως αυτό είναι ένα εύρημα χαμηλότερης προτεραιότητας από ζητήματα PID, mount ή user namespace, αλλά επιβεβαιώνει πόσο απομονωμένη είναι πραγματικά η διεργασία.

Σε περισσότερα περιβάλλοντα, το UTS namespace είναι καλύτερα να θεωρείται ως ένα υποστηρικτικό επίπεδο απομόνωσης. Σπάνια είναι το πρώτο πράγμα που θα κυνηγήσετε σε ένα breakout, αλλά εξακολουθεί να αποτελεί μέρος της συνολικής συνέπειας και ασφάλειας της container view.
{{#include ../../../../../banners/hacktricks-training.md}}
