# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το UTS namespace απομονώνει το **hostname** και το **NIS domain name** που βλέπει η διαδικασία. Με την πρώτη ματιά αυτό μπορεί να φαίνεται ασήμαντο σε σύγκριση με τα mount, PID, ή user namespaces, αλλά αποτελεί μέρος αυτού που κάνει ένα container να φαίνεται σαν ξεχωριστός host. Μέσα στο namespace, το workload μπορεί να βλέπει και μερικές φορές να αλλάζει ένα hostname που είναι τοπικό σε αυτό το namespace αντί για global στο μηχάνημα.

## Εργαστήριο

Μπορείτε να δημιουργήσετε ένα UTS namespace με:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Η αλλαγή του hostname παραμένει τοπική σε εκείνο το UTS namespace και δεν τροποποιεί το global hostname του host. Αυτό είναι μια απλή αλλά αποτελεσματική επίδειξη της ιδιότητας απομόνωσης.

## Χρήση κατά την εκτέλεση

Κανονικά containers αποκτούν ένα απομονωμένο UTS namespace. Docker και Podman μπορούν να συνδεθούν στο host UTS namespace μέσω `--uts=host`, και παρόμοια μοτίβα κοινοποίησης host μπορούν να εμφανιστούν και σε άλλα runtimes και συστήματα ορχήστρωσης. Τις περισσότερες φορές, όμως, η ιδιωτική απομόνωση UTS αποτελεί απλώς μέρος της τυπικής ρύθμισης του container και απαιτεί λίγη προσοχή από τον χειριστή.

## Επίδραση στην ασφάλεια

Παρότι το UTS namespace συνήθως δεν είναι το πιο επικίνδυνο για κοινοποίηση, συμβάλλει στην ακεραιότητα των ορίων του container. Εάν το host UTS namespace είναι εκτεθειμένο και η διεργασία διαθέτει τα απαραίτητα προνόμια, μπορεί να είναι σε θέση να τροποποιήσει πληροφορίες σχετικές με το hostname του host. Αυτό μπορεί να επηρεάσει την παρακολούθηση, την καταγραφή, τις επιχειρησιακές υποθέσεις ή σενάρια που λαμβάνουν αποφάσεις εμπιστοσύνης βάσει δεδομένων ταυτότητας του host.

## Κατάχρηση

Εάν το host UTS namespace κοινοποιηθεί, το πρακτικό ερώτημα είναι εάν η διεργασία μπορεί να τροποποιήσει τις ρυθμίσεις ταυτότητας του host και όχι μόνο να τις διαβάσει:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Εάν το container έχει επίσης τα απαραίτητα προνόμια, ελέγξτε αν το hostname μπορεί να αλλάξει:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Αυτό είναι κυρίως ένα ζήτημα ακεραιότητας και επιχειρησιακής επίδρασης παρά ένα πλήρες escape, αλλά εξακολουθεί να δείχνει ότι το container μπορεί να επηρεάσει άμεσα ένα host-global property.

Επιπτώσεις:

- παραποίηση ταυτότητας του host
- σύγχυση στα logs, στο monitoring ή σε automation που εμπιστεύονται το hostname
- συνήθως δεν αποτελεί πλήρες escape από μόνο του εκτός αν συνδυαστεί με άλλες αδυναμίες

Σε Docker-style περιβάλλοντα, ένα χρήσιμο host-side pattern ανίχνευσης είναι:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers που εμφανίζουν `UTSMode=host` μοιράζονται το host UTS namespace και πρέπει να εξεταστούν πιο προσεκτικά αν επίσης φέρουν capabilities που τους επιτρέπουν να καλούν `sethostname()` ή `setdomainname()`.

## Έλεγχοι

Αυτές οι εντολές αρκούν για να δείτε εάν το workload έχει τη δική του προβολή hostname ή μοιράζεται το host UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Τι είναι ενδιαφέρον εδώ:

- Το να ταιριάζουν namespace identifiers με μια διεργασία του host μπορεί να υποδεικνύει κοινοχρησία του host UTS.
- Εάν η αλλαγή του hostname επηρεάζει περισσότερα από το ίδιο το container, το workload έχει μεγαλύτερη επιρροή στην host identity απ' ό,τι θα έπρεπε.
- Αυτό συνήθως θεωρείται εύρημα χαμηλότερης προτεραιότητας από προβλήματα PID, mount ή user namespace, αλλά εξακολουθεί να επιβεβαιώνει πόσο απομονωμένη είναι πραγματικά η διεργασία.

Σε περισσότερα περιβάλλοντα, το UTS namespace πρέπει να θεωρείται κυρίως ως ένα υποστηρικτικό επίπεδο απομόνωσης. Σπάνια είναι το πρώτο πράγμα που κυνηγάς σε ένα breakout, αλλά παραμένει μέρος της συνολικής συνέπειας και ασφάλειας της container view.
