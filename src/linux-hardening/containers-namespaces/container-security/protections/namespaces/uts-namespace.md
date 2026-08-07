# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το UTS namespace απομονώνει το **hostname** και το **NIS domain name** που βλέπει η διεργασία. Εκ πρώτης όψεως, αυτό μπορεί να φαίνεται ασήμαντο σε σύγκριση με τα mount, PID ή user namespaces, αλλά αποτελεί μέρος αυτού που κάνει ένα container να φαίνεται σαν ξεχωριστός host. Μέσα στο namespace, το workload μπορεί να βλέπει και, σε ορισμένες περιπτώσεις, να αλλάζει ένα hostname που είναι τοπικό για το συγκεκριμένο namespace αντί να είναι global για το machine.

Από μόνο του, αυτό συνήθως δεν αποτελεί το επίκεντρο ενός breakout. Ωστόσο, όταν το host UTS namespace είναι shared, μια επαρκώς privileged διεργασία μπορεί να επηρεάσει ρυθμίσεις που σχετίζονται με την ταυτότητα του host, κάτι που μπορεί να έχει operational και περιστασιακά security επιπτώσεις.

## Lab

Μπορείτε να δημιουργήσετε ένα UTS namespace με:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Η αλλαγή του hostname παραμένει τοπική σε αυτό το namespace και δεν αλλάζει το global hostname του host. Αυτό αποτελεί μια απλή αλλά αποτελεσματική επίδειξη της ιδιότητας isolation.

## Χρήση κατά το Runtime

Τα κανονικά containers αποκτούν ένα isolated UTS namespace. Τα Docker και Podman μπορούν να συνδεθούν στο UTS namespace του host μέσω του `--uts=host`, ενώ παρόμοια μοτίβα διαμοιρασμού του host μπορεί να εμφανίζονται και σε άλλα runtimes και orchestration systems. Τις περισσότερες φορές, ωστόσο, το private UTS isolation αποτελεί απλώς μέρος της κανονικής ρύθμισης του container και απαιτεί ελάχιστη προσοχή από τον operator.

## Security Impact

Παρόλο που το UTS namespace συνήθως δεν είναι το πιο επικίνδυνο namespace για διαμοιρασμό, εξακολουθεί να συμβάλλει στην ακεραιότητα του container boundary. Αν το UTS namespace του host είναι εκτεθειμένο και η διεργασία διαθέτει τα απαραίτητα privileges, ενδέχεται να μπορεί να τροποποιήσει πληροφορίες που σχετίζονται με το hostname του host. Αυτό μπορεί να επηρεάσει το monitoring, το logging, τις operational assumptions ή scripts που λαμβάνουν αποφάσεις trust με βάση δεδομένα ταυτότητας του host.

## Κατάχρηση

Αν το UTS namespace του host είναι shared, το πρακτικό ερώτημα είναι αν η διεργασία μπορεί να τροποποιήσει τις ρυθμίσεις ταυτότητας του host αντί απλώς να τις διαβάσει:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Αν το container διαθέτει επίσης το απαραίτητο privilege, ελέγξτε αν μπορεί να αλλάξει το hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Αυτό αποτελεί κυρίως ζήτημα ακεραιότητας και λειτουργικού αντίκτυπου και όχι πλήρες escape, αλλά εξακολουθεί να δείχνει ότι το container μπορεί να επηρεάσει άμεσα μια ιδιότητα καθολική για το host.

Impact:

- παραποίηση της ταυτότητας του host
- σύγχυση σε logs, monitoring ή automation που εμπιστεύονται το hostname
- συνήθως δεν αποτελεί από μόνο του πλήρες escape, εκτός αν συνδυαστεί με άλλες αδυναμίες

Σε περιβάλλοντα τύπου Docker, ένα χρήσιμο pattern για detection από την πλευρά του host είναι:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Τα containers που εμφανίζουν `UTSMode=host` μοιράζονται το UTS namespace του host και θα πρέπει να ελέγχονται πιο προσεκτικά αν διαθέτουν επίσης capabilities που τους επιτρέπουν να καλούν τις `sethostname()` ή `setdomainname()`.

## Έλεγχοι

Αυτές οι εντολές αρκούν για να διαπιστώσετε αν το workload έχει τη δική του προβολή hostname ή αν μοιράζεται το UTS namespace του host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Τι είναι ενδιαφέρον εδώ:

- Η αντιστοίχιση των αναγνωριστικών namespace με μια διεργασία του host μπορεί να υποδεικνύει κοινή χρήση του UTS namespace με τον host.
- Αν η αλλαγή του hostname επηρεάζει περισσότερα από το ίδιο το container, το workload έχει μεγαλύτερη επιρροή στην ταυτότητα του host από όσο θα έπρεπε.
- Συνήθως αυτό το εύρημα έχει χαμηλότερη προτεραιότητα από ζητήματα PID, mount ή user namespace, αλλά εξακολουθεί να επιβεβαιώνει πόσο απομονωμένη είναι πραγματικά η διεργασία.

Στα περισσότερα περιβάλλοντα, το UTS namespace θεωρείται καλύτερα ένα υποστηρικτικό επίπεδο απομόνωσης. Σπάνια είναι το πρώτο πράγμα που εξετάζεις σε ένα breakout, αλλά εξακολουθεί να αποτελεί μέρος της συνολικής συνέπειας και ασφάλειας της προβολής του container.

{{#include ../../../../../banners/hacktricks-training.md}}
