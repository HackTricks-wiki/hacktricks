# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το UTS Namespace απομονώνει το **hostname** και το **NIS domain name** που βλέπει η διεργασία. Εκ πρώτης όψεως, αυτό μπορεί να φαίνεται ασήμαντο σε σύγκριση με τα mount, PID ή user namespaces, αλλά αποτελεί μέρος αυτού που κάνει ένα container να φαίνεται σαν ξεχωριστός host. Μέσα στο namespace, το workload μπορεί να βλέπει και, σε ορισμένες περιπτώσεις, να αλλάζει ένα hostname που είναι τοπικό σε εκείνο το namespace αντί να είναι global για το machine.

Από μόνο του, αυτό συνήθως δεν αποτελεί το επίκεντρο ενός breakout story. Ωστόσο, όταν γίνεται share το UTS namespace του host, μια διεργασία με επαρκή privileges μπορεί να επηρεάσει ρυθμίσεις που σχετίζονται με την ταυτότητα του host, κάτι που μπορεί να έχει operational και περιστασιακά security επιπτώσεις.

## Εργαστήριο

Μπορείτε να δημιουργήσετε ένα UTS namespace με:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Η αλλαγή του hostname παραμένει τοπική σε αυτό το namespace και δεν τροποποιεί το global hostname του host. Αυτή είναι μια απλή αλλά αποτελεσματική επίδειξη της ιδιότητας απομόνωσης.

## Χρήση κατά το Runtime

Τα κανονικά containers λαμβάνουν ένα isolated UTS namespace. Τα Docker και Podman μπορούν να συνδεθούν στο UTS namespace του host μέσω του `--uts=host`, ενώ παρόμοια μοτίβα κοινής χρήσης του host μπορεί να εμφανίζονται σε άλλα runtimes και orchestration systems. Ωστόσο, τις περισσότερες φορές, το private UTS isolation αποτελεί απλώς μέρος της κανονικής ρύθμισης του container και απαιτεί ελάχιστη προσοχή από τον operator.

## Επιπτώσεις στην Ασφάλεια

Παρόλο που το UTS namespace συνήθως δεν είναι το πιο επικίνδυνο namespace για κοινή χρήση, εξακολουθεί να συμβάλλει στην ακεραιότητα του ορίου του container. Αν το UTS namespace του host είναι εκτεθειμένο και η διεργασία διαθέτει τα απαραίτητα privileges, ενδέχεται να μπορεί να τροποποιήσει πληροφορίες σχετικές με το hostname του host. Αυτό μπορεί να επηρεάσει το monitoring, το logging, λειτουργικές παραδοχές ή scripts που λαμβάνουν αποφάσεις εμπιστοσύνης βάσει δεδομένων ταυτότητας του host.

## Κατάχρηση

Αν το UTS namespace του host είναι κοινόχρηστο, το πρακτικό ερώτημα είναι αν η διεργασία μπορεί να τροποποιήσει τις ρυθμίσεις ταυτότητας του host και όχι απλώς να τις διαβάσει:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Αν το container διαθέτει επίσης το απαιτούμενο privilege, ελέγξτε αν είναι δυνατή η αλλαγή του hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Πρόκειται κυρίως για ζήτημα ακεραιότητας και λειτουργικού αντίκτυπου και όχι για πλήρες escape, αλλά εξακολουθεί να δείχνει ότι το container μπορεί να επηρεάσει άμεσα μια ιδιότητα καθολική για το host.

Επίπτωση:

- παραποίηση της ταυτότητας του host
- σύγχυση σε logs, monitoring ή automation που εμπιστεύονται το hostname
- συνήθως δεν αποτελεί από μόνο του πλήρες escape, εκτός αν συνδυαστεί με άλλες αδυναμίες

Σε περιβάλλοντα τύπου Docker, ένα χρήσιμο μοτίβο detection από την πλευρά του host είναι:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers με `UTSMode=host` μοιράζονται το UTS namespace του host και θα πρέπει να ελέγχονται πιο προσεκτικά αν διαθέτουν επίσης capabilities που τους επιτρέπουν να καλούν τις `sethostname()` ή `setdomainname()`.

## Έλεγχοι

Αυτές οι εντολές αρκούν για να δείτε αν το workload έχει τη δική του προβολή hostname ή αν μοιράζεται το UTS namespace του host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Τι είναι ενδιαφέρον εδώ:

- Η αντιστοίχιση των αναγνωριστικών namespace με μια διεργασία του host μπορεί να υποδεικνύει κοινή χρήση του host UTS.
- Αν η αλλαγή του hostname επηρεάζει κάτι περισσότερο από το ίδιο το container, το workload έχει μεγαλύτερη επιρροή στην ταυτότητα του host απ’ όση θα έπρεπε.
- Αυτό είναι συνήθως εύρημα χαμηλότερης προτεραιότητας σε σχέση με ζητήματα PID, mount ή user namespace, αλλά εξακολουθεί να επιβεβαιώνει πόσο πραγματικά απομονωμένη είναι η διεργασία.

Στα περισσότερα περιβάλλοντα, το UTS namespace αντιμετωπίζεται καλύτερα ως υποστηρικτικό επίπεδο απομόνωσης. Σπάνια είναι το πρώτο πράγμα που εξετάζεις σε ένα breakout, αλλά εξακολουθεί να αποτελεί μέρος της συνολικής συνέπειας και ασφάλειας της οπτικής του container.
{{#include ../../../../../banners/hacktricks-training.md}}
