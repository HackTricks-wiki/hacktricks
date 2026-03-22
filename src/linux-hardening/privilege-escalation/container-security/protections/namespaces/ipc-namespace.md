# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Το IPC namespace απομονώνει **System V IPC objects** και **POSIX message queues**. Αυτό περιλαμβάνει τμήματα shared memory, semaphores, και message queues που διαφορετικά θα ήταν ορατά ανάμεσα σε μη σχετιζόμενες processes στο host. Σε πρακτικούς όρους, αυτό εμποδίζει ένα container από το να συνδεθεί επιπόλαια σε IPC objects που ανήκουν σε άλλα workloads ή στο host.

Σε σύγκριση με mount, PID, ή user namespaces, το IPC namespace συχνά συζητιέται λιγότερο, αλλά αυτό δεν πρέπει να συγχέεται με ασήμαντο. Το shared memory και οι σχετικοί μηχανισμοί IPC μπορούν να περιέχουν πολύ χρήσιμο state. Αν το host IPC namespace εκτεθεί, το workload μπορεί να αποκτήσει ορατότητα σε inter-process coordination objects ή δεδομένα που ποτέ δεν προορίστηκαν να διασχίσουν το όριο του container.

## Operation

Όταν το runtime δημιουργεί ένα νέο IPC namespace, η διεργασία αποκτά το δικό της απομονωμένο σετ IPC identifiers. Αυτό σημαίνει ότι εντολές όπως `ipcs` δείχνουν μόνο τα objects διαθέσιμα σε εκείνο το namespace. Εάν το container αντίθετα ενταχθεί στο host IPC namespace, αυτά τα objects γίνονται μέρος μιας κοινής global προβολής.

Αυτό έχει ιδιαίτερη σημασία σε περιβάλλοντα όπου εφαρμογές ή services χρησιμοποιούν heavily shared memory. Ακόμα και όταν το container δεν μπορεί άμεσα να ξεφύγει μέσω IPC μόνο, το namespace μπορεί να leak πληροφορίες ή να επιτρέψει cross-process interference που ουσιαστικά βοηθά μια μετέπειτα επίθεση.

## Lab

Μπορείτε να δημιουργήσετε ένα ιδιωτικό IPC namespace με:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Και σύγκρινε τη συμπεριφορά κατά το χρόνο εκτέλεσης με:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker και Podman απομονώνουν το IPC από προεπιλογή. Το Kubernetes συνήθως δίνει στο Pod το δικό του IPC namespace, κοινό ανάμεσα στα containers στο ίδιο Pod αλλά όχι εξ ορισμού με το host. Η κοινή χρήση του host IPC είναι δυνατή, αλλά πρέπει να θεωρείται σημαντική μείωση της απομόνωσης και όχι απλώς μια μικρή επιλογή runtime.

## Misconfigurations

Το προφανές λάθος είναι `--ipc=host` ή `hostIPC: true`. Αυτό μπορεί να γίνει για συμβατότητα με παρωχημένο λογισμικό ή για ευκολία, αλλά αλλάζει σημαντικά το μοντέλο εμπιστοσύνης. Ένα άλλο επαναλαμβανόμενο ζήτημα είναι η απλή παράβλεψη του IPC επειδή φαίνεται λιγότερο δραματικό από το host PID ή το host networking. Στην πραγματικότητα, αν το workload διαχειρίζεται browsers, databases, scientific workloads ή άλλο λογισμικό που χρησιμοποιεί εντατικά shared memory, η επιφάνεια IPC μπορεί να είναι πολύ σημαντική.

## Abuse

Όταν το host IPC είναι κοινό, ένας επιτιθέμενος μπορεί να επιθεωρήσει ή να παρέμβει σε shared memory αντικείμενα, να αποκτήσει νέες πληροφορίες για τη συμπεριφορά του host ή γειτονικών workloads, ή να συνδυάσει τις πληροφορίες αυτές με ορατότητα διεργασιών και δυνατότητες τύπου ptrace. Η κοινή χρήση IPC συχνά αποτελεί υποστηρικτική αδυναμία παρά την πλήρη διαδρομή διαφυγής, αλλά οι υποστηρικτικές αδυναμίες έχουν σημασία επειδή συντομεύουν και σταθεροποιούν τις πραγματικές αλυσίδες επίθεσης.

Το πρώτο χρήσιμο βήμα είναι να απαριθμήσετε ποια IPC αντικείμενα είναι ορατά:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Εάν το host IPC namespace κοινοποιείται, μεγάλα shared-memory segments ή ενδιαφέροντες object owners μπορούν να αποκαλύψουν άμεσα τη συμπεριφορά της εφαρμογής:
```bash
ipcs -m -p
ipcs -q -p
```
Σε ορισμένα περιβάλλοντα, τα ίδια τα περιεχόμενα του `/dev/shm` leak filenames, artifacts ή tokens που αξίζει να ελεγχθούν:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
Η κοινή χρήση IPC σπάνια δίνει άμεσα host root από μόνη της, αλλά μπορεί να εκθέσει δεδομένα και κανάλια συντονισμού που καθιστούν πολύ πιο εύκολες τις μετέπειτα επιθέσεις σε διεργασίες.

### Πλήρες Παράδειγμα: `/dev/shm` Ανάκτηση μυστικών

Το πιο ρεαλιστικό πλήρες σενάριο κατάχρησης είναι η κλοπή δεδομένων παρά direct escape. Εάν το host IPC ή μια ευρεία διάταξη shared-memory είναι εκτεθειμένη, ευαίσθητα artifacts μπορούν μερικές φορές να ανακτηθούν απευθείας:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Επιπτώσεις:

- εξαγωγή μυστικών ή δεδομένων συνεδρίας που έχουν παραμείνει στη shared memory
- ενημέρωση για τις εφαρμογές που είναι ενεργές στον host
- καλύτερος στοχευμός για μετέπειτα επιθέσεις βασισμένες σε PID-namespace ή ptrace

Η κοινή χρήση IPC κατανοείται λοιπόν καλύτερα ως ένας **ενισχυτής επίθεσης** παρά ως αυτόνομο host-escape primitive.

## Checks

Αυτές οι εντολές προορίζονται να απαντήσουν αν το workload έχει ιδιωτική προβολή IPC, αν είναι ορατά ουσιαστικά shared-memory ή message objects, και αν το `/dev/shm` αποκαλύπτει χρήσιμα artifacts.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Τι είναι ενδιαφέρον εδώ:

- Εάν το `ipcs -a` αποκαλύπτει αντικείμενα που ανήκουν σε απροσδόκητους χρήστες ή υπηρεσίες, το namespace μπορεί να μην είναι τόσο απομονωμένο όσο αναμένεται.
- Τα μεγάλα ή ασυνήθιστα τμήματα κοινής μνήμης αξίζουν συχνά περαιτέρω διερεύνησης.
- Ένα ευρύ mount του `/dev/shm` δεν είναι αυτόματα bug, αλλά σε ορισμένα περιβάλλοντα leaks ονόματα αρχείων, artifacts και προσωρινά μυστικά.

IPC σπάνια λαμβάνει τόση προσοχή όσο οι μεγαλύτεροι τύποι namespace, αλλά σε περιβάλλοντα που το χρησιμοποιούν εντατικά, η κοινή χρήση του με το host είναι ουσιαστικά μια απόφαση ασφάλειας.
{{#include ../../../../../banners/hacktricks-training.md}}
