# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système **Mandatory Access Control (MAC) basé sur des labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les Linux capabilities semblent suffisants pour une action, le noyau peut quand même la refuser parce que le **contexte source** n'est pas autorisé à accéder au **contexte cible** avec la classe/permission demandée.

Un contexte ressemble généralement à :
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue privesc, le `type` (domaine pour les processus, type pour les objets) est généralement le champ le plus important :

- Un processus s'exécute dans un **domaine** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et sockets ont un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La politique décide si un domaine peut lire/écrire/exécuter ou effectuer une transition vers l'autre

## Énumération rapide

Si SELinux est activé, énumérez-le tôt car il peut expliquer pourquoi des chemins privesc courants sous Linux échouent ou pourquoi un wrapper privilégié autour d'un outil SELinux "inoffensif" est en réalité critique :
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Vérifications complémentaires utiles :
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Observations intéressantes:

- `Disabled` or `Permissive` mode suppriment la plupart de la valeur de SELinux en tant que barrière.
- `unconfined_t` signifie généralement que SELinux est présent mais n'impose pas de contraintes significatives à ce processus.
- `default_t`, `file_t`, ou des libellés visiblement incorrects sur des chemins personnalisés indiquent souvent un mauvais étiquetage ou un déploiement incomplet.
- Les substitutions locales dans `file_contexts.local` prévalent sur les paramètres par défaut de la politique ; examinez-les attentivement.

## Analyse de la politique

SELinux est bien plus facile à attaquer ou à contourner lorsque vous pouvez répondre à deux questions :

1. **Que peut accéder mon domaine actuel ?**
2. **Dans quels domaines puis-je effectuer une transition ?**

Les outils les plus utiles pour cela sont `sepolicy` et **SETools** (`seinfo`, `sesearch`, `sedta`) :
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Ceci est particulièrement utile lorsqu'un hôte utilise **des utilisateurs confinés** plutôt que de mapper tout le monde sur `unconfined_u`. Dans ce cas, recherchez :

- les mappages d'utilisateurs via `semanage login -l`
- les rôles autorisés via `semanage user -l`
- les domaines d'administration accessibles tels que `sysadm_t`, `secadm_t`, `webadm_t`
- entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées comme celles-ci, SELinux fait partie du périmètre des privilèges :
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Vérifiez également si `newrole` est disponible :
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` and `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un meilleur role/type, ils deviennent des primitives d'escalade de privilèges à haute valeur.

## Fichiers, réétiquetage, et mauvaises configurations à haute valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est :

- `chcon`: changement temporaire de label sur un chemin spécifique
- `semanage fcontext`: règle persistante chemin→label
- `restorecon` / `setfiles`: réappliquer la politique / le label par défaut

Cela a beaucoup d'importance pendant un privesc car **le réétiquetage n'est pas juste cosmétique**. Il peut transformer un fichier de "bloqué par la politique" en "lisible/exécutable par un service confiné et privilégié".

Vérifiez les règles de réétiquetage locales et la dérive de réétiquetage :
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Commandes à haute valeur à rechercher dans `sudo -l`, root wrappers, scripts d'automatisation ou capabilities de fichiers :
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Particulièrement intéressants :

- `semanage fcontext`: modifie de façon persistante le label qu'un chemin doit recevoir
- `restorecon` / `setfiles`: réapplique ces changements à grande échelle
- `semodule -i`: charge un module de politique personnalisé
- `semanage permissive -a <domain_t>`: met un domaine en mode permissif sans basculer l'ensemble de l'hôte
- `setsebool -P`: modifie de manière permanente les booléens de la politique
- `load_policy`: recharge la politique active

Ce sont souvent des **primitives d'assistance**, pas des exploits root autonomes. Leur intérêt est qu'elles vous permettent de :

- mettre un domaine cible en mode permissif
- élargir l'accès entre votre domaine et un type protégé
- réétiqueter des fichiers contrôlés par l'attaquant afin qu'un service privilégié puisse les lire ou les exécuter
- affaiblir un service confiné suffisamment pour qu'un bug local existant devienne exploitable

Exemples de vérifications :
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si vous pouvez charger un module de politique en tant que root, vous contrôlez généralement la frontière SELinux :
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
C'est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être traités comme des surfaces d'administration sensibles pendant post-exploitation. Ils peuvent transformer silencieusement une chaîne bloquée en une chaîne fonctionnelle sans modifier les permissions UNIX classiques.

## Indices d'audit

AVC denials sont souvent un signal offensif, pas seulement un bruit défensif. Ils vous indiquent :

- quel objet/type cible vous avez atteint
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si un petit changement de politique permettrait à la chaîne de fonctionner
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si une tentative de local exploit ou de persistence continue d'échouer avec `EACCES` ou d'étranges erreurs "permission denied" malgré des permissions DAC semblant provenir de root, il est généralement utile de vérifier SELinux avant d'écarter le vecteur.

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est mappé à un utilisateur SELinux dans la politique, ce qui permet au système d'imposer différents rôles et domaines autorisés selon les comptes.

Vérifications rapides :
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Sur de nombreux systèmes courants, les utilisateurs sont mappés sur `unconfined_u`, ce qui réduit l'impact pratique du confinement des utilisateurs. Cependant, dans des déploiements durcis, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` beaucoup plus intéressants parce que **le chemin d'escalade peut dépendre de l'entrée dans un rôle/type SELinux plus permissif, et pas seulement du fait de devenir UID 0**.

## SELinux dans les conteneurs

Les runtimes de conteneurs lancent couramment des charges de travail dans un domaine confiné tel que `container_t` et étiquettent le contenu des conteneurs comme `container_file_t`. Si un processus de conteneur s'échappe mais s'exécute toujours avec le label de conteneur, les écritures sur l'hôte peuvent encore échouer parce que la frontière des labels est restée intacte.

Exemple rapide :
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Opérations modernes de conteneurs à noter :

- `--security-opt label=disable` peut effectivement déplacer la charge de travail vers un type lié aux conteneurs non confiné tel que `spc_t`
- bind mounts avec `:z` / `:Z` entraînent le relabeling du chemin hôte pour un usage partagé/privé par le conteneur
- un relabeling étendu du contenu de l'hôte peut lui-même constituer un problème de sécurité

Cette page garde le contenu relatif aux conteneurs court pour éviter les duplications. Pour les cas d'abus spécifiques aux conteneurs et des exemples d'exécution, consultez :

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Références

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
