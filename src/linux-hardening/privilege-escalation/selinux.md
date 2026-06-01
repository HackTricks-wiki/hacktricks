# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système de **Mandatory Access Control (MAC)** basé sur des **labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les capacités Linux semblent suffisants pour une action, le noyau peut quand même la refuser parce que le **source context** n'est pas autorisé à accéder au **target context** avec la classe/permission demandée.

Un contexte ressemble généralement à :
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue de la privesc, le `type` (domain pour les processes, type pour les objets) est généralement le champ le plus important :

- Un process s'exécute dans un **domain** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et sockets ont un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy décide si un domain peut lire/écrire/exécuter/transitionner vers l'autre

## Fast Enumeration

Si SELinux est activé, enumérez-le tôt car il peut expliquer pourquoi les chemins courants de privesc Linux échouent ou pourquoi un wrapper privilégié autour d'un outil SELinux "inoffensif" est en réalité critique :
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Vérifications de suivi utiles :
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
Découvertes intéressantes :

- Le mode `Disabled` ou `Permissive` retire la majeure partie de la valeur de SELinux en tant que boundary.
- `unconfined_t` signifie généralement que SELinux est présent, mais ne contraint pas réellement ce processus.
- `default_t`, `file_t`, ou des labels manifestement incorrects sur des chemins custom indiquent souvent un mauvais labelling ou un déploiement incomplet.
- Les overrides locaux dans `file_contexts.local` priment sur les valeurs par défaut de la policy, donc il faut les examiner attentivement.

## Policy Analysis

SELinux est beaucoup plus facile à attaquer ou contourner lorsque vous pouvez répondre à deux questions :

1. **À quoi mon domain actuel peut-il accéder ?**
2. **Vers quels domains puis-je transitionner ?**

Les outils les plus utiles pour cela sont `sepolicy` et **SETools** (`seinfo`, `sesearch`, `sedta`):
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
C'est particulièrement utile lorsqu'un hôte utilise des **confined users** plutôt que de mapper tout le monde vers `unconfined_u`. Dans ce cas, recherchez :

- des mappages d'utilisateurs via `semanage login -l`
- des rôles autorisés via `semanage user -l`
- des admin domains atteignables tels que `sysadm_t`, `secadm_t`, `webadm_t`
- des entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées comme celles-ci, SELinux fait partie de la frontière de privilège :
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Vérifiez aussi si `newrole` est disponible :
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de choisir un meilleur rôle/type, ils deviennent des primitives d’escalade à forte valeur.

## Files, Relabeling, and High-Value Misconfigurations

La différence opérationnelle la plus importante entre les outils SELinux courants est :

- `chcon` : changement temporaire de label sur un chemin spécifique
- `semanage fcontext` : règle persistante de chemin vers label
- `restorecon` / `setfiles` : applique à nouveau la policy/le label par défaut

Cela compte énormément pendant la privesc, car **le relabeling n’est pas seulement cosmétique**. Cela peut faire passer un fichier de "bloqué par policy" à "lisible/exécutable par un service privilégié confiné".

Vérifiez les règles de relabel locales et le relabel drift :
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un détail subtil mais utile : `restorecon` tout court ne **réinitialise pas toujours complètement un label suspect**. Si le type cible est dans `customizable_types`, vous pouvez avoir besoin de `-F` pour forcer une réinitialisation complète. D’un point de vue offensif, cela explique pourquoi un `chcon` inhabituel peut parfois survivre à un nettoyage rapide du type « on a déjà exécuté `restorecon` ».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Commandes à forte valeur à rechercher dans `sudo -l`, les root wrappers, les scripts d'automatisation ou les file capabilities :
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si l'une des capacités MAC apparaît, vérifiez aussi la [page des capacités Linux](linux-capabilities.md) ; `cap_mac_admin` et `cap_mac_override` sont inhabituelles mais directement pertinentes lorsque SELinux fait partie de la boundary.

Particulièrement intéressant :

- `semanage fcontext`: modifie de façon persistante l'étiquette qu'un path doit recevoir
- `restorecon` / `setfiles`: réapplique ces changements à grande échelle
- `semodule -i`: charge un module de policy personnalisé
- `semanage permissive -a <domain_t>`: rend un domain permissif sans basculer tout l'hôte
- `setsebool -P`: modifie de façon permanente les booléens de policy
- `load_policy`: recharge la policy active

Ce sont souvent des **helper primitives**, pas des exploits root autonomes. Leur intérêt est qu'elles vous permettent de :

- rendre un target domain permissif
- élargir l'accès entre votre domain et un type protégé
- relabel des fichiers contrôlés par l'attaquant pour qu'un service privilégié puisse les lire ou les exécuter
- affaiblir suffisamment un service confiné pour qu'un bug local existant devienne exploitable

Vérifications d'exemple :
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si vous pouvez charger un policy module en tant que root, vous contrôlez généralement la frontière SELinux :
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
C'est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être considérés comme des surfaces d'administration sensibles pendant le post-exploitation. Ils peuvent convertir silencieusement une chaîne bloquée en une chaîne fonctionnelle sans modifier les permissions UNIX classiques.

## Hidden Denials and Module Extraction

Une frustration offensive très courante est une chaîne qui échoue avec un simple `EACCES` alors que le refus AVC attendu n'apparaît jamais. Les règles `dontaudit` peuvent masquer exactement la permission dont vous avez besoin. Si vous pouvez exécuter `semodule` via `sudo` ou un autre wrapper privilégié, désactiver temporairement `dontaudit` peut transformer un échec silencieux en un indice précis de policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
C’est aussi utile pour vérifier ce que les admins locaux ont déjà modifié. Un petit module custom ou une règle permissive à un seul domaine est souvent la raison pour laquelle un service cible se comporte de façon beaucoup plus laxiste que ne le laisserait penser la base policy.

## Audit Clues

Les refus AVC sont souvent un signal offensif, pas seulement du bruit défensif. Ils vous indiquent :

- quel objet/type cible vous avez touché
- quelle permission a été refusée
- quel domain vous contrôlez actuellement
- si un petit changement de policy rendrait la chaîne fonctionnelle
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local ou une tentative de persistence échoue sans cesse avec `EACCES` ou de étranges erreurs "permission denied" malgré des permissions DAC qui semblent root, SELinux vaut généralement la peine d'être vérifié avant d'écarter ce vecteur.

## SELinux Users

Il existe des SELinux users en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est mappé à un utilisateur SELinux dans le cadre de la policy, ce qui permet au système d'imposer différents rôles et domains autorisés sur différents comptes.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Sur de nombreux systèmes grand public, les utilisateurs sont mappés vers `unconfined_u`, ce qui réduit l’impact pratique du confinement des utilisateurs. Sur des déploiements durcis, toutefois, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` bien plus intéressants parce que **le chemin d’escalade peut dépendre de l’entrée dans un rôle/type SELinux plus privilégié, et pas seulement du passage à UID 0**. N’oubliez pas non plus que certains utilisateurs confinés ne peuvent pas invoquer `sudo`/`su` du tout, sauf si la policy autorise explicitement la transition setuid sous-jacente, de sorte qu’un hôte utilisant `staff_u` + `sysadm_r` peut transformer une règle apparemment mineure `sudo ROLE=` / `TYPE=` en vraie frontière de privilège.

## SELinux in Containers

Les runtimes de containers lancent couramment les workloads dans un domaine confiné tel que `container_t` et étiquettent le contenu du container comme `container_file_t`. Si un processus de container s’échappe mais s’exécute toujours avec le label du container, les écritures sur l’hôte peuvent encore échouer parce que la frontière de label est restée intacte.

Exemple rapide :
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La partie `c647,c780` n’est pas décorative. Dans de nombreux déploiements de containers, les runtimes attribuent dynamiquement des catégories MCS afin que deux processus exécutés en tant que `container_t` restent malgré tout séparés l’un de l’autre. Si un escape vous amène dans un namespace de host mais conserve l’ensemble de catégories d’origine, des incompatibilités de catégories peuvent encore expliquer pourquoi certains chemins du host restent illisibles ou non inscriptibles.

À noter concernant les opérations modernes sur les containers :

- `--security-opt label=disable` peut effectivement déplacer la charge de travail vers un type lié aux containers mais non confiné, comme `spc_t`
- les bind mounts avec `:z` / `:Z` déclenchent un relabeling du chemin du host pour un usage de container partagé/privé
- un relabeling trop large du contenu du host peut devenir en soi un problème de sécurité

Cette page garde le contenu container volontairement court pour éviter les répétitions. Pour les cas d’abus spécifiques aux containers et les exemples de runtime, consultez :

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Références

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
