# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système de **Mandatory Access Control (MAC) basé sur des labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les Linux capabilities semblent suffisants pour effectuer une action, le kernel peut tout de même la refuser, car le **contexte source** n'est pas autorisé à accéder au **contexte cible** avec la classe/permission demandée.

Un contexte ressemble généralement à ceci :
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue de la privesc, le champ `type` (domaine pour les processus, type pour les objets) est généralement le plus important :

- Un processus s’exécute dans un **domaine** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et les sockets possèdent un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy détermine si un domaine peut lire, écrire, exécuter ou effectuer une transition vers l’autre

## Énumération rapide

Si SELinux est activé, énumérez-le dès le début, car cela peut expliquer pourquoi les chemins courants de privesc sous Linux échouent ou pourquoi un wrapper privilégié autour d’un outil SELinux « inoffensif » est en réalité critique :
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
Constats intéressants :

- Les modes `Disabled` ou `Permissive` réduisent considérablement la valeur de SELinux en tant que limite de sécurité.
- `unconfined_t` signifie généralement que SELinux est présent, mais qu’il ne restreint pas réellement ce processus.
- `default_t`, `file_t` ou des labels manifestement incorrects sur des chemins personnalisés indiquent souvent un mauvais étiquetage ou un déploiement incomplet.
- Les surcharges locales dans `file_contexts.local` ont priorité sur les valeurs par défaut de la policy ; examinez-les donc attentivement.

## Analyse de la policy

SELinux est beaucoup plus facile à attaquer ou à contourner lorsque vous pouvez répondre à deux questions :

1. **À quoi mon domaine actuel peut-il accéder ?**
2. **Vers quels domaines puis-je effectuer une transition ?**

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
C'est particulièrement utile lorsqu'un hôte utilise des **utilisateurs confinés** plutôt que de mapper tout le monde vers `unconfined_u`. Dans ce cas, recherchez :

- les mappings d'utilisateurs via `semanage login -l`
- les rôles autorisés via `semanage user -l`
- les domaines d'administration accessibles tels que `sysadm_t`, `secadm_t`, `webadm_t`
- les entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées comme celle-ci, SELinux fait partie de la limite de privilèges :
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Vérifiez également si `newrole` est disponible :
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un rôle/type plus favorable, ils deviennent des primitives d'escalade à forte valeur.

## Fichiers, re-étiquetage et mauvaises configurations à forte valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est la suivante :

- `chcon` : modification temporaire du label sur un chemin spécifique
- `semanage fcontext` : règle persistante associant un chemin à un label
- `restorecon` / `setfiles` : réappliquer le label défini par la policy/par défaut

Cela est particulièrement important lors d'une privesc, car le **re-étiquetage n'est pas qu'une question d'apparence**. Il peut transformer un fichier « bloqué par la policy » en fichier « lisible/exécutable par un service confiné privilégié ».

Recherchez les règles locales de re-étiquetage ainsi que les écarts de re-étiquetage :
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un détail subtil mais utile : `restorecon` simple ne **réinitialise pas toujours complètement un label suspect**. Si le type cible se trouve dans `customizable_types`, vous devrez peut-être utiliser `-F` pour forcer une réinitialisation complète. D’un point de vue offensif, cela explique pourquoi un `chcon` inhabituel peut parfois survivre à un nettoyage superficiel durant lequel on affirme avoir déjà exécuté « restorecon ».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Commandes à fort potentiel à rechercher dans `sudo -l`, les wrappers root, les scripts d’automatisation ou les capabilities de fichiers :
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si l’une ou l’autre des capacités MAC apparaît, consultez également la [Linux capabilities page](linux-capabilities.md) ; `cap_mac_admin` et `cap_mac_override` sont inhabituelles, mais directement pertinentes lorsque SELinux fait partie de la boundary.

Particulièrement intéressants :

- `semanage fcontext` : modifie de manière persistante le label qu’un chemin doit recevoir
- `restorecon` / `setfiles` : réappliquent ces modifications à grande échelle
- `semodule -i` : charge un custom policy module
- `semanage permissive -a <domain_t>` : rend un domain permissive sans basculer tout l’hôte
- `setsebool -P` : modifie de manière permanente les policy booleans
- `load_policy` : recharge la policy active

Il s’agit souvent de **helper primitives**, et non d’exploits root autonomes. Leur intérêt est de permettre de :

- rendre un target domain permissive
- élargir les accès entre votre domain et un protected type
- re-étiqueter des fichiers contrôlés par l’attaquant afin qu’un service privilégié puisse les lire ou les exécuter
- affaiblir suffisamment un service confiné pour qu’un bug local existant devienne exploitable

Exemples de vérifications :
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si vous pouvez charger un module de politique en tant que root, vous contrôlez généralement la frontière SELinux :
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
C'est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être considérés comme des surfaces d'administration sensibles pendant le post-exploitation. Ils peuvent silencieusement transformer une chaîne bloquée en chaîne fonctionnelle sans modifier les permissions UNIX classiques.

## Refus masqués et extraction de modules

Une frustration très courante lors d'une attaque est une chaîne qui échoue avec un simple `EACCES`, alors que le refus AVC attendu n'apparaît jamais. Les règles `dontaudit` peuvent masquer la permission exacte dont vous avez besoin. Si vous pouvez exécuter `semodule` via `sudo` ou un autre wrapper privilégié, désactiver temporairement `dontaudit` peut transformer un échec silencieux en un indice précis sur la policy :
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Cela est également utile pour examiner ce que les administrateurs locaux ont déjà modifié. Un petit module personnalisé ou une règle permissive visant un seul domaine explique souvent pourquoi un service cible se comporte de manière beaucoup plus permissive que ne le laisserait penser la policy de base.

## Indices d’audit

Les refus AVC constituent souvent un signal offensif, et pas seulement du bruit défensif. Ils vous indiquent :

- quel objet/type cible vous avez atteint
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si une petite modification de la policy permettrait à la chaîne de fonctionner
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local ou une tentative de persistence échoue constamment avec `EACCES` ou d'étranges erreurs « permission denied » malgré des permissions DAC qui semblent être celles de root, SELinux mérite généralement d'être vérifié avant d'abandonner le vecteur.

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est associé à un utilisateur SELinux dans le cadre de la policy, ce qui permet au système d'imposer différents rôles et domaines autorisés selon les comptes.

Vérifications rapides :
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Sur de nombreux systèmes courants, les utilisateurs sont associés à `unconfined_u`, ce qui réduit l’impact pratique de la confinement des utilisateurs. Toutefois, dans les déploiements renforcés, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` bien plus intéressants, car **le chemin d’escalade peut dépendre de l’accès à un rôle/type SELinux plus privilégié, et pas uniquement de l’obtention de l’UID 0**. Notez également que certains utilisateurs confinés ne peuvent pas invoquer `sudo`/`su` si la policy n’autorise pas explicitement la transition setuid sous-jacente. Ainsi, un hôte utilisant `staff_u` + `sysadm_r` peut transformer une règle `sudo ROLE=` / `TYPE=` apparemment mineure en véritable frontière de privilèges.

## SELinux dans les Containers

Les runtimes de conteneurs lancent généralement les workloads dans un domaine confiné tel que `container_t` et étiquettent le contenu des conteneurs avec `container_file_t`. Si un processus de conteneur s’échappe tout en conservant le label du conteneur, les écritures sur l’hôte peuvent toujours échouer, car la frontière des labels est restée intacte.

Exemple rapide :
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La partie `c647,c780` n'est pas décorative. Dans de nombreux déploiements de containers, les runtimes attribuent dynamiquement des catégories MCS afin que deux processus s'exécutant sous `container_t` restent séparés l'un de l'autre. Si un escape vous place dans un namespace de l'hôte tout en conservant l'ensemble de catégories d'origine, des incompatibilités de catégories peuvent toujours expliquer pourquoi certains chemins de l'hôte restent illisibles ou non modifiables.

Opérations modernes sur les containers à noter :

- `--security-opt label=disable` peut effectivement déplacer le workload vers un type lié aux containers non confiné, tel que `spc_t`
- les bind mounts avec `:z` / `:Z` déclenchent le changement de label du chemin de l'hôte pour une utilisation partagée/privée par les containers
- un changement de label étendu du contenu de l'hôte peut constituer un problème de sécurité en soi

Cette page garde la partie sur les containers concise afin d'éviter les duplications. Pour les cas d'abus spécifiques aux containers et les exemples de runtime, consultez :

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Références

- [Documentation Red Hat : utiliser SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools : outils d'analyse des policies pour SELinux](https://github.com/SELinuxProject/setools)
- [Gérer les utilisateurs confinés et non confinés - documentation RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
