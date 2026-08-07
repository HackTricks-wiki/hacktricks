# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système de **Mandatory Access Control (MAC)** basé sur les **labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les Linux capabilities semblent suffisants pour une action, le kernel peut toujours la refuser, car le **contexte source** n’est pas autorisé à accéder au **contexte cible** avec la classe/permission demandée.

Un contexte ressemble généralement à ceci :
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue de la privesc, le `type` (domain pour les processus, type pour les objets) est généralement le champ le plus important :

- Un processus s’exécute dans un **domain** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et les sockets possèdent un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy détermine si un domain peut lire, écrire, exécuter ou effectuer une transition vers l’autre

## Énumération rapide

Si SELinux est activé, énumérez-le rapidement, car cela peut expliquer pourquoi les chemins courants de privesc sous Linux échouent ou pourquoi un wrapper privilégié autour d’un outil SELinux « inoffensif » est en réalité critique :
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
Points intéressants :

- Le mode `Disabled` ou `Permissive` supprime l’essentiel de la valeur de SELinux en tant que frontière.
- `unconfined_t` signifie généralement que SELinux est présent, mais ne contraint pas réellement ce processus.
- `default_t`, `file_t` ou des labels manifestement incorrects sur des chemins personnalisés indiquent souvent un étiquetage incorrect ou un déploiement incomplet.
- Les remplacements locaux dans `file_contexts.local` ont priorité sur les valeurs par défaut de la policy ; examinez-les donc attentivement.

## Analyse de la policy

SELinux est beaucoup plus facile à attaquer ou à contourner lorsque vous pouvez répondre à deux questions :

1. **À quoi mon domaine actuel peut-il accéder ?**
2. **Vers quels domaines puis-je effectuer une transition ?**

Les outils les plus utiles pour cela sont `sepolicy` et **SETools** (`seinfo`, `sesearch`, `sedta`) :<sup>[[2]](#references)</sup>
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
Ceci est particulièrement utile lorsqu’un hôte utilise des **confined users** plutôt que de mapper tout le monde vers `unconfined_u`. Dans ce cas, recherchez :<sup>[[3]](#references)</sup>

- les mappings d’utilisateurs via `semanage login -l`
- les rôles autorisés via `semanage user -l`
- les domaines admin accessibles tels que `sysadm_t`, `secadm_t`, `webadm_t`
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
`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un rôle/type plus permissif, ils deviennent des primitives d'escalade à haute valeur.

## Fichiers, réétiquetage et mauvaises configurations à haute valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est la suivante :<sup>[[1]](#references)</sup>

- `chcon` : modification temporaire du label sur un chemin spécifique
- `semanage fcontext` : règle persistante associant un chemin à un label
- `restorecon` / `setfiles` : réapplication du label défini par la policy/par défaut

Cela est très important pendant le privesc, car le **réétiquetage n'est pas seulement cosmétique**. Il peut transformer un fichier « bloqué par la policy » en fichier « lisible/exécutable par un service privilégié confiné ».

Vérifiez les règles locales de réétiquetage et les dérives de réétiquetage :
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un détail subtil mais utile : `restorecon` simple ne **rétablit pas toujours complètement un label suspect**. Si le type cible se trouve dans `customizable_types`, vous devrez peut-être utiliser `-F` pour forcer une réinitialisation complète. D’un point de vue offensif, cela explique pourquoi un `chcon` inhabituel peut parfois survivre à un nettoyage sommaire après lequel on affirme « nous avons déjà exécuté restorecon ».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Commandes à forte valeur à rechercher dans `sudo -l`, les wrappers root, les scripts d’automatisation ou les file capabilities :
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si l’une ou l’autre des capacités MAC apparaît, consultez également la [page Linux capabilities](linux-capabilities.md) ; `cap_mac_admin` et `cap_mac_override` sont inhabituelles, mais directement pertinentes lorsque SELinux fait partie de la boundary.

Particulièrement intéressants :

- `semanage fcontext` : modifie de manière persistante le label qu’un chemin doit recevoir
- `restorecon` / `setfiles` : réappliquent ces modifications à grande échelle
- `semodule -i` : charge un custom policy module
- `semanage permissive -a <domain_t>` : rend un domaine permissive sans basculer tout le host
- `setsebool -P` : modifie définitivement les policy booleans
- `load_policy` : recharge la policy active

Il s’agit souvent de **helper primitives**, et non de root exploits autonomes. Leur intérêt est de permettre de :

- rendre un target domain permissive
- élargir l’accès entre votre domaine et un protected type
- relabel des fichiers contrôlés par l’attaquant afin qu’un service privilégié puisse les lire ou les exécuter
- affaiblir un service confiné afin qu’un bug local existant devienne exploitable

Exemples de vérifications :
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si vous pouvez charger un module de policy en tant que root, vous contrôlez généralement la frontière SELinux :
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
C'est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être considérés comme des surfaces d'administration sensibles pendant la post-exploitation. Ils peuvent convertir silencieusement une chaîne bloquée en chaîne fonctionnelle sans modifier les permissions UNIX classiques.

## Denials masqués et extraction de modules

Une frustration offensive très courante concerne une chaîne qui échoue avec un simple `EACCES` alors que le denial AVC attendu n'apparaît jamais. Les règles `dontaudit` peuvent masquer la permission exacte dont vous avez besoin. Si vous pouvez exécuter `semodule` via `sudo` ou un autre wrapper privilégié, désactiver temporairement `dontaudit` peut transformer un échec silencieux en un indice précis concernant la policy :<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Cela est également utile pour vérifier ce que les administrateurs locaux ont déjà modifié. Un petit module personnalisé ou une règle permissive pour un seul domaine est souvent la raison pour laquelle un service cible se comporte de manière beaucoup plus permissive que ne le laisserait penser la policy de base.

## Indices d’audit

Les refus AVC sont souvent un signal offensif, et pas seulement du bruit défensif. Ils vous indiquent :

- quel objet/type cible vous avez atteint
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si une petite modification de policy permettrait à la chaîne de fonctionner
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si une tentative d’exploit local ou de persistence échoue systématiquement avec `EACCES` ou d’étranges erreurs « permission denied » malgré des permissions DAC qui semblent être celles de root, il vaut généralement la peine de vérifier SELinux avant d’abandonner le vecteur.

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est associé à un utilisateur SELinux dans le cadre de la policy, ce qui permet au système d’imposer des rôles et des domaines autorisés différents selon les comptes.<sup>[[3]](#references)</sup>

Vérifications rapides :
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Sur de nombreux systèmes courants, les utilisateurs sont associés à `unconfined_u`, ce qui réduit l'impact pratique de la confinement des utilisateurs. Toutefois, sur les déploiements renforcés, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` beaucoup plus intéressants, car **le chemin d'escalade peut dépendre de l'entrée dans un meilleur rôle/type SELinux, et pas seulement de l'obtention de l'UID 0**. N'oubliez pas non plus que certains utilisateurs confinés ne peuvent pas invoquer `sudo`/`su` du tout, à moins que la policy n'autorise explicitement la transition sous-jacente setuid. Ainsi, un hôte utilisant `staff_u` + `sysadm_r` peut transformer une règle apparemment mineure `sudo ROLE=` / `TYPE=` en véritable limite de privilèges.<sup>[[3]](#references)</sup>

## SELinux dans les Containers

Les runtimes de containers lancent généralement les workloads dans un domaine confiné tel que `container_t` et étiquettent le contenu des containers avec `container_file_t`. Si un processus de container s'échappe tout en conservant le label du container, les écritures sur l'hôte peuvent toujours échouer, car la limite de label est restée intacte.

Exemple rapide :
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La partie `c647,c780` n'est pas décorative. Dans de nombreux déploiements de conteneurs, les runtimes attribuent dynamiquement des catégories MCS afin que deux processus exécutés sous `container_t` restent séparés l'un de l'autre. Si un escape vous place dans un namespace de l'hôte tout en conservant l'ensemble de catégories d'origine, les incohérences de catégories peuvent toujours expliquer pourquoi certains chemins de l'hôte restent illisibles ou non inscriptibles.

Opérations modernes sur les conteneurs à retenir :

- `--security-opt label=disable` peut effectivement déplacer la workload vers un type lié aux conteneurs non confiné, tel que `spc_t`
- les bind mounts avec `:z` / `:Z` déclenchent le changement de label du chemin de l'hôte pour une utilisation partagée/privée par les conteneurs
- un changement de label étendu du contenu de l'hôte peut devenir en soi un problème de sécurité

Cette page conserve une section courte sur les conteneurs afin d'éviter les duplications. Pour les cas d'abus spécifiques aux conteneurs et les exemples de runtimes, consultez :

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Références

- [1] [Documentation Red Hat : Utiliser SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools : Outils d'analyse des policies pour SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestion des utilisateurs confinés et non confinés - Documentation RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Page du manuel Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
