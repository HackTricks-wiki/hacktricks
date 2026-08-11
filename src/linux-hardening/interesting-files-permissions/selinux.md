# SELinux

SELinux est un système de **Mandatory Access Control (MAC)** basé sur des **labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les Linux capabilities semblent suffisants pour une action, le kernel peut tout de même la refuser, car le **source context** n’est pas autorisé à accéder au **target context** avec la classe/permission demandée.<sup>[[1]](#references)</sup>

Un contexte ressemble généralement à ceci :<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue de la `privesc`, le champ `type` (domaine pour les processus, type pour les objets) est généralement le champ le plus important :<sup>[[1]](#references)</sup>

- Un processus s’exécute dans un **domaine** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et les sockets possèdent un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy décide si un domaine peut lire/écrire/exécuter ou effectuer une transition vers l’autre

## Énumération rapide

Si SELinux est activé, faites son énumération rapidement, car cela peut expliquer pourquoi les chemins courants de `privesc` sous Linux échouent, ou pourquoi un wrapper privilégié autour d’un outil SELinux « inoffensif » est en réalité critique :<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Vérifications de suivi utiles :<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Points intéressants :<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Le mode `Disabled` ou `Permissive` supprime la majeure partie de la valeur de SELinux en tant que boundary.
- `unconfined_t` signifie généralement que SELinux est présent, mais ne restreint pas réellement ce processus.
- `default_t`, `file_t` ou des labels manifestement incorrects sur des chemins personnalisés indiquent souvent un mauvais étiquetage ou un déploiement incomplet.
- Les overrides locaux dans `file_contexts.local` sont prioritaires par rapport aux valeurs par défaut de la policy ; examinez-les donc attentivement.

## Analyse de la policy

SELinux est beaucoup plus facile à attaquer ou à contourner lorsque vous pouvez répondre à deux questions :

1. **À quoi mon domaine actuel peut-il accéder ?**
2. **Dans quels domaines puis-je effectuer une transition ?**

Les outils les plus utiles pour cela sont `sepolicy` et **SETools** (`seinfo`, `sesearch`, `sedta`) :<sup>[[2]](#references)[[9]](#references)</sup>
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
Cela est particulièrement utile lorsqu’un hôte utilise des **utilisateurs confinés** au lieu de mapper tout le monde vers `unconfined_u`. Dans ce cas, recherchez :<sup>[[3]](#references)</sup>

- les correspondances utilisateur via `semanage login -l`
- les rôles autorisés via `semanage user -l`
- les domaines d’administration accessibles tels que `sysadm_t`, `secadm_t`, `webadm_t`
- les entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées comme celle-ci, SELinux fait partie de la limite de privilèges :<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Vérifiez également si `newrole` est disponible:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un rôle/type plus avantageux, ils deviennent des primitives d’escalade à forte valeur.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Fichiers, réétiquetage et mauvaises configurations à forte valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est la suivante :<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon` : modification temporaire du label sur un chemin spécifique
- `semanage fcontext` : règle persistante d’association chemin-label
- `restorecon` / `setfiles` : réappliquer le label défini par la policy/par défaut

Cela est très important pendant une privesc, car le **réétiquetage n’est pas seulement cosmétique**. Il peut transformer un fichier « bloqué par la policy » en fichier « lisible/exécutable par un service confiné privilégié ».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Vérifiez les règles locales de réétiquetage et les dérives de réétiquetage :<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Un détail subtil mais utile : `restorecon` standard ne **rétablit pas toujours complètement un label suspect**. Si le type cible figure dans `customizable_types`, vous devrez peut-être utiliser `-F` pour forcer une réinitialisation complète. D’un point de vue offensif, cela explique pourquoi un `chcon` inhabituel peut parfois survivre à un nettoyage superficiel du type « nous avons déjà exécuté restorecon ».<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Commandes à forte valeur à rechercher dans `sudo -l`, les root wrappers, les scripts d’automatisation ou les file capabilities :<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Si l’une ou l’autre des capacités MAC apparaît, consultez également la [page sur les Linux capabilities](linux-capabilities.md) ; la documentation des Linux capabilities décrit `cap_mac_admin` et `cap_mac_override` comme spécifiques à Smack. Ne supposez donc pas que leurs seuls noms permettent de contourner SELinux.<sup>[[5]](#references)</sup>

Particulièrement intéressants :<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext` : modifie de manière persistante le label qu’un chemin doit recevoir
- `restorecon` / `setfiles` : réapplique ces modifications à grande échelle
- `semodule -i` : charge un module de policy personnalisé
- `semanage permissive -a <domain_t>` : rend un domaine permissive sans basculer tout l’hôte
- `setsebool -P` : modifie définitivement les policy booleans
- `load_policy` : recharge la policy active

Il s’agit souvent de **primitives auxiliaires**, et non de root exploits autonomes. Leur intérêt est de vous permettre de :<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- rendre un domaine cible permissive
- élargir l’accès entre votre domaine et un type protégé
- réétiqueter des fichiers contrôlés par l’attaquant afin qu’un service privilégié puisse les lire ou les exécuter
- affaiblir suffisamment un service confiné pour qu’une faille locale existante devienne exploitable

Exemples de vérifications :<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Si vous pouvez charger un policy module en tant que root, vous contrôlez généralement la boundary SELinux :<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
C’est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être considérés comme des surfaces d’administration sensibles pendant la post-exploitation. Ils peuvent convertir silencieusement une chaîne bloquée en chaîne fonctionnelle sans modifier les permissions UNIX classiques.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Refus cachés et extraction de modules

Une frustration très courante en offensive est une chaîne qui échoue avec un simple `EACCES`, alors que le refus AVC attendu n’apparaît jamais. Les règles `dontaudit` peuvent masquer la permission exacte dont vous avez besoin. Si vous pouvez exécuter `semodule` via `sudo` ou un autre wrapper privilégié, désactiver temporairement `dontaudit` peut transformer un échec silencieux en indice de policy précis :<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Cela est également utile pour examiner ce que les administrateurs locaux ont déjà modifié. Un petit module personnalisé ou une règle permissive limitée à un domaine est souvent la raison pour laquelle un service cible se comporte de manière beaucoup plus permissive que ne le laisserait penser la policy de base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Indices d’audit

Les refus AVC sont souvent un signal offensif, et pas seulement du bruit défensif. Ils vous indiquent :<sup>[[1]](#references)[[15]](#references)</sup>

- quel objet/type cible vous avez atteint
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si une petite modification de la policy permettrait à la chaîne de fonctionner
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si un exploit local ou une tentative de persistence échoue continuellement avec `EACCES` ou d'étranges erreurs « permission denied » malgré des permissions DAC semblant être celles de root, SELinux mérite généralement d'être vérifié avant d'écarter le vecteur.<sup>[[1]](#references)</sup>

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est associé à un utilisateur SELinux dans le cadre de la policy, ce qui permet au système d'imposer différents rôles et domaines autorisés à différents comptes.<sup>[[3]](#references)</sup>

Vérifications rapides :<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Sur de nombreux systèmes courants, les utilisateurs sont associés à `unconfined_u`, ce qui réduit l’impact pratique du confinement des utilisateurs. Dans les déploiements renforcés, cependant, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` bien plus intéressants, car **le chemin d’escalade peut dépendre de l’entrée dans un rôle/type SELinux plus privilégié, et pas uniquement de l’obtention de l’UID 0**. N’oubliez pas non plus que certains utilisateurs confinés ne peuvent pas invoquer `sudo`/`su` du tout, sauf si la policy autorise explicitement la transition setuid sous-jacente. Ainsi, un hôte utilisant `staff_u` + `sysadm_r` peut transformer une règle `sudo ROLE=` / `TYPE=` apparemment mineure en véritable limite de privilèges.<sup>[[3]](#references)</sup>

## SELinux dans les conteneurs

Les container runtimes lancent généralement les workloads dans un domaine confiné tel que `container_t` et étiquettent le contenu des conteneurs avec `container_file_t`. Si un processus de conteneur s’échappe tout en conservant le label du conteneur, les écritures sur l’hôte peuvent toujours échouer, car la limite de labels est restée intacte.<sup>[[1]](#references)[[17]](#references)</sup>

Exemple rapide :<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
La partie `c647,c780` n'est pas décorative. Dans de nombreux déploiements de containers, les runtimes attribuent dynamiquement des catégories MCS afin que deux processus exécutés avec `container_t` restent séparés l'un de l'autre. Si un escape vous place dans un namespace de l'hôte tout en conservant l'ensemble de catégories d'origine, les incompatibilités de catégories peuvent encore expliquer pourquoi certains chemins de l'hôte restent illisibles ou non modifiables.<sup>[[17]](#references)</sup>

Opérations modernes sur les containers à noter :<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` désactive la séparation des labels SELinux pour le container
- les bind mounts avec `:z` / `:Z` déclenchent le re-étiquetage du chemin de l'hôte pour une utilisation partagée/privée par les containers
- le re-étiquetage étendu du contenu de l'hôte peut devenir en soi un problème de sécurité

Cette page conserve un contenu court sur les containers afin d'éviter les duplications. Pour les cas d'abus spécifiques aux containers et les exemples de runtime, consultez :

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Documentation Red Hat : Utiliser SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools : outils d'analyse de policy pour SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestion des utilisateurs confinés et non confinés - documentation RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - page du manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - page du manuel Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentation Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Pourquoi utiliser Multi-Category Security pour vos containers Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentation Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - page du manuel Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
