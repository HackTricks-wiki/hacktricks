# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système de **contrôle d'accès obligatoire (MAC) basé sur des étiquettes**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les capacités Linux semblent suffisants pour effectuer une action, le noyau peut tout de même la refuser, car le **contexte source** n'est pas autorisé à accéder au **contexte cible** avec la classe/permission demandée.<sup>[[1]](#references)</sup>

Un contexte ressemble généralement à ceci :<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Du point de vue de l’élévation de privilèges, le champ `type` (domaine pour les processus, type pour les objets) est généralement le plus important :<sup>[[1]](#references)</sup>

- Un processus s’exécute dans un **domaine** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et les sockets ont un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La policy décide si un domaine peut lire, écrire, exécuter ou effectuer une transition vers l’autre

## Énumération rapide

Si SELinux est activé, énumérez-le tôt, car cela peut expliquer pourquoi les méthodes classiques d’élévation de privilèges sous Linux échouent ou pourquoi un wrapper privilégié autour d’un outil SELinux « inoffensif » est en réalité critique :<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Vérifications complémentaires utiles :<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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

Constats intéressants :<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Les modes `Disabled` ou `Permissive` réduisent considérablement la valeur de SELinux comme frontière de sécurité.
- `unconfined_t` signifie généralement que SELinux est présent, mais qu’il ne contraint pas réellement ce processus.
- `default_t`, `file_t` ou des labels manifestement incorrects sur des chemins personnalisés indiquent souvent un étiquetage incorrect ou un déploiement incomplet.
- Les remplacements locaux dans `file_contexts.local` ont priorité sur les paramètres par défaut de la policy : examinez-les donc attentivement.

## Analyse de la policy

SELinux est beaucoup plus facile à attaquer ou à contourner lorsqu’on peut répondre à deux questions :

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

C'est particulièrement utile lorsqu'un hôte utilise des **utilisateurs confinés** plutôt que de mapper tout le monde sur `unconfined_u`. Dans ce cas, recherchez :<sup>[[3]](#references)</sup>

- les mappages d'utilisateurs via `semanage login -l`
- les rôles autorisés via `semanage user -l`
- les domaines d'administration accessibles, tels que `sysadm_t`, `secadm_t`, `webadm_t`
- les entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées de ce type, SELinux fait partie de la limite de privilèges :<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Vérifiez également si `newrole` est disponible :<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un rôle/type plus avantageux, ils deviennent des primitives d’escalade à forte valeur.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Auditer les points d’entrée de transition modifiables

Un graphe de transition n’est qu’une piste concernant la policy. Pour en faire un chemin d’attaque, identifiez le type d’exécutable qui permet d’entrer dans un domaine plus utile, puis vérifiez si vous pouvez modifier un exécutable portant ce label ou le remplacer via son répertoire parent.<sup>[[9]](#references)[[20]](#references)</sup> Une transition `execve` automatique nécessite une règle `type_transition` applicable, un accès d’exécution depuis le domaine source, un accès `entrypoint` dans le domaine cible et l’autorisation de transition entre les domaines.<sup>[[20]](#references)</sup> Le domaine cible peut bénéficier d’un accès SELinux, mais l’exécution ne modifie pas à elle seule l’UID Linux ; vérifiez séparément les [SUID/SGID et les ACL](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Utilisez le type `entrypoint` indiqué pour vérifier les règles sous-jacentes, puis inspectez le chemin et son répertoire parent pour détecter tout accès en écriture.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Corrélez le type d’entrypoint à un chemin exécutable réel. Vérifiez les permissions DAC, les ACL, les permissions d’écriture SELinux sur le fichier ou le répertoire parent, le label du fichier et tout booléen conditionnel avant de considérer qu’une règle de policy est exploitable.<sup>[[20]](#references)[[22]](#references)</sup> Si un chemin est remplacé plutôt que modifié sur place, vérifiez le contexte du nouvel inode : les labels du système de fichiers sont stockés dans des attributs étendus, et le remplacement peut ne pas conserver le type d’entrypoint.<sup>[[21]](#references)</sup> Les programmes compatibles avec SELinux peuvent demander une transition avec `setexeccon` ; l’absence de règle automatique `type_transition` n’exclut donc pas toute transition.<sup>[[20]](#references)</sup>

## Fichiers, réétiquetage et mauvaises configurations à forte valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est la suivante :<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon` : changement temporaire du label d’un chemin spécifique
- `semanage fcontext` : règle persistante associant un chemin à un label
- `restorecon` / `setfiles` : réappliquer le label de la policy/par défaut

C’est très important lors d’une privesc, car **le réétiquetage n’est pas qu’une question d’apparence**. Il peut rendre un fichier, auparavant « bloqué par la policy », « lisible/exécutable par un service confiné privilégié ».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Recherchez les règles locales de réétiquetage et les écarts de réétiquetage :<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Un détail subtil, mais utile : `restorecon` sans option ne rétablit **pas toujours complètement une étiquette suspecte**. Si le type cible figure dans `customizable_types`, vous devrez peut-être utiliser `-F` pour forcer une réinitialisation complète. D’un point de vue offensif, cela explique pourquoi un `chcon` inhabituel peut parfois résister à un nettoyage du type « nous avons déjà exécuté restorecon ».<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Commandes à forte valeur à rechercher dans `sudo -l`, les wrappers root, les scripts d’automatisation ou les capabilities de fichiers :<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Si l’une ou l’autre des capacités MAC apparaît, consultez également la [page des capacités Linux](linux-capabilities.md) ; la documentation sur les capacités Linux décrit `cap_mac_admin` et `cap_mac_override` comme spécifiques à Smack : ne supposez donc pas que leurs noms suffisent à contourner SELinux.<sup>[[5]](#references)</sup>

Particulièrement intéressant :<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext` : modifie de façon persistante le label qu’un chemin doit recevoir
- `restorecon` / `setfiles` : réapplique ces modifications à grande échelle
- `semodule -i` : charge un module de policy personnalisé
- `semanage permissive -a <domain_t>` : rend un domain permissive sans basculer l’hôte entier
- `setsebool -P` : modifie de façon permanente les policy booleans
- `load_policy` : recharge la policy active

Il s’agit souvent de **primitives auxiliaires**, et non de root exploits autonomes. Elles sont utiles car elles permettent de :<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- rendre un domain cible permissive
- élargir les accès entre votre domain et un type protégé
- réétiqueter des fichiers contrôlés par un attaquant afin qu’un service privilégié puisse les lire ou les exécuter
- affaiblir suffisamment un service confiné pour rendre exploitable un bug local existant

Exemples de vérifications :<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Si vous pouvez charger un module de politique en tant que root, vous contrôlez généralement la frontière SELinux :<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

C’est pourquoi `audit2allow`, `semodule` et `semanage permissive` doivent être considérés comme des surfaces d’administration sensibles lors de la post-exploitation. Ils peuvent transformer silencieusement une chaîne bloquée en une chaîne fonctionnelle sans modifier les permissions UNIX classiques.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Refus masqués et extraction de modules

Une frustration très courante en offensive est une chaîne qui échoue avec un banal `EACCES` alors que le refus AVC attendu n’apparaît jamais. Les règles `dontaudit` peuvent masquer la permission exacte dont vous avez besoin. Si vous pouvez exécuter `semodule` via `sudo` ou un autre wrapper privilégié, désactiver temporairement `dontaudit` peut transformer un échec silencieux en un indice précis sur la policy :<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

C'est également utile pour examiner ce que les admins locaux ont déjà modifié. Un petit module personnalisé ou une règle permissive limitée à un domaine explique souvent pourquoi un service cible se comporte de manière bien plus permissive que ne le laisserait penser la politique de base.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Indices d’audit

Les refus AVC sont souvent des signaux offensifs, pas seulement du bruit défensif. Ils vous indiquent :<sup>[[1]](#references)[[15]](#references)</sup>

- quel objet/type cible vous avez atteint
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si une petite modification de la politique permettrait à la chaîne de fonctionner

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Si un exploit local ou une tentative de persistance échoue systématiquement avec `EACCES` ou des erreurs étranges du type « permission denied », malgré des permissions DAC qui semblent accorder les privilèges root, il vaut généralement la peine de vérifier SELinux avant d’abandonner ce vecteur.<sup>[[1]](#references)</sup>

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est associé à un utilisateur SELinux dans le cadre de la policy, ce qui permet au système d’imposer des rôles et des domaines autorisés différents selon les comptes.<sup>[[3]](#references)</sup>

Vérifications rapides :<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Sur de nombreux systèmes courants, les utilisateurs sont associés à `unconfined_u`, ce qui réduit l’impact pratique du confinement des utilisateurs. Toutefois, dans les déploiements renforcés, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` beaucoup plus intéressants, car **le chemin d’élévation des privilèges peut dépendre du passage à un rôle/type SELinux plus favorable, et pas seulement du fait de devenir UID 0**. N’oubliez pas non plus que certains utilisateurs confinés ne peuvent pas invoquer `sudo`/`su` à moins que la policy n’autorise explicitement la transition setuid sous-jacente. Ainsi, un hôte utilisant `staff_u` + `sysadm_r` peut transformer une règle `sudo ROLE=` / `TYPE=` apparemment mineure en véritable frontière de privilèges.<sup>[[3]](#references)</sup>

## SELinux dans les conteneurs

Les runtimes de conteneurs lancent généralement les workloads dans un domaine confiné tel que `container_t` et étiquettent le contenu des conteneurs avec `container_file_t`. Si un processus de conteneur s’échappe tout en conservant l’étiquette du conteneur, les écritures sur l’hôte peuvent toujours échouer, car la frontière des étiquettes est restée intacte.<sup>[[1]](#references)[[17]](#references)</sup>

Exemple rapide :<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

La partie `c647,c780` n’est pas décorative. Dans de nombreux déploiements de conteneurs, les runtimes attribuent dynamiquement des catégories MCS afin que deux processus exécutés en tant que `container_t` restent isolés l’un de l’autre. Si une évasion vous place dans un espace de noms de l’hôte tout en conservant l’ensemble de catégories d’origine, des incompatibilités de catégories peuvent expliquer pourquoi certains chemins de l’hôte restent illisibles ou impossibles à modifier.<sup>[[17]](#references)</sup>

Fonctionnalités récentes liées aux conteneurs à noter :<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` désactive la séparation des conteneurs par étiquettes SELinux
- les montages bind avec `:z` / `:Z` déclenchent le réétiquetage du chemin de l’hôte pour une utilisation partagée/privée par les conteneurs
- le réétiquetage étendu du contenu de l’hôte peut devenir un problème de sécurité à part entière

Cette page limite le contenu sur les conteneurs afin d’éviter les répétitions. Pour les cas d’abus propres aux conteneurs et les exemples de runtime, consultez :

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Documentation Red Hat : Utilisation de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools : Outils d’analyse des politiques pour SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gestion des utilisateurs confinés et non confinés - Documentation RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - page de manuel Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - page de manuel Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - page de manuel Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - page de manuel Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - page de manuel Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentation de podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Pourquoi utiliser la sécurité multi-catégorie pour vos conteneurs Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentation de podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - page de manuel Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Carnet SELinux : transitions de domaine et d’objet](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10 : Utilisation de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Manuel de SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
