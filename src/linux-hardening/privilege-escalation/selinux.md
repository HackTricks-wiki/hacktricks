# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux est un système de **Mandatory Access Control (MAC) basé sur des labels**. En pratique, cela signifie que même si les permissions DAC, les groupes ou les Linux capabilities semblent suffisants pour une action, le noyau peut quand même la refuser parce que le **contexte source** n'est pas autorisé à accéder au **contexte cible** avec la classe/permission demandée.

Un contexte ressemble généralement à :
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Du point de vue de l'escalade de privilèges, le `type` (domaine pour les processus, type pour les objets) est généralement le champ le plus important :

- Un processus s'exécute dans un **domaine** tel que `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Les fichiers et sockets ont un **type** tel que `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- La politique détermine si un domaine peut lire/écrire/exécuter/passer à un autre

## Enumération rapide

Si SELinux est activé, énumérez-le tôt car il peut expliquer pourquoi des chemins de privesc Linux courants échouent ou pourquoi un wrapper privilégié autour d'un outil SELinux "harmless" est en réalité critique:
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
Observations intéressantes :

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## Analyse de la politique

SELinux est beaucoup plus facile à attaquer ou à contourner quand on peut répondre à deux questions :

1. **À quoi mon domaine actuel peut-il accéder ?**
2. **Dans quels domaines puis-je basculer ?**

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
Ceci est particulièrement utile lorsqu'un hôte utilise des **utilisateurs confinés** plutôt que d'assigner tout le monde à `unconfined_u`. Dans ce cas, recherchez :

- mappages d'utilisateurs via `semanage login -l`
- rôles autorisés via `semanage user -l`
- domaines admin accessibles tels que `sysadm_t`, `secadm_t`, `webadm_t`
- entrées `sudoers` utilisant `ROLE=` ou `TYPE=`

Si `sudo -l` contient des entrées comme celles-ci, SELinux fait partie de la frontière de privilèges :
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Vérifiez également si `newrole` est disponible :
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` et `newrole` ne sont pas automatiquement exploitables, mais si un wrapper privilégié ou une règle `sudoers` vous permet de sélectionner un meilleur rôle/type, ils deviennent des primitives d'escalade de grande valeur.

## Fichiers, réétiquetage et mauvaises configurations à haute valeur

La différence opérationnelle la plus importante entre les outils SELinux courants est :

- `chcon`: temporary label change on a specific path
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: apply the policy/default label again

Cela compte beaucoup pendant privesc car **le réétiquetage n'est pas que cosmétique**. Il peut transformer un fichier de "bloqué par la politique" en "lisible/exécutable par un service confiné privilégié".

Vérifiez les règles locales de réétiquetage et la dérive d'étiquetage :
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Commandes de grande valeur à rechercher dans `sudo -l`, root wrappers, scripts d'automatisation ou file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Particulièrement intéressants :

- `semanage fcontext`: modifie de façon persistante le label qu'un chemin doit recevoir
- `restorecon` / `setfiles`: réapplique ces modifications à grande échelle
- `semodule -i`: charge un module de politique personnalisé
- `semanage permissive -a <domain_t>`: rend un seul domaine permissif sans basculer l'ensemble de l'hôte
- `setsebool -P`: modifie de façon permanente les booléens de la politique
- `load_policy`: recharge la politique active

Ce sont souvent des **helper primitives**, et non des exploits root autonomes. Leur intérêt est qu'elles vous permettent de :

- rendre un domaine cible permissif
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
C'est pourquoi `audit2allow`, `semodule`, et `semanage permissive` doivent être considérés comme des surfaces d'administration sensibles pendant post-exploitation. Ils peuvent silencieusement convertir une chaîne bloquée en une chaîne fonctionnelle sans modifier les permissions UNIX classiques.

## Indices d'audit

Les AVC denials sont souvent un signal offensif, pas seulement du bruit défensif. Ils vous indiquent :

- quel target object/type vous avez ciblé
- quelle permission a été refusée
- quel domaine vous contrôlez actuellement
- si un petit changement de policy permettrait de faire fonctionner la chaîne
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Si une tentative d'exploit local ou de persistance échoue systématiquement avec `EACCES` ou d'étranges erreurs "permission denied" malgré des permissions DAC donnant l'apparence de root, SELinux vaut généralement la peine d'être vérifié avant d'abandonner le vecteur.

## Utilisateurs SELinux

Il existe des utilisateurs SELinux en plus des utilisateurs Linux classiques. Chaque utilisateur Linux est associé à un utilisateur SELinux dans la politique, ce qui permet au système d'imposer différents rôles et domaines autorisés à différents comptes.

Vérifications rapides :
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Sur de nombreux systèmes grand public, les utilisateurs sont mappés à `unconfined_u`, ce qui réduit l'impact pratique du confinement des utilisateurs. Sur des déploiements durcis, cependant, les utilisateurs confinés peuvent rendre `sudo`, `su`, `newrole` et `runcon` beaucoup plus intéressants parce que **le chemin d'escalade peut dépendre de l'entrée dans un rôle/type SELinux plus approprié, et pas seulement du fait de devenir UID 0**.

## SELinux dans les conteneurs

Les runtimes de conteneurs lancent couramment des charges de travail dans un domaine confiné tel que `container_t` et étiquettent le contenu du conteneur comme `container_file_t`. Si un processus de conteneur s'échappe mais s'exécute toujours avec le label du conteneur, les écritures sur l'hôte peuvent toujours échouer parce que la frontière des labels est restée intacte.

Exemple rapide :
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Points importants concernant les opérations modernes de conteneurs :

- `--security-opt label=disable` peut effectivement déplacer la charge de travail vers un type lié aux conteneurs non confiné tel que `spc_t`
- bind mounts avec `:z` / `:Z` déclenchent le relabeling du chemin hôte pour une utilisation partagée/privée par le conteneur
- un relabeling étendu du contenu de l'hôte peut constituer un problème de sécurité en soi

This page keeps the container content short to avoid duplication. For the container-specific abuse cases and runtime examples, check:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Documentation Red Hat : Utilisation de SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools : outils d'analyse de politiques pour SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
