# Évaluation et durcissement

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Une bonne évaluation de container doit répondre à deux questions parallèles. Premièrement, que peut faire un attaquant depuis le workload actuel ? Deuxièmement, quels choix d'opérateur ont rendu cela possible ? Les outils d'énumération aident à répondre à la première question, et les recommandations de durcissement aident à répondre à la seconde. Rassembler les deux sur une même page rend la section plus utile comme référence de terrain plutôt que comme simple catalogue de techniques d'escape.

## Outils d'énumération

Un certain nombre d'outils restent utiles pour caractériser rapidement un environnement de container :

- `linpeas` peut identifier de nombreux indicateurs de container, des sockets montés, des ensembles de capability, des systèmes de fichiers dangereux, et des indices de breakout.
- `CDK` se concentre spécifiquement sur les environnements de container et inclut l'énumération ainsi que quelques vérifications automatisées d'escape.
- `amicontained` est léger et utile pour identifier les restrictions de container, les capability, l'exposition des namespace, et les classes de breakout probables.
- `deepce` est un autre énumérateur axé sur les container avec des vérifications orientées breakout.
- `grype` est utile lorsque l'évaluation inclut une revue des vulnérabilités des image-package plutôt que seulement une analyse d'escape à l'exécution.

La valeur de ces outils est la rapidité et la couverture, pas la certitude. Ils aident à révéler rapidement la posture approximative, mais les résultats intéressants nécessitent encore une interprétation manuelle par rapport au modèle réel de runtime, namespace, capability et mount.

## Priorités de durcissement

Les principes de durcissement les plus importants sont conceptuellement simples même si leur mise en œuvre varie selon la plateforme. Évitez les privileged containers. Évitez les mounted runtime sockets. Ne donnez pas aux containers des writable host paths à moins qu'il n'y ait une raison très spécifique. Utilisez les user namespaces ou le rootless execution lorsque c'est faisable. Retirez toutes les capability et ne remettez que celles dont le workload a réellement besoin. Gardez seccomp, AppArmor et SELinux activés plutôt que de les désactiver pour corriger des problèmes de compatibilité d'application. Limitez les ressources afin qu'un container compromis ne puisse pas trivialement provoquer un déni de service de l'hôte.

L'hygiène des images et du build compte autant que la posture d'exécution. Utilisez des images minimales, rebuilds fréquents, scannez-les, exigez la provenance lorsque c'est pratique, et gardez les secrets hors des layers. Un container exécuté en non-root avec une image petite et une surface syscall et capability restreinte est beaucoup plus facile à défendre qu'une grande image de convenance exécutée en root équivalent host avec des outils de debug préinstallés.

## Exemples d'épuisement de ressources

Les contrôles de ressources ne sont pas glamour, mais ils font partie de la sécurité des container car ils limitent le rayon d'impact d'une compromission. Sans limites de mémoire, CPU ou PID, un simple shell peut suffire à dégrader l'hôte ou les workloads voisins.

Exemples de tests impactant l'hôte :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles parce qu'ils montrent que tous les résultats dangereux liés au container ne sont pas forcément un "escape" net. Des limites cgroup faibles peuvent néanmoins transformer de la code execution en un impact opérationnel réel.

## Outils de durcissement

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d'audit côté hôte utile car il vérifie les problèmes de configuration courants par rapport aux directives de benchmark largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L'outil ne remplace pas le threat modeling, mais il reste utile pour trouver des daemon, mount, network et runtime defaults configurés de manière négligente qui s'accumulent au fil du temps.

## Checks

Utilisez ces commandes comme des vérifications rapides lors de l'évaluation :
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un processus root avec des capacités étendues et `Seccomp: 0` mérite une attention immédiate.
- Des mounts suspects et des runtime sockets offrent souvent un chemin vers l'impact plus rapide que n'importe quel kernel exploit.
- La combinaison d'une posture runtime faible et de limites de ressources laxistes indique généralement un environnement de container globalement permissif plutôt qu'une erreur isolée.
{{#include ../../../banners/hacktricks-training.md}}
