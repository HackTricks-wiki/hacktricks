# Évaluation et durcissement

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Une bonne évaluation des conteneurs devrait répondre à deux questions parallèles. Premièrement, que peut faire un attaquant à partir du workload actuel ? Deuxièmement, quels choix d'opérateur ont rendu cela possible ? Les outils d'énumération aident pour la première question, et les conseils de durcissement aident pour la seconde. Regrouper les deux sur une même page rend la section plus utile comme référence de terrain plutôt que comme simple catalogue de tricks d'escape.

## Outils d'énumération

Un certain nombre d'outils restent utiles pour caractériser rapidement un environnement de conteneurs :

- `linpeas` peut identifier de nombreux indicateurs liés aux conteneurs, des sockets montés, des capability sets, des systèmes de fichiers dangereux et des hints de breakout.
- `CDK` se concentre spécifiquement sur les environnements de conteneurs et inclut l'énumération ainsi que quelques vérifications automatisées d'escape.
- `amicontained` est léger et utile pour identifier les restrictions des conteneurs, les capabilities, l'exposition des namespaces et les classes de breakout probables.
- `deepce` est un autre outil d'énumération orienté conteneurs avec des vérifications axées breakout.
- `grype` est utile lorsque l'évaluation inclut une revue des vulnérabilités des packages d'image plutôt que seulement une analyse d'escape à l'exécution.

La valeur de ces outils réside dans la vitesse et la couverture, pas dans la certitude. Ils aident à révéler rapidement la posture générale, mais les découvertes intéressantes nécessitent encore une interprétation manuelle par rapport au modèle réel de runtime, namespace, capability et mount.

## Priorités de durcissement

Les principes de durcissement les plus importants sont conceptuellement simples, même si leur implémentation varie selon la plateforme. Éviter les containers privilegiés. Éviter les sockets runtime montés. Ne pas donner aux conteneurs des chemins host en écriture sauf s'il existe une raison très spécifique. Utiliser les user namespaces ou l'exécution rootless lorsque c'est faisable. Supprimer toutes les capabilities et ne réajouter que celles dont le workload a réellement besoin. Garder seccomp, AppArmor et SELinux activés plutôt que de les désactiver pour résoudre des problèmes de compatibilité applicative. Limiter les ressources afin qu'un conteneur compromis ne puisse pas trivialement provoquer une denial of service sur l'hôte.

L'hygiène des images et des builds compte autant que la posture à l'exécution. Utiliser des images minimales, rebuild fréquemment, les scanner, exiger la provenance quand c'est possible, et garder les secrets hors des layers. Un container qui tourne en non-root avec une petite image et une surface syscall et capability étroite est beaucoup plus facile à défendre qu'une grosse image de convenience tournant en root équivalent host avec des outils de debugging préinstallés.

## Exemples d'épuisement de ressources

Les contrôles de ressources ne sont pas glamour, mais ils font partie de la sécurité des conteneurs parce qu'ils limitent le blast radius d'une compromission. Sans limites de mémoire, CPU ou PID, un simple shell peut suffire à dégrader l'hôte ou les workloads voisins.

Exemples de tests impactant l'hôte :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles car ils montrent que tous les résultats dangereux d'un conteneur ne constituent pas une "escape" nette. Des limites cgroup faibles peuvent encore transformer l'exécution de code en un impact opérationnel réel.

## Outils de durcissement

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d'audit côté hôte utile car il vérifie les problèmes de configuration courants par rapport aux recommandations de benchmark largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L'outil ne remplace pas le threat modeling, mais il reste précieux pour repérer des daemon, mount, network, and runtime defaults négligents qui s'accumulent au fil du temps.

## Vérifications

Utilisez-les comme commandes rapides de première passe pendant l'évaluation :
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un processus root avec des capabilities étendues et `Seccomp: 0` mérite une attention immédiate.
- Les mounts suspects et les runtime sockets fournissent souvent un chemin plus rapide vers l'impact que n'importe quel kernel exploit.
- La combinaison d'une posture runtime faible et de limites de ressources faibles indique généralement un environnement de container globalement permissif plutôt qu'une seule erreur isolée.
{{#include ../../../banners/hacktricks-training.md}}
