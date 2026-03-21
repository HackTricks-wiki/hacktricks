# Évaluation et durcissement

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Une bonne évaluation de conteneur doit répondre à deux questions parallèles. D'abord, que peut faire un attaquant depuis le workload courant ? Ensuite, quels choix d'opérateur ont rendu cela possible ? Les outils d'énumération aident pour la première question, et les recommandations de durcissement aident pour la seconde. Regrouper les deux sur une même page rend la section plus utile comme référence terrain plutôt que comme simple catalogue d'astuces d'évasion.

## Outils d'énumération

Un certain nombre d'outils restent utiles pour caractériser rapidement un environnement de conteneur :

- `linpeas` peut identifier de nombreux indicateurs liés aux conteneurs, les sockets montés, les capability sets, les systèmes de fichiers dangereux et les indices d'évasion.
- `CDK` se concentre spécifiquement sur les environnements container et inclut l'énumération ainsi que certaines vérifications automatisées d'escape.
- `amicontained` est léger et utile pour identifier les restrictions de container, les capabilities, l'exposition des namespaces et les classes probables de breakout.
- `deepce` est un autre outil d'énumération centré sur les containers avec des contrôles orientés breakout.
- `grype` est utile lorsque l'évaluation inclut la revue des vulnérabilités des packages d'image plutôt qu'une simple analyse des escapes à l'exécution.

La valeur de ces outils tient à la rapidité et à la couverture, pas à la certitude. Ils aident à révéler rapidement la posture générale, mais les découvertes intéressantes doivent encore être interprétées manuellement par rapport au modèle réel d'exécution, d'espace de noms, de capability et de montage.

## Priorités de durcissement

Les principes de durcissement les plus importants sont conceptuellement simples, même si leur implémentation varie selon la plateforme. Évitez les conteneurs privilégiés. Évitez les sockets runtime montés. Ne donnez pas aux conteneurs des chemins host écrits sauf s'il y a une raison très spécifique. Utilisez les user namespaces ou l'exécution rootless lorsque c'est possible. Supprimez toutes les capabilities et ne rétablissez que celles dont le workload a vraiment besoin. Gardez seccomp, AppArmor et SELinux activés plutôt que de les désactiver pour résoudre des problèmes de compatibilité applicative. Limitez les ressources afin qu'un conteneur compromis ne puisse pas trivialement refuser le service à l'hôte.

L'hygiène des images et du build compte autant que la posture à l'exécution. Utilisez des images minimales, reconstruisez fréquemment, scannez-les, exigez la provenance quand c'est pratique, et évitez les secrets dans les layers. Un conteneur s'exécutant en non-root avec une petite image et une surface syscall et capability étroite est bien plus facile à défendre qu'une grande image de commodité s'exécutant en root équivalent host avec des outils de debug préinstallés.

## Exemples d'épuisement de ressources

Les contrôles de ressources ne sont pas glamour, mais ils font partie de la sécurité des conteneurs car ils limitent le rayon d'impact d'une compromission. Sans limites mémoire, CPU ou PID, un simple shell peut suffire à dégrader l'hôte ou les workloads voisins.

Exemples de tests impactant l'hôte :
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ces exemples sont utiles car ils montrent que tous les résultats dangereux liés aux conteneurs ne constituent pas nécessairement un "escape" propre. Des limites faibles de cgroup peuvent encore transformer code execution en un impact opérationnel réel.

## Outils de durcissement

Pour les environnements centrés sur Docker, `docker-bench-security` reste une base d'audit côté hôte utile car il vérifie les problèmes de configuration courants par rapport aux recommandations de référence largement reconnues :
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
L'outil ne remplace pas la modélisation des menaces, mais il reste utile pour identifier des valeurs par défaut négligées pour les daemons, mount, network et runtime qui s'accumulent avec le temps.

## Vérifications

Utilisez-les comme commandes de première passe rapides lors de l'évaluation :
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un processus root avec broad capabilities et `Seccomp: 0` mérite une attention immédiate.
- Les mounts suspects et les runtime sockets offrent souvent un chemin plus rapide vers l'impact que n'importe quel kernel exploit.
- La combinaison d'une weak runtime posture et de weak resource limits indique généralement un environnement container permissif plutôt qu'une seule erreur isolée.
