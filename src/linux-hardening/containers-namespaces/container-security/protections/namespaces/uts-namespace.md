# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Le UTS namespace isole le **hostname** et le **NIS domain name** visibles par le processus. À première vue, cela peut sembler trivial comparé aux namespaces mount, PID ou user, mais il contribue à donner l'impression qu'un container est son propre hôte. À l'intérieur du namespace, la workload peut voir et parfois modifier un hostname local à ce namespace plutôt que global à la machine.

À lui seul, ce mécanisme n'est généralement pas au cœur d'un scénario de breakout. Cependant, lorsque le UTS namespace de l'hôte est partagé, un processus suffisamment privilégié peut influencer les paramètres liés à l'identité de l'hôte, ce qui peut avoir une importance opérationnelle et, occasionnellement, en matière de sécurité.

## Lab

Vous pouvez créer un UTS namespace avec :
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Le changement du hostname reste local à ce namespace et ne modifie pas le hostname global de l’hôte. Il s’agit d’une démonstration simple, mais efficace, de la propriété d’isolation.

## Utilisation au runtime

Les containers normaux disposent d’un namespace UTS isolé. Docker et Podman peuvent rejoindre le namespace UTS de l’hôte via `--uts=host`, et des modèles similaires de partage avec l’hôte peuvent apparaître dans d’autres runtimes et systèmes d’orchestration. La plupart du temps, cependant, l’isolation UTS privée fait simplement partie de la configuration normale d’un container et nécessite peu d’attention de la part de l’opérateur.

## Impact sur la sécurité

Même si le namespace UTS n’est généralement pas le plus dangereux à partager, il contribue tout de même à l’intégrité de la frontière du container. Si le namespace UTS de l’hôte est exposé et que le processus dispose des privilèges nécessaires, il peut être en mesure de modifier les informations liées au hostname de l’hôte. Cela peut affecter le monitoring, la journalisation, les hypothèses opérationnelles ou les scripts qui prennent des décisions de confiance à partir des données d’identité de l’hôte.

## Abus

Si le namespace UTS de l’hôte est partagé, la question pratique est de savoir si le processus peut modifier les paramètres d’identité de l’hôte plutôt que de simplement les lire :
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si le container dispose également du privilège nécessaire, testez si le hostname peut être modifié :
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Il s’agit principalement d’un problème d’intégrité et d’impact opérationnel plutôt que d’un full escape, mais cela montre tout de même que le container peut influencer directement une propriété globale de l’hôte.

Impact :

- altération de l’identité de l’hôte
- logs, monitoring ou automatisation confus qui font confiance au hostname
- généralement pas un full escape à lui seul, sauf s’il est combiné à d’autres faiblesses

Dans les environnements de type Docker, un pattern utile de détection côté hôte est :
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Les conteneurs indiquant `UTSMode=host` partagent le namespace UTS de l’hôte et doivent être examinés plus attentivement s’ils disposent également de capabilities leur permettant d’appeler `sethostname()` ou `setdomainname()`.

## Vérifications

Ces commandes suffisent pour déterminer si le workload possède sa propre vue du hostname ou s’il partage le namespace UTS de l’hôte.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Ce qui est intéressant ici :

- Des identifiants de namespace correspondants à ceux d’un processus hôte peuvent indiquer un partage de l’UTS namespace avec l’hôte.
- Si la modification du hostname affecte autre chose que le container lui-même, le workload exerce davantage d’influence sur l’identité de l’hôte qu’il ne le devrait.
- Il s’agit généralement d’une finding moins prioritaire que les problèmes liés aux PID, au mount ou au user namespace, mais cela confirme tout de même le niveau réel d’isolation du processus.

Dans la plupart des environnements, l’UTS namespace doit être considéré comme une couche d’isolation complémentaire. Il s’agit rarement du premier élément à examiner lors d’un breakout, mais il fait toujours partie de la cohérence globale et de la sécurité de la vue du container.
{{#include ../../../../../banners/hacktricks-training.md}}
