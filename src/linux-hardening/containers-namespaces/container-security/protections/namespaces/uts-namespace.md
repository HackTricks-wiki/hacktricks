# Namespace UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Le namespace UTS isole le **hostname** et le **nom de domaine NIS** vus par le processus. À première vue, cela peut sembler trivial par rapport aux namespaces mount, PID ou user, mais il participe à donner l’impression qu’un container est son propre hôte. À l’intérieur du namespace, le workload peut voir et parfois modifier un hostname local à ce namespace plutôt que global à la machine.

À lui seul, ce n’est généralement pas l’élément central d’un scénario de breakout. Cependant, lorsque le namespace UTS de l’hôte est partagé, un processus suffisamment privilégié peut influencer les paramètres liés à l’identité de l’hôte, ce qui peut avoir une importance opérationnelle et parfois être pertinent du point de vue de la sécurité.

## Lab

Vous pouvez créer un namespace UTS avec :
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Le changement de hostname reste local à ce namespace et ne modifie pas le hostname global de l'hôte. Il s'agit d'une démonstration simple mais efficace de la propriété d'isolation.

## Utilisation au runtime

Les containers normaux disposent d'un namespace UTS isolé. Docker et Podman peuvent rejoindre le namespace UTS de l'hôte via `--uts=host`, et des modèles similaires de partage avec l'hôte peuvent apparaître dans d'autres runtimes et systèmes d'orchestration. Cependant, la plupart du temps, l'isolation UTS privée fait simplement partie de la configuration normale du container et nécessite peu d'intervention de la part de l'opérateur.

## Impact sur la sécurité

Même si le namespace UTS n'est généralement pas le plus dangereux à partager, il contribue tout de même à l'intégrité de la boundary du container. Si le namespace UTS de l'hôte est exposé et que le processus dispose des privilèges nécessaires, il peut être en mesure de modifier les informations liées au hostname de l'hôte. Cela peut affecter le monitoring, les logs, les hypothèses opérationnelles ou les scripts qui prennent des décisions de confiance basées sur les données d'identité de l'hôte.

## Abus

Si le namespace UTS de l'hôte est partagé, la question pratique est de savoir si le processus peut modifier les paramètres d'identité de l'hôte plutôt que de simplement les lire :
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si le conteneur dispose également du privilège nécessaire, vérifiez si le nom d’hôte peut être modifié :
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Il s’agit principalement d’un problème d’intégrité et d’impact opérationnel plutôt que d’un full escape, mais cela montre tout de même que le conteneur peut influencer directement une propriété globale de l’hôte.

Impact :

- altération de l’identité de l’hôte
- confusion dans les logs, la supervision ou l’automatisation qui font confiance au hostname
- généralement pas un full escape à lui seul, sauf s’il est combiné à d’autres faiblesses

Dans les environnements de type Docker, un pattern utile de détection côté hôte est :
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Les conteneurs affichant `UTSMode=host` partagent le namespace UTS de l’hôte et doivent être examinés plus attentivement s’ils disposent également de capabilities leur permettant d’appeler `sethostname()` ou `setdomainname()`.

## Vérifications

Ces commandes suffisent pour déterminer si la charge de travail possède sa propre vue du hostname ou si elle partage le namespace UTS de l’hôte.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Ce qui est intéressant ici :

- Des identifiants d'espace de noms correspondant à ceux d'un processus de l'hôte peuvent indiquer un partage de l'espace de noms UTS de l'hôte.
- Si la modification du hostname affecte autre chose que le conteneur lui-même, la charge de travail exerce davantage d'influence sur l'identité de l'hôte qu'elle ne le devrait.
- Il s'agit généralement d'une constatation moins prioritaire que les problèmes liés aux espaces de noms PID, mount ou user, mais elle confirme tout de même le niveau réel d'isolation du processus.

Dans la plupart des environnements, l'espace de noms UTS doit être considéré comme une couche d'isolation complémentaire. C'est rarement le premier élément que l'on examine lors d'un breakout, mais il fait tout de même partie de la cohérence et de la sécurité globales de la vue du conteneur.

{{#include ../../../../../banners/hacktricks-training.md}}
