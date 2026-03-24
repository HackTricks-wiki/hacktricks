# Espace de noms UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms UTS isole le **hostname** et le **NIS domain name** vus par le processus. À première vue, cela peut sembler trivial comparé aux mount, PID, ou user namespaces, mais c'est une des composantes qui fait qu'un container semble être sa propre machine hôte. À l'intérieur de l'espace de noms, la charge de travail peut voir et parfois modifier un hostname qui est local à cet espace de noms plutôt que global à la machine.

En soi, ce n'est généralement pas le point central d'une histoire de breakout. Cependant, une fois que l'espace de noms UTS de l'hôte est partagé, un processus suffisamment privilégié peut influencer les paramètres liés à l'identité de l'hôte, ce qui peut avoir des conséquences opérationnelles et, occasionnellement, de sécurité.

## Laboratoire

Vous pouvez créer un espace de noms UTS avec:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Le changement de hostname reste local à ce UTS namespace et n'altère pas le hostname global de l'hôte. C'est une démonstration simple mais efficace de la propriété d'isolation.

## Runtime Usage

Les containers normaux obtiennent un UTS namespace isolé. Docker et Podman peuvent rejoindre le UTS namespace de l'hôte via `--uts=host`, et des schémas similaires de partage avec l'hôte peuvent apparaître dans d'autres runtimes et systèmes d'orchestration. La plupart du temps, cependant, l'isolation UTS privée fait simplement partie de la configuration normale du container et nécessite peu d'attention de l'opérateur.

## Security Impact

Même si le UTS namespace n'est généralement pas le plus dangereux à partager, il contribue néanmoins à l'intégrité de la frontière du container. Si le UTS namespace de l'hôte est exposé et que le processus dispose des privilèges nécessaires, il peut être capable de modifier les informations liées au hostname de l'hôte. Cela peut affecter le monitoring, le logging, les hypothèses opérationnelles, ou des scripts qui prennent des décisions de confiance basées sur les données d'identité de l'hôte.

## Abuse

Si le UTS namespace de l'hôte est partagé, la question pratique est de savoir si le processus peut modifier les paramètres d'identité de l'hôte plutôt que de simplement les lire :
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si le conteneur dispose également du privilège nécessaire, testez si le nom d'hôte peut être modifié :
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Il s'agit principalement d'un problème d'intégrité et d'impact opérationnel plutôt qu'un full escape, mais cela montre quand même que le container peut influencer directement une propriété globale de l'hôte.

Impact :

- falsification de l'identité de l'hôte
- perturbation des logs, du monitoring ou de l'automatisation qui font confiance au hostname
- généralement pas un full escape en soi à moins d'être combiné avec d'autres faiblesses

Dans les environnements de type Docker, un schéma de détection côté hôte utile est :
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Les conteneurs indiquant `UTSMode=host` partagent le namespace UTS de l'hôte et doivent être examinés plus attentivement s'ils disposent également de capabilities leur permettant d'appeler `sethostname()` ou `setdomainname()`.

## Vérifications

Ces commandes suffisent pour vérifier si la charge de travail a sa propre vue du nom d'hôte ou partage le namespace UTS de l'hôte.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Ce qui est intéressant ici :

- La correspondance des identifiants de namespace avec un processus host peut indiquer un partage UTS avec le host.
- Si changer le hostname affecte plus que le container lui-même, le workload a plus d'influence sur l'identité du host qu'il ne devrait.
- C'est généralement une découverte de moindre priorité que les problèmes PID, mount, ou user namespace, mais cela confirme néanmoins à quel point le processus est réellement isolé.

Dans la plupart des environnements, le UTS namespace est plutôt une couche d'isolation de support. Ce n'est que rarement la première chose que vous poursuivez lors d'un breakout, mais elle fait toujours partie de la cohérence et de la sécurité globales de la vue container.
{{#include ../../../../../banners/hacktricks-training.md}}
