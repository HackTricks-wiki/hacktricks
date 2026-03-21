# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

L'UTS namespace isole le **hostname** et le **NIS domain name** vus par le processus. À première vue, cela peut sembler trivial comparé aux mount, PID ou user namespaces, mais cela fait partie de ce qui donne à un container l'apparence d'un hôte distinct. À l'intérieur du namespace, la workload peut voir et parfois modifier un hostname qui est local à ce namespace plutôt que global à la machine.

En soi, cela n'est généralement pas le point central d'une breakout story. Cependant, une fois que l'UTS namespace de l'hôte est partagé, un processus suffisamment privilégié peut influencer les paramètres liés à l'identité de l'hôte, ce qui peut avoir des conséquences opérationnelles et, occasionnellement, en matière de sécurité.

## Lab

Vous pouvez créer un UTS namespace avec:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Le changement du nom d'hôte reste local à ce UTS namespace et n'altère pas le nom d'hôte global de la machine hôte. C'est une démonstration simple mais efficace de la propriété d'isolation.

## Utilisation à l'exécution

Les conteneurs normaux obtiennent un UTS namespace isolé. Docker et Podman peuvent rejoindre le UTS namespace de l'hôte via `--uts=host`, et des schémas similaires de partage d'hôte peuvent apparaître dans d'autres runtimes et systèmes d'orchestration. La plupart du temps, cependant, l'isolation UTS privée fait simplement partie de la configuration normale des conteneurs et demande peu d'attention de la part de l'opérateur.

## Impact sur la sécurité

Même si le UTS namespace n'est généralement pas le plus dangereux à partager, il contribue néanmoins à l'intégrité de la frontière du conteneur. Si le UTS namespace de l'hôte est exposé et que le processus dispose des privilèges nécessaires, il peut être capable de modifier les informations liées au nom d'hôte de la machine hôte. Cela peut affecter la surveillance, la journalisation, les hypothèses opérationnelles, ou des scripts qui prennent des décisions de confiance basées sur les données d'identité de l'hôte.

## Abus

Si le UTS namespace de l'hôte est partagé, la question pratique est de savoir si le processus peut modifier les paramètres d'identité de l'hôte plutôt que de simplement les lire :
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
Ceci est principalement un problème d'intégrité et d'impact opérationnel plutôt qu'un full escape, mais cela montre néanmoins que le container peut influencer directement une propriété globale de l'hôte.

Impact:

- falsification de l'identité de l'hôte
- perturber les logs, le monitoring ou l'automatisation qui font confiance au hostname
- généralement pas un full escape en soi, à moins d'être combiné avec d'autres faiblesses

Sur les environnements Docker-style, un pattern de détection côté hôte utile est:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Les conteneurs affichant `UTSMode=host` partagent le namespace UTS de l'hôte et doivent être examinés plus attentivement s'ils possèdent également des capabilities leur permettant d'appeler `sethostname()` ou `setdomainname()`.

## Vérifications

Ces commandes suffisent pour savoir si la charge de travail dispose de sa propre vue du hostname ou partage le namespace UTS de l'hôte.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Ce qui est intéressant ici :

- La correspondance des identifiants de namespace avec un processus de l'hôte peut indiquer que le UTS namespace est partagé avec l'hôte.
- Si le changement du hostname affecte plus que le conteneur lui-même, la charge de travail a plus d'influence sur l'identité de l'hôte qu'elle ne devrait.
- Ceci est généralement une découverte de moindre priorité que les problèmes liés à PID, mount ou user namespace, mais cela confirme quand même le degré d'isolation réel du processus.

Dans la plupart des environnements, l'UTS namespace doit plutôt être considéré comme une couche d'isolation de soutien. C'est rarement la première chose que l'on poursuit lors d'un breakout, mais cela fait toujours partie de la cohérence et de la sécurité globales de la vue du conteneur.
