# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le UTS namespace isole le **hostname** et le **NIS domain name** vus par le processus. À première vue, cela peut sembler anodin comparé aux mount, PID ou user namespaces, mais cela fait partie de ce qui donne au container l'apparence d'un host à part entière. À l'intérieur de l'namespace, le workload peut voir et parfois modifier un hostname qui est local à cet namespace plutôt que global à la machine.

Pris isolément, ce n'est généralement pas le cœur d'une histoire de breakout. Cependant, une fois que le host UTS namespace est partagé, un processus suffisamment privilégié peut influencer les paramètres liés à l'identité de l'hôte, ce qui peut avoir des conséquences opérationnelles et, parfois, des implications en matière de sécurité.

## Lab

Vous pouvez créer un UTS namespace avec:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Le changement de hostname reste local à ce namespace et n'altère pas le hostname global de l'hôte. Il s'agit d'une démonstration simple mais efficace de la propriété d'isolation.

## Utilisation à l'exécution

Les containers normaux disposent d'un namespace UTS isolé. Docker et Podman peuvent rejoindre le namespace UTS de l'hôte via `--uts=host`, et des schémas similaires de partage de l'hôte peuvent apparaître dans d'autres runtimes et systèmes d'orchestration. La plupart du temps, cependant, l'isolation privée UTS fait simplement partie de la configuration normale du container et nécessite peu d'attention de l'opérateur.

## Impact sur la sécurité

Même si le namespace UTS n'est généralement pas le plus dangereux à partager, il contribue néanmoins à l'intégrité de la frontière du container. Si le namespace UTS de l'hôte est exposé et que le processus dispose des privilèges nécessaires, il peut être capable de modifier les informations liées au hostname de l'hôte. Cela peut affecter la supervision, la journalisation, les hypothèses opérationnelles, ou des scripts qui prennent des décisions de confiance basées sur les données d'identité de l'hôte.

## Abus

Si le namespace UTS de l'hôte est partagé, la question pratique est de savoir si le processus peut modifier les paramètres d'identité de l'hôte plutôt que de se contenter de les lire :
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Si le conteneur dispose aussi du privilège nécessaire, vérifiez si le nom d'hôte peut être modifié :
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Il s'agit principalement d'un problème d'intégrité et d'impact opérationnel plutôt que d'un escape complet, mais cela montre néanmoins que le conteneur peut directement influencer une propriété globale de l'hôte.

Impact:

- falsification de l'identité de l'hôte
- perturbation des logs, du monitoring ou de l'automatisation qui font confiance au hostname
- généralement pas un escape complet en soi à moins d'être combiné avec d'autres faiblesses

Sur les environnements Docker-style, un motif de détection côté hôte utile est :
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Les conteneurs affichant `UTSMode=host` partagent le namespace UTS de l'hôte et doivent être examinés plus attentivement s'ils possèdent également des capabilities leur permettant d'appeler `sethostname()` ou `setdomainname()`.

## Checks

Ces commandes suffisent pour vérifier si la charge de travail dispose de sa propre vue du nom d'hôte ou partage le namespace UTS de l'hôte.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- Le fait que les identifiants de namespace correspondent à un processus de l'hôte peut indiquer que le UTS namespace est partagé avec l'hôte.
- Si la modification du hostname affecte plus que le conteneur lui‑même, la charge de travail a plus d'influence sur l'identité de l'hôte que prévu.
- Il s'agit généralement d'une découverte de moindre priorité comparée aux problèmes de PID, de mount ou de user namespace, mais cela confirme quand même à quel point le processus est réellement isolé.

Dans la plupart des environnements, le UTS namespace est mieux considéré comme une couche d'isolation de support. Il est rarement la première chose que l'on recherche lors d'un breakout, mais il fait toujours partie de la cohérence et de la sécurité globales de la vue du conteneur.
{{#include ../../../../../banners/hacktricks-training.md}}
