# Sécurité des images, signature et secrets

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

La sécurité des conteneurs commence avant le lancement de la charge de travail. L'image détermine quels binaires, interprètes, bibliothèques, scripts de démarrage et configurations embarquées atteignent la production. Si l'image est backdoored, obsolète ou construite avec des secrets intégrés, le runtime hardening qui suit opère déjà sur un artefact compromis.

C'est pourquoi la provenance des images, l'analyse des vulnérabilités, la vérification des signatures et la gestion des secrets doivent faire partie de la même conversation que les namespaces et seccomp. Ils protègent une phase différente du cycle de vie, mais les défaillances à ce niveau définissent souvent la surface d'attaque que le runtime devra ensuite contenir.

## Registres d'images et confiance

Les images peuvent provenir de registres publics tels que Docker Hub ou de registres privés gérés par une organisation. La question de sécurité n'est pas simplement l'emplacement de l'image, mais de savoir si l'équipe peut établir sa provenance et son intégrité. Récupérer des images non signées ou mal suivies depuis des sources publiques augmente le risque que du contenu malveillant ou altéré entre en production. Même les registres hébergés en interne nécessitent une propriété claire, des processus de revue et une politique de confiance.

Docker Content Trust utilisait historiquement les concepts de Notary et TUF pour exiger des images signées. L'écosystème exact a évolué, mais la leçon durable reste utile : l'identité et l'intégrité d'une image doivent être vérifiables plutôt que présumées.

Exemple historique du workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Le but de l'exemple n'est pas que chaque équipe doive utiliser les mêmes outils, mais que la signature et la gestion des clés sont des tâches opérationnelles, pas une théorie abstraite.

## Analyse des vulnérabilités

L'analyse des images aide à répondre à deux questions différentes. Premièrement, l'image contient-elle des paquets ou bibliothèques connus vulnérables ? Deuxièmement, l'image contient-elle des logiciels inutiles qui élargissent la surface d'attaque ? Une image remplie de debugging tools, shells, interpreters, and stale packages est à la fois plus facile à exploiter et plus difficile à comprendre.

Exemples de scanners couramment utilisés incluent :
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Les résultats fournis par ces outils doivent être interprétés avec prudence. Une vulnérabilité dans un paquet inutilisé n'implique pas le même niveau de risque qu'un chemin RCE exposé, mais les deux restent pertinents pour les décisions de hardening.

## Secrets de build

Une des erreurs les plus anciennes dans les pipelines de build de conteneurs consiste à intégrer des secrets directement dans l'image ou à les transmettre via des variables d'environnement qui deviennent ensuite visibles via `docker inspect`, les logs de build, ou des couches récupérées. Les secrets utilisés au moment de la build devraient être montés de façon éphémère pendant la build plutôt que copiés dans le système de fichiers de l'image.

BuildKit a amélioré ce modèle en permettant une gestion dédiée des secrets au moment de la build. Au lieu d'écrire un secret dans une couche, l'étape de build peut le consommer de façon transitoire :
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Cela importe car les couches d'image sont des artefacts durables. Une fois qu'un secret entre dans une couche validée, le fait de supprimer ultérieurement le fichier dans une autre couche n'efface pas réellement la divulgation initiale de l'historique de l'image.

## Secrets d'exécution

Les secrets nécessaires à une workload en cours d'exécution devraient également éviter les schémas ad hoc tels que les variables d'environnement en clair autant que possible. Volumes, intégrations dédiées de gestion des secrets, Docker secrets et Kubernetes Secrets sont des mécanismes courants. Aucun de ces mécanismes n'élimine totalement le risque, surtout si l'attaquant a déjà l'exécution de code dans la workload, mais ils restent préférables au stockage permanent des identifiants dans l'image ou à leur exposition accidentelle via des outils d'inspection.

Une simple déclaration de secret au style Docker Compose ressemble à :
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Dans Kubernetes, les Secret objects, les projected volumes, les service-account tokens et les cloud workload identities créent un modèle plus vaste et plus puissant, mais ils multiplient aussi les opportunités d'exposition accidentelle via des host mounts, un RBAC permissif ou une conception de Pod faible.

## Abus

Lors de l'analyse d'une cible, l'objectif est de déterminer si des secrets ont été intégrés dans l'image, leaked dans les layers, ou montés dans des emplacements d'exécution prévisibles :
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ces commandes permettent de distinguer trois problèmes différents : des leaks de configuration d'application, des leaks au niveau de l'image, et des fichiers secrets injectés à l'exécution. Si un secret apparaît sous `/run/secrets`, un projected volume, ou un cloud identity token path, l'étape suivante est de déterminer s'il donne accès uniquement à la workload courante ou à un control plane beaucoup plus vaste.

### Exemple complet : secret intégré dans le système de fichiers de l'image

Si un build pipeline a copié des fichiers `.env` ou des credentials dans l'image finale, le post-exploitation devient simple :
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impact dépend de l'application, mais des clés de signature embarquées, des secrets JWT, ou des identifiants cloud peuvent facilement transformer une compromission de conteneur en compromission d'API, en mouvement latéral, ou en falsification de tokens d'application de confiance.

### Full Example: Build-Time Secret Leakage Check

Si l'on craint que l'historique de l'image ait capturé une couche contenant des secrets :
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ce type de revue est utile car un secret peut avoir été supprimé de la vue finale du système de fichiers tout en restant dans une couche antérieure ou dans les métadonnées de build.

## Vérifications

Ces vérifications visent à déterminer si l'image et le pipeline de gestion des secrets ont probablement augmenté la surface d'attaque avant l'exécution.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ce qui est intéressant ici :

- Un historique de build suspect peut révéler des credentials copiés, du matériel SSH, ou des étapes de build non sécurisées.
- Les Secrets sous des chemins de volumes projetés peuvent conduire à un accès au cluster ou au cloud, et pas seulement à l'application locale.
- Un grand nombre de fichiers de configuration contenant des credentials en clair indique généralement que l'image ou le deployment model transporte plus de matériel de confiance que nécessaire.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time Secret mounts, but not automatically | Les Secrets peuvent être montés de façon éphémère pendant `build` ; la signature et le scanning des images nécessitent des choix explicites de workflow | copying Secrets into the image, passing Secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Des workflows de build robustes sont disponibles, mais les opérateurs doivent encore les choisir intentionnellement | embedding Secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | La livraison des Secrets à l'exécution est de premier ordre, mais l'exposition dépend de RBAC, du design des pods et des host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Les registries publiques et privées dépendent toutes deux de la politique, de la signature et des décisions d'admission | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
