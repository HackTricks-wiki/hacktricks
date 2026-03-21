# Sécurité des images, signature et secrets

{{#include ../../../banners/hacktricks-training.md}}

## Overview

La sécurité des containers commence avant le lancement de la charge de travail. L'image détermine quels binaires, interprètes, bibliothèques, scripts de démarrage et configurations intégrées atteignent la production. Si l'image est backdoored, obsolète ou construite avec des secrets intégrés, le durcissement au runtime qui suit opère déjà sur un artefact compromis.

C'est pourquoi la provenance des images, l'analyse des vulnérabilités, la vérification des signatures et la gestion des secrets font partie de la même discussion que les namespaces et seccomp. Elles protègent une phase différente du cycle de vie, mais les échecs ici définissent souvent la surface d'attaque que le runtime devra ensuite contenir.

## Image Registries And Trust

Les images peuvent provenir de registres publics tels que Docker Hub ou de registres privés gérés par une organisation. La question de sécurité n'est pas simplement où réside l'image, mais si l'équipe peut établir sa provenance et son intégrité. Récupérer des images non signées ou mal suivies depuis des sources publiques augmente le risque que du contenu malveillant ou altéré entre en production. Même les registres hébergés en interne nécessitent une propriété claire, un processus de revue et une politique de confiance.

Docker Content Trust historically used Notary and TUF concepts to require signed images. The exact ecosystem has evolved, but the enduring lesson remains useful: image identity and integrity should be verifiable rather than assumed.

Exemple de workflow historique Docker Content Trust :
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Le but de l'exemple n'est pas que chaque équipe doive utiliser le même outillage, mais que la signature et la gestion des clés sont des tâches opérationnelles, et non une théorie abstraite.

## Analyse des vulnérabilités

L'analyse d'image aide à répondre à deux questions distinctes. Premièrement, l'image contient-elle des paquets ou bibliothèques connus comme vulnérables ? Deuxièmement, l'image embarque-t-elle des logiciels inutiles qui élargissent la surface d'attaque ? Une image remplie de debugging tools, shells, interpreters et de paquets obsolètes est à la fois plus facile à exploiter et plus difficile à analyser.

Exemples de scanners couramment utilisés :
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Les résultats de ces outils doivent être interprétés avec prudence. Une vulnérabilité dans un paquet inutilisé n'a pas le même niveau de risque qu'un chemin RCE exposé, mais les deux restent néanmoins pertinents pour les décisions de durcissement.

## Secrets au moment du build

Une des erreurs les plus anciennes dans les pipelines de build de containers est d'incorporer des secrets directement dans l'image ou de les transmettre via des variables d'environnement qui deviennent ensuite visibles via `docker inspect`, les logs de build, ou des couches récupérées. Les secrets au moment du build doivent être montés de façon éphémère pendant la build plutôt que copiés dans le système de fichiers de l'image.

BuildKit a amélioré ce modèle en permettant une gestion dédiée des secrets au moment du build. Au lieu d'écrire un secret dans une couche, l'étape de build peut le consommer de manière transitoire :
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Cela a de l'importance car les couches d'image sont des artefacts durables. Une fois qu'un secret entre dans une couche enregistrée, supprimer ensuite le fichier dans une autre couche n'efface pas véritablement la divulgation initiale de l'historique de l'image.

## Runtime Secrets

Les secrets nécessaires à une charge de travail en cours d'exécution doivent également éviter les schémas ad hoc tels que les variables d'environnement en clair dans la mesure du possible. Volumes, intégrations dédiées de gestion des secrets, Docker secrets et Kubernetes Secrets sont des mécanismes courants. Aucun d'entre eux n'élimine tous les risques, surtout si l'attaquant dispose déjà d'une exécution de code dans la charge de travail, mais ils restent préférables au stockage permanent des identifiants dans l'image ou à leur exposition accidentelle via des outils d'inspection.

Une déclaration de secret de type Docker Compose simple ressemble à :
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
Dans Kubernetes, Secret objects, projected volumes, service-account tokens, et cloud workload identities créent un modèle plus large et plus puissant, mais elles créent aussi davantage d'opportunités d'exposition accidentelle via host mounts, un RBAC trop permissif, ou une conception de Pod faible.

## Abus

Lors de l'examen d'une cible, l'objectif est de déterminer si des secrets ont été intégrés dans l'image, leaked dans les layers, ou montés dans des emplacements d'exécution prédictibles :
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ces commandes aident à distinguer trois problèmes différents : application configuration leaks, image-layer leaks et des fichiers secrets injectés à l'exécution. Si un secret apparaît sous `/run/secrets`, un projected volume, ou un chemin de token d'identité cloud, l'étape suivante est de déterminer s'il donne accès uniquement à la charge de travail courante ou à un plan de contrôle beaucoup plus étendu.

### Exemple complet : secret intégré dans le système de fichiers de l'image

Si un pipeline de build a copié des fichiers `.env` ou des identifiants dans l'image finale, post-exploitation devient simple :
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impact dépend de l'application, mais des clés de signature embarquées, des JWT secrets ou des identifiants cloud peuvent facilement transformer une compromission d'un conteneur en compromission d'API, en lateral movement, ou en falsification de tokens d'application de confiance.

### Exemple complet : vérification des fuites de secrets au moment de la build

Si la préoccupation est que l'historique de l'image ait capturé une couche contenant un secret :
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ce type d'examen est utile car un secret peut avoir été supprimé de la vue finale du système de fichiers tout en restant dans une couche antérieure ou dans les métadonnées de build.

## Vérifications

Ces vérifications visent à déterminer si l'image et le pipeline de gestion des secrets sont susceptibles d'avoir augmenté la surface d'attaque avant l'exécution.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ce qui est intéressant ici :

- Un historique de build suspect peut révéler des credentials copiées, du matériel SSH, ou des étapes de build non sécurisées.
- Les Secrets situés sous des chemins de volumes projetés peuvent conduire à un accès au cluster ou au cloud, pas seulement à l'accès local de l'application.
- Un grand nombre de fichiers de configuration contenant des credentials en clair indique généralement que l'image ou le modèle de déploiement transporte plus de matériel de confiance que nécessaire.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker / BuildKit | Prend en charge les montages de secrets sécurisés au moment du build, mais pas automatiquement | Les Secrets peuvent être montés de manière éphémère pendant le `build` ; la signature et le scan des images nécessitent des choix explicites de workflow | copier des secrets dans l'image, passer des secrets via `ARG` ou `ENV`, désactiver les vérifications de provenance |
| Podman / Buildah | Prend en charge des builds natifs OCI et des workflows compatibles avec les Secrets | Des workflows de build robustes existent, mais les opérateurs doivent toujours les choisir intentionnellement | intégrer des secrets dans les Containerfiles, contextes de build trop larges, montages bind permissifs pendant les builds |
| Kubernetes | objets Secret natifs et volumes projetés | La livraison des secrets à l'exécution est de premier ordre, mais l'exposition dépend de RBAC, du design des pods et des montages d'hôte | montages de Secret trop larges, mauvaise utilisation des tokens de service-account, accès `hostPath` aux volumes gérés par kubelet |
| Registries | L'intégrité est optionnelle sauf si elle est appliquée | Les registries publiques et privées dépendent toutes deux des politiques, de la signature et des décisions d'admission | récupération libre d'images non signées, contrôle d'admission faible, mauvaise gestion des clés |
