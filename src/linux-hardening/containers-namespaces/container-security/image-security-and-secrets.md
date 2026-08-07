# Sécurité des images, signature et secrets

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

La sécurité des conteneurs commence avant le lancement du workload. L'image détermine quels binaires, interpréteurs, bibliothèques, scripts de démarrage et configurations intégrées atteignent la production. Si l'image contient une backdoor, est obsolète ou a été construite avec des secrets intégrés, le hardening du runtime qui suit opère déjà sur un artefact compromis.

C'est pourquoi la provenance des images, le vulnerability scanning, la vérification des signatures et la gestion des secrets doivent être abordés au même titre que les namespaces et seccomp. Ils protègent une phase différente du cycle de vie, mais les défaillances à ce stade définissent souvent la surface d'attaque que le runtime devra ensuite contenir.

## Registres d'images et confiance

Les images peuvent provenir de registres publics tels que Docker Hub ou de registres privés gérés par une organisation. La question de sécurité n'est pas simplement de savoir où l'image est hébergée, mais si l'équipe peut établir sa provenance et son intégrité. Le pull d'images non signées ou mal suivies depuis des sources publiques augmente le risque que du contenu malveillant ou altéré entre en production. Même les registres hébergés en interne ont besoin d'une propriété claire, d'une review et d'une trust policy.

Docker Content Trust utilisait historiquement les concepts de Notary et TUF pour exiger des images signées. L'écosystème exact a évolué, mais la leçon fondamentale reste utile : l'identité et l'intégrité des images doivent pouvoir être vérifiées plutôt que supposées.

Exemple de workflow historique Docker Content Trust :
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
L'objectif de l'exemple n'est pas que toutes les équipes doivent continuer à utiliser les mêmes outils, mais que la signature et la gestion des clés sont des tâches opérationnelles, et non une théorie abstraite.

## Analyse des vulnérabilités

L'analyse des images permet de répondre à deux questions différentes. Premièrement, l'image contient-elle des packages ou des bibliothèques connus pour être vulnérables ? Deuxièmement, l'image contient-elle des logiciels inutiles qui élargissent la surface d'attaque ? Une image remplie d'outils de debugging, de shells, d'interpréteurs et de packages obsolètes est à la fois plus facile à exploiter et plus difficile à évaluer.

Voici quelques exemples de scanners couramment utilisés :
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Les résultats de ces outils doivent être interprétés avec précaution. Une vulnérabilité dans un package inutilisé ne présente pas le même niveau de risque qu'un chemin RCE exposé, mais les deux restent pertinents pour les décisions de hardening.

## Secrets au moment du build

L'une des erreurs les plus anciennes dans les pipelines de build de conteneurs consiste à intégrer directement des secrets dans l'image ou à les transmettre via des variables d'environnement qui deviennent ensuite visibles avec `docker inspect`, dans les logs de build ou dans des layers récupérés. Les secrets utilisés au moment du build doivent être montés de manière éphémère pendant le build, plutôt que copiés dans le système de fichiers de l'image.

BuildKit a amélioré ce modèle en permettant une gestion dédiée des secrets au moment du build. Au lieu d'écrire un secret dans un layer, l'étape de build peut le consommer temporairement :
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Cela est important, car les couches d'image sont des artefacts persistants. Une fois qu'un secret est inclus dans une couche committée, supprimer ensuite le fichier dans une autre couche ne supprime pas réellement la divulgation initiale de l'historique de l'image.

## Secrets d'exécution

Les secrets nécessaires à un workload en cours d'exécution doivent également éviter, dans la mesure du possible, les approches ad hoc telles que les variables d'environnement en clair. Les volumes, les intégrations dédiées de secret-management, Docker secrets et Kubernetes Secrets sont des mécanismes courants. Aucun de ces mécanismes ne supprime tous les risques, en particulier si l'attaquant dispose déjà d'une exécution de code dans le workload, mais ils restent préférables au stockage permanent des identifiants dans l'image ou à leur exposition imprudente via des outils d'inspection.

Une déclaration de secret simple, de style Docker Compose, ressemble à ceci :
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
Dans Kubernetes, les objets Secret, les volumes projetés, les service-account tokens et les cloud workload identities créent un modèle plus vaste et plus puissant, mais ils offrent également davantage de possibilités d’exposition accidentelle via les montages de l’hôte, un RBAC trop permissif ou une conception faible des Pod.

## Abus

Lors de l’analyse d’une cible, l’objectif est de déterminer si des secrets ont été intégrés à l’image, divulgués dans les layers ou montés dans des emplacements d’exécution prévisibles :
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ces commandes permettent de distinguer trois problèmes différents : les leaks de configuration de l’application, les leaks dans les couches de l’image et les fichiers secrets injectés au runtime. Si un secret apparaît sous `/run/secrets`, dans un volume projeté ou à un chemin de token d’identité cloud, l’étape suivante consiste à déterminer s’il accorde un accès uniquement au workload actuel ou à un control plane beaucoup plus vaste.

### Exemple complet : Secret intégré au système de fichiers de l’image

Si une pipeline de build a copié des fichiers `.env` ou des identifiants dans l’image finale, le post-exploitation devient simple :
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L’impact dépend de l’application, mais des clés de signature intégrées, des secrets JWT ou des cloud credentials peuvent facilement transformer la compromission d’un container en compromission d’API, en lateral movement ou en falsification de tokens d’application de confiance.

### Exemple complet : vérification des secrets leakés au build

Si le problème est que l’historique de l’image a capturé une layer contenant un secret :
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ce type de revue est utile, car un secret peut avoir été supprimé de la vue finale du système de fichiers tout en étant toujours présent dans une couche précédente ou dans les métadonnées de build.

## Vérifications

Ces vérifications visent à déterminer si l’image et le pipeline de gestion des secrets sont susceptibles d’avoir accru la surface d’attaque avant l’exécution.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ce qui est intéressant ici :

- Un historique de build suspect peut révéler des identifiants copiés, du matériel SSH ou des étapes de build dangereuses.
- Les secrets situés sous des chemins de volumes projetés peuvent donner accès au cluster ou au cloud, et pas seulement à l'application locale.
- Un grand nombre de fichiers de configuration contenant des identifiants en clair indique généralement que l'image ou le modèle de déploiement transporte plus de matériel de confiance que nécessaire.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker / BuildKit | Prend en charge les montages de secrets sécurisés au moment du build, mais pas automatiquement | Les secrets peuvent être montés de manière éphémère pendant le `build` ; la signature et le scan des images nécessitent des choix explicites dans le workflow | copier des secrets dans l'image, transmettre des secrets via `ARG` ou `ENV`, désactiver les contrôles de provenance |
| Podman / Buildah | Prend en charge les builds natifs OCI et les workflows tenant compte des secrets | Des workflows de build robustes sont disponibles, mais les opérateurs doivent tout de même les sélectionner intentionnellement | intégrer des secrets dans les Containerfiles, utiliser des contextes de build trop larges, autoriser des bind mounts permissifs pendant les builds |
| Kubernetes | Objets Secret natifs et volumes projetés | La transmission des secrets au runtime est intégrée, mais l'exposition dépend du RBAC, de la conception des pods et des montages de l'hôte | montages de Secret trop larges, utilisation abusive des tokens de service, accès `hostPath` aux volumes gérés par le kubelet |
| Registries | L'intégrité est optionnelle, sauf si elle est imposée | Les registries publics et privés dépendent tous deux des politiques, de la signature et des décisions d'admission | télécharger librement des images non signées, contrôle d'admission faible, mauvaise gestion des clés |

{{#include ../../../banners/hacktricks-training.md}}
