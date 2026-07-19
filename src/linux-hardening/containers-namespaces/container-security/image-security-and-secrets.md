# Sécurité, signature et secrets des images

{{#include ../../../banners/hacktricks-training.md}}

## Registres d’images et confiance

La sécurité des conteneurs commence avant le lancement de la charge de travail. L’image détermine quels binaires, interpréteurs, bibliothèques, scripts de démarrage et configurations intégrées atteignent la production. Si l’image contient une backdoor, est obsolète ou a été construite avec des secrets intégrés, le hardening du runtime qui suit opère déjà sur un artefact compromis.

C’est pourquoi la provenance des images, le vulnerability scanning, la vérification des signatures et la gestion des secrets doivent être abordés au même titre que les namespaces et seccomp. Ils protègent une phase différente du cycle de vie, mais les défaillances à ce niveau définissent souvent la surface d’attaque que le runtime devra ensuite contenir.

## Registres d’images et confiance

Les images peuvent provenir de registres publics tels que Docker Hub ou de registres privés gérés par une organisation. La question de sécurité n’est pas simplement de savoir où se trouve l’image, mais si l’équipe peut établir sa provenance et son intégrité. Le fait de récupérer des images non signées ou mal suivies depuis des sources publiques augmente le risque que du contenu malveillant ou altéré entre en production. Même les registres hébergés en interne ont besoin d’une responsabilité claire, d’un processus de revue et d’une policy de confiance.

Docker Content Trust utilisait historiquement les concepts de Notary et TUF pour exiger des images signées. L’écosystème exact a évolué, mais la leçon durable reste pertinente : l’identité et l’intégrité des images doivent être vérifiables plutôt que supposées.

Exemple de workflow historique de Docker Content Trust :
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
L’objectif de l’exemple n’est pas que chaque équipe doive encore utiliser les mêmes outils, mais que la signature et la gestion des clés sont des tâches opérationnelles, et non une théorie abstraite.

## Analyse des vulnérabilités

L’analyse des images aide à répondre à deux questions différentes. Premièrement, l’image contient-elle des packages ou des bibliothèques connus pour être vulnérables ? Deuxièmement, l’image contient-elle des logiciels inutiles qui élargissent la surface d’attaque ? Une image remplie d’outils de débogage, de shells, d’interpréteurs et de packages obsolètes est à la fois plus facile à exploiter et plus difficile à analyser.

Voici quelques exemples de scanners couramment utilisés :
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Les résultats de ces outils doivent être interprétés avec prudence. Une vulnérabilité présente dans un package inutilisé ne présente pas le même niveau de risque qu’un chemin RCE exposé, mais tous deux restent pertinents pour les décisions de hardening.

## Secrets au moment du build

L’une des erreurs les plus anciennes dans les pipelines de build de conteneurs consiste à intégrer directement des secrets dans l’image ou à les transmettre via des variables d’environnement qui deviennent ensuite visibles avec `docker inspect`, dans les logs de build ou dans des layers récupérées. Les secrets utilisés au moment du build doivent être montés temporairement pendant le build plutôt que copiés dans le système de fichiers de l’image.

BuildKit a amélioré ce modèle en permettant une gestion dédiée des secrets au moment du build. Au lieu d’écrire un secret dans une layer, l’étape de build peut le consommer temporairement :
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Cela est important, car les image layers sont des artefacts persistants. Une fois qu’un secret est intégré à une layer commitée, supprimer ultérieurement le fichier dans une autre layer ne supprime pas réellement la divulgation initiale de l’historique de l’image.

## Secrets au runtime

Les secrets nécessaires à un workload en cours d’exécution doivent également éviter, autant que possible, les approches ad hoc telles que les variables d’environnement en clair. Les volumes, les intégrations dédiées de gestion des secrets, Docker secrets et Kubernetes Secrets sont des mécanismes courants. Aucun de ces mécanismes n’élimine tous les risques, en particulier si l’attaquant dispose déjà d’une exécution de code dans le workload, mais ils restent préférables au stockage permanent des identifiants dans l’image ou à leur exposition involontaire via des outils d’inspection.

Une déclaration simple de secret au format Docker Compose ressemble à ceci :
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
Dans Kubernetes, les objets Secret, les volumes projetés, les tokens de comptes de service et les identités de workload cloud créent un modèle plus large et plus puissant, mais offrent également davantage de possibilités d’exposition accidentelle via des montages de l’hôte, un RBAC trop permissif ou une conception faible des Pod.

## Abus

Lors de l’examen d’une cible, l’objectif est de déterminer si des secrets ont été intégrés dans l’image, ont fait l’objet d’un leak dans les layers ou ont été montés dans des emplacements d’exécution prévisibles :
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ces commandes permettent de distinguer trois problèmes différents : les leaks de configuration de l’application, les leaks dans les couches de l’image et les fichiers de secrets injectés au runtime. Si un secret apparaît sous `/run/secrets`, dans un volume projeté ou dans un chemin de jeton d’identité cloud, l’étape suivante consiste à déterminer s’il donne accès uniquement au workload actuel ou à un control plane beaucoup plus vaste.

### Exemple complet : secret intégré dans le système de fichiers de l’image

Si un pipeline de build a copié des fichiers `.env` ou des credentials dans l’image finale, le post-exploitation devient simple :
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impact dépend de l'application, mais des clés de signature intégrées, des secrets JWT ou des identifiants cloud peuvent facilement transformer une compromission du container en compromission de l'API, en mouvement latéral ou en falsification de tokens d'application approuvés.

### Exemple complet : vérification du leak de secrets au build

Si la crainte est que l'historique de l'image ait capturé un layer contenant un secret :
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ce type d’examen est utile, car un secret peut avoir été supprimé de la vue finale du système de fichiers tout en restant présent dans une couche antérieure ou dans les métadonnées de build.

## Vérifications

Ces vérifications visent à déterminer si l’image et le pipeline de gestion des secrets ont probablement augmenté la surface d’attaque avant l’exécution.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ce qui est intéressant ici :

- Un historique de build suspect peut révéler des identifiants copiés, du matériel SSH ou des étapes de build dangereuses.
- Les secrets situés sous des chemins de volumes projetés peuvent permettre un accès au cluster ou au cloud, et pas seulement un accès à l’application locale.
- Un grand nombre de fichiers de configuration contenant des identifiants en clair indique généralement que l’image ou le modèle de déploiement contient plus de matériel de confiance que nécessaire.

## Valeurs par défaut à l’exécution

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker / BuildKit | Prend en charge les montages sécurisés de secrets au moment du build, mais pas automatiquement | Les secrets peuvent être montés temporairement pendant le `build` ; la signature et le scan des images nécessitent des choix explicites dans le workflow | copier des secrets dans l’image, transmettre des secrets via `ARG` ou `ENV`, désactiver les vérifications de provenance |
| Podman / Buildah | Prend en charge les builds natifs OCI et les workflows prenant en compte les secrets | Des workflows de build robustes sont disponibles, mais les opérateurs doivent tout de même les sélectionner intentionnellement | intégrer des secrets dans les Containerfiles, utiliser des contextes de build trop larges, autoriser des bind mounts trop permissifs pendant les builds |
| Kubernetes | Objets Secret natifs et volumes projetés | La distribution des secrets à l’exécution est native, mais l’exposition dépend du RBAC, de la conception des pods et des montages de l’hôte | montages de Secret trop larges, mauvaise utilisation des tokens de service account, accès `hostPath` aux volumes gérés par le kubelet |
| Registries | L’intégrité est optionnelle, sauf si elle est imposée | Les registries publics et privés dépendent tous deux des politiques, de la signature et des décisions d’admission | récupérer librement des images non signées, contrôle d’admission faible, mauvaise gestion des clés |
{{#include ../../../banners/hacktricks-training.md}}
