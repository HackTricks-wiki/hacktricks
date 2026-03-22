# Sécurité des images, signature et secrets

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

La sécurité des conteneurs commence avant le lancement de la charge de travail. L'image détermine quels binaires, interpréteurs, bibliothèques, scripts de démarrage et configurations intégrées atteindront la production. Si l'image est backdoored, obsolète, ou construite avec des secrets intégrés, le durcissement à l'exécution qui suit travaille déjà sur un artefact compromis.

C'est pourquoi la provenance des images, la détection des vulnérabilités, la vérification des signatures et la gestion des secrets doivent faire partie de la même discussion que les namespaces et seccomp. Ils protègent une phase différente du cycle de vie, mais les échecs à ce niveau définissent souvent la surface d'attaque que le runtime devra ensuite contenir.

## Registres d'images et confiance

Les images peuvent provenir de registres publics comme Docker Hub ou de registres privés gérés par une organisation. La question de sécurité n'est pas simplement l'emplacement de l'image, mais si l'équipe peut établir la provenance et l'intégrité. Récupérer des images non signées ou mal suivies depuis des sources publiques augmente le risque d'introduction en production de contenus malveillants ou altérés. Même les registres hébergés en interne nécessitent une propriété claire, une revue et une politique de confiance.

Docker Content Trust utilisait historiquement les concepts de Notary et TUF pour exiger des images signées. L'écosystème exact a évolué, mais la leçon qui perdure reste utile : l'identité et l'intégrité des images doivent être vérifiables plutôt que supposées.

Exemple de workflow historique Docker Content Trust :
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Le but de l'exemple n'est pas que chaque équipe doive nécessairement utiliser les mêmes outils, mais de montrer que signing et key management sont des tâches opérationnelles, pas de la théorie abstraite.

## Analyse des vulnérabilités

L'analyse d'images permet de répondre à deux questions distinctes. Premièrement, l'image contient-elle des paquets ou bibliothèques connus comme vulnérables ? Deuxièmement, l'image contient-elle des logiciels inutiles qui élargissent la surface d'attaque ? Une image remplie de debugging tools, shells, interpreters, et de paquets obsolètes est à la fois plus facile à exploiter et plus difficile à analyser.

Exemples de scanners couramment utilisés incluent :
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Les résultats de ces outils doivent être interprétés avec prudence. Une vulnérabilité dans un package inutilisé n'a pas le même niveau de risque qu'un chemin RCE exposé, mais les deux restent pertinents pour les décisions de hardening.

## Build-Time Secrets

Une des erreurs les plus anciennes dans les pipelines de build de conteneurs est d'intégrer des secrets directement dans l'image ou de les transmettre via des variables d'environnement qui deviennent ensuite visibles via `docker inspect`, les logs de build, ou des couches récupérées. Les secrets de build devraient être montés de façon éphémère pendant la build plutôt que copiés dans le système de fichiers de l'image.

BuildKit a amélioré ce modèle en permettant une gestion dédiée des secrets au moment de la build. Plutôt que d'écrire un secret dans une couche, l'étape de build peut le consommer de façon transitoire :
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Cela importe car les couches d'image sont des artefacts durables. Une fois qu'un secret entre dans une couche enregistrée, supprimer ensuite le fichier dans une autre couche ne supprime pas réellement la divulgation initiale de l'historique de l'image.

## Secrets d'exécution

Les secrets nécessaires à une charge de travail en cours d'exécution devraient également éviter les schémas ad hoc tels que les variables d'environnement en clair autant que possible. Volumes, intégrations dédiées de gestion des secrets, Docker secrets et Kubernetes Secrets sont des mécanismes courants. Aucun de ces mécanismes n'élimine tous les risques, surtout si l'attaquant dispose déjà d'une exécution de code dans la charge de travail, mais ils restent préférables au stockage permanent des identifiants dans l'image ou à leur exposition accidentelle via des outils d'inspection.

Une simple déclaration de secret au format Docker Compose ressemble à :
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
Dans Kubernetes, les Secret objects, les projected volumes, les service-account tokens et les cloud workload identities créent un modèle plus large et plus puissant, mais ils créent aussi davantage d'occasions d'exposition accidentelle via des host mounts, un RBAC trop permissif, ou une conception de Pod faible.

## Abus

Lors de l'examen d'une cible, le but est de découvrir si des secrets ont été intégrés dans l'image, leaked dans les layers, ou montés dans des emplacements d'exécution prévisibles :
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ces commandes aident à distinguer trois problèmes différents : application configuration leaks, image-layer leaks, et des fichiers secrets injectés à l'exécution. Si un secret apparaît sous `/run/secrets`, un volume projeté, ou un chemin du jeton d'identité cloud, l'étape suivante consiste à déterminer s'il n'accorde l'accès qu'à la charge de travail actuelle ou à un plan de contrôle beaucoup plus vaste.

### Exemple complet : secret intégré dans le système de fichiers de l'image

Si une pipeline de build a copié des fichiers `.env` ou des identifiants dans l'image finale, post-exploitation devient simple :
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
L'impact dépend de l'application, mais des clés de signature embarquées, des JWT secrets ou des cloud credentials peuvent facilement transformer un container compromise en API compromise, lateral movement ou forgery of trusted application tokens.

### Exemple complet : Build-Time Secret Leakage Check

Si la crainte est que l'historique de l'image ait capturé une couche contenant un secret :
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ce type de revue est utile car un secret peut avoir été supprimé de la vue finale du système de fichiers alors qu'il reste dans une couche antérieure ou dans les métadonnées de construction.

## Vérifications

Ces vérifications visent à déterminer si l'image et le pipeline de gestion des secrets ont probablement augmenté la surface d'attaque avant l'exécution.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Ce qui est intéressant ici :

- Un historique de build suspect peut révéler des identifiants copiés, du matériel SSH, ou des étapes de build non sécurisées.
- Secrets situés dans des chemins de volumes projetés peuvent donner accès au cluster ou au cloud, pas seulement à l'application locale.
- Un grand nombre de fichiers de configuration contenant des identifiants en clair indique généralement que l'image ou le modèle de déploiement transporte plus d'éléments de confiance que nécessaire.

## Paramètres d'exécution par défaut

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker / BuildKit | Prend en charge le montage sécurisé de Secrets au moment de la build, mais pas automatiquement | Les Secrets peuvent être montés de façon éphémère pendant la `build` ; la signature et le scanning d'images exigent des choix de workflow explicites | copier des secrets dans l'image, transmettre des secrets via `ARG` ou `ENV`, désactiver les vérifications de provenance |
| Podman / Buildah | Prend en charge les builds natifs OCI et les workflows prenant en charge les secrets | Des workflows de build solides sont disponibles, mais les opérateurs doivent toujours les choisir intentionnellement | intégrer des secrets dans les Containerfiles, contextes de build trop larges, bind mounts permissifs pendant les builds |
| Kubernetes | Objets Secret natifs et volumes projetés | La distribution de secrets à l'exécution est de première classe, mais l'exposition dépend de RBAC, du design des pods et des montages sur l'hôte | montages de Secret trop larges, mauvais usage de service-account token, `hostPath` access to kubelet-managed volumes |
| Registries | L'intégrité est optionnelle sauf si elle est appliquée | Les registries publiques et privées dépendent toutes deux de la politique, de la signature et des décisions d'admission | pull d'images non signées librement, contrôle d'admission faible, mauvaise gestion des clés |
{{#include ../../../banners/hacktricks-training.md}}
