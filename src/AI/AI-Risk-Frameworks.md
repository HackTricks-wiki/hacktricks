# Risques liés à l'IA

{{#include ../banners/hacktricks-training.md}}

## Top 10 OWASP des vulnérabilités du Machine Learning

Owasp a identifié les 10 principales vulnérabilités du Machine Learning susceptibles d'affecter les systèmes d'IA. Ces vulnérabilités peuvent entraîner divers problèmes de sécurité, notamment l'empoisonnement des données, l'inversion de modèle et les attaques adversariales. Comprendre ces vulnérabilités est essentiel pour créer des systèmes d'IA sécurisés.

Pour obtenir une liste détaillée et actualisée des 10 principales vulnérabilités du Machine Learning, consultez le projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack** : Un attaquant ajoute de minuscules modifications, souvent invisibles, aux **données entrantes** afin que le modèle prenne une mauvaise décision.\
*Exemple* : Quelques taches de peinture sur un panneau stop trompent une voiture autonome qui "voit" alors un panneau de limitation de vitesse.

- **Data Poisoning Attack** : Le **jeu de données d'entraînement** est délibérément pollué par de mauvais échantillons, ce qui apprend au modèle des règles nuisibles.\
*Exemple* : Des binaires de malware sont étiquetés à tort comme "bénins" dans un corpus d'entraînement antivirus, permettant ensuite à des malwares similaires de passer inaperçus.

- **Model Inversion Attack** : En sondant les sorties, un attaquant construit un **modèle inverse** qui reconstitue des caractéristiques sensibles des entrées originales.\
*Exemple* : Recréer l'image IRM d'un patient à partir des prédictions d'un modèle de détection du cancer.

- **Membership Inference Attack** : L'adversaire vérifie si un **enregistrement spécifique** a été utilisé pendant l'entraînement en observant les différences de confiance.\
*Exemple* : Confirmer qu'une transaction bancaire d'une personne apparaît dans les données d'entraînement d'un modèle de détection de fraude.

- **Model Theft** : Des requêtes répétées permettent à un attaquant d'apprendre les frontières de décision et de **cloner le comportement du modèle** (ainsi que sa propriété intellectuelle).\
*Exemple* : Collecter suffisamment de paires de questions-réponses auprès d'une API ML-as-a-Service pour créer un modèle local presque équivalent.

- **AI Supply-Chain Attack** : Compromettre n'importe quel composant (données, bibliothèques, poids pré-entraînés, CI/CD) du **pipeline ML** afin de corrompre les modèles en aval.\
*Exemple* : Une dépendance empoisonnée provenant d'un model-hub installe un modèle d'analyse des sentiments contenant une backdoor dans de nombreuses applications.

- **Transfer Learning Attack** : Une logique malveillante est intégrée dans un **modèle pré-entraîné** et survit au fine-tuning effectué pour la tâche de la victime.\
*Exemple* : Un backbone de vision contenant un déclencheur caché continue d'inverser les labels après son adaptation à l'imagerie médicale.

- **Model Skewing** : Des données subtilement biaisées ou mal étiquetées **déplacent les sorties du modèle** afin de favoriser les objectifs de l'attaquant.\
*Exemple* : Injecter des e-mails de spam "propres" étiquetés comme ham afin qu'un filtre anti-spam laisse passer de futurs e-mails similaires.

- **Output Integrity Attack** : L'attaquant **modifie les prédictions du modèle pendant leur transit**, sans modifier le modèle lui-même, trompant ainsi les systèmes en aval.\
*Exemple* : Inverser le verdict "malveillant" d'un classificateur de malware en "bénin" avant que l'étape de mise en quarantaine du fichier ne le reçoive.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle** lui-même, souvent après l'obtention d'un accès en écriture, afin d'en altérer le comportement.\
*Exemple* : Modifier les poids d'un modèle de détection de fraude en production afin que les transactions provenant de certaines cartes soient toujours approuvées.


## Risques SAIF de Google

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google présente différents risques associés aux systèmes d'IA :

- **Data Poisoning** : Des acteurs malveillants modifient ou injectent des données d'entraînement ou de tuning afin de dégrader la précision, d'implanter des backdoors ou de fausser les résultats, compromettant ainsi l'intégrité du modèle tout au long du cycle de vie des données.

- **Unauthorized Training Data** : L'ingestion de datasets protégés par le droit d'auteur, sensibles ou non autorisés crée des risques juridiques, éthiques et liés aux performances, car le modèle apprend à partir de données qu'il n'était pas autorisé à utiliser.

- **Model Source Tampering** : La manipulation, par la supply chain ou par un initié, du code du modèle, de ses dépendances ou de ses poids avant ou pendant l'entraînement peut intégrer une logique cachée qui persiste même après un nouvel entraînement.

- **Excessive Data Handling** : Des contrôles faibles de conservation et de gouvernance des données amènent les systèmes à stocker ou traiter davantage de données personnelles que nécessaire, augmentant l'exposition et les risques de conformité.

- **Model Exfiltration** : Les attaquants volent les fichiers ou poids du modèle, entraînant une perte de propriété intellectuelle et permettant la création de services imités ou la conduite d'attaques ultérieures.

- **Model Deployment Tampering** : Des adversaires modifient les artefacts du modèle ou l'infrastructure de serving afin que le modèle en fonctionnement diffère de la version validée, ce qui peut modifier son comportement.

- **Denial of ML Service** : Inonder les APIs ou envoyer des entrées "sponge" peut épuiser les ressources de calcul ou l'énergie et mettre le modèle hors ligne, à l'image des attaques DoS classiques.

- **Model Reverse Engineering** : En collectant un grand nombre de paires entrée-sortie, les attaquants peuvent cloner ou distiller le modèle, favorisant les produits d'imitation et les attaques adversariales personnalisées.

- **Insecure Integrated Component** : Des plugins, agents ou services en amont vulnérables permettent aux attaquants d'injecter du code ou d'élever leurs privilèges au sein du pipeline d'IA.

- **Prompt Injection** : Concevoir des prompts, directement ou indirectement, afin d'y dissimuler des instructions qui outrepassent l'intention du système et font exécuter au modèle des commandes non prévues.

- **Model Evasion** : Des entrées soigneusement conçues poussent le modèle à mal classifier, à halluciner ou à produire du contenu interdit, ce qui érode la sécurité et la confiance.

- **Sensitive Data Disclosure** : Le modèle révèle des informations privées ou confidentielles provenant de ses données d'entraînement ou du contexte utilisateur, en violation de la vie privée et des réglementations.

- **Inferred Sensitive Data** : Le modèle déduit des attributs personnels qui n'ont jamais été fournis, créant de nouveaux préjudices liés à la vie privée par inférence.

- **Insecure Model Output** : Des réponses non nettoyées transmettent du code malveillant, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions** : Des agents intégrés de manière autonome exécutent des opérations réelles non prévues (écritures de fichiers, appels d'API, achats, etc.) sans supervision suffisante de l'utilisateur.

## Matrice MITRE AI ATLAS

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d'IA. Elle classe diverses techniques d'attaque et tactiques que les adversaires peuvent utiliser contre les modèles d'IA, ainsi que les façons d'utiliser les systèmes d'IA pour réaliser différentes attaques.

## LLMJacking (vol de tokens et revente d'accès à des LLM hébergés dans le cloud)

Les attaquants volent des tokens de session actifs ou des identifiants d'API cloud et invoquent sans autorisation des LLM payants hébergés dans le cloud. L'accès est souvent revendu via des reverse proxies qui utilisent le compte de la victime, par exemple des déploiements "oai-reverse-proxy". Les conséquences incluent des pertes financières, une utilisation du modèle contraire aux règles et une attribution au tenant de la victime.

TTPs :
- Collecter les tokens sur les machines de développeurs ou les browsers infectés ; voler les secrets CI/CD ; acheter des cookies ayant fait l'objet d'un leak.
- Mettre en place un reverse proxy qui transmet les requêtes au véritable fournisseur, dissimule la clé en amont et multiplexe de nombreux clients.
- Abuser des endpoints de base-model directs afin de contourner les guardrails d'entreprise et les rate limits.

Mitigations :
- Lier les tokens à l'empreinte de l'appareil, aux plages d'adresses IP et à l'attestation du client ; imposer des expirations courtes et effectuer le refresh avec MFA.
- Limiter au minimum la portée des clés (aucun accès aux outils, lecture seule lorsque cela est applicable) ; effectuer une rotation en cas d'anomalie.
- Terminer tout le trafic côté serveur derrière une policy gateway qui applique des filtres de sécurité, des quotas par route et l'isolation des tenants.
- Surveiller les schémas d'utilisation inhabituels (pics soudains de dépenses, régions atypiques, chaînes UA) et révoquer automatiquement les sessions suspectes.
- Préférer mTLS ou des JWT signés émis par votre IdP à des clés d'API statiques de longue durée.

## Renforcement de l'inférence LLM auto-hébergée

L'exécution d'un serveur LLM local pour des données confidentielles crée une surface d'attaque différente de celle des APIs hébergées dans le cloud : les endpoints d'inférence ou de debug peuvent provoquer un leak de prompts, la stack de serving expose généralement un reverse proxy et les nœuds de périphériques GPU donnent accès à de vastes surfaces `ioctl()`. Si vous évaluez ou déployez un service d'inférence on-prem, examinez au moins les points suivants.

### Fuite de prompts via les endpoints de debug et de monitoring

Traitez l'API d'inférence comme un **service sensible multi-utilisateur**. Les routes de debug ou de monitoring peuvent exposer le contenu des prompts, l'état des slots, les métadonnées du modèle ou les informations relatives aux files d'attente internes. Dans `llama.cpp`, l'endpoint `/slots` est particulièrement sensible, car il expose l'état de chaque slot et est uniquement destiné à l'inspection ou à la gestion des slots.

- Placez un reverse proxy devant le serveur d'inférence et **refusez tout par défaut**.
- N'autorisez que les combinaisons exactes méthode HTTP + chemin dont le client ou l'UI a besoin.
- Désactivez les endpoints d'introspection dans le backend lui-même lorsque cela est possible, par exemple `llama-server --no-slots`.
- Liez le reverse proxy à `127.0.0.1` et exposez-le via un transport authentifié tel que la redirection de port locale SSH, au lieu de le publier sur le LAN.

Exemple d'allowlist avec nginx :
```nginx
map "$request_method:$uri" $llm_whitelist {
default 0;

"GET:/health"              1;
"GET:/v1/models"           1;
"POST:/v1/completions"     1;
"POST:/v1/chat/completions" 1;
}

server {
listen 127.0.0.1:80;

location / {
if ($llm_whitelist = 0) { return 403; }
proxy_pass http://unix:/run/llama-cpp/llama-cpp.sock:;
}
}
```
### Conteneurs rootless sans réseau et sockets UNIX

Si le daemon d'inférence prend en charge l'écoute sur un socket UNIX, préférez cette option à TCP et exécutez le conteneur avec **aucune pile réseau** :
```bash
podman run --rm -d \
--network none \
--user 1000:1000 \
--userns=keep-id \
--umask=007 \
--volume /var/lib/models:/models:ro \
--volume /srv/llm/socks:/run/llama-cpp \
ghcr.io/ggml-org/llama.cpp:server-cuda13 \
--host /run/llama-cpp/llama-cpp.sock \
--model /models/model.gguf \
--parallel 4 \
--no-slots
```
Avantages :
- `--network none` supprime l’exposition TCP/IP entrante/sortante et évite les helpers en mode utilisateur dont les conteneurs rootless auraient autrement besoin.
- Un socket UNIX permet d’utiliser les permissions POSIX/ACL sur le chemin du socket comme première couche de contrôle d’accès.
- `--userns=keep-id` et Podman rootless réduisent l’impact d’un breakout de conteneur, car le root du conteneur n’est pas le root de l’hôte.
- Les montages de modèles en lecture seule réduisent le risque de modification malveillante des modèles depuis l’intérieur du conteneur.

### Minimisation des device nodes GPU

Pour l’inférence s’appuyant sur un GPU, les fichiers `/dev/nvidia*` constituent des surfaces d’attaque locales à forte valeur, car ils exposent de grands gestionnaires `ioctl()` du driver et potentiellement des chemins partagés de gestion de la mémoire GPU.

- Ne laissez pas `/dev/nvidia*` accessibles en écriture à tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACL afin que seul l’UID mappé du conteneur puisse les ouvrir.
- Blacklistez les modules inutilaires tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les serveurs d’inférence sans écran.
- Préchargez uniquement les modules requis au démarrage au lieu de laisser le runtime les charger opportunistement avec `modprobe` lors du démarrage de l’inférence.

Exemple :
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un point important de la revue concerne **`/dev/nvidia-uvm`**. Même si la workload n'utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent tout de même nécessiter `nvidia-uvm`. Comme ce device est partagé et gère la mémoire virtuelle du GPU, traitez-le comme une surface d'exposition de données inter-tenant. Si l'inference backend le permet, un backend Vulkan peut constituer un compromis intéressant, car il peut éviter d'exposer `nvidia-uvm` au container.

### Confinement LSM pour les inference workers

AppArmor/SELinux/seccomp doivent être utilisés comme défense en profondeur autour du processus d'inference :

- N'autorisez que les shared libraries, les chemins des modèles, le socket directory et les GPU device nodes réellement nécessaires.
- Refusez explicitement les capabilities à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Conservez le model directory en lecture seule et limitez les chemins inscriptibles aux runtime socket/cache directories uniquement.
- Surveillez les denial logs, car ils fournissent une télémétrie de détection utile lorsqu'un model server ou un post-exploitation payload tente de s'échapper de son comportement attendu.

Exemple de règles AppArmor pour un worker utilisant un GPU :
```text
deny capability sys_admin,
deny capability sys_module,
deny capability sys_rawio,
deny capability sys_ptrace,

/usr/lib/x86_64-linux-gnu/** mr,
/dev/nvidiactl rw,
/dev/nvidia0 rw,
/var/lib/models/** r,
owner /srv/llm/** rw,
```
## Phantom Squatting : les domaines hallucinés par les LLM comme vecteur de supply chain IA

Le **Phantom Squatting** est l'équivalent **domaine/URL du slopsquatting**. Au lieu d'halluciner le nom d'un package inexistant, le LLM hallucine un **domaine de portail, d'API, de webhook, de facturation, de SSO, de téléchargement ou de support** plausible pour une marque réelle, puis un attaquant enregistre cet espace de noms avant qu'un humain ou un agent ne l'utilise.

Cela est important, car dans de nombreux workflows assistés par IA, la sortie du modèle est traitée comme une **dépendance de confiance** :
- Les développeurs copient le endpoint suggéré dans le code ou les intégrations CI/CD.
- Les agents IA récupèrent automatiquement de la documentation, des schémas, des APK, des ZIP ou des cibles de webhook.
- Les runbooks ou documents générés peuvent intégrer la fausse URL comme si elle faisait autorité.

### Workflow offensif

1. **Sonder la surface d'hallucination** : poser des questions spécifiques à une marque sur des workflows réalistes tels que les portails `admin`, `billing`, `sandbox`, `benefits`, `api`, `download`, `support`, `webhook` ou `mobile app`.
2. **Normaliser les candidats** : résoudre les URL générées, ramener les réponses NXDOMAIN au domaine parent enregistrable et dédupliquer les familles de prompts. Les corpus de prompts doivent rester diversifiés, par exemple en supprimant les quasi-doublons avec la **similarité de Jaccard**.
3. **Prioriser les hallucinations prévisibles** :
- **Thermal Hallucination Persistence (THP)** : le même faux domaine apparaît à différentes températures, y compris à basse température comme `T=0.1`.
- **Consensus inter-modèles** : plusieurs familles de LLM génèrent le même faux domaine.
4. **Enregistrer et armer** le domaine parent, puis héberger du phishing, de faux téléchargements d'APK/ZIP, des collecteurs d'identifiants, des documents malveillants ou des endpoints d'API qui collectent des secrets ou des payloads de webhook. Les **hallucinations purement au niveau du domaine** sont les plus faciles à monétiser, car l'attaquant contrôle tout l'espace de noms ; les hallucinations de sous-domaine/chemin peuvent tout de même être exploitées lorsque le parent normalisé n'est pas enregistré.
5. **Exploiter la fenêtre de réputation nulle** : les domaines nouvellement enregistrés ne possèdent souvent pas encore d'historique dans les blocklists, de réputation URL ni de télémétrie mature ; ils peuvent donc contourner les contrôles jusqu'à ce que les détections rattrapent leur retard. Les attaquants peuvent prolonger cette fenêtre avec des réponses bénignes réservées aux crawlers, du cloaking par redirection, des barrières CAPTCHA ou une mise en scène différée des payloads.

### Pourquoi les agents sont exposés

Pour une victime humaine, le faux domaine nécessite généralement encore un clic et une action supplémentaire. Dans un **workflow agentique**, le LLM peut être à la fois le **leurre** et l'**exécuteur** : l'agent reçoit l'URL hallucinée, la récupère, analyse la réponse et peut ensuite leak des tokens, exécuter des instructions, télécharger une dépendance ou injecter des données empoisonnées dans la CI/CD sans aucune vérification humaine.

### Prompts offensifs pratiques

Les prompts à fort rendement ressemblent généralement à des tâches d'entreprise normales plutôt qu'à des leurres de phishing explicites :
- « Quelle est l'URL du sandbox de paiement pour les intégrations de `<brand>` ? »
- « Quel endpoint de webhook dois-je utiliser pour les notifications de build de `<brand>` ? »
- « Où se trouve le portail des avantages salariés / de facturation / SSO de `<brand>` ? »
- « Donne-moi le téléchargement direct de l'APK Android ou du client desktop de `<brand>`. »

### Inversion défensive

Traitez cela comme un problème de surveillance proactive des domaines, et pas uniquement comme un problème de prompt injection :
- Constituez un **corpus de prompts de marques** et sondez périodiquement les LLM dont dépendent vos utilisateurs ou agents.
- Stockez les URL hallucinées et suivez celles qui restent stables selon les températures et les modèles.
- Suivez l'**Adversarial Exploitation Window (AEW)** : le délai entre la première hallucination et l'enregistrement par l'attaquant. Un AEW positif signifie que les défenseurs peuvent pré-enregistrer, sinkhole ou bloquer préventivement le domaine avant son armement.
- Surveillez les transitions **NXDOMAIN → enregistré** pour les domaines parents.
- Lors de l'enregistrement, analysez le registrar, la date de création, les nameservers, le masquage de la confidentialité, le contenu de la page, les captures d'écran, le statut de page parkée et la similarité avec les ressources de la marque.
- Ajoutez des policy gates afin que les agents et les développeurs ne **fassent pas confiance par défaut aux domaines générés par les LLM** : exigez des allowlists, une validation de propriété, des vérifications CT/RDAP ou une approbation humaine avant la première utilisation.

Cela relève simultanément de plusieurs catégories de risques liés à l'IA : **attaque de la supply chain IA**, **sortie de modèle non sécurisée** et **actions malveillantes** lorsque les agents consomment automatiquement l'URL hallucinée.

## Références
- [Unit 42 – Les risques des LLM assistants de code : contenu nuisible, détournement et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Présentation du schéma LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (revente d'un accès LLM volé)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Analyse approfondie du déploiement d'un serveur LLM on-premise à privilèges limités](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Quadlets Podman : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Spécification CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)
- [Unit 42 – Phantom Squatting : les domaines hallucinés par l'IA comme vecteur de supply chain logicielle](https://unit42.paloaltonetworks.com/phantom-squatting-hallucinated-web-domains/)
- [Socket – Slopsquatting : comment les hallucinations de l'IA alimentent une nouvelle catégorie d'attaques de supply chain](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks)

{{#include ../banners/hacktricks-training.md}}
