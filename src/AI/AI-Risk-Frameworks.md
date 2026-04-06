# Risques liés à l'IA

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Machine Learning Vulnerabilities

Owasp a identifié les 10 principales vulnérabilités du machine learning pouvant affecter les systèmes d'IA. Ces vulnérabilités peuvent provoquer divers problèmes de sécurité, notamment du data poisoning, de la model inversion et des attaques adversariales. Comprendre ces vulnérabilités est crucial pour construire des systèmes d'IA sécurisés.

Pour une liste à jour et détaillée des top 10, consultez le projet [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Input Manipulation Attack**: Un attaquant ajoute de minuscules modifications, souvent invisibles, aux **données entrantes** pour faire prendre une mauvaise décision au modèle.\
*Example*: Quelques éclats de peinture sur un panneau stop trompent une voiture autonome en lui faisant "voir" un panneau de limitation de vitesse.

- **Data Poisoning Attack**: L'**ensemble d'entraînement** est délibérément pollué par des exemples malveillants, apprenant au modèle des règles nuisibles.\
*Example*: Des binaires de malware sont étiquetés à tort comme "benign" dans un corpus d'entraînement d'antivirus, permettant à des malwares similaires de passer inaperçus par la suite.

- **Model Inversion Attack**: En sondant les sorties, un attaquant construit un **modèle inverse** qui reconstruit des caractéristiques sensibles des entrées originales.\
*Example*: Reconstituer l'image IRM d'un patient à partir des prédictions d'un modèle de détection du cancer.

- **Membership Inference Attack**: L'adversaire teste si un **enregistrement spécifique** a été utilisé pendant l'entraînement en repérant des différences de confiance.\
*Example*: Confirmer qu'une transaction bancaire d'une personne figure dans les données d'entraînement d'un modèle de détection de fraude.

- **Model Theft**: Des requêtes répétées permettent à un attaquant d'apprendre les frontières de décision et de **cloner le comportement du modèle** (et la propriété intellectuelle).\
*Example*: Collecter suffisamment de paires Q&A depuis une API ML-as-a-Service pour construire un modèle local quasi équivalent.

- **AI Supply‑Chain Attack**: Compromettre n'importe quel composant (données, bibliothèques, poids pré‑entraînés, CI/CD) dans la **pipeline ML** pour corrompre les modèles en aval.\
*Example*: Une dépendance empoisonnée sur un model‑hub installe un modèle d'analyse de sentiment backdoor across de nombreuses apps.

- **Transfer Learning Attack**: Une logique malveillante est implantée dans un **modèle pré‑entraîné** et survit au fine‑tuning sur la tâche de la victime.\
*Example*: Un backbone vision avec un trigger caché renverse toujours les labels après adaptation pour l'imagerie médicale.

- **Model Skewing**: Des données subtilement biaisées ou mal étiquetées **décalent les sorties du modèle** pour favoriser l'agenda de l'attaquant.\
*Example*: Injecter des spams "propres" étiquetés comme ham pour qu'un filtre anti‑spam laisse passer des emails similaires à l'avenir.

- **Output Integrity Attack**: L'attaquant **altère les prédictions du modèle en transit**, pas le modèle lui‑même, trompant les systèmes en aval.\
*Example*: Inverser le verdict "malicious" d'un classifieur de malware en "benign" avant que l'étape de quarantaine de fichiers ne l'analyse.

- **Model Poisoning** --- Modifications directes et ciblées des **paramètres du modèle** eux‑mêmes, souvent après acquisition d'un accès en écriture, pour altérer le comportement.\
*Example*: Retoucher des poids d'un modèle de détection de fraude en production pour que les transactions provenant de certaines cartes soient toujours approuvées.

## Google SAIF Risks

Le [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) de Google décrit divers risques associés aux systèmes d'IA :

- **Data Poisoning**: Des acteurs malveillants modifient ou injectent des données d'entraînement/tuning pour dégrader la précision, implanter des backdoors ou biaiser les résultats, sapeant l'intégrité du modèle sur tout le cycle de vie des données.

- **Unauthorized Training Data**: L'ingestion de jeux de données protégés par le droit d'auteur, sensibles ou non autorisés crée des risques juridiques, éthiques et de performance car le modèle apprend à partir de données qu'il n'aurait pas dû utiliser.

- **Model Source Tampering**: La manipulation de la chaîne d'approvisionnement ou par un initié du code du modèle, des dépendances ou des poids avant ou pendant l'entraînement peut intégrer une logique cachée qui persiste même après un retraining.

- **Excessive Data Handling**: Des contrôles faibles de rétention et de gouvernance des données entraînent le stockage ou le traitement de plus de données personnelles que nécessaire, augmentant l'exposition et le risque de conformité.

- **Model Exfiltration**: Les attaquants volent des fichiers/poids du modèle, provoquant une perte de propriété intellectuelle et habilitant des services copies ou des attaques de suivi.

- **Model Deployment Tampering**: Les adversaires modifient les artefacts du modèle ou l'infrastructure de serving pour que le modèle en cours d'exécution diffère de la version validée, pouvant altérer son comportement.

- **Denial of ML Service**: Inonder les API ou envoyer des inputs "sponge" peut épuiser le compute/l'énergie et mettre le modèle hors ligne, rappelant les attaques DoS classiques.

- **Model Reverse Engineering**: En récoltant un grand nombre de paires input‑output, les attaquants peuvent cloner ou distiller le modèle, alimentant des produits d'imitation et des attaques adversariales sur mesure.

- **Insecure Integrated Component**: Des plugins vulnérables, agents ou services en amont permettent aux attaquants d'injecter du code ou d'escalader des privilèges dans la pipeline IA.

- **Prompt Injection**: Construire des prompts (directement ou indirectement) pour faire passer des instructions qui outrepassent l'intention système, forçant le modèle à exécuter des commandes non prévues.

- **Model Evasion**: Des inputs soigneusement conçus déclenchent des erreurs de classification, des hallucinations ou des sorties interdites, érodant la sécurité et la confiance.

- **Sensitive Data Disclosure**: Le modèle révèle des informations privées ou confidentielles issues de ses données d'entraînement ou du contexte utilisateur, violant la vie privée et les régulations.

- **Inferred Sensitive Data**: Le modèle déduit des attributs personnels jamais fournis, créant de nouveaux préjudices de vie privée par inférence.

- **Insecure Model Output**: Des réponses non assainies transmettent du code dangereux, de la désinformation ou du contenu inapproprié aux utilisateurs ou aux systèmes en aval.

- **Rogue Actions**: Des agents intégrés de manière autonome exécutent des opérations réelles non souhaitées (écritures de fichiers, appels API, achats, etc.) sans supervision utilisateur adéquate.

## Mitre AI ATLAS Matrix

La [MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) fournit un cadre complet pour comprendre et atténuer les risques associés aux systèmes d'IA. Elle catégorise diverses techniques et tactiques d'attaque que des adversaires peuvent utiliser contre des modèles IA et explique aussi comment utiliser des systèmes IA pour effectuer différentes attaques.

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

Les attaquants volent des tokens de session actifs ou des identifiants d'API cloud et invoquent des LLMs hébergés payants dans le cloud sans autorisation. L'accès est souvent revendu via des reverse proxies qui mettent en avant le compte de la victime, par ex. des déploiements "oai-reverse-proxy". Les conséquences incluent des pertes financières, un mauvais usage du modèle en dehors des politiques et une attribution au tenant victime.

TTPs:
- Harvest tokens from infected developer machines or browsers; stole CI/CD secrets; buy leaked cookies.
- Stand up a reverse proxy that forwards requests to the genuine provider, hiding the upstream key and multiplexing many customers.
- Abuse direct base-model endpoints to bypass enterprise guardrails and rate limits.

Mitigations:
- Bind tokens to device fingerprint, IP ranges, and client attestation; enforce short expirations and refresh with MFA.
- Scope keys minimally (no tool access, read-only where applicable); rotate on anomaly.
- Terminate all traffic server-side behind a policy gateway that enforces safety filters, per-route quotas, and tenant isolation.
- Monitor for unusual usage patterns (sudden spend spikes, atypical regions, UA strings) and auto-revoke suspicious sessions.
- Prefer mTLS or signed JWTs issued by your IdP over long-lived static API keys.

## Sécurisation de l'inférence LLM autohébergée

Faire tourner un serveur LLM local pour des données confidentielles crée une surface d'attaque différente des APIs cloud‑hébergées : les endpoints d'inférence/debug peuvent leak des prompts, la stack de serving expose généralement un reverse proxy, et les nœuds de device GPU donnent accès à de larges surfaces `ioctl()`. Si vous évaluez ou déployez un service d'inférence on‑prem, examinez au minimum les points suivants.

### Prompt leakage via debug and monitoring endpoints

Considérez l'API d'inférence comme un **service multi‑utilisateur sensible**. Les routes de debug ou de monitoring peuvent exposer le contenu des prompts, l'état des slots, les métadonnées du modèle ou des informations de file d'attente internes. Dans `llama.cpp`, le endpoint `/slots` est particulièrement sensible car il expose l'état par slot et n'est destiné qu'à l'inspection/gestion des slots.

- Placez un reverse proxy devant le serveur d'inférence et **deny by default**.
- Only allowlist the exact HTTP method + path combinations that are needed by the client/UI.
- Disable introspection endpoints in the backend itself whenever possible, for example `llama-server --no-slots`.
- Bind the reverse proxy to `127.0.0.1` and expose it through an authenticated transport such as SSH local port forwarding instead of publishing it on the LAN.

Example allowlist with nginx:
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

Si le daemon d'inférence prend en charge l'écoute sur un socket UNIX, privilégiez cela plutôt que TCP et exécutez le conteneur sans **pile réseau** :
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
Avantages:
- `--network none` supprime l'exposition TCP/IP entrante/sortante et évite les helpers en mode utilisateur dont les conteneurs rootless auraient autrement besoin.
- Un socket UNIX permet d'utiliser les permissions POSIX/ACLs sur le chemin du socket comme première couche de contrôle d'accès.
- `--userns=keep-id` et rootless Podman réduisent l'impact d'un échappement de conteneur car le root du conteneur n'est pas le root de l'hôte.
- Les montages de modèle en lecture seule réduisent la probabilité d'altération du modèle depuis l'intérieur du conteneur.

### Minimisation des device-nodes GPU

Pour l'inférence sur GPU, les fichiers `/dev/nvidia*` sont des surfaces d'attaque locales à haute valeur car ils exposent de larges handlers `ioctl()` du driver et potentiellement des chemins partagés de gestion de la mémoire GPU.

- Ne laissez pas `/dev/nvidia*` en écriture pour tous.
- Restreignez `nvidia`, `nvidiactl` et `nvidia-uvm` avec `NVreg_DeviceFileUID/GID/Mode`, des règles udev et des ACLs afin que seul l'UID mappé du conteneur puisse les ouvrir.
- Mettez sur blacklist les modules inutiles tels que `nvidia_drm`, `nvidia_modeset` et `nvidia_peermem` sur les hôtes d'inférence headless.
- Préchargez uniquement les modules requis au boot au lieu de laisser le runtime les `modprobe` de manière opportuniste pendant le démarrage de l'inférence.

Exemple:
```bash
options nvidia NVreg_DeviceFileUID=0
options nvidia NVreg_DeviceFileGID=0
options nvidia NVreg_DeviceFileMode=0660
```
Un point important à vérifier est **`/dev/nvidia-uvm`**. Même si la charge de travail n'utilise pas explicitement `cudaMallocManaged()`, les runtimes CUDA récents peuvent quand même nécessiter `nvidia-uvm`. Comme ce device est partagé et gère la gestion de la mémoire virtuelle GPU, considérez-le comme une surface d'exposition de données cross-tenant. Si l'inference backend le supporte, un backend Vulkan peut être un compromis intéressant car il peut éviter d'exposer `nvidia-uvm` au container.

### Confinement LSM pour les workers d'inférence

AppArmor/SELinux/seccomp doivent être utilisés en défense en profondeur autour du processus d'inférence :

- Autoriser uniquement les bibliothèques partagées, les chemins des modèles, le répertoire de sockets et les nœuds de périphérique GPU réellement requis.
- Refuser explicitement les capacités à haut risque telles que `sys_admin`, `sys_module`, `sys_rawio` et `sys_ptrace`.
- Garder le répertoire des modèles en lecture seule et limiter les chemins en écriture aux seuls répertoires runtime de sockets/cache.
- Surveiller les logs de refus car ils fournissent une télémétrie de détection utile lorsque le serveur de modèles ou un post-exploitation payload tente de s'échapper de son comportement attendu.

Exemple de règles AppArmor pour un worker avec GPU :
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
## Références
- [Unit 42 – Les risques des Code Assistant LLMs : contenus nuisibles, mauvaise utilisation et tromperie](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [Aperçu du schéma LLMJacking – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (revente d'accès LLM volés)](https://gitgud.io/khanon/oai-reverse-proxy)
- [Synacktiv - Analyse approfondie du déploiement d'un serveur LLM sur site faiblement privilégié](https://www.synacktiv.com/en/publications/deep-dive-into-the-deployment-of-an-on-premise-low-privileged-llm-server.html)
- [README du serveur llama.cpp](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
- [Podman quadlets : podman-systemd.unit](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [Spécification CNCF Container Device Interface (CDI)](https://github.com/cncf-tags/container-device-interface/blob/main/SPEC.md)

{{#include ../banners/hacktricks-training.md}}
